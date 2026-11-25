package web

import (
	"context"
	"encoding/csv"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/max-zit/rmmzit/internal/proto"
	"github.com/max-zit/rmmzit/internal/store"
)

// Display name, moving to another site and removing: on the device page
// and for the devices chosen in the device list.

// sitesFor lists the sites of the customers the user may see, to move
// devices into.
func (s *Server) sitesFor(ctx context.Context, u *store.User) ([]store.Site, error) {
	return s.store.SitesFor(ctx, u)
}

// targetSite returns the site of a form value when the user may see its
// customer, or nil.
func (s *Server) targetSite(ctx context.Context, u *store.User, v string) *store.Site {
	id, err := strconv.ParseInt(v, 10, 64)
	if err != nil || id <= 0 {
		return nil
	}
	x, err := s.store.Site(ctx, id)
	if err != nil || !u.SeesCustomer(x.CustomerID) {
		return nil
	}
	return x
}

func (s *Server) handleDeviceRename(w http.ResponseWriter, r *http.Request) {
	d := s.deviceFor(w, r)
	if d == nil {
		return
	}
	if !userFrom(r).CanWrite() {
		s.forbidden(w, r)
		return
	}
	name := store.CleanDeviceName(r.FormValue("name"))
	to := "/devices/" + strconv.FormatInt(d.ID, 10)
	if name == d.Name {
		s.redirect(w, r, to, "")
		return
	}
	if err := s.store.RenameDevice(r.Context(), d.ID, name); err != nil {
		s.serverError(w, r, err)
		return
	}
	if name == "" {
		s.audit(r, "device.rename", deviceTarget(d), "display name %q removed; the device shows its hostname %q", d.Name, d.RealHostname)
	} else {
		s.audit(r, "device.rename", deviceTarget(d), "display name of %q set to %q (was %q)", d.RealHostname, name, d.Name)
	}
	s.redirect(w, r, to, "Saved.")
}

func (s *Server) handleDeviceMove(w http.ResponseWriter, r *http.Request) {
	d := s.deviceFor(w, r)
	if d == nil {
		return
	}
	u := userFrom(r)
	if !u.CanWrite() {
		s.forbidden(w, r)
		return
	}
	to := "/devices/" + strconv.FormatInt(d.ID, 10)
	x := s.targetSite(r.Context(), u, r.FormValue("site"))
	if x == nil {
		s.redirect(w, r, to, "Choose a site.")
		return
	}
	if x.ID == d.SiteID {
		s.redirect(w, r, to, "")
		return
	}
	if err := s.store.MoveDevice(r.Context(), d.ID, x.ID); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "device.move", deviceTarget(d), "moved %q from site %q of %q to site %q of %q", d.Hostname, d.Site, d.Customer, x.Name, x.Customer)
	s.redirect(w, r, to, "The device was moved. The policies of its new site and customer apply now.")
}

// removeDevice removes a device; an online agent is asked to uninstall
// itself first. removing reports that it answered.
func (s *Server) removeDevice(r *http.Request, d *store.Device) (removing bool, err error) {
	// An online agent uninstalls itself first (and gives Windows Update its
	// own settings back); an offline one is removed by hand.
	removing = s.call(r.Context(), d.ID, s.issuer(r), proto.KindAgentRemove, nil, nil, 15*time.Second) == nil
	if err := s.store.DeleteDevice(r.Context(), d.ID); err != nil {
		return removing, err
	}
	s.disconnect(d.ID)
	what := "its agent can no longer connect"
	if removing {
		what = "its agent is uninstalling itself"
	}
	s.audit(r, "device.delete", "device:"+strconv.FormatInt(d.ID, 10), "removed device %q from site %q of %q; %s", d.Hostname, d.Site, d.Customer, what)
	return removing, nil
}

// bulkRemove removes the chosen devices, eight at a time (each online
// agent gets up to 15 seconds to answer).
func (s *Server) bulkRemove(r *http.Request, devs []*store.Device) (removed int) {
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for _, d := range devs {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer func() { <-sem; wg.Done() }()
			if _, err := s.removeDevice(r, d); err != nil {
				s.log.Warn("device list remove", "device", d.ID, "err", err)
				return
			}
			mu.Lock()
			removed++
			mu.Unlock()
		}()
	}
	wg.Wait()
	return removed
}

// bulkMove moves the chosen devices into one site.
func (s *Server) bulkMove(r *http.Request, devs []*store.Device, x *store.Site) (moved int) {
	for _, d := range devs {
		if d.SiteID == x.ID {
			continue
		}
		if err := s.store.MoveDevice(r.Context(), d.ID, x.ID); err != nil {
			s.log.Warn("device list move", "device", d.ID, "err", err)
			continue
		}
		s.audit(r, "device.move", deviceTarget(d), "moved %q from site %q of %q to site %q of %q (device list)", d.Hostname, d.Site, d.Customer, x.Name, x.Customer)
		moved++
	}
	return moved
}

// apiDeviceName sets the display name: {"name": "SERVER-MADRID-01"}, or ""
// to show the hostname again.
func (s *Server) apiDeviceName(r *http.Request, u *store.User) (int, any, error) {
	d, err := s.apiDeviceFor(r, u)
	if err != nil {
		return 0, nil, err
	}
	var in struct {
		Name *string `json:"name"`
	}
	if err := apiBody(r, &in); err != nil {
		return 0, nil, err
	}
	if in.Name == nil {
		return 0, nil, apiErr(http.StatusBadRequest, "name is missing")
	}
	name := store.CleanDeviceName(*in.Name)
	if name != d.Name {
		if err := s.store.RenameDevice(r.Context(), d.ID, name); err != nil {
			return 0, nil, err
		}
		s.audit(r, "device.rename", deviceTarget(d), "display name of %q set to %q (was %q) (API)", d.RealHostname, name, d.Name)
	}
	d, err = s.store.Device(r.Context(), d.ID)
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, map[string]any{"device": s.deviceJSON(d)}, nil
}

// deviceCSV writes the device list as shown (search, filters, group) as a
// CSV file. A cell that a spreadsheet would read as a formula gets a
// leading apostrophe.
func (s *Server) deviceCSV(w http.ResponseWriter, r *http.Request, d *devicesData) {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="rmmzit-devices-`+s.now().Format("20060102-1504")+`.csv"`)
	c := csv.NewWriter(w)
	_ = c.Write([]string{"id", "name", "hostname", "customer", "site", "os", "os_build", "agent", "online", "user", "last_seen", "tags"})
	for _, x := range d.Devices {
		var tags []string
		for _, t := range d.DevTags[x.ID] {
			tags = append(tags, t.Name)
		}
		row := []string{strconv.FormatInt(x.ID, 10), x.Hostname, x.RealHostname, x.Customer, x.Site, x.OS, x.OSBuild, x.AgentVersion,
			strconv.FormatBool(d.Online(x)), x.LastUser, fmtTime(x.LastSeenAt), strings.Join(tags, ", ")}
		for i := range row {
			row[i] = csvCell(row[i])
		}
		_ = c.Write(row)
	}
	c.Flush()
	s.audit(r, "devices.export", "devices", "exported %d devices as CSV", len(d.Devices))
}

// csvCell keeps a spreadsheet from running a value as a formula.
func csvCell(v string) string {
	if v != "" && strings.ContainsRune("=+-@\t\r", rune(v[0])) {
		return "'" + v
	}
	return v
}
