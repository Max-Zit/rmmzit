package web

import (
	"context"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/max-zit/rmmzit/internal/proto"
	"github.com/max-zit/rmmzit/internal/store"
)

// Wake-on-LAN: the console asks online agents in the same site as the
// sleeping computer to send the magic packet for its MAC addresses (from
// its inventory). Agents in the same IPv4 network come first; at most
// wakeRelays are used.

const (
	wakeRelays       = 3
	wakeAgentVersion = "0.14.0" // the first agent with wol.send
)

// wakeMACs are the usable MAC addresses of a device's network cards.
func wakeMACs(d *store.Device) []string {
	if d.Inventory == nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, a := range d.Inventory.Network {
		m, ok := proto.ParseMAC(a.MAC)
		if !ok {
			continue
		}
		s := net.HardwareAddr(m[:]).String()
		if !seen[s] && len(out) < proto.MaxWakeMACs {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// sameNet24 reports whether two devices have IPv4 addresses in one /24.
func sameNet24(a, b *store.Device) bool {
	nets := map[string]bool{}
	for _, d := range []*store.Device{a} {
		if d.Inventory == nil {
			return false
		}
		for _, n := range d.Inventory.Network {
			for _, ip := range n.IPs {
				if v := net.ParseIP(ip).To4(); v != nil {
					nets[string(v[:3])] = true
				}
			}
		}
	}
	if b.Inventory == nil {
		return false
	}
	for _, n := range b.Inventory.Network {
		for _, ip := range n.IPs {
			if v := net.ParseIP(ip).To4(); v != nil && nets[string(v[:3])] {
				return true
			}
		}
	}
	return false
}

// wakeRelaysFor picks the online agents that send the packet.
func (s *Server) wakeRelaysFor(ctx context.Context, u *store.User, d *store.Device) ([]*store.Device, error) {
	list, err := s.store.Devices(ctx, u, store.DeviceFilter{SiteID: d.SiteID, Limit: 2000})
	if err != nil {
		return nil, err
	}
	var out []*store.Device
	for _, x := range list {
		if x.ID != d.ID && x.Online(s.now(), onlineWindow) && s.Connected(x.ID) && !tooOldFor(x, wakeAgentVersion) {
			out = append(out, x)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return sameNet24(d, out[i]) && !sameNet24(d, out[j]) })
	if len(out) > wakeRelays {
		out = out[:wakeRelays]
	}
	return out, nil
}

func (s *Server) handleDeviceWake(w http.ResponseWriter, r *http.Request) {
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
	macs := wakeMACs(d)
	if len(macs) == 0 {
		s.redirectErr(w, r, to, uiErr("The inventory of this device has no network card address (MAC) to wake it with."))
		return
	}
	relays, err := s.wakeRelaysFor(r.Context(), u, d)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if len(relays) == 0 {
		s.redirectErr(w, r, to, uiErr("No online device with agent 0.14 or newer in the same site can send the wake-up packet."))
		return
	}
	var names []string
	for _, x := range relays {
		var res proto.WakeResult
		if err := s.call(r.Context(), x.ID, u.Username, proto.KindWake, proto.WakeArgs{MACs: macs}, &res, 20*time.Second); err != nil {
			s.log.Warn("wake-on-LAN through a device failed", "device", d.ID, "relay", x.ID, "err", err)
			continue
		}
		names = append(names, x.Hostname)
	}
	if len(names) == 0 {
		s.redirectErr(w, r, to, uiErr("The devices of the site could not send the wake-up packet."))
		return
	}
	s.audit(r, "device.wake", "device:"+strconv.FormatInt(d.ID, 10), "Wake-on-LAN for %q (%s) sent through %s", d.Hostname, strings.Join(macs, ", "), strings.Join(names, ", "))
	s.redirect(w, r, to, translate(s.lang(r, u), "Wake-up packet sent through %s. The computer comes online in a minute or two if Wake-on-LAN is switched on in its BIOS and network card.", strings.Join(names, ", ")))
}
