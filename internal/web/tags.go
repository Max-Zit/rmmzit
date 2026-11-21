package web

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/max-zit/rmmzit/internal/store"
)

// Tags and dynamic groups. Tags are shared names on devices: technicians
// put them on the devices they see, scripts can run on them, and
// administrators assign policies to them (see mayAssign). A dynamic group is
// a saved search of the device list; its devices are those matching now.

// handleDeviceTagAdd puts a tag (new or existing) on a device.
func (s *Server) handleDeviceTagAdd(w http.ResponseWriter, r *http.Request) {
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
	t, created, err := s.store.EnsureTag(r.Context(), r.FormValue("name"), u.Username)
	if err != nil {
		s.redirectErr(w, r, to, uiErr("Type the name of a tag (1 to 40 characters, no commas)."))
		return
	}
	if created {
		s.audit(r, "tag.create", "tag:"+strconv.FormatInt(t.ID, 10), "created tag %q", t.Name)
	}
	if err := s.store.SetDeviceTag(r.Context(), t.ID, []int64{d.ID}, true); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "device.tag", "device:"+strconv.FormatInt(d.ID, 10), "tag %q added to %q", t.Name, d.Hostname)
	s.redirect(w, r, to, "")
}

// handleDeviceTagRemove takes a tag off a device.
func (s *Server) handleDeviceTagRemove(w http.ResponseWriter, r *http.Request) {
	d := s.deviceFor(w, r)
	if d == nil {
		return
	}
	if !userFrom(r).CanWrite() {
		s.forbidden(w, r)
		return
	}
	tid, ok := pathID(r, "tid")
	t, err := s.store.TagByID(r.Context(), tid)
	if !ok || err != nil {
		s.notFound(w, r)
		return
	}
	if err := s.store.SetDeviceTag(r.Context(), t.ID, []int64{d.ID}, false); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "device.tag", "device:"+strconv.FormatInt(d.ID, 10), "tag %q removed from %q", t.Name, d.Hostname)
	s.redirect(w, r, "/devices/"+strconv.FormatInt(d.ID, 10), "")
}

// handleTags is Settings → Tags (administrators): rename and delete.
func (s *Server) handleTags(w http.ResponseWriter, r *http.Request) {
	tags, err := s.store.Tags(r.Context(), nil) // administrators only
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "tags", &Page{Title: "Tags", Nav: "settings", Data: tags})
}

func (s *Server) handleTagChange(w http.ResponseWriter, r *http.Request) {
	tid, ok := pathID(r, "tid")
	t, err := s.store.TagByID(r.Context(), tid)
	if !ok || err != nil {
		s.notFound(w, r)
		return
	}
	switch r.FormValue("action") {
	case "rename":
		err := s.store.RenameTag(r.Context(), t.ID, r.FormValue("name"))
		switch {
		case errors.Is(err, store.ErrConflict):
			s.redirectErr(w, r, "/settings/tags", uiErr("Another tag already has this name."))
			return
		case err != nil && errors.Is(err, store.ErrBadTagName):
			s.redirectErr(w, r, "/settings/tags", uiErr("Type the name of a tag (1 to 40 characters, no commas)."))
			return
		case err != nil:
			s.serverError(w, r, err)
			return
		}
		s.audit(r, "tag.rename", "tag:"+strconv.FormatInt(t.ID, 10), "tag %q renamed to %q", t.Name, r.FormValue("name"))
	case "delete":
		if err := s.store.DeleteTag(r.Context(), t.ID); err != nil {
			s.serverError(w, r, err)
			return
		}
		s.audit(r, "tag.delete", "tag:"+strconv.FormatInt(t.ID, 10), "deleted tag %q (from its devices, with its policy assignment)", t.Name)
		s.policiesChanged()
	default:
		s.notFound(w, r)
		return
	}
	s.redirect(w, r, "/settings/tags", "Saved.")
}

// handleGroupSave saves the current search of the device list as a group.
func (s *Server) handleGroupSave(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	if !u.CanWrite() {
		s.forbidden(w, r)
		return
	}
	view := parseDeviceView(r)
	if view.Q == "" && !view.F.Any() {
		s.redirectErr(w, r, "/devices", uiErr("Search or filter the devices first, then save that as a group."))
		return
	}
	raw, err := json.Marshal(view)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	id, err := s.store.SaveDeviceGroup(r.Context(), r.FormValue("name"), raw, u.Username)
	switch {
	case errors.Is(err, store.ErrConflict):
		s.redirectErr(w, r, "/devices", uiErr("Another group already has this name."))
		return
	case errors.Is(err, store.ErrBadTagName):
		s.redirectErr(w, r, "/devices", uiErr("Type the name of the group (1 to 40 characters, no commas)."))
		return
	case err != nil:
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "group.create", "group:"+strconv.FormatInt(id, 10), "saved device group %q", r.FormValue("name"))
	s.redirect(w, r, "/devices?group="+strconv.FormatInt(id, 10), "")
}

// handleGroupDelete removes a group (administrators and its creator).
func (s *Server) handleGroupDelete(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	gid, ok := pathID(r, "gid")
	g, err := s.store.DeviceGroup(r.Context(), u, gid)
	if !ok || err != nil {
		s.notFound(w, r)
		return
	}
	if !(&devicesData{}).MayDeleteGroup(u, *g) {
		s.forbidden(w, r)
		return
	}
	if err := s.store.DeleteDeviceGroup(r.Context(), g.ID); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "group.delete", "group:"+strconv.FormatInt(g.ID, 10), "deleted device group %q", g.Name)
	s.redirect(w, r, "/devices", "Saved.")
}
