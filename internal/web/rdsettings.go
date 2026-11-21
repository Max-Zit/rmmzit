package web

import (
	"context"
	"net/http"
)

const settingRemote = "remote_desktop"

// RemoteSettings control remote desktop sessions.
type RemoteSettings struct {
	// ShowNotice shows a notice on the remote screen while a technician is
	// connected (default on).
	ShowNotice bool `json:"show_notice"`
	// Clipboard exchanges copied text between the technician and the remote
	// computer (default on).
	Clipboard bool `json:"clipboard"`
	// ReadOnlyView lets read-only users watch the screens of the devices
	// they see, view only (default off).
	ReadOnlyView bool `json:"readonly_view,omitempty"`
}

func defaultRemote() RemoteSettings { return RemoteSettings{ShowNotice: true, Clipboard: true} }

// Remote loads the remote desktop settings.
func (s *Server) Remote(ctx context.Context) RemoteSettings {
	x := defaultRemote()
	if err := s.store.GetSetting(ctx, settingRemote, &x); err != nil {
		return defaultRemote()
	}
	return x
}

func (s *Server) handleRemoteSettings(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, http.StatusOK, "rdsettings", &Page{Title: "Remote desktop", Nav: "settings", Data: s.Remote(r.Context())})
}

func (s *Server) handleRemoteSave(w http.ResponseWriter, r *http.Request) {
	x := RemoteSettings{ShowNotice: r.FormValue("show_notice") == "1", Clipboard: r.FormValue("clipboard") == "1", ReadOnlyView: r.FormValue("readonly_view") == "1"}
	if err := s.store.SetSetting(r.Context(), settingRemote, x); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "settings.remote", "settings", "remote desktop notice on the remote screen: %v, clipboard: %v, read-only users may watch screens: %v", x.ShowNotice, x.Clipboard, x.ReadOnlyView)
	s.redirect(w, r, "/settings/remote", "Saved.")
}
