package web

import (
	"net/http"
	"strings"
	"time"

	"github.com/max-zit/rmmzit/internal/store"
	"github.com/max-zit/rmmzit/internal/update"
)

// The notice of a new RMMZit version at the top of every console page, for
// administrators (they install updates). The version comes only from the
// signature-checked release check (CheckUpdate); the notice never installs
// anything: Install opens Settings → RMMZit updates, where the confirmation
// stays. × hides it for that user for five days, or until a newer version.

const updateHideFor = 5 * 24 * time.Hour

// updateNotice is what the layout shows.
type updateNotice struct {
	Version   string // available
	Installed string
	Container bool   // updated by pulling a new image: no Install button
	NotesURL  string // release notes (the GitHub release of an official source)
	External  bool   // NotesURL is another site (opens in a new tab)
	Back      string // the page to return to after ×
}

// showUpdateNotice is the rule: a newer signed version than the installed
// one, which the user has not hidden (a hidden version shows again after
// five days, and at once when an even newer version comes).
func showUpdateNotice(latest, installed string, u *store.User, now time.Time) bool {
	if latest == "" || !update.Newer(latest, installed) {
		return false
	}
	if u.UpdateHiddenUntil != nil && now.Before(*u.UpdateHiddenUntil) && !update.Newer(latest, u.UpdateHiddenVersion) {
		return false
	}
	return true
}

// updateNoticeFor returns the notice for a page, or nil: administrators
// only, and not on the updates page itself.
func (s *Server) updateNoticeFor(r *http.Request, u *store.User) *updateNotice {
	if u == nil || !u.IsAdmin() || r.URL.Path == "/settings/version" || strings.HasPrefix(r.URL.Path, "/settings/version/") {
		return nil
	}
	s.upd.mu.Lock()
	latest := s.upd.latest
	s.upd.mu.Unlock()
	if latest == nil || !showUpdateNotice(latest.Version, s.Version, u, s.now()) {
		return nil
	}
	n := &updateNotice{Version: latest.Version, Installed: s.Version, Container: s.Container, Back: safeNext(r.URL.RequestURI())}
	if src := s.updateSource(r.Context()); src == update.DefaultSource || src == update.TestingSource {
		n.NotesURL, n.External = "https://github.com/Max-Zit/rmmzit/releases/tag/v"+latest.Version, true
	} else {
		n.NotesURL = "/settings/version#new-version" // the notes of the signed manifest
	}
	return n
}

// handleHideUpdateNotice is the × of the notice.
func (s *Server) handleHideUpdateNotice(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	v := strings.TrimSpace(r.FormValue("version"))
	back := safeNext(r.FormValue("back"))
	if v == "" || len(v) > 20 {
		http.Redirect(w, r, back, http.StatusSeeOther)
		return
	}
	if err := s.store.HideUpdateNotice(r.Context(), u.ID, v, s.now().Add(updateHideFor)); err != nil {
		s.serverError(w, r, err)
		return
	}
	http.Redirect(w, r, back, http.StatusSeeOther)
}
