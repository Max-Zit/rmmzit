package web_test

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// The new-version notice: administrators see it on every page but the
// updates page, other roles never (and get 403 on hiding it); × hides it
// for that user in every browser, it comes back after five days and at
// once for a newer version; Docker consoles get no Install button.
func TestUpdateNotice(t *testing.T) {
	e := newEnv(t)
	admin, sec := e.setupAdmin("192.168.1.10")
	tech := e.signedIn(t, admin, "updtech", "technician", "192.168.1.41")
	ro := e.signedIn(t, admin, "updro", "readonly", "192.168.1.42")
	const marker = `class="flash warn upd"`

	if strings.Contains(admin.get("/devices").body, marker) {
		t.Fatal("notice without a newer version")
	}
	e.srv.SetLatestForTest("99.0.0")
	b := admin.get("/devices").body
	if !strings.Contains(b, marker) || !strings.Contains(b, "99.0.0") || !strings.Contains(b, `href="/settings/version#new-version">Install`) ||
		!strings.Contains(b, `releases/tag/v99.0.0" target="_blank"`) {
		t.Fatal("administrator: notice missing or incomplete")
	}
	if strings.Contains(admin.get("/settings/version").body, marker) {
		t.Fatal("notice on the updates page itself")
	}
	for _, c := range []*client{tech, ro} {
		if strings.Contains(c.get("/devices").body, marker) {
			t.Fatal("a non-administrator sees the notice")
		}
		if r := c.post("/settings/version/hide-notice", "version", "99.0.0", "back", "/devices"); r.code != http.StatusForbidden {
			t.Fatalf("non-administrator hides the notice: %d", r.code)
		}
	}

	// × returns to the same page (only a local path) and hides it in another
	// browser of the same user too.
	if r := admin.post("/settings/version/hide-notice", "version", "99.0.0", "back", "/customers?x=1"); r.code != http.StatusSeeOther || r.loc != "/customers?x=1" {
		t.Fatalf("hide: %d %s", r.code, r.loc)
	}
	if r := admin.post("/settings/version/hide-notice", "version", "99.0.0", "back", "//evil.example/x"); r.loc != "/" {
		t.Fatalf("open redirect after hiding: %s", r.loc)
	}
	other := e.client("192.168.1.11")
	other.post("/login", "username", "admin", "password", "admin password 123")
	other.post("/login/2fa", "code", e.code(sec))
	for _, c := range []*client{admin, other} {
		if strings.Contains(c.get("/devices").body, marker) {
			t.Fatal("hidden notice still shown")
		}
	}
	// A newer version shows it again at once.
	e.srv.SetLatestForTest("99.0.1")
	if !strings.Contains(admin.get("/devices").body, "99.0.1") {
		t.Fatal("a newer version did not show the notice again")
	}
	// Hidden again, back after five days.
	admin.post("/settings/version/hide-notice", "version", "99.0.1", "back", "/devices")
	// (sessions end after 8 hours: sign in again after each jump)
	fresh := func(ip string) *client {
		c := e.client(ip)
		c.post("/login", "username", "admin", "password", "admin password 123")
		c.post("/login/2fa", "code", e.code(sec))
		if r := c.get("/devices"); r.code != http.StatusOK {
			t.Fatalf("sign-in after the clock jump: %d", r.code)
		}
		return c
	}
	e.now = e.now.Add(4 * 24 * time.Hour)
	if strings.Contains(fresh("192.168.1.12").get("/devices").body, marker) {
		t.Fatal("notice back before five days")
	}
	e.now = e.now.Add(25 * time.Hour)
	admin = fresh("192.168.1.13")
	if !strings.Contains(admin.get("/devices").body, marker) {
		t.Fatal("notice not back after five days")
	}

	// Docker: no Install button, the commands instead.
	e.srv.Container = true
	b = admin.get("/devices").body
	if strings.Contains(b, `#new-version">Install`) || !strings.Contains(b, `#new-version">Commands`) || !strings.Contains(b, "Pull the new image") {
		t.Fatal("container console: wrong notice")
	}
}
