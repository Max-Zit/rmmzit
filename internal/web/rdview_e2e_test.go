package web_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/max-zit/rmmzit/internal/proto"
)

// signedIn makes a user with a role and signs it in from its own address.
func (e *env) signedIn(t *testing.T, admin *client, name, role, ip string) *client {
	t.Helper()
	admin.post("/users", "username", name, "password", name+" password 1", "role", role, "all_customers", "1")
	c := e.client(ip)
	c.post("/login", "username", name, "password", name+" password 1")
	sec := secretRE.FindStringSubmatch(c.get("/login/enroll").body)[1]
	c.post("/login/enroll", "code", e.code(sec))
	c.post("/account/password", "current", name+" password 1", "password", name+" password 22", "password2", name+" password 22")
	return c
}

// View-only remote desktop: technicians choose it, read-only users get it
// only when the setting allows, and never the other parts of a session.
func TestRemoteViewOnly(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.setupAdmin("192.168.1.10")
	d := e.device(t, "win-view", "Microsoft Windows 11 Pro")
	id := itoa(d.ID)
	tech := e.signedIn(t, admin, "viewtech", "technician", "192.168.1.41")
	ro := e.signedIn(t, admin, "viewro", "readonly", "192.168.1.42")

	// Technician: the device page offers both, the view-only page says so.
	if b := tech.get("/devices/" + id).body; !strings.Contains(b, `/rd?view=1"`) || !strings.Contains(b, `/devices/`+id+`/rd"`) {
		t.Fatal("technician: device page lacks the view-only tile")
	}
	r := tech.get("/devices/" + id + "/rd?view=1")
	if r.code != http.StatusOK || !strings.Contains(r.body, `data-view="1"`) || !strings.Contains(r.body, `/rd/ws?view=1`) || !strings.Contains(r.body, `id="rd-cad" hidden`) {
		t.Fatalf("technician view-only page: %d", r.code)
	}
	if r := tech.get("/devices/" + id + "/rd"); !strings.Contains(r.body, `data-view="0"`) {
		t.Fatal("technician: a normal session became view-only")
	}

	// Read-only user, setting off (default): no tile, page and socket refused.
	if b := ro.get("/devices/" + id).body; strings.Contains(b, "/rd?view=1") {
		t.Fatal("read-only user sees the screen tile while the setting is off")
	}
	for _, p := range []string{"/rd", "/rd?view=1", "/rd/ws?view=1"} {
		if c := ro.get("/devices/" + id + p).code; c != http.StatusForbidden {
			t.Errorf("read-only %s with the setting off: %d", p, c)
		}
	}

	// Setting on: view-only only, even when the URL asks for control.
	admin.post("/settings/remote", "show_notice", "1", "clipboard", "1", "readonly_view", "1")
	if !e.srv.Remote(t.Context()).ReadOnlyView {
		t.Fatal("setting not saved")
	}
	if b := ro.get("/devices/" + id).body; !strings.Contains(b, "/rd?view=1") || strings.Contains(b, `/devices/`+id+`/rd"`) {
		t.Fatal("read-only device page: wrong screen tiles")
	}
	for _, p := range []string{"/rd", "/rd?view=0"} {
		if r := ro.get("/devices/" + id + p); r.code != http.StatusOK || !strings.Contains(r.body, `data-view="1"`) || !strings.Contains(r.body, `data-clip="0"`) {
			t.Errorf("read-only %s: %d, not view-only", p, r.code)
		}
	}
	// Files, terminal and uploads stay closed to read-only users.
	if c := ro.do(http.MethodPost, "/devices/"+id+"/rd/upload", nil, nil).code; c != http.StatusForbidden {
		t.Errorf("read-only upload: %d", c)
	}
	for _, p := range []string{"/files", "/terminal"} {
		if c := ro.get("/devices/" + id + p).code; c != http.StatusForbidden {
			t.Errorf("read-only %s: %d", p, c)
		}
	}
	if b := admin.get("/audit").body; !strings.Contains(b, "read-only users may watch screens: true") {
		t.Fatal("setting change not audited")
	}
}

// Only acknowledgements, quality, monitor and refresh pass in view only.
func TestViewOnlyInput(t *testing.T) {
	for _, ok := range []string{"ack", "q", "mon", "full"} {
		if !proto.ViewOnlyInput(ok) {
			t.Errorf("%s refused", ok)
		}
	}
	for _, no := range []string{"m", "k", "text", "clip", "cad", "stage", "files", "", "ACK", "mon "} {
		if proto.ViewOnlyInput(no) {
			t.Errorf("%q allowed", no)
		}
	}
}
