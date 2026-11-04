package web_test

import (
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/max-zit/rmmzit/internal/store"
	"github.com/max-zit/rmmzit/internal/web"
)

// TestDocLinksMatchAccess opens every console page the guide links to, in
// every language, as a technician and as a read-only user: a page the guide
// shows as a link opens, a page it shows as text is refused. So the guide's
// link rule stays in step with the console's access rules.
func TestDocLinksMatchAccess(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.setupAdmin("192.168.1.10")
	paths := web.DocLinkPaths()
	if len(paths) < 10 {
		t.Fatalf("only %d linked console pages found", len(paths))
	}
	for i, role := range []string{store.RoleTechnician, store.RoleReadOnly} {
		name := "doclinks" + role
		admin.post("/users", "username", name, "password", name+" password 1", "role", role, "all_customers", "1")
		c := e.client("192.168.1." + strconv.Itoa(41+i))
		c.post("/login", "username", name, "password", name+" password 1")
		sec := secretRE.FindStringSubmatch(c.get("/login/enroll").body)[1]
		c.post("/login/enroll", "code", e.code(sec))
		c.post("/account/password", "current", name+" password 1", "password", name+" password 22", "password2", name+" password 22")
		u := &store.User{Role: role}
		for p := range paths {
			r := c.get(p)
			if r.code == http.StatusNotFound || r.code == http.StatusSeeOther {
				continue // pages of things that do not exist in a fresh console
			}
			if may := web.MayOpenForTest(u, p); may && r.code == http.StatusForbidden {
				t.Errorf("%s: the guide links to %s, which is refused", role, p)
			} else if !may && r.code != http.StatusForbidden {
				t.Errorf("%s: the guide shows %s as text, but it opens (%d)", role, p, r.code)
			}
		}
		if b := c.get("/docs/settings").body; strings.Contains(b, `<a href="/settings/version"`) {
			t.Errorf("%s: the guide still links to an administrator page", role)
		}
	}
	if b := admin.get("/docs/settings").body; !strings.Contains(b, `<a href="/settings/version"`) {
		t.Error("the administrator lost the guide's links")
	}
}
