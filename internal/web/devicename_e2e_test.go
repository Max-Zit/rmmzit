package web_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/max-zit/rmmzit/internal/agent"
	"github.com/max-zit/rmmzit/internal/proto"
	"github.com/max-zit/rmmzit/internal/store"
)

// Display names: given at enrollment (enroll --name, MSI DEVICENAME=) or in
// the console, shown instead of the hostname, never changed by the agent.
func TestDeviceName(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.setupAdmin("192.168.1.10")
	ctx := context.Background()
	agent.ProtectDir = func(string) error { return nil }

	cust, _ := e.st.CreateCustomer(ctx, "Name Ltd", "")
	site, _ := e.st.CreateSite(ctx, cust, "Madrid", "", "")
	tok, _ := e.st.CreateEnrollToken(ctx, site, "", "admin", time.Hour, 1)
	url, fp := agentServer(t, e)
	dir := t.TempDir()
	cfg, err := agent.EnrollWith(ctx, dir, agent.EnrollData{Server: url, Fingerprint: fp, Token: tok, Name: "  SERVER-MADRID-01\u202e\x00 "})
	if err != nil {
		t.Fatal(err)
	}
	d, _ := e.st.Device(ctx, cfg.DeviceID)
	if d.Name != "SERVER-MADRID-01" || d.Hostname != "SERVER-MADRID-01" || d.RealHostname == "" || d.RealHostname == d.Name {
		t.Fatalf("enrolled with a name: %+v", d)
	}
	id := itoa(d.ID)

	// The agent reports its hostname; the name stays.
	a := &agent.Agent{Dir: dir, Cfg: cfg, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Info:    func() agent.SysInfo { return agent.SysInfo{OS: "Windows"} },
		Collect: func(context.Context) *proto.Inventory { return &proto.Inventory{} },
		Metrics: func(context.Context) *proto.Metrics { return &proto.Metrics{} }}
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { _ = a.Run(runCtx); close(done) }()
	waitFor(t, "agent channel", func() bool { return e.srv.Connected(d.ID) })
	cancel()
	<-done
	if d, _ = e.st.Device(ctx, d.ID); d.Name != "SERVER-MADRID-01" {
		t.Fatalf("the agent changed the name: %+v", d)
	}

	// The list shows the name with the hostname next to it; search finds both.
	for _, q := range []string{"", "MADRID", strings.ToLower(d.RealHostname)} {
		b := admin.get("/devices?q=" + q).body
		if !strings.Contains(b, ">SERVER-MADRID-01</a>") || !strings.Contains(b, d.RealHostname) {
			t.Fatalf("device list (q=%q) does not show the name and hostname", q)
		}
	}
	// API: name as shown, hostname as reported.
	apiTok := tokenRE.FindString(admin.post("/account/tokens", "name", "names", "role", "readonly", "days", "30").body)
	code, body := apiCall(e, apiTok, "GET", "/api/v1/devices/"+id, "")
	var got struct {
		Device struct{ Name, Hostname string }
	}
	if err := json.Unmarshal([]byte(body), &got); code != http.StatusOK || err != nil {
		t.Fatalf("API: %d %v", code, err)
	}
	dev := got.Device
	if dev.Name != "SERVER-MADRID-01" || dev.Hostname != d.RealHostname {
		t.Fatalf("API: %+v", dev)
	}

	// API: a read-only token may not rename, a writing one may.
	if c, _ := apiCall(e, apiTok, "PUT", "/api/v1/devices/"+id+"/name", `{"name":"x"}`); c != http.StatusForbidden {
		t.Fatalf("read-only token renamed: %d", c)
	}
	rwTok := tokenRE.FindString(admin.post("/account/tokens", "name", "names rw", "role", "admin", "days", "30").body)
	if c, body := apiCall(e, rwTok, "PUT", "/api/v1/devices/"+id+"/name", `{"name":" API name "}`); c != http.StatusOK || !strings.Contains(body, `"name": "API name"`) {
		t.Fatalf("API rename: %d %s", c, body)
	}
	if c, _ := apiCall(e, rwTok, "PUT", "/api/v1/devices/"+id+"/name", `{}`); c != http.StatusBadRequest {
		t.Fatalf("API rename without a name: %d", c)
	}

	// CSV export of the list: names that a spreadsheet would run are quoted.
	admin.post("/devices/"+id+"/name", "name", "=HYPERLINK(1)")
	if r := admin.get("/devices?q=hyperlink&format=csv"); !strings.HasPrefix(r.body, "id,name,hostname,") || !strings.Contains(r.body, ",'=HYPERLINK(1),") {
		t.Fatalf("CSV export: %q", r.body)
	}
	if b := admin.get("/devices?q=hyperlink").body; !strings.Contains(b, "q=hyperlink&amp;format=csv") && !strings.Contains(b, "format=csv&amp;q=hyperlink") {
		t.Fatal("no CSV link for the search shown")
	}

	// Rename in the console, then back to the hostname.
	admin.post("/devices/"+id+"/name", "name", "Web 1")
	if d, _ = e.st.Device(ctx, d.ID); d.Hostname != "Web 1" {
		t.Fatalf("renamed: %+v", d)
	}
	admin.post("/devices/"+id+"/name", "name", strings.Repeat("x", 300))
	if d, _ = e.st.Device(ctx, d.ID); len(d.Name) != store.MaxDeviceName {
		t.Fatalf("long name kept %d characters", len(d.Name))
	}
	admin.post("/devices/"+id+"/name", "name", "")
	if d, _ = e.st.Device(ctx, d.ID); d.Name != "" || d.Hostname != d.RealHostname {
		t.Fatalf("name removed: %+v", d)
	}
	if !e.audited(t, "device.rename") {
		t.Fatal("rename not audited")
	}
}

// Same hostname: the list marks devices that report one hostname, counting
// only the devices the user may see.
func TestSameHostname(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.setupAdmin("192.168.1.10")
	ctx := context.Background()
	a := e.device(t, "clone", "Microsoft Windows 11 Pro")
	other, _ := e.st.CreateCustomer(ctx, "Other Ltd", "")
	e.deviceIn(t, other, "CLONE")
	e.device(t, "unique", "Microsoft Windows 11 Pro")
	if b := admin.get("/devices").body; strings.Count(b, "Same hostname") != 2 {
		t.Fatalf("administrator: %d marks", strings.Count(b, "Same hostname"))
	}
	tech := e.signedInFor(t, admin, "clonetech", a.CustomerID, "192.168.1.51")
	if b := tech.get("/devices").body; strings.Contains(b, "Same hostname") {
		t.Fatal("a device of another customer counts for a user who cannot see it")
	}
}

// Moving devices to another site and removing the chosen ones: only into
// sites of customers the user may see.
func TestDeviceMoveAndBulkRemove(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.setupAdmin("192.168.1.10")
	ctx := context.Background()
	pc := e.device(t, "move-pc", "Microsoft Windows 11 Pro")
	branch, _ := e.st.CreateSite(ctx, pc.CustomerID, "Branch", "", "")
	other, _ := e.st.CreateCustomer(ctx, "Other Ltd", "")
	otherSite, _ := e.st.CreateSite(ctx, other, "Secret site", "", "")
	tech := e.signedInFor(t, admin, "movetech", pc.CustomerID, "192.168.1.51")
	id := itoa(pc.ID)

	b := tech.get("/devices/" + id).body
	if !strings.Contains(b, "Branch") || strings.Contains(b, "Secret site") {
		t.Fatal("device page: the sites to move into are not the user's")
	}
	if b := tech.get("/devices").body; strings.Contains(b, "Secret site") {
		t.Fatal("device list offers a site of another customer")
	}
	// Into another customer's site: refused, nothing moves.
	tech.post("/devices/"+id+"/move", "site", itoa(otherSite))
	tech.post("/devices/bulk", "action", "move", "site", itoa(otherSite), "ids", id)
	if d, _ := e.st.Device(ctx, pc.ID); d.SiteID != pc.SiteID {
		t.Fatal("a technician moved a device into another customer's site")
	}
	tech.post("/devices/"+id+"/move", "site", itoa(branch))
	if d, _ := e.st.Device(ctx, pc.ID); d.SiteID != branch {
		t.Fatalf("moved: site %d", d.SiteID)
	}
	tech.post("/devices/bulk", "action", "move", "site", itoa(pc.SiteID), "ids", id)
	if d, _ := e.st.Device(ctx, pc.ID); d.SiteID != pc.SiteID {
		t.Fatal("bulk move did not move the device back")
	}
	if !e.audited(t, "device.move") {
		t.Fatal("move not audited")
	}

	// Remove: a device of another customer in the list is skipped.
	theirs := e.deviceIn(t, other, "their-pc")
	second := e.device(t, "second-pc", "Microsoft Windows 11 Pro")
	r := tech.post("/devices/bulk", "do", "delete", "ids", id, "ids", itoa(second.ID), "ids", itoa(theirs.ID))
	if r.code != http.StatusSeeOther {
		t.Fatalf("bulk remove: %d", r.code)
	}
	for _, x := range []*store.Device{pc, second} {
		if _, err := e.st.Device(ctx, x.ID); err == nil {
			t.Fatalf("%s was not removed", x.Hostname)
		}
	}
	if _, err := e.st.Device(ctx, theirs.ID); err != nil {
		t.Fatal("a technician removed another customer's device")
	}

	// Read-only users may do neither.
	if c := e.signedIn(t, admin, "roname", "readonly", "192.168.1.61").post("/devices/"+itoa(theirs.ID)+"/name", "name", "x").code; c != http.StatusForbidden && c != http.StatusNotFound {
		t.Fatalf("read-only rename: %d", c)
	}
}

func TestCleanDeviceName(t *testing.T) {
	for in, want := range map[string]string{
		"  Web  1 ":              "Web 1",
		"a\tb\nc":                "a b c",
		"evil\u202eexe.txt":      "evil exe.txt",
		"\x00":                   "",
		"Šabac-01 čćžšđ":         "Šabac-01 čćžšđ",
		"bad\xffutf8":            "badutf8",
		strings.Repeat("é", 150): strings.Repeat("é", store.MaxDeviceName),
	} {
		if got := store.CleanDeviceName(in); got != want {
			t.Errorf("CleanDeviceName(%q) = %q, want %q", in, got, want)
		}
	}
}

// audited reports an audit entry with this action.
func (e *env) audited(t *testing.T, action string) bool {
	t.Helper()
	es, err := e.st.AuditEntries(context.Background(), store.AuditFilter{Limit: 500})
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range es {
		if x.Action == action {
			return true
		}
	}
	return false
}

// deviceTable is the device list's table (without the bar above it).
func deviceTable(body string) string {
	if i := strings.Index(body, "<table"); i >= 0 {
		return body[i:]
	}
	return body
}
