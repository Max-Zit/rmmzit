package web_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/max-zit/rmmzit/internal/agent"
	"github.com/max-zit/rmmzit/internal/proto"
)

// Wake-on-LAN: an offline device of a site is woken through an online
// agent of the same site; read-only users may not; a device without a
// MAC address or without a relay gets a clear message.
func TestWakeOnLAN(t *testing.T) {
	e := newEnv(t)
	e.useRealClock()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	e.srv.CommandKey = key
	admin, _ := e.setupAdmin("192.168.1.10")
	ctx := context.Background()
	cust, _ := e.st.CreateCustomer(ctx, "Wake Ltd", "")
	site, _ := e.st.CreateSite(ctx, cust, "Office", "", "")

	// The sleeping computer: enrolled, offline, with a network card.
	tok, _ := e.st.CreateEnrollToken(ctx, site, "", "admin", time.Hour, 2)
	pc, err := e.st.EnrollDevice(ctx, tok, []byte(strings.Repeat("w", 32)), "sleepy", "", "Windows", "0.14.0", "10.0.0.9")
	if err != nil {
		t.Fatal(err)
	}
	id := itoa(pc.ID)
	if r := admin.post("/devices/" + id + "/wake"); !strings.Contains(r.loc, "/devices/"+id) {
		t.Fatalf("wake without MAC: %d %s", r.code, r.loc)
	}
	if b := admin.get("/devices/" + id).body; !strings.Contains(b, "no network card address") {
		t.Fatal("no message for a device without MAC")
	}
	_ = e.st.SaveInventory(ctx, pc.ID, &proto.Inventory{Hostname: "sleepy", Network: []proto.NetAdapter{{Name: "eth", MAC: "00:15:5D:AA:BB:CC", IPs: []string{"10.0.0.9"}}}})
	if b := admin.get("/devices/" + id).body; !strings.Contains(b, "/devices/"+id+"/wake") {
		t.Fatal("no Wake up button for an offline device with a MAC")
	}
	admin.post("/devices/" + id + "/wake")
	if b := admin.get("/devices/" + id).body; !strings.Contains(b, "No online device") {
		t.Fatal("no message without a relay")
	}

	// A relay agent in the same site.
	agent.ProtectDir = func(string) error { return nil }
	url, fp := agentServer(t, e)
	dir := t.TempDir()
	cfg, err := agent.Enroll(ctx, dir, url, fp, tok)
	if err != nil {
		t.Fatal(err)
	}
	runCtx, cancel := context.WithCancel(ctx)
	a := &agent.Agent{Dir: dir, Cfg: cfg, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Info:    func() agent.SysInfo { return agent.SysInfo{OS: "Windows"} },
		Collect: func(context.Context) *proto.Inventory { return &proto.Inventory{} }, Metrics: func(context.Context) *proto.Metrics { return &proto.Metrics{} }}
	done := make(chan struct{})
	go func() { _ = a.Run(runCtx); close(done) }()
	defer func() { cancel(); <-done }()
	waitFor(t, "relay agent", func() bool { return e.srv.Connected(cfg.DeviceID) })

	ro := e.signedIn(t, admin, "wakero", "readonly", "192.168.1.42")
	if c := ro.post("/devices/" + id + "/wake").code; c != http.StatusForbidden {
		t.Fatalf("read-only wake: %d", c)
	}
	if r := admin.post("/devices/" + id + "/wake"); r.code != http.StatusSeeOther {
		t.Fatalf("wake: %d", r.code)
	}
	if b := admin.get("/devices/" + id).body; !strings.Contains(b, "Wake-up packet sent through") {
		t.Fatalf("wake did not go through the relay: %s", flashText(b))
	}
	if b := admin.get("/audit").body; !strings.Contains(b, "device.wake") || !strings.Contains(b, "00:15:5d:aa:bb:cc") {
		t.Fatal("wake not audited")
	}
}

func flashText(b string) string {
	i := strings.Index(b, `class="flash`)
	if i < 0 {
		return "(no message)"
	}
	j := strings.Index(b[i:], "</div>")
	return b[i : i+j]
}
