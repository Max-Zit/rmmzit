package web_test

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/max-zit/rmmzit/internal/store"
)

// Trusted reverse proxies (issue #18): from a listed proxy the console
// takes the client from X-Forwarded-For / X-Real-IP for the allowed
// networks, the sign-in protection and the audit log; from any other
// address the headers change nothing.
func TestTrustedProxy(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.setupAdmin("192.168.1.10")
	ctx := context.Background()
	save := func(proxies string) resp {
		return admin.post("/settings/network", "mgmt_listen", ":8443", "agent_listen", ":8444",
			"mgmt_allowed", "192.168.0.0/16\n203.0.113.0/24", "trusted_proxies", proxies)
	}
	if r := save("0.0.0.0/0"); r.code != http.StatusBadRequest || !strings.Contains(r.body, "cannot be every address") {
		t.Fatalf("a proxy list that trusts everyone was accepted: %d", r.code)
	}

	wrong := url.Values{"username": {"admin"}, "password": {"wrong password!"}}
	blocked := func(ip string) bool {
		bs, _ := e.st.Blocks(ctx)
		for _, b := range bs {
			if b.IP == ip {
				return true
			}
		}
		return false
	}

	// No trusted proxy: a forged header is ignored; the peer is blocked.
	spoof := e.client("192.168.1.77")
	for range 5 {
		spoof.do(http.MethodPost, "/login", wrong, map[string]string{"X-Forwarded-For": "203.0.113.50"})
	}
	if !blocked("192.168.1.77") || blocked("203.0.113.50") {
		t.Fatal("without a trusted proxy the header changed the address")
	}

	if r := save("10.0.0.5"); r.code != http.StatusSeeOther {
		t.Fatalf("save trusted proxies: %d %s", r.code, r.body)
	}
	proxy := e.client("10.0.0.5")
	// Through the proxy: the right-most address that is not a proxy counts
	// (the left one was written by the client and is not believed).
	for range 5 {
		proxy.do(http.MethodPost, "/login", wrong, map[string]string{"X-Forwarded-For": "198.18.0.1, 203.0.113.9"})
	}
	if !blocked("203.0.113.9") || blocked("10.0.0.5") || blocked("198.18.0.1") {
		t.Fatal("the client behind the trusted proxy was not the one blocked")
	}
	// Another client behind the same proxy can still sign in.
	if r := proxy.do(http.MethodPost, "/login", url.Values{"username": {"admin"}, "password": {"admin password 123"}},
		map[string]string{"X-Real-IP": "203.0.113.10"}); r.code != http.StatusSeeOther {
		t.Fatalf("a second client behind the proxy was locked out: %d", r.code)
	}
	via := e.client("10.0.0.5")
	via.cookies = admin.cookies
	// An action through the proxy is audited with the client's address.
	via.do(http.MethodPost, "/customers", url.Values{"name": {"Proxy Ltd"}}, map[string]string{"X-Forwarded-For": "203.0.113.10"})
	es, _ := e.st.AuditEntries(ctx, store.AuditFilter{Limit: 500})
	found := false
	for _, x := range es {
		found = found || x.IP == "203.0.113.10" && x.Action == "customer.create"
	}
	if !found {
		t.Fatal("the audit log does not show the client behind the proxy")
	}
	// The allowed networks apply to the client, not to the proxy.
	if r := proxy.do(http.MethodGet, "/login", nil, map[string]string{"X-Forwarded-For": "198.51.100.1"}); r.code != http.StatusForbidden {
		t.Fatalf("a client outside the allowed networks came in through the proxy: %d", r.code)
	}
	// A broken header is not believed: the proxy's own address counts, and
	// the proxy itself is not in the allowed networks.
	if r := proxy.do(http.MethodGet, "/login", nil, map[string]string{"X-Forwarded-For": "203.0.113.9, not-an-ip"}); r.code != http.StatusForbidden {
		t.Fatalf("broken header: %d", r.code)
	}
	if r := admin.get("/settings/network"); !strings.Contains(r.body, ">10.0.0.5<") {
		t.Fatalf("the trusted proxies are not shown: %d %s", r.code, r.loc)
	}
}
