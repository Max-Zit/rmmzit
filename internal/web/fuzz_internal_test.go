package web

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/max-zit/rmmzit/internal/proto"
)

// Fuzz targets for what the console receives from outside: agent messages,
// sign-in redirects and SSO state, identity provider metadata, uploaded
// certificates and the lists typed into forms. None needs the database.

// Agent messages: no panic, and the limits hold for whatever an agent sends.
func FuzzDecodeAgentMessage(f *testing.F) {
	for _, s := range []string{
		`{"t":"hello","d":{"agent_version":"0.13.4"}}`,
		`{"t":"heartbeat","d":{"metrics":{"cpu":1,"disks":[{},{}],"stopped_auto":["a"]}}}`,
		`{"t":"result","d":{"id":"x","error":"e"}}`,
		`{"t":"patch_report","d":{}}`,
		`{"t":"inventory","d":{"software":[{"name":"a"}]}}`,
		`{"t":"heartbeat","d":null}`,
		`{"t":"nope"}`, `{}`, `[]`, `{"t":"inventory","d":"x"}`,
	} {
		f.Add([]byte(s))
	}
	f.Add([]byte(`{"t":"heartbeat","d":{"metrics":{"disks":[` + strings.Repeat(`{},`, 100) + `{}]}}}`))
	f.Add([]byte(`{"t":"inventory","d":{"software":[` + strings.Repeat(`{},`, 6000) + `{}]}}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		var env proto.Envelope
		if json.Unmarshal(b, &env) != nil {
			return // the connection is closed
		}
		m, err := decodeAgentMessage(env)
		if err != nil {
			return
		}
		if m.Heartbeat != nil && m.Heartbeat.Metrics != nil && (len(m.Heartbeat.Metrics.Disks) > maxAgentDisks || len(m.Heartbeat.Metrics.StoppedAuto) > maxStoppedAuto) {
			t.Fatal("heartbeat over the limits")
		}
		if m.Inventory != nil && len(m.Inventory.Software) > maxAgentSoftware {
			t.Fatal("inventory over the limit")
		}
		set := 0
		for _, p := range []bool{m.Hello != nil, m.Heartbeat != nil, m.Result != nil, m.Patch != nil, m.Inventory != nil} {
			if p {
				set++
			}
		}
		if set != 1 {
			t.Fatalf("%d parts decoded from %q", set, b)
		}
	})
}

// A redirect after sign-in stays on the console.
func FuzzSafeNext(f *testing.F) {
	for _, s := range []string{"/devices", "//evil.example", "/\\evil.example", "/\t/evil.example", "https://evil.example", "/%2F%2Fevil", "", "/a?b=//c", "\x00/"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, p string) {
		got := safeNext(p)
		if got == "/" {
			return
		}
		if got != p || !strings.HasPrefix(got, "/") || strings.HasPrefix(got, "//") || strings.HasPrefix(got, "/\\") {
			t.Fatalf("safeNext(%q) = %q", p, got)
		}
		// What a browser makes of it: control characters dropped, "\" read as "/".
		clean := strings.Map(func(r rune) rune {
			if r < 0x20 || r == 0x7f {
				return -1
			}
			if r == '\\' {
				return '/'
			}
			return r
		}, got)
		if strings.HasPrefix(clean, "//") {
			t.Fatalf("safeNext(%q) = %q leads to another host", p, got)
		}
	})
}

// The SSO state comes back from the browser: only what this console signed
// (and has not expired) is accepted, unchanged.
func FuzzParseState(f *testing.F) {
	good := signState("oidc", "/devices")
	f.Add(good, 0, byte(0))
	f.Add(good, 3, byte(1))
	f.Add("x.y", 0, byte(0))
	f.Add("", 0, byte(0))
	f.Fuzz(func(t *testing.T, tok string, at int, flip byte) {
		if v, ok := parseState(tok); ok && tok != good {
			// Only a token signed with the key passes; the fuzzer cannot sign.
			t.Fatalf("parseState accepted a foreign token %q: %v", tok, v)
		}
		if flip != 0 && len(good) > 0 {
			b := []byte(good)
			i := at % len(b)
			if i < 0 {
				i = -i
			}
			b[i] ^= flip
			if string(b) != good {
				if _, ok := parseState(string(b)); ok {
					// base64 may ignore changed padding bits of the last
					// character; anything else must fail.
					if i != len(b)-1 && b[i] != '.' && i != strings.IndexByte(good, '.')-1 {
						t.Fatalf("changed token accepted (byte %d)", i)
					}
				}
			}
		}
	})
}

// Identity provider metadata (pasted or fetched by the administrator).
func FuzzParseIDPMetadata(f *testing.F) {
	f.Add([]byte(`<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp/sso"/></IDPSSODescriptor></EntityDescriptor>`))
	f.Add([]byte(`<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"><EntityDescriptor entityID="a"/></EntitiesDescriptor>`))
	f.Add([]byte(`<!DOCTYPE x [<!ENTITY a "aaaa">]><EntityDescriptor>&a;</EntityDescriptor>`))
	f.Add([]byte("not xml"))
	f.Fuzz(func(t *testing.T, b []byte) {
		ed, err := parseIDPMetadata(b)
		if err == nil && (ed == nil || len(ed.IDPSSODescriptors) == 0) {
			t.Fatal("metadata without an identity provider accepted")
		}
	})
}

// Uploaded certificate and key: arbitrary PEM never panics or passes.
func FuzzParseKeyPair(f *testing.F) {
	f.Add([]byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"), []byte("-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----\n"), "rmm.example.com")
	f.Add([]byte(""), []byte(""), "")
	f.Fuzz(func(t *testing.T, cert, key []byte, host string) {
		if c, err := ParseKeyPair(cert, key, host, time.Now()); err == nil && c == nil {
			t.Fatal("no certificate and no error")
		}
	})
}

// Lists typed into forms.
func FuzzFormLists(f *testing.F) {
	f.Add("a@example.com, b@example.com;c@example.com")
	f.Add("4624 4625,1102")
	f.Add("customer:12")
	f.Add("\"x\r\nBcc: e@evil\" <a@example.com>")
	f.Add("-1,99999999999999999999,0x10")
	f.Fuzz(func(t *testing.T, s string) {
		if mails, err := parseEmails(s); err == nil {
			if len(mails) > 20 {
				t.Fatalf("%d addresses accepted", len(mails))
			}
			for _, m := range mails {
				if strings.ContainsAny(m, "\r\n,;<> ") || !strings.Contains(m, "@") {
					t.Fatalf("address %q from %q", m, s)
				}
			}
		}
		if ids, err := parseEventIDs(s); err == nil {
			for _, n := range ids {
				if n < 0 || n > 65535 {
					t.Fatalf("event ID %d from %q", n, s)
				}
			}
		}
		if codes, ok := parseCodes(s); ok && (len(codes) == 0 || len(codes) > 20) {
			t.Fatalf("%d codes accepted from %q", len(codes), s)
		}
		if kind, id, ok := parseTargetRef(s); ok {
			if (kind != "customer" && kind != "site" && kind != "device") || id <= 0 || s != kind+":"+strconv.FormatInt(id, 10) && !strings.HasPrefix(s, kind+":+") && !strings.HasPrefix(s, kind+":0") {
				t.Fatalf("parseTargetRef(%q) = %s %d", s, kind, id)
			}
		}
	})
}
