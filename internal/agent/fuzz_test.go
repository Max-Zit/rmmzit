package agent

import (
	"net/url"
	"strings"
	"testing"

	"github.com/max-zit/rmmzit/internal/proto"
)

// Fuzz targets for what an agent reads from outside: the enrollment code a
// technician pastes (or an installer passes), and the output of package
// managers the agent parses.

// An accepted enrollment code always names an https server without path,
// user or query, a 64-digit fingerprint and a token.
func FuzzParseEnrollCode(f *testing.F) {
	fp := strings.Repeat("ab", 32)
	f.Add(proto.MakeEnrollCode(proto.EnrollData{Server: "https://rmm.example.com:8444", Fingerprint: fp, Token: "tok"}))
	f.Add(proto.MakeEnrollCode(proto.EnrollData{Server: "https://user@evil.example/x?y", Fingerprint: fp, Token: "t"}))
	f.Add(proto.MakeEnrollCode(proto.EnrollData{Server: "http://rmm.example.com", Fingerprint: "AB:CD", Token: " "}))
	f.Add("CZ1-e30")
	f.Add("RZ1-!!!")
	f.Add("  RZ1-" + strings.Repeat("A", 300))
	f.Fuzz(func(t *testing.T, code string) {
		d, err := ParseEnrollCode(code)
		if err != nil {
			return
		}
		u, perr := url.Parse(d.Server)
		if perr != nil || u.Scheme != "https" || u.Host == "" || u.Path != "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			t.Fatalf("code %q gave server %q", code, d.Server)
		}
		if len(d.Fingerprint) != 64 || strings.Trim(d.Fingerprint, "0123456789abcdef") != "" {
			t.Fatalf("code %q gave fingerprint %q", code, d.Fingerprint)
		}
		if strings.TrimSpace(d.Token) == "" {
			t.Fatalf("code %q gave an empty token", code)
		}
		// What the console makes from the parsed data reads back the same.
		if again, err := ParseEnrollCode(proto.MakeEnrollCode(proto.EnrollData(d))); err != nil || again != d {
			t.Fatalf("round trip of %q: %+v %v", code, again, err)
		}
	})
}

// Output of winget and Chocolatey (third-party programs): no panic, and
// every package found has an id.
func FuzzParsePackageLists(f *testing.F) {
	f.Add("Name   Id          Version Available Source\n----------------------------------------\nGit    Git.Git     2.40    2.41      winget\n", false)
	f.Add("git|2.40.0|2.41.0|false\n7zip|23.01|23.01|false\n", true)
	f.Add("\x00\n-\n", false)
	f.Fuzz(func(t *testing.T, out string, outdated bool) {
		for _, p := range append(parseWingetTable(out), parseChoco(out, outdated)...) {
			if strings.TrimSpace(p.ID) == "" {
				t.Fatalf("package without id from %q: %+v", out, p)
			}
		}
	})
}
