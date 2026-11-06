package netacl

import (
	"strings"
	"testing"
)

// The network allow-lists are typed by an administrator; a list that
// parses gives masked networks that format and parse back the same.
func FuzzParseList(f *testing.F) {
	f.Add("10.0.0.0/8\n192.168.1.5 # office\n::1, fe80::/10")
	f.Add("999.1.1.0/24")
	f.Add("::ffff:10.0.0.1/128")
	f.Add(strings.Repeat("10.0.0.1,", 300))
	f.Fuzz(func(t *testing.T, s string) {
		list := Split(s)
		ps, err := Parse(list)
		if err != nil {
			return
		}
		if len(ps) > MaxEntries {
			t.Fatalf("%d networks accepted", len(ps))
		}
		for _, p := range ps {
			if !p.IsValid() || p != p.Masked() || p.Addr().Is4In6() {
				t.Fatalf("network %v from %q", p, s)
			}
		}
		again, err := Parse(Strings(ps))
		if err != nil || len(again) != len(ps) {
			t.Fatalf("formatted list does not parse back: %v", err)
		}
		for i := range ps {
			if again[i] != ps[i] {
				t.Fatalf("%v became %v", ps[i], again[i])
			}
		}
	})
}
