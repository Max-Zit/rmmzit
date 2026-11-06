package update

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"
)

// Fuzz targets for release manifests and versions, which come from the
// update source (GitHub or a mirror).

// A manifest is accepted only with a valid signature of a trusted key, and
// then names only plain files.
func FuzzVerifyManifest(f *testing.F) {
	pub, key, _ := ed25519.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{5}, 64)))
	keys := []string{base64.StdEncoding.EncodeToString(pub)}
	good := []byte(`{"product":"RMMZit","version":"0.13.4","files":[{"name":"rmmzit-server_0.13.4_amd64.deb","sha256":"` + strings.Repeat("a", 64) + `"}]}`)
	f.Add(good, true)
	f.Add([]byte(`{"product":"RMMZit","version":"0.13.4","files":[{"name":"../x","sha256":"`+strings.Repeat("a", 64)+`"}]}`), true)
	f.Add([]byte(`{"product":"x","version":"1"}`), false)
	f.Add([]byte("{}"), true)
	f.Fuzz(func(t *testing.T, raw []byte, signed bool) {
		sig := []byte("AAAA")
		if signed {
			sig = Sign(raw, key)
		}
		m, err := Verify(raw, sig, keys)
		if err != nil {
			return
		}
		if !signed {
			t.Fatal("an unsigned manifest was accepted")
		}
		if !versionRe.MatchString(m.Version) {
			t.Fatalf("version %q accepted", m.Version)
		}
		for _, file := range m.Files {
			if !SafeName(file.Name) || strings.ContainsAny(file.Name, `/\`) || strings.Contains(file.Name, "..") {
				t.Fatalf("file name %q accepted", file.Name)
			}
		}
	})
}

// Version comparison never says both a > b and b > a.
func FuzzNewer(f *testing.F) {
	f.Add("0.13.4", "0.13.3")
	f.Add("1.0.0-rc1", "1.0.0")
	f.Add("x.y.z", "")
	f.Fuzz(func(t *testing.T, a, b string) {
		if Newer(a, b) && Newer(b, a) {
			t.Fatalf("Newer(%q, %q) both ways", a, b)
		}
		if Newer(a, a) {
			t.Fatalf("Newer(%q, itself)", a)
		}
	})
}
