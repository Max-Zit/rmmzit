package web

import (
	"context"
	"io/fs"
	"strings"
	"time"

	"github.com/max-zit/rmmzit/internal/store"
	"github.com/max-zit/rmmzit/internal/update"
)

// CallForTest sends a command without arguments (tests).
func (s *Server) CallForTest(ctx context.Context, deviceID int64, kind string) error {
	return s.call(ctx, deviceID, "test", kind, nil, nil, 10*time.Second)
}

// MayOpenForTest and DocLinkPaths expose the guide's link rule (tests).
var MayOpenForTest = mayOpen

// DocLinkPaths lists the console pages the guide links to, in all languages.
func DocLinkPaths() map[string]bool {
	paths := map[string]bool{}
	_ = fs.WalkDir(docsFS, "docs", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, _ := fs.ReadFile(docsFS, p)
		for _, m := range docLink.FindAllStringSubmatch(string(b), -1) {
			if !strings.HasPrefix(m[1], "/docs") {
				paths[m[1]] = true
			}
		}
		return nil
	})
	return paths
}

// SetLatestForTest sets the result of the last release check (tests).
func (s *Server) SetLatestForTest(version string) {
	s.upd.mu.Lock()
	defer s.upd.mu.Unlock()
	s.upd.latest = &update.Manifest{Product: update.ManifestProduct, Version: version}
}

// RDConsentForTest exposes the remote desktop consent decision (tests).
func (s *Server) RDConsentForTest(ctx context.Context, d *store.Device) (bool, error) {
	return s.rdConsent(ctx, d)
}
