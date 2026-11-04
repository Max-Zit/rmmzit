package web

import (
	"context"
	"io/fs"
	"strings"
	"time"
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
