package web

import (
	"io/fs"
	"strings"
	"testing"
)

// The product name in the console is RMMZit, also where the brand is set in
// two parts ("RMM" and a bold "Zit").
func TestBrandName(t *testing.T) {
	for _, f := range []fs.FS{templateFS, docsFS} {
		_ = fs.WalkDir(f, ".", func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			b, _ := fs.ReadFile(f, p)
			low := strings.ToLower(string(b))
			if strings.Contains(low, "controlzit") || strings.Contains(string(b), "Control<") {
				t.Errorf("%s names the product by its old name", p)
			}
			return nil
		})
	}
	b, _ := fs.ReadFile(templateFS, "templates/_layout.html")
	if !strings.Contains(string(b), "RMM<b>Zit</b>") {
		t.Error("the sidebar does not show RMM<b>Zit</b>")
	}
}
