package rmmzit

import (
	"strings"
	"testing"
)

func TestNotices(t *testing.T) {
	n := Notices()
	for _, want := range []string{"GNU AFFERO GENERAL PUBLIC LICENSE", "# Third-party licenses", "github.com/jackc/pgx", "Lucide"} {
		if !strings.Contains(n, want) {
			t.Errorf("notices without %q", want)
		}
	}
}
