//go:build linux

package rd

import (
	"strings"
	"testing"
)

func TestWrapASCII(t *testing.T) {
	lines := wrapASCII("Ana Šimić wants to connect "+strings.Repeat("x", 80)+" and more words here", 20)
	for _, l := range lines {
		if len(l) > 20 {
			t.Fatalf("line longer than 20: %q", l)
		}
		for _, r := range l {
			if r < 0x20 || r >= 0x7f {
				t.Fatalf("not ASCII: %q", l)
			}
		}
	}
	if lines[0] != "Ana ?imi? wants to" || len(lines) > 6 {
		t.Fatalf("lines %q", lines)
	}
}
