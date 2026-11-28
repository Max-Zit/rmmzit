package rd

import (
	"strings"
	"testing"
)

func TestConsentText(t *testing.T) {
	if s := consentText("Ana", false); !strings.HasPrefix(s, "Ana wants to connect to this computer and control it") {
		t.Fatalf("control: %q", s)
	}
	if s := consentText("Ana", true); !strings.Contains(s, "view this screen") || strings.Contains(s, "control") {
		t.Fatalf("view only: %q", s)
	}
}
