//go:build !windows && !linux

package rd

import (
	"context"
	"time"
)

// AskConsent cannot ask on this system.
func AskConsent(context.Context, string, bool, time.Duration) Consent { return ConsentUnavailable }
