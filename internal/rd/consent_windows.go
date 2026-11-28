//go:build windows

package rd

import (
	"context"
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var pMessageBoxTimeout = user32.NewProc("MessageBoxTimeoutW")

const (
	mbYesNo         = 0x00000004
	mbIconQuestion  = 0x00000020
	mbDefButton2    = 0x00000100 // "No" is the default: Enter does not allow
	mbSystemModal   = 0x00001000
	mbSetForeground = 0x00010000
	mbTopmost       = 0x00040000
	idYes           = 6
	idNo            = 7
	idTimeout       = 32000
)

// AskConsent asks the signed-in user whether the technician may connect.
// Without a user on the input desktop (sign-in screen, locked screen) it
// returns ConsentNobody: the technician then sees only that screen.
func AskConsent(ctx context.Context, technician string, viewOnly bool, timeout time.Duration) Consent {
	type answer struct{ c Consent }
	res := make(chan answer, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		h, _, _ := pOpenInputDesktop.Call(0, 0, desktopAllAccess)
		if h == 0 {
			res <- answer{ConsentNobody}
			return
		}
		defer pCloseDesktop.Call(h) //nolint:errcheck
		if deskName(h) != "Default" {
			res <- answer{ConsentNobody}
			return
		}
		if r, _, _ := pSetThreadDesktop.Call(h); r == 0 {
			res <- answer{ConsentUnavailable}
			return
		}
		text, _ := windows.UTF16PtrFromString(consentText(technician, viewOnly))
		title, _ := windows.UTF16PtrFromString("RMMZit remote desktop")
		r, _, _ := pMessageBoxTimeout.Call(0, uintptr(unsafe.Pointer(text)), uintptr(unsafe.Pointer(title)), // #nosec G103 -- Win32 strings
			mbYesNo|mbIconQuestion|mbDefButton2|mbSystemModal|mbSetForeground|mbTopmost, 0, uintptr(min(max(timeout.Milliseconds(), 1000), 600000))) // #nosec G115 -- clamped to 1–600 s
		switch r {
		case idYes:
			res <- answer{ConsentYes}
		case idTimeout:
			res <- answer{ConsentTimeout}
		case idNo:
			res <- answer{ConsentNo}
		default:
			res <- answer{ConsentUnavailable}
		}
	}()
	select {
	case a := <-res:
		return a.c
	case <-ctx.Done():
		return ConsentNo
	}
}
