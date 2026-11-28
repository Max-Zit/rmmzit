//go:build windows

package rd

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The consent window: a small card in the middle of the screen with the
// technician's name, what they want, a countdown, and the buttons Allow
// (accent) and Deny. Esc and Enter deny; Allow takes a click, so typing in
// another program cannot allow a session by accident.

var (
	pSetTimer         = user32.NewProc("SetTimer")
	pKillTimer        = user32.NewProc("KillTimer")
	pInvalidateRect   = user32.NewProc("InvalidateRect")
	pSetForeground    = user32.NewProc("SetForegroundWindow")
	pRoundRect        = gdi32.NewProc("RoundRect")
	pGetStockObject   = gdi32.NewProc("GetStockObject")
	pGetDeviceCaps    = gdi32.NewProc("GetDeviceCaps")
	consentProcOnce   sync.Once
	consentProcPtr    uintptr
	consentMu         sync.Mutex
	consentState      *consentWin
	consentBrushCache = map[uint32]uintptr{}
)

const (
	wmKeyDown     = 0x0100
	wmTimer       = 0x0113
	wmLButtonDown = 0x0201
	csDropShadow  = 0x00020000
	vkEscape      = 0x1B
	vkReturn      = 0x0D
	nullPen       = 8
	logPixelsY    = 90
	dtLeft        = 0x00
	dtWordBreak   = 0x10

	// Colors (0x00BBGGRR).
	colAccent   = 0x00E5464F // #4f46e5
	colWhite    = 0x00FFFFFF
	colText     = 0x00271811 // #111827
	colMuted    = 0x00806B6B // #6b6b80
	colDenyBg   = 0x00EBE7E5 // #e5e7eb
	colBorder   = 0x00DBD5D1 // #d1d5db
	consentBase = 96
)

type consentWin struct {
	scale             float64
	title, name, what string
	left              int
	answer            Consent
	fonts             map[string]uintptr
	allow, deny       rect
}

func (c *consentWin) px(v int) int32 { return int32(float64(v) * c.scale) } // #nosec G115 -- small sizes

func brush(col uint32) uintptr {
	if b, ok := consentBrushCache[col]; ok {
		return b
	}
	b, _, _ := pCreateSolidBrush.Call(uintptr(col))
	consentBrushCache[col] = b
	return b
}

func (c *consentWin) font(key string, size, weight int) uintptr {
	if f, ok := c.fonts[key]; ok {
		return f
	}
	face, _ := windows.UTF16PtrFromString("Segoe UI")
	f, _, _ := pCreateFont.Call(uintptr(-c.px(size)), 0, 0, 0, uintptr(weight), 0, 0, 0, 1, 0, 0, 5, 0, uintptr(unsafe.Pointer(face))) // #nosec G103 G115 -- ClearType, negative = pixel height
	c.fonts[key] = f
	return f
}

func drawText(hdc uintptr, s string, r rect, color uint32, font uintptr, flags uintptr) {
	u, _ := windows.UTF16FromString(s)
	_, _, _ = pSelectObject.Call(hdc, font)
	_, _, _ = pSetTextColor.Call(hdc, uintptr(color))
	_, _, _ = pDrawText.Call(hdc, uintptr(unsafe.Pointer(&u[0])), uintptr(len(u)-1), uintptr(unsafe.Pointer(&r)), flags) // #nosec G103 -- Win32 buffers
}

func (c *consentWin) paint(hwnd uintptr) {
	var ps paintStruct
	hdc, _, _ := pBeginPaint.Call(hwnd, uintptr(unsafe.Pointer(&ps))) // #nosec G103 -- Win32 struct
	var rc rect
	_, _, _ = pGetClientRect.Call(hwnd, uintptr(unsafe.Pointer(&rc))) // #nosec G103 -- Win32 struct
	fill := func(r rect, col uint32) { _, _, _ = pFillRect.Call(hdc, uintptr(unsafe.Pointer(&r)), brush(col)) } // #nosec G103 -- Win32 struct
	fill(rc, colBorder)
	inner := rect{rc.Left + 1, rc.Top + 1, rc.Right - 1, rc.Bottom - 1}
	fill(inner, colWhite)
	head := rect{inner.Left, inner.Top, inner.Right, inner.Top + c.px(46)}
	fill(head, colAccent)
	_, _, _ = pSetBkMode.Call(hdc, 1) // TRANSPARENT
	pad := c.px(22)
	drawText(hdc, c.title, rect{head.Left + pad, head.Top, head.Right - pad, head.Bottom}, colWhite, c.font("head", 15, 600), dtLeft|dtVCenter|dtSingleLine)
	y := head.Bottom + c.px(18)
	drawText(hdc, c.name, rect{inner.Left + pad, y, inner.Right - pad, y + c.px(26)}, colText, c.font("name", 18, 700), dtLeft|dtSingleLine|dtEndEllipsis)
	y += c.px(28)
	drawText(hdc, c.what, rect{inner.Left + pad, y, inner.Right - pad, y + c.px(44)}, colText, c.font("body", 14, 400), dtLeft|dtWordBreak)
	y += c.px(46)
	drawText(hdc, fmt.Sprintf("Allow only if you expect it. Closes in %d s.", c.left), rect{inner.Left + pad, y, inner.Right - pad, y + c.px(20)}, colMuted, c.font("small", 12, 400), dtLeft|dtSingleLine)
	// Buttons, bottom right: Deny, then Allow.
	bw, bh, gap := c.px(116), c.px(38), c.px(12)
	by := inner.Bottom - pad - bh
	c.allow = rect{inner.Right - pad - bw, by, inner.Right - pad, by + bh}
	c.deny = rect{c.allow.Left - gap - bw, by, c.allow.Left - gap, by + bh}
	pen, _, _ := pGetStockObject.Call(nullPen)
	_, _, _ = pSelectObject.Call(hdc, pen)
	round := func(r rect, col uint32) {
		_, _, _ = pSelectObject.Call(hdc, brush(col))
		_, _, _ = pRoundRect.Call(hdc, uintptr(r.Left), uintptr(r.Top), uintptr(r.Right), uintptr(r.Bottom), uintptr(c.px(10)), uintptr(c.px(10))) // #nosec G115 -- small coordinates
	}
	round(c.deny, colDenyBg)
	round(c.allow, colAccent)
	drawText(hdc, "Deny", c.deny, colText, c.font("btn", 14, 600), dtCenter|dtVCenter|dtSingleLine)
	drawText(hdc, "Allow", c.allow, colWhite, c.font("btn", 14, 600), dtCenter|dtVCenter|dtSingleLine)
	_, _, _ = pEndPaint.Call(hwnd, uintptr(unsafe.Pointer(&ps))) // #nosec G103 -- Win32 struct
}

func inRect(r rect, x, y int32) bool { return x >= r.Left && x < r.Right && y >= r.Top && y < r.Bottom }

func consentProc(hwnd uintptr, m uint32, wp, lp uintptr) uintptr {
	consentMu.Lock()
	c := consentState
	consentMu.Unlock()
	if c != nil {
		done := func(a Consent) {
			c.answer = a
			_, _, _ = pKillTimer.Call(hwnd, 1)
			_, _, _ = pDestroyWindow.Call(hwnd)
		}
		switch m {
		case wmPaint:
			c.paint(hwnd)
			return 0
		case wmTimer:
			if c.left--; c.left <= 0 {
				done(ConsentTimeout)
			} else {
				_, _, _ = pInvalidateRect.Call(hwnd, 0, 0)
			}
			return 0
		case wmLButtonDown:
			x, y := int32(int16(lp&0xffff)), int32(int16(lp>>16&0xffff)) // #nosec G115 -- client coordinates
			switch {
			case inRect(c.allow, x, y):
				done(ConsentYes)
			case inRect(c.deny, x, y):
				done(ConsentNo)
			}
			return 0
		case wmKeyDown:
			if wp == vkEscape || wp == vkReturn {
				done(ConsentNo)
			}
			return 0
		case wmClose:
			done(ConsentNo)
			return 0
		case wmDestroy:
			_, _, _ = pPostQuitMessage.Call(0)
			return 0
		}
	}
	r, _, _ := pDefWindowProc.Call(hwnd, uintptr(m), wp, lp)
	return r
}

// AskConsent asks the signed-in user whether the technician may connect.
// Without a user on the input desktop (sign-in screen, locked screen) it
// returns ConsentNobody: the technician then sees only that screen.
func AskConsent(ctx context.Context, technician string, viewOnly bool, timeout time.Duration) Consent {
	res := make(chan Consent, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		h, _, _ := pOpenInputDesktop.Call(0, 0, desktopAllAccess)
		if h == 0 {
			res <- ConsentNobody
			return
		}
		defer pCloseDesktop.Call(h) //nolint:errcheck
		if deskName(h) != "Default" {
			res <- ConsentNobody
			return
		}
		if r, _, _ := pSetThreadDesktop.Call(h); r == 0 {
			res <- ConsentUnavailable
			return
		}
		res <- showConsent(technician, viewOnly, timeout)
	}()
	select {
	case a := <-res:
		return a
	case <-ctx.Done():
		return ConsentNo
	}
}

func showConsent(technician string, viewOnly bool, timeout time.Duration) Consent {
	_, _, _ = pSetProcessDPIAware.Call()
	sdc, _, _ := pGetDC.Call(0)
	dpi, _, _ := pGetDeviceCaps.Call(sdc, logPixelsY)
	_, _, _ = pReleaseDC.Call(0, sdc)
	if dpi == 0 {
		dpi = consentBase
	}
	what := "wants to connect to this computer and control it with RMMZit remote desktop."
	if viewOnly {
		what = "wants to view this screen with RMMZit remote desktop (no control)."
	}
	c := &consentWin{scale: float64(dpi) / consentBase, title: "RMMZit  ·  Remote desktop", name: technician, what: what,
		left: max(int(timeout/time.Second), 1), answer: ConsentTimeout, fonts: map[string]uintptr{}}
	consentMu.Lock()
	consentState = c
	consentMu.Unlock()
	defer func() {
		consentMu.Lock()
		consentState = nil
		consentMu.Unlock()
		for _, f := range c.fonts {
			_, _, _ = pDeleteObject.Call(f)
		}
	}()
	inst, _, _ := pGetModuleHandle.Call(0)
	consentProcOnce.Do(func() { consentProcPtr = syscall.NewCallback(consentProc) })
	cls, _ := windows.UTF16PtrFromString("RMMZitConsent")
	arrow, _, _ := pLoadCursor.Call(0, 32512)
	wc := wndClassEx{Style: csDropShadow, WndProc: consentProcPtr, ClassName: cls, Cursor: windows.Handle(arrow), Instance: windows.Handle(inst)}
	wc.Size = uint32(unsafe.Sizeof(wc))
	_, _, _ = pRegisterClassEx.Call(uintptr(unsafe.Pointer(&wc))) // #nosec G103 -- Win32 struct; fails harmlessly when already registered
	w, h := int(c.px(460)), int(c.px(250))
	x, y := (metric(0)-w)/2, (metric(1)-h)/3
	title, _ := windows.UTF16PtrFromString("RMMZit remote desktop")
	hwnd, _, _ := pCreateWindowEx.Call(wsExTopmost|wsExToolWindow, uintptr(unsafe.Pointer(cls)), uintptr(unsafe.Pointer(title)), // #nosec G103 -- Win32 strings
		wsPopup|wsVisible, uintptr(x), uintptr(y), uintptr(w), uintptr(h), 0, 0, inst, 0) // #nosec G115 -- screen coordinates
	if hwnd == 0 {
		return ConsentUnavailable
	}
	_, _, _ = pSetForeground.Call(hwnd)
	_, _, _ = pSetTimer.Call(hwnd, 1, 1000, 0)
	var m msg
	for {
		r, _, _ := pGetMessage.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0) // #nosec G103 -- Win32 struct
		if r == 0 || int32(r) == -1 {                                     // #nosec G115 -- GetMessage returns -1 on error
			break
		}
		_, _, _ = pTranslateMessage.Call(uintptr(unsafe.Pointer(&m))) // #nosec G103 -- Win32 struct
		_, _, _ = pDispatchMessage.Call(uintptr(unsafe.Pointer(&m)))  // #nosec G103 -- Win32 struct
	}
	return c.answer
}
