//go:build linux

package rd

import (
	"context"
	"fmt"
	"time"

	"github.com/jezek/xgb"
	"github.com/jezek/xgb/xproto"
)

// AskConsent shows a card in the middle of the X screen like the Windows
// one: a coloured header, the technician's name, what they want, a
// countdown and the buttons Allow and Deny; it waits for a click.
func AskConsent(ctx context.Context, technician string, viewOnly bool, timeout time.Duration) Consent {
	c, err := xgb.NewConn()
	if err != nil {
		return ConsentUnavailable
	}
	defer c.Close()
	scr := xproto.Setup(c).DefaultScreen(c)
	const (
		accent, white, text, muted, denyBg, border = 0x4f46e5, 0xffffff, 0x111827, 0x6b6b80, 0xe5e7eb, 0xd1d5db
		w, pad, headH, btnW, btnH                  = 520, 22, 40, 116, 36
	)
	what := "wants to connect to this computer and control it with RMMZit remote desktop."
	if viewOnly {
		what = "wants to view this screen with RMMZit remote desktop (no control)."
	}
	body := wrapASCII(what, 52)
	name := wrapASCII(technician, 40)
	if len(name) == 0 {
		name = []string{"A technician"}
	}
	h := headH + 18 + 24 + len(body)*20 + 12 + 18 + 18 + btnH + pad
	sw, sh := int(scr.WidthInPixels), int(scr.HeightInPixels)
	x, y := (sw-w)/2, (sh-h)/3
	win, _ := xproto.NewWindowId(c)
	xproto.CreateWindow(c, scr.RootDepth, win, scr.Root, int16(x), int16(y), uint16(w), uint16(h), 1, // #nosec G115 -- screen size
		xproto.WindowClassInputOutput, scr.RootVisual,
		xproto.CwBackPixel|xproto.CwBorderPixel|xproto.CwOverrideRedirect|xproto.CwEventMask,
		[]uint32{white, border, 1, xproto.EventMaskExposure | xproto.EventMaskButtonPress | xproto.EventMaskKeyPress})
	title := "RMMZit remote desktop"
	xproto.ChangeProperty(c, xproto.PropModeReplace, win, xproto.AtomWmName, xproto.AtomString, 8, uint32(len(title)), []byte(title)) // #nosec G115 -- constant

	openFont := func(names ...string) (xproto.Font, int, bool) {
		for _, n := range names {
			f, _ := xproto.NewFontId(c)
			if xproto.OpenFontChecked(c, f, uint16(len(n)), n).Check() == nil { // #nosec G115 -- short names
				return f, 0, true
			}
		}
		return 0, 0, false
	}
	big, _, bigOK := openFont("-misc-fixed-bold-r-normal--18-*-*-*-*-*-iso8859-1", "9x18bold", "fixed")
	small, _, smallOK := openFont("-misc-fixed-medium-r-normal--14-*-*-*-*-*-iso8859-1", "7x14", "fixed")
	gc := func(fg, bg uint32, f xproto.Font, ok bool) xproto.Gcontext {
		g, _ := xproto.NewGcontextId(c)
		mask, vals := uint32(xproto.GcForeground|xproto.GcBackground), []uint32{fg, bg}
		if ok {
			mask, vals = mask|xproto.GcFont, append(vals, uint32(f))
		}
		xproto.CreateGC(c, g, xproto.Drawable(win), mask, vals)
		return g
	}
	headGC := gc(white, accent, big, bigOK)
	nameGC := gc(text, white, big, bigOK)
	bodyGC := gc(text, white, small, smallOK)
	mutedGC := gc(muted, white, small, smallOK)
	allowGC := gc(white, accent, big, bigOK)
	denyGC := gc(text, denyBg, big, bigOK)
	fill := func(col uint32) xproto.Gcontext { return gc(col, col, 0, false) }
	accentFill, denyFill := fill(accent), fill(denyBg)

	by := h - pad - btnH
	allow := xproto.Rectangle{X: int16(w - pad - btnW), Y: int16(by), Width: btnW, Height: btnH} // #nosec G115 -- small sizes
	deny := xproto.Rectangle{X: allow.X - 12 - btnW, Y: int16(by), Width: btnW, Height: btnH}    // #nosec G115 -- small sizes
	left := max(int(timeout/time.Second), 1)
	label := func(g xproto.Gcontext, r xproto.Rectangle, s string) {
		tx := r.X + int16((int(r.Width)-len(s)*9)/2)                                                // #nosec G115 -- 9 px glyphs of the bold font
		xproto.ImageText8(c, byte(len(s)), xproto.Drawable(win), g, tx, r.Y+int16(r.Height)/2+6, s) // #nosec G115 -- button labels and sizes are small
	}
	countdown := func() {
		s := fmt.Sprintf("Allow only if you expect it. Closes in %d s.   ", left)
		xproto.ImageText8(c, byte(len(s)), xproto.Drawable(win), mutedGC, pad, int16(by-14), s) // #nosec G115 -- short text
	}
	draw := func() {
		xproto.PolyFillRectangle(c, xproto.Drawable(win), accentFill, []xproto.Rectangle{{X: 0, Y: 0, Width: w, Height: headH}})
		xproto.ImageText8(c, byte(len("RMMZit  -  Remote desktop")), xproto.Drawable(win), headGC, pad, headH/2+6, "RMMZit  -  Remote desktop")
		ty := int16(headH + 18 + 16)
		xproto.ImageText8(c, byte(len(name[0])), xproto.Drawable(win), nameGC, pad, ty, name[0]) // #nosec G115 -- at most 40
		ty += 26
		for _, l := range body {
			xproto.ImageText8(c, byte(len(l)), xproto.Drawable(win), bodyGC, pad, ty, l) // #nosec G115 -- at most 52
			ty += 20
		}
		countdown()
		xproto.PolyFillRectangle(c, xproto.Drawable(win), denyFill, []xproto.Rectangle{deny})
		xproto.PolyFillRectangle(c, xproto.Drawable(win), accentFill, []xproto.Rectangle{allow})
		label(denyGC, deny, "Deny")
		label(allowGC, allow, "Allow")
		c.Sync()
	}
	xproto.MapWindow(c, win)
	draw()
	in := func(r xproto.Rectangle, x, y int16) bool {
		return x >= r.X && x < r.X+int16(r.Width) && y >= r.Y && y < r.Y+int16(r.Height) // #nosec G115 -- small sizes
	}
	res := make(chan Consent, 1)
	go func() {
		for {
			ev, err := c.WaitForEvent()
			if ev == nil && err == nil {
				return // connection closed
			}
			switch e := ev.(type) {
			case xproto.ExposeEvent:
				draw()
			case xproto.ButtonPressEvent:
				switch {
				case in(allow, e.EventX, e.EventY):
					res <- ConsentYes
					return
				case in(deny, e.EventX, e.EventY):
					res <- ConsentNo
					return
				}
			case xproto.KeyPressEvent:
				if e.Detail == 9 || e.Detail == 36 { // Esc, Return (evdev keycodes): deny
					res <- ConsentNo
					return
				}
			}
		}
	}()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case a := <-res:
			return a
		case <-ctx.Done():
			return ConsentNo
		case <-tick.C:
			if left--; left <= 0 {
				return ConsentTimeout
			}
			xproto.ConfigureWindow(c, win, xproto.ConfigWindowStackMode, []uint32{xproto.StackModeAbove})
			countdown()
			c.Sync()
		}
	}
}

// wrapASCII breaks text into lines of at most n characters; other than
// printable ASCII becomes "?" (the core X font).
func wrapASCII(text string, n int) []string {
	b := make([]byte, 0, len(text))
	for _, r := range text {
		if r >= 0x20 && r < 0x7f {
			b = append(b, byte(r))
		} else {
			b = append(b, '?')
		}
	}
	var lines []string
	line := ""
	for _, word := range splitWords(string(b)) {
		switch {
		case len(word) > n:
			word = word[:n]
			fallthrough
		case line == "":
			if line != "" {
				lines = append(lines, line)
			}
			line = word
		case len(line)+1+len(word) > n:
			lines = append(lines, line)
			line = word
		default:
			line += " " + word
		}
	}
	if line != "" {
		lines = append(lines, line)
	}
	if len(lines) > 6 {
		lines = lines[:6]
	}
	return lines
}

func splitWords(s string) []string {
	var out []string
	cur := ""
	for _, r := range s {
		if r == ' ' {
			if cur != "" {
				out = append(out, cur)
			}
			cur = ""
			continue
		}
		cur += string(r)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}
