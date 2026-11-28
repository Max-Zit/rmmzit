//go:build linux

package rd

import (
	"context"
	"time"

	"github.com/jezek/xgb"
	"github.com/jezek/xgb/xproto"
)

// AskConsent shows a small window in the middle of the X screen with the
// question and the buttons Allow and Deny, and waits for a click.
func AskConsent(ctx context.Context, technician string, viewOnly bool, timeout time.Duration) Consent {
	c, err := xgb.NewConn()
	if err != nil {
		return ConsentUnavailable
	}
	defer c.Close()
	scr := xproto.Setup(c).DefaultScreen(c)
	lines := wrapASCII(consentText(technician, viewOnly), 60)
	const charW, lineH, pad, btnW, btnH = 9, 22, 16, 110, 30
	w := 60*charW + 2*pad
	h := pad + len(lines)*lineH + pad + btnH + pad
	sw, sh := int(scr.WidthInPixels), int(scr.HeightInPixels)
	w = min(w, sw)
	x, y := (sw-w)/2, (sh-h)/3
	win, _ := xproto.NewWindowId(c)
	const bg, fg, btnBg = 0xffffff, 0x111827, 0x2563eb
	xproto.CreateWindow(c, scr.RootDepth, win, scr.Root, int16(x), int16(y), uint16(w), uint16(h), 2, // #nosec G115 -- screen size
		xproto.WindowClassInputOutput, scr.RootVisual,
		xproto.CwBackPixel|xproto.CwBorderPixel|xproto.CwOverrideRedirect|xproto.CwEventMask,
		[]uint32{bg, btnBg, 1, xproto.EventMaskExposure | xproto.EventMaskButtonPress})
	font, _ := xproto.NewFontId(c)
	fontOK := xproto.OpenFontChecked(c, font, uint16(len("-misc-fixed-bold-r-normal--18-*-*-*-*-*-iso8859-1")), "-misc-fixed-bold-r-normal--18-*-*-*-*-*-iso8859-1").Check() == nil
	if !fontOK {
		fontOK = xproto.OpenFontChecked(c, font, 5, "fixed").Check() == nil
	}
	gc, _ := xproto.NewGcontextId(c)
	btn, _ := xproto.NewGcontextId(c)
	mask, vals := uint32(xproto.GcForeground|xproto.GcBackground), []uint32{fg, bg}
	bmask, bvals := uint32(xproto.GcForeground|xproto.GcBackground), []uint32{0xffffff, btnBg}
	if fontOK {
		mask, vals = mask|xproto.GcFont, append(vals, uint32(font))
		bmask, bvals = bmask|xproto.GcFont, append(bvals, uint32(font))
	}
	xproto.CreateGC(c, gc, xproto.Drawable(win), mask, vals)
	xproto.CreateGC(c, btn, xproto.Drawable(win), bmask, bvals)
	fill, _ := xproto.NewGcontextId(c)
	xproto.CreateGC(c, fill, xproto.Drawable(win), xproto.GcForeground, []uint32{btnBg})
	by := pad + len(lines)*lineH + pad
	allow := xproto.Rectangle{X: int16(w/2 - btnW - 8), Y: int16(by), Width: btnW, Height: btnH} // #nosec G115 -- small sizes
	deny := xproto.Rectangle{X: int16(w/2 + 8), Y: int16(by), Width: btnW, Height: btnH}         // #nosec G115 -- small sizes
	draw := func() {
		for i, l := range lines {
			xproto.ImageText8(c, byte(len(l)), xproto.Drawable(win), gc, pad, int16(pad+(i+1)*lineH-6), l) // #nosec G115 -- at most 60
		}
		xproto.PolyFillRectangle(c, xproto.Drawable(win), fill, []xproto.Rectangle{allow, deny})
		xproto.ImageText8(c, 5, xproto.Drawable(win), btn, allow.X+32, allow.Y+20, "Allow")
		xproto.ImageText8(c, 4, xproto.Drawable(win), btn, deny.X+36, deny.Y+20, "Deny")
		c.Sync()
	}
	title := "RMMZit remote desktop"
	xproto.ChangeProperty(c, xproto.PropModeReplace, win, xproto.AtomWmName, xproto.AtomString, 8, uint32(len(title)), []byte(title)) // #nosec G115 -- constant
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
			}
		}
	}()
	keepUp := time.NewTicker(time.Second)
	defer keepUp.Stop()
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	for {
		select {
		case a := <-res:
			return a
		case <-deadline.C:
			return ConsentTimeout
		case <-ctx.Done():
			return ConsentNo
		case <-keepUp.C:
			xproto.ConfigureWindow(c, win, xproto.ConfigWindowStackMode, []uint32{xproto.StackModeAbove})
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
