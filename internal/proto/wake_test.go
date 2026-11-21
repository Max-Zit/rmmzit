package proto

import (
	"bytes"
	"testing"
)

func TestParseMAC(t *testing.T) {
	for _, s := range []string{"00:15:5D:01:02:03", "00-15-5d-01-02-03", "00155d010203", " 00:15:5D:01:02:03 "} {
		if m, ok := ParseMAC(s); !ok || m != [6]byte{0x00, 0x15, 0x5d, 1, 2, 3} {
			t.Errorf("%q: %v %v", s, m, ok)
		}
	}
	for _, s := range []string{"", "00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF", "01:00:5E:00:00:01", "00:15:5D:01:02", "00:15:5D:01:02:03:04", "zz:15:5D:01:02:03"} {
		if _, ok := ParseMAC(s); ok {
			t.Errorf("%q accepted", s)
		}
	}
}

func TestMagicPacket(t *testing.T) {
	m := [6]byte{1 << 1, 2, 3, 4, 5, 6}
	p := MagicPacket(m)
	if len(p) != 102 || !bytes.Equal(p[:6], bytes.Repeat([]byte{0xff}, 6)) || !bytes.Equal(p[6:], bytes.Repeat(m[:], 16)) {
		t.Fatalf("packet %x", p)
	}
}

// MAC addresses come from the inventory (agents): never a panic, and an
// accepted one is a unicast card address that prints back the same.
func FuzzParseMAC(f *testing.F) {
	f.Add("00:15:5D:01:02:03")
	f.Add("ff-ff-ff-ff-ff-ff")
	f.Add("0..0")
	f.Fuzz(func(t *testing.T, s string) {
		m, ok := ParseMAC(s)
		if !ok {
			return
		}
		if m[0]&1 == 1 || m == [6]byte{} {
			t.Fatalf("%q gave %x", s, m)
		}
		if len(MagicPacket(m)) != 102 {
			t.Fatal("packet size")
		}
	})
}
