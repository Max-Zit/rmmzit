package proto

import (
	"bytes"
	"crypto/ed25519"
	"strings"
	"testing"
	"time"
)

// Fuzz targets for data an agent or console receives from the other side.

// A signed command is accepted only when it is signed, for this agent and
// fresh; changing any byte of it is noticed.
func FuzzVerifyCommand(f *testing.F) {
	pub, key, _ := ed25519.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{1}, 64)))
	f.Add("c1", "agent-1", "agent-1", "fs.list", int64(0), int64(60), uint16(0), byte(0))
	f.Add("c2", "agent-1", "agent-2", "script.run", int64(-30), int64(60), uint16(5), byte(1))
	f.Add("", "a", "a", "x", int64(600), int64(60), uint16(3), byte(0x80))
	f.Add("c3", "a", "a", "x", int64(0), int64(3600), uint16(0), byte(0))
	now := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	f.Fuzz(func(t *testing.T, id, agentID, me, kind string, issuedSec, validSec int64, flipAt uint16, flip byte) {
		issued := now.Add(time.Duration(issuedSec%100000) * time.Second)
		c := Command{ID: id, AgentID: agentID, Kind: kind, IssuedAt: issued, Expires: issued.Add(time.Duration(validSec%100000) * time.Second)}
		sc, err := Sign(key, c)
		if err != nil {
			return
		}
		got, err := Verify(pub, sc, me, now)
		if err == nil {
			if got.AgentID != me || got.ID == "" {
				t.Fatalf("accepted a command for %q/%q as %q", got.AgentID, got.ID, me)
			}
			if now.After(got.Expires.Add(MaxCommandAge)) || got.IssuedAt.After(now.Add(MaxCommandAge)) || got.Expires.Sub(got.IssuedAt) > 30*time.Minute {
				t.Fatalf("accepted a command outside its time window: %+v", got)
			}
		}
		if flip != 0 && len(sc.Command) > 0 {
			bad := SignedCommand{Command: bytes.Clone(sc.Command), Sig: sc.Sig}
			bad.Command[int(flipAt)%len(bad.Command)] ^= flip
			if _, err := Verify(pub, bad, me, now); err == nil {
				t.Fatal("a changed command was accepted")
			}
		}
	})
}

// Arbitrary bytes as a signed command never pass.
func FuzzVerifyCommandBytes(f *testing.F) {
	pub, key, _ := ed25519.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{2}, 64)))
	sc, _ := Sign(key, Command{ID: "x", AgentID: "a", Kind: "k"})
	f.Add(sc.Command, sc.Sig, []byte(pub))
	f.Add([]byte("{}"), []byte{}, []byte{})
	f.Fuzz(func(t *testing.T, cmd, sig, pk []byte) {
		if bytes.Equal(pk, pub) && bytes.Equal(cmd, sc.Command) && bytes.Equal(sig, sc.Sig) {
			return // the genuine command
		}
		if _, err := Verify(pk, SignedCommand{Command: cmd, Sig: sig}, "a", time.Now()); err == nil && bytes.Equal(pk, pub) {
			t.Fatal("an unsigned command was accepted")
		}
	})
}

// Remote desktop tile messages from an agent: no panic, no tile reaching
// past the message, and what decodes encodes back to the same bytes.
func FuzzDecodeTiles(f *testing.F) {
	f.Add(EncodeTiles([]Tile{{X: 1, Y: 2, W: 3, H: 4, Data: []byte("jpeg")}}))
	f.Add(EncodeTiles(nil))
	f.Add([]byte{RDTiles, 0xff, 0xff})
	f.Add([]byte{RDTiles, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, b []byte) {
		tiles, err := DecodeTiles(b)
		if err != nil {
			return
		}
		total := 0
		for _, tl := range tiles {
			total += 12 + len(tl.Data)
		}
		if 3+total > len(b) {
			t.Fatalf("tiles hold %d bytes of a %d-byte message", 3+total, len(b))
		}
		if re := EncodeTiles(tiles); !bytes.Equal(re, b[:len(re)]) {
			t.Fatal("tiles do not encode back to the message")
		}
	})
}

// Registry paths from the console: a clean path has a known root, no empty
// parts and no line breaks, and cleaning it again changes nothing.
func FuzzCleanRegPath(f *testing.F) {
	for _, s := range []string{`HKLM\SOFTWARE\x`, `hkey_local_machine/Software`, `HKCU\x`, `HKLM\\a`, "HKLM\\a\x00b", `\HKU\.DEFAULT\`, strings.Repeat(`HKLM\a`, 40)} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, p string) {
		c, err := CleanRegPath(p)
		if err != nil {
			return
		}
		parts := strings.Split(c, `\`)
		known := false
		for _, r := range RegRoots {
			known = known || parts[0] == r
		}
		if !known || len(parts) > 32 {
			t.Fatalf("CleanRegPath(%q) = %q", p, c)
		}
		for _, s := range parts[1:] {
			if s == "" || strings.ContainsAny(s, "\x00\r\n") {
				t.Fatalf("CleanRegPath(%q) = %q has a bad part", p, c)
			}
		}
		if again, err := CleanRegPath(c); err != nil || again != c {
			t.Fatalf("CleanRegPath(%q) = %q, again %q %v", p, c, again, err)
		}
	})
}
