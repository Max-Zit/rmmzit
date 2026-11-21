package proto

import (
	"encoding/hex"
	"strings"
)

// KindWake asks an agent to send Wake-on-LAN magic packets for other
// computers of its network. The server sends only MAC addresses; the agent
// builds the packet itself and sends it to its own networks' broadcast
// addresses (UDP 9 and 7), so the command cannot send anything else or
// anywhere else.
const KindWake = "wol.send"

// MaxWakeMACs limits one wol.send.
const MaxWakeMACs = 8

// WakeArgs is the argument of wol.send.
type WakeArgs struct {
	MACs []string `json:"macs"`
}

// WakeResult is the answer: how many packets went out.
type WakeResult struct {
	Sent int `json:"sent"`
}

// ParseMAC reads a 6-byte MAC address written with ":" or "-" between the
// bytes, or without separators. The all-zero and broadcast addresses and
// multicast addresses are no network card and are refused.
func ParseMAC(s string) ([6]byte, bool) {
	var m [6]byte
	s = strings.NewReplacer(":", "", "-", "", ".", "").Replace(strings.TrimSpace(s))
	if len(s) != 12 {
		return m, false
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return m, false
	}
	copy(m[:], b)
	if m == [6]byte{} || m == [6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff} || m[0]&1 == 1 {
		return m, false
	}
	return m, true
}

// MagicPacket is the Wake-on-LAN packet: six 0xFF bytes and the MAC address
// sixteen times.
func MagicPacket(m [6]byte) []byte {
	p := make([]byte, 0, 102)
	for i := 0; i < 6; i++ {
		p = append(p, 0xff)
	}
	for i := 0; i < 16; i++ {
		p = append(p, m[:]...)
	}
	return p
}
