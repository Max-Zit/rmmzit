package agent

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/max-zit/rmmzit/internal/proto"
)

func TestDirectedBroadcast(t *testing.T) {
	for in, want := range map[string]string{"192.168.101.5/24": "192.168.101.255", "10.1.2.3/8": "10.255.255.255", "172.16.5.9/20": "172.16.15.255"} {
		ip, n, _ := net.ParseCIDR(in)
		n.IP = ip
		if got := directedBroadcast(n); got.String() != want {
			t.Errorf("%s: %v", in, got)
		}
	}
	for _, in := range []string{"10.0.0.1/31", "10.0.0.1/32"} {
		ip, n, _ := net.ParseCIDR(in)
		n.IP = ip
		if got := directedBroadcast(n); got != nil {
			t.Errorf("%s: %v", in, got)
		}
	}
}

// The agent sends exactly the magic packet of the MAC address.
func TestSendWake(t *testing.T) {
	l, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	old := wakePorts
	wakePorts = []int{l.LocalAddr().(*net.UDPAddr).Port}
	defer func() { wakePorts = old }()
	m, _ := proto.ParseMAC("00:15:5D:AA:BB:CC")
	n, err := sendWake([][6]byte{m}, []net.IP{net.IPv4(127, 0, 0, 1)})
	if err != nil || n != 1 {
		t.Fatalf("sent %d: %v", n, err)
	}
	_ = l.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 200)
	k, _, err := l.ReadFrom(buf)
	if err != nil || !bytes.Equal(buf[:k], proto.MagicPacket(m)) {
		t.Fatalf("received %x: %v", buf[:k], err)
	}
}
