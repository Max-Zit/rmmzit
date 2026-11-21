package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"time"

	"github.com/max-zit/rmmzit/internal/proto"
)

// Wake-on-LAN: this agent sends magic packets for computers of its network
// (the server chooses agents in the same site). Only MAC addresses come in;
// the packets go to the broadcast addresses of this computer's own IPv4
// networks and 255.255.255.255, UDP ports 9 and 7.

func init() {
	register(proto.KindWake, func(ctx context.Context, raw json.RawMessage) (any, error) {
		var a proto.WakeArgs
		if err := args(raw, &a); err != nil {
			return nil, err
		}
		if len(a.MACs) == 0 || len(a.MACs) > proto.MaxWakeMACs {
			return nil, errors.New("bad Wake-on-LAN request")
		}
		var macs [][6]byte
		for _, s := range a.MACs {
			m, ok := proto.ParseMAC(s)
			if !ok {
				return nil, errors.New("bad MAC address")
			}
			macs = append(macs, m)
		}
		n, err := sendWake(macs, broadcastAddrs())
		return proto.WakeResult{Sent: n}, err
	})
}

// broadcastAddrs lists 255.255.255.255 and the broadcast address of every
// IPv4 network of the interfaces that are up (not loopback).
func broadcastAddrs() []net.IP {
	out := []net.IP{net.IPv4bcast}
	ifs, _ := net.Interfaces()
	for _, i := range ifs {
		if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 || i.Flags&net.FlagBroadcast == 0 {
			continue
		}
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			n, ok := a.(*net.IPNet)
			if !ok || n.IP.To4() == nil {
				continue
			}
			if b := directedBroadcast(n); b != nil {
				out = append(out, b)
			}
		}
	}
	return out
}

// directedBroadcast is the last address of an IPv4 network (nil for /31
// and /32, which have none).
func directedBroadcast(n *net.IPNet) net.IP {
	ip, mask := n.IP.To4(), n.Mask
	if ip == nil || len(mask) != net.IPv4len {
		return nil
	}
	if ones, _ := mask.Size(); ones >= 31 {
		return nil
	}
	b := make(net.IP, net.IPv4len)
	for i := range b {
		b[i] = ip[i] | ^mask[i]
	}
	return b
}

// wakePorts are the UDP ports of the magic packet (tests change them).
var wakePorts = []int{9, 7}

func sendWake(macs [][6]byte, dests []net.IP) (int, error) {
	c, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		return 0, err
	}
	defer c.Close()
	_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
	sent := 0
	var last error
	for _, m := range macs {
		p := proto.MagicPacket(m)
		for _, d := range dests {
			for _, port := range wakePorts {
				if _, err := c.WriteTo(p, &net.UDPAddr{IP: d, Port: port}); err != nil {
					last = err
					continue
				}
				sent++
			}
		}
	}
	if sent == 0 && last != nil {
		return 0, last
	}
	return sent, nil
}
