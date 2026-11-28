package netacl

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Trusted is the list of reverse proxies whose word on the real client
// address is taken (PROXY protocol, X-Forwarded-For). Empty: none.
type Trusted struct {
	p atomic.Pointer[[]netip.Prefix]
}

// NewTrusted returns a list of trusted proxies.
func NewTrusted(nets []netip.Prefix) *Trusted {
	t := &Trusted{}
	t.Set(nets)
	return t
}

// Set replaces the networks.
func (t *Trusted) Set(nets []netip.Prefix) {
	n := append([]netip.Prefix(nil), nets...)
	t.p.Store(&n)
}

// Has reports whether the address is a trusted proxy.
func (t *Trusted) Has(a netip.Addr) bool {
	if t == nil {
		return false
	}
	p := t.p.Load()
	return p != nil && len(*p) > 0 && Contains(*p, a.Unmap())
}

// HasAddr is Has for a "host:port" or bare host string.
func (t *Trusted) HasAddr(hostport string) bool {
	a, ok := AddrOf(hostport)
	return ok && t.Has(a)
}

// CheckTrusted refuses networks that would trust everyone.
func CheckTrusted(nets []netip.Prefix) error {
	for _, p := range nets {
		if p.Bits() == 0 {
			return errors.New("a trusted proxy cannot be every address (" + p.String() + ")")
		}
	}
	return nil
}

// ---- PROXY protocol (v1 text, v2 binary), from trusted proxies only

// proxyV2Sig starts a version 2 header.
var proxyV2Sig = []byte("\r\n\r\n\x00\r\nQUIT\n")

// errNoHeader: the connection does not start with a PROXY header.
var errNoHeader = errors.New("no PROXY header")

// ReadProxyHeader reads a PROXY protocol header at the start of r. It
// returns the client address it names; ok is false when the header names
// none (v1 UNKNOWN, v2 LOCAL or another family: the proxy's own check).
// Without a header it returns errNoHeader and reads nothing.
func ReadProxyHeader(r *bufio.Reader) (src netip.AddrPort, ok bool, err error) {
	if b, _ := r.Peek(len(proxyV2Sig)); bytes.Equal(b, proxyV2Sig) {
		return readProxyV2(r)
	}
	if b, _ := r.Peek(6); string(b) == "PROXY " {
		return readProxyV1(r)
	}
	return netip.AddrPort{}, false, errNoHeader
}

func readProxyV1(r *bufio.Reader) (netip.AddrPort, bool, error) {
	// At most 107 bytes including CRLF.
	var line []byte
	for len(line) < 107 {
		c, err := r.ReadByte()
		if err != nil {
			return netip.AddrPort{}, false, err
		}
		line = append(line, c)
		if c == '\n' {
			break
		}
	}
	s, found := strings.CutSuffix(string(line), "\r\n")
	if !found {
		return netip.AddrPort{}, false, errors.New("PROXY v1: the header is not one line")
	}
	f := strings.Split(s, " ")
	if len(f) >= 2 && f[1] == "UNKNOWN" {
		return netip.AddrPort{}, false, nil
	}
	if len(f) != 6 || f[1] != "TCP4" && f[1] != "TCP6" {
		return netip.AddrPort{}, false, errors.New("PROXY v1: malformed header")
	}
	a, err := netip.ParseAddr(f[2])
	if err != nil || a.Is4() != (f[1] == "TCP4") || a.Zone() != "" {
		return netip.AddrPort{}, false, errors.New("PROXY v1: bad source address")
	}
	if _, err := netip.ParseAddr(f[3]); err != nil {
		return netip.AddrPort{}, false, errors.New("PROXY v1: bad destination address")
	}
	port, err := strconv.ParseUint(f[4], 10, 16)
	if err != nil || f[4] != strconv.FormatUint(port, 10) {
		return netip.AddrPort{}, false, errors.New("PROXY v1: bad source port")
	}
	if p, err := strconv.ParseUint(f[5], 10, 16); err != nil || f[5] != strconv.FormatUint(p, 10) {
		return netip.AddrPort{}, false, errors.New("PROXY v1: bad destination port")
	}
	return netip.AddrPortFrom(a, uint16(port)), true, nil
}

func readProxyV2(r *bufio.Reader) (netip.AddrPort, bool, error) {
	var hdr [16]byte
	if _, err := readFull(r, hdr[:]); err != nil {
		return netip.AddrPort{}, false, err
	}
	if hdr[12]>>4 != 2 {
		return netip.AddrPort{}, false, errors.New("PROXY v2: unknown version")
	}
	cmd, fam := hdr[12]&0x0f, hdr[13]
	n := int(binary.BigEndian.Uint16(hdr[14:16]))
	if n > 1024 { // addresses plus TLVs; real headers are far smaller
		return netip.AddrPort{}, false, errors.New("PROXY v2: header too long")
	}
	body := make([]byte, n)
	if _, err := readFull(r, body); err != nil {
		return netip.AddrPort{}, false, err
	}
	switch cmd {
	case 0: // LOCAL: the proxy's own connection (health check)
		return netip.AddrPort{}, false, nil
	case 1: // PROXY
	default:
		return netip.AddrPort{}, false, errors.New("PROXY v2: unknown command")
	}
	switch fam {
	case 0x11: // TCP over IPv4
		if n < 12 {
			return netip.AddrPort{}, false, errors.New("PROXY v2: short IPv4 addresses")
		}
		a := netip.AddrFrom4([4]byte(body[0:4]))
		return netip.AddrPortFrom(a, binary.BigEndian.Uint16(body[8:10])), true, nil
	case 0x21: // TCP over IPv6
		if n < 36 {
			return netip.AddrPort{}, false, errors.New("PROXY v2: short IPv6 addresses")
		}
		a := netip.AddrFrom16([16]byte(body[0:16])).Unmap()
		return netip.AddrPortFrom(a, binary.BigEndian.Uint16(body[32:34])), true, nil
	}
	return netip.AddrPort{}, false, nil // UDP, Unix sockets, unspecified: keep the proxy's address
}

func readFull(r *bufio.Reader, b []byte) (int, error) {
	n := 0
	for n < len(b) {
		m, err := r.Read(b[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

// proxyConn is a connection whose client address came from a PROXY header.
type proxyConn struct {
	net.Conn
	r      *bufio.Reader
	remote net.Addr
}

func (c *proxyConn) Read(b []byte) (int, error) { return c.r.Read(b) }
func (c *proxyConn) RemoteAddr() net.Addr       { return c.remote }

// ProxyListener reads the PROXY header of connections from trusted
// proxies, so RemoteAddr is the client's address; connections from other
// addresses pass unchanged, and a header from them is never read (it
// fails the TLS handshake). A trusted proxy may also connect without a
// header (then X-Forwarded-For may apply). Headers are read in their own
// goroutines, so a slow proxy does not hold up other connections.
type ProxyListener struct {
	net.Listener
	Trusted *Trusted
	Timeout time.Duration // for the header; default 10 s
	// OnError is called when a trusted proxy sent a broken header.
	OnError func(remote string, err error)

	once  sync.Once
	conns chan net.Conn
	errc  chan error
	done  chan struct{}
}

func (l *ProxyListener) start() {
	l.conns, l.errc, l.done = make(chan net.Conn), make(chan error, 1), make(chan struct{})
	go func() {
		for {
			c, err := l.Listener.Accept()
			if err != nil {
				l.errc <- err
				return
			}
			if !l.Trusted.HasAddr(c.RemoteAddr().String()) {
				select {
				case l.conns <- c:
				case <-l.done:
					_ = c.Close()
					return
				}
				continue
			}
			go l.handshake(c)
		}
	}()
}

func (l *ProxyListener) handshake(c net.Conn) {
	t := l.Timeout
	if t <= 0 {
		t = 10 * time.Second
	}
	_ = c.SetReadDeadline(time.Now().Add(t))
	r := bufio.NewReaderSize(c, 512)
	src, ok, err := ReadProxyHeader(r)
	_ = c.SetReadDeadline(time.Time{})
	out := net.Conn(&proxyConn{Conn: c, r: r, remote: c.RemoteAddr()})
	switch {
	case errors.Is(err, errNoHeader):
	case err != nil:
		if l.OnError != nil {
			l.OnError(c.RemoteAddr().String(), err)
		}
		_ = c.Close()
		return
	case ok:
		out.(*proxyConn).remote = net.TCPAddrFromAddrPort(src)
	}
	select {
	case l.conns <- out:
	case <-l.done:
		_ = c.Close()
	}
}

// Accept returns the next connection.
func (l *ProxyListener) Accept() (net.Conn, error) {
	l.once.Do(l.start)
	select {
	case c := <-l.conns:
		return c, nil
	case err := <-l.errc:
		l.errc <- err // later calls fail the same way
		return nil, err
	}
}

// Close stops the listener.
func (l *ProxyListener) Close() error {
	l.once.Do(l.start)
	select {
	case <-l.done:
	default:
		close(l.done)
	}
	return l.Listener.Close()
}

// ---- X-Forwarded-For

// ForwardedFor is the client address of a request that came through
// trusted proxies: the right-most address of X-Forwarded-For that is not
// a trusted proxy (the left-most one when all are), or else X-Real-IP.
// ok is false when the headers name no valid address; a broken entry
// makes the whole header untrusted.
func ForwardedFor(t *Trusted, xff []string, realIP string) (netip.Addr, bool) {
	var hops []netip.Addr
	for _, h := range xff {
		for _, part := range strings.Split(h, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			a, ok := AddrOf(part)
			if !ok {
				return netip.Addr{}, false
			}
			hops = append(hops, a)
		}
	}
	if len(hops) > 0 {
		for i := len(hops) - 1; i >= 0; i-- {
			if !t.Has(hops[i]) {
				return hops[i], true
			}
		}
		return hops[0], true
	}
	if realIP = strings.TrimSpace(realIP); realIP != "" {
		return AddrOf(realIP)
	}
	return netip.Addr{}, false
}
