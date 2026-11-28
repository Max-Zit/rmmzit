package netacl

import (
	"bufio"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func v2(cmd, fam byte, body []byte) string {
	h := append([]byte{}, proxyV2Sig...)
	h = append(h, 0x20|cmd, fam, 0, 0)
	binary.BigEndian.PutUint16(h[14:16], uint16(len(body)))
	return string(append(h, body...))
}

func TestReadProxyHeader(t *testing.T) {
	v4 := append(append([]byte{203, 0, 113, 9}, 10, 0, 0, 1), 0x1f, 0x90, 0x20, 0xfb) // 8080 -> 8443
	v6 := make([]byte, 36)
	copy(v6, netip.MustParseAddr("2001:db8::7").AsSlice())
	binary.BigEndian.PutUint16(v6[32:], 51000)
	for _, c := range []struct {
		in   string
		want string // "" = no address, "err" = error, "none" = no header
	}{
		{"PROXY TCP4 203.0.113.9 10.0.0.1 51000 8443\r\nGET", "203.0.113.9:51000"},
		{"PROXY TCP6 2001:db8::7 2001:db8::1 51000 8443\r\n", "[2001:db8::7]:51000"},
		{"PROXY UNKNOWN\r\n", ""},
		{"PROXY TCP4 2001:db8::7 10.0.0.1 1 2\r\n", "err"},
		{"PROXY TCP4 203.0.113.9 10.0.0.1 051000 8443\r\n", "err"},
		{"PROXY TCP4 203.0.113.9 10.0.0.1 70000 8443\r\n", "err"},
		{"PROXY TCP4 203.0.113.9 10.0.0.1 1 2\n", "err"},
		{"PROXY TCP4 203.0.113.9\r\n", "err"},
		{"PROXY " + strings.Repeat("x", 200), "err"},
		{v2(1, 0x11, v4), "203.0.113.9:8080"},
		{v2(1, 0x21, v6), "[2001:db8::7]:51000"},
		{v2(0, 0x11, v4), ""}, // LOCAL
		{v2(1, 0x12, v4), ""}, // UDP
		{v2(1, 0x11, v4[:5]), "err"},
		{v2(2, 0x11, v4), "err"},
		{"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03rest-of-a-client-hello", "none"},
		{"GET / HTTP/1.1\r\n", "none"},
	} {
		src, ok, err := ReadProxyHeader(bufio.NewReader(strings.NewReader(c.in)))
		got := ""
		switch {
		case err == errNoHeader:
			got = "none"
		case err != nil:
			got = "err"
		case ok:
			got = src.String()
		}
		if got != c.want {
			t.Errorf("%q: got %q, want %q (%v)", c.in, got, c.want, err)
		}
	}
}

func TestForwardedFor(t *testing.T) {
	tr := NewTrusted([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")})
	for _, c := range []struct {
		xff  []string
		real string
		want string
	}{
		{[]string{"198.18.0.1, 203.0.113.9"}, "", "203.0.113.9"},
		{[]string{"203.0.113.9, 10.0.0.7"}, "", "203.0.113.9"}, // a second proxy is skipped
		{[]string{"203.0.113.9", "10.0.0.7"}, "", "203.0.113.9"},
		{[]string{"10.0.0.8, 10.0.0.7"}, "", "10.0.0.8"},
		{[]string{"[2001:db8::7]:443"}, "", "2001:db8::7"},
		{nil, "203.0.113.10", "203.0.113.10"},
		{[]string{"203.0.113.9, junk"}, "203.0.113.10", ""},
		{nil, "", ""},
	} {
		a, ok := ForwardedFor(tr, c.xff, c.real)
		got := ""
		if ok {
			got = a.String()
		}
		if got != c.want {
			t.Errorf("%v %q: got %q, want %q", c.xff, c.real, got, c.want)
		}
	}
	if err := CheckTrusted([]netip.Prefix{netip.MustParsePrefix("::/0")}); err == nil {
		t.Fatal("::/0 accepted as a trusted proxy")
	}
	var none *Trusted
	if none.Has(netip.MustParseAddr("10.0.0.1")) || NewTrusted(nil).Has(netip.MustParseAddr("10.0.0.1")) {
		t.Fatal("an empty list trusts someone")
	}
}

// The listener over real TCP: a trusted proxy names the client, others
// cannot, a trusted proxy may send no header, a broken header closes.
func TestProxyListener(t *testing.T) {
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tr := NewTrusted([]netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")})
	broken := make(chan string, 1)
	l := &ProxyListener{Listener: raw, Trusted: tr, Timeout: 2 * time.Second, OnError: func(r string, err error) { broken <- err.Error() }}
	defer l.Close()
	send := func(s string) {
		c, err := net.Dial("tcp", raw.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.WriteString(c, s)
		time.AfterFunc(3*time.Second, func() { _ = c.Close() })
	}
	accept := func() (string, string) {
		t.Helper()
		c, err := l.Accept()
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		b := make([]byte, 5)
		_, _ = io.ReadFull(c, b)
		a, _ := AddrOf(c.RemoteAddr().String())
		return a.String(), string(b)
	}

	send("PROXY TCP4 203.0.113.9 10.0.0.1 51000 8443\r\nhello")
	if a, data := accept(); a != "203.0.113.9" || data != "hello" {
		t.Fatalf("trusted proxy: %s %q", a, data)
	}
	send("plain")
	if a, data := accept(); a != "127.0.0.1" || data != "plain" {
		t.Fatalf("trusted proxy without a header: %s %q", a, data)
	}
	send("PROXY TCP4 203.0.113.9\r\n")
	if e := <-broken; !strings.Contains(e, "malformed") {
		t.Fatalf("broken header: %s", e)
	}
	// Not trusted: the header is data, the address stays.
	tr.Set(nil)
	send("PROXY TCP4 203.0.113.9 10.0.0.1 51000 8443\r\n")
	if a, data := accept(); a != "127.0.0.1" || data != "PROXY" {
		t.Fatalf("untrusted peer named a client: %s %q", a, data)
	}
}

// PROXY headers come from the network; whatever the bytes, the reader
// returns an address only for a well-formed header and never panics.
func FuzzReadProxyHeader(f *testing.F) {
	f.Add([]byte("PROXY TCP4 203.0.113.9 10.0.0.1 51000 8443\r\n"))
	f.Add([]byte("PROXY TCP6 2001:db8::7 2001:db8::1 1 2\r\n"))
	f.Add([]byte(v2(1, 0x11, []byte{1, 2, 3, 4, 5, 6, 7, 8, 0, 1, 0, 2})))
	f.Add([]byte(v2(1, 0x21, make([]byte, 36))))
	f.Add([]byte("\r\n\r\n\x00\r\nQUIT\n\x21\x11\xff\xff"))
	f.Fuzz(func(t *testing.T, b []byte) {
		src, ok, err := ReadProxyHeader(bufio.NewReader(strings.NewReader(string(b))))
		if ok && (err != nil || !src.IsValid() || src.Addr().Is4In6()) {
			t.Fatalf("address %v (err %v) from %q", src, err, b)
		}
	})
}

// X-Forwarded-For is sent by clients; a result is always one of the
// addresses in the header.
func FuzzForwardedFor(f *testing.F) {
	f.Add("198.18.0.1, 203.0.113.9", "")
	f.Add("", "203.0.113.10")
	f.Add("[2001:db8::7]:443,10.0.0.7", "x")
	tr := NewTrusted([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")})
	f.Fuzz(func(t *testing.T, xff, real string) {
		a, ok := ForwardedFor(tr, []string{xff}, real)
		if ok && !a.IsValid() {
			t.Fatalf("invalid address from %q %q", xff, real)
		}
	})
}
