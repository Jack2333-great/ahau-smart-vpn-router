package enlink

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// Expected ciphertext produced independently with OpenSSL AES-128-CBC.
func TestPasswordOpenSSLVector(t *testing.T) {
	got, err := EncryptPassword("synthetic-password", "0123456789abcdef")
	if err != nil || got != "SanqAingpSUVL+dRaWKxnrxfV0sxd1ed80DIX0gu14o=" {
		t.Fatalf("cipher mismatch %q %v", got, err)
	}
	for _, key := range []string{"short", "0123456789abcde\xff"} {
		if _, err := EncryptPassword("x", key); err == nil {
			t.Fatal("invalid key accepted")
		}
	}
}

// This vector was generated offline by the installed 32-bit libfko.dll on
// Windows, with synthetic data. The random salt was recovered from its own
// Salted__ envelope. It checks the complete ciphertext/HMAC/identifier wire.
func TestSPAWindowsLibraryVector(t *testing.T) {
	got, err := encodeSPA(SPAOptions{Username: "synthetic-user", Access: "tcp/443", PasswordMaterial: "synthetic-shared-secret"}, "1234567890123456", 1793178157, [8]byte{0x71, 0xef, 0x7d, 0xcc, 0x88, 0xda, 0x91, 0xf0})
	want := "9x733MiNqR8HYFXA3v7L3kXY+932IPE26EDzFMmO+21bHx88p2LsBKwn8qPgRer6lUf9f2slJR+KxBkSGxJrZ0wIMJJsn3EInzBWM9AmsC7cPWxLwuF3xg8AadIopF4Mg2bthFxlj8xZC0bZ6qr9VWTwvL2IgoOVwtmdIoEOfZYWwSKWfLB1gAPMCSz/5QBxnXwjar+EqHvLCmP4KdwVN0IIphb1OqjrQenlink"
	if err != nil || string(got) != want {
		t.Fatalf("SPA vector mismatch\ngot: %s\nerr: %v", got, err)
	}
}
func TestAuthVector(t *testing.T) {
	b, err := AuthFrame("a", "bc")
	if err != nil {
		t.Fatal(err)
	}
	want := "010100160000000001000000010001610200026263ff"
	if hex.EncodeToString(b) != want {
		t.Fatalf("%x", b)
	}
	if _, err := AuthFrame(strings.Repeat("安", 86), "x"); err == nil {
		t.Fatal("oversize UTF8 accepted")
	}
}
func assignment() []byte {
	return []byte{1, 2, 0, 29, 128, 1, 0, 4, 1, 0, 0, 0, 11, 0, 4, 10, 0, 0, 2, 12, 0, 4, 255, 255, 255, 0, 43, 0, 255}
}

type fragmentReader struct{ r io.Reader }

func (r fragmentReader) Read(p []byte) (int, error) {
	if len(p) > 1 {
		p = p[:1]
	}
	return r.r.Read(p)
}
func ipv4() []byte {
	b := make([]byte, 40)
	b[0] = 0x45
	b[9] = 6
	binary.BigEndian.PutUint16(b[2:4], 40)
	copy(b[12:16], []byte{10, 0, 0, 2})
	copy(b[16:20], []byte{192, 0, 2, 5})
	b[22] = 1
	b[23] = 187
	b[32] = 0x50
	return b
}
func downFrame(p []byte) []byte {
	h := []byte{1, 4, 0, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint16(h[2:4], uint16(8+len(p)))
	return append(h, p...)
}
func TestFragmentedCoalescedStream(t *testing.T) {
	packet := ipv4()
	ack := []byte{1, 2, 0, 12, 0, 0, 0, 0, 3, 0, 0, 0}
	stream := append(assignment(), append(ack, downFrame(packet)...)...)
	r := fragmentReader{bytes.NewReader(stream)}
	a, err := ReadAssignment(r)
	if err != nil || a.Mask.String() != "10.0.0.2/24" {
		t.Fatalf("%v %v", a, err)
	}
	f, err := ReadFrame(r)
	if err != nil || !f.Heartbeat {
		t.Fatal("lost heartbeat", err)
	}
	f, err = ReadFrame(r)
	if err != nil || !bytes.Equal(f.Packet, packet) {
		t.Fatal("lost coalesced packet", err)
	}
}
func TestAssignmentRejectsMalformed(t *testing.T) {
	base := assignment()
	tests := [][]byte{base[:11], append([]byte(nil), base...), append([]byte(nil), base...), append([]byte(nil), base...)}
	tests[1][10] = 128
	tests[2][14] = 255
	tests[3][25] = 1
	for _, b := range tests {
		if _, err := ReadAssignment(bytes.NewReader(b)); err == nil {
			t.Fatalf("accepted malformed %x", b)
		}
	}
}
func TestDataHeaderAndLimits(t *testing.T) {
	p := ipv4()
	b, err := DataFrame(p, 1)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(b[:12]) != "010400340000000000000001" {
		t.Fatalf("bad header %x", b[:12])
	}
	p[3]++
	if _, err := DataFrame(p, 1); err == nil {
		t.Fatal("length mismatch accepted")
	}
	if _, err := ReadFrame(bytes.NewReader([]byte{1, 4, 0, 7, 0, 0, 0, 0})); err == nil {
		t.Fatal("underflow accepted")
	}
}
func TestACLConservativeFiltering(t *testing.T) {
	acl, err := ParseACL("TCP;192.0.2.0/24;443")
	if err != nil {
		t.Fatal(err)
	}
	p := ipv4()
	if !acl.Allows(p) {
		t.Fatal("authorized packet denied")
	}
	p[23] = 80
	if acl.Allows(p) {
		t.Fatal("wrong port accepted")
	}
	p[23] = 187
	p[6] = 0x20
	if acl.Allows(p) {
		t.Fatal("fragment accepted")
	}
	p[6] = 0
	p[16] = 198
	if acl.Allows(p) {
		t.Fatal("outside prefix accepted")
	}
	for _, s := range []string{"TCP;192.0.2.1:192.0.2.3/24;ANY", "TCP;::/0;ANY", "ICMP;0.0.0.0/0;ANY", "TCP;192.0.2.1;0", "TCP;192.0.2.1;100-90"} {
		if _, err := ParseACL(s); err == nil {
			t.Fatalf("accepted %s", s)
		}
	}
}
func TestEndpointTrustIdentity(t *testing.T) {
	e, err := ParseEndpoint("vpn.example:443||192.0.2.1:444")
	if err != nil || e.ServerName != "vpn.example" || e.Address != "192.0.2.1:444" {
		t.Fatalf("%v %v", e, err)
	}
	for _, s := range []string{"vpn.example", "vpn.example:0", "vpn.example:443||evil.example:443"} {
		if _, err := ParseEndpoint(s); err == nil {
			t.Fatalf("accepted %s", s)
		}
	}
}
func TestControllerMockFlow(t *testing.T) {
	var stages []string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stages = append(stages, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("systemInfo") != "Linux" {
			t.Error("incorrect platform")
		}
		switch r.URL.Path {
		case api + "auth/generateKey":
			http.SetCookie(w, &http.Cookie{Name: "sid", Value: "synthetic-cookie", Path: "/", Secure: true})
			io.WriteString(w, `{"code":"200","data":"0123456789abcdef"}`)
		case api + "auth/login":
			var v map[string]string
			json.NewDecoder(r.Body).Decode(&v)
			if v["password"] != "SanqAingpSUVL+dRaWKxnrxfV0sxd1ed80DIX0gu14o=" || v["key"] != "0123456789abcdef" || v["username"] != "synthetic-user" {
				t.Error("incorrect login encoding")
			}
			if r.Header.Get("Authorization") != "sid=synthetic-cookie" {
				t.Error("cookie authorization missing")
			}
			io.WriteString(w, `{"code":200,"data":{"id":"u1","username":"synthetic-user","sid":"synthetic-sid"}}`)
		case api + "user/terminal/rules/u1":
			io.WriteString(w, `{"code":200,"data":{"server":"vpn.example:443||192.0.2.1:443||443","gateway_list":[{"id":"g1","ip":"vpn.example:443||192.0.2.1:443","inIpList":["TCP;192.0.2.5;443"]}]}}`)
		case api + "auth/logout":
			io.WriteString(w, `{"code":200,"data":null}`)
		default:
			t.Errorf("unexpected API %s", r.URL.Path)
			w.WriteHeader(404)
		}
	})
	s := httptest.NewTLSServer(handler)
	defer s.Close()
	c, err := NewController(s.URL+"/", "", "synthetic-device")
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(s.Certificate())
	c.HTTP.Transport.(*http.Transport).TLSClientConfig.RootCAs = pool
	l, err := c.Login(context.Background(), "synthetic-user", "synthetic-password")
	if err != nil {
		t.Fatal(err)
	}
	r, err := c.Rules(context.Background(), l)
	if err != nil || len(r.Gateways) != 1 {
		t.Fatal(err)
	}
	if err = c.Logout(context.Background(), l); err != nil {
		t.Fatal(err)
	}
	if len(stages) != 4 {
		t.Fatal(stages)
	}
}
func TestControllerRejectsUntrustedTLSAndRedirect(t *testing.T) {
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "https://elsewhere.invalid", 302) }))
	defer s.Close()
	c, _ := NewController(s.URL, "", "device")
	if _, err := c.GenerateKey(context.Background()); err == nil {
		t.Fatal("untrusted TLS accepted")
	}
	pool := x509.NewCertPool()
	pool.AddCert(s.Certificate())
	c.HTTP.Transport.(*http.Transport).TLSClientConfig.RootCAs = pool
	if _, err := c.GenerateKey(context.Background()); err == nil || !strings.Contains(err.Error(), "302") {
		t.Fatalf("redirect not rejected: %v", err)
	}
}
func TestGatewayTLSAuthAndHeartbeat(t *testing.T) {
	// Reuse httptest only for certificate generation, then speak the binary
	// protocol over our own listener; no HTTP tunnel emulation.
	certServer := httptest.NewTLSServer(http.NotFoundHandler())
	cert := certServer.TLS.Certificates[0]
	pool := x509.NewCertPool()
	pool.AddCert(certServer.Certificate())
	certServer.Close()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	serverDone := make(chan error, 1)
	go func() {
		c, e := ln.Accept()
		if e != nil {
			serverDone <- e
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(2 * time.Second))
		want, _ := AuthFrame("user", "session")
		b := make([]byte, len(want))
		_, e = io.ReadFull(c, b)
		if e != nil || !bytes.Equal(b, want) {
			serverDone <- errors.New("bad auth bytes")
			return
		}
		for _, v := range assignment() {
			if e = writeAll(c, []byte{v}); e != nil {
				serverDone <- e
				return
			}
		}
		for {
			b = make([]byte, 12)
			_, e = io.ReadFull(c, b)
			if e != nil {
				serverDone <- nil
				return
			}
			if !bytes.Equal(b, HeartbeatFrame()) {
				serverDone <- errors.New("bad heartbeat")
				return
			}
			if e = writeAll(c, []byte{1, 2, 0, 12, 0, 0, 0, 0, 3, 0, 0, 0}); e != nil {
				serverDone <- nil
				return
			}
		}
	}()
	h, _, _ := net.SplitHostPort(ln.Addr().String())
	tun, err := DialGateway(context.Background(), Endpoint{ln.Addr().String(), h}, &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}, Login{Username: "user", SID: "session"})
	if err != nil {
		t.Fatal(err)
	}
	if tun.Assignment.IP != netip.MustParseAddr("10.0.0.2") {
		t.Fatal(tun.Assignment)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Millisecond)
	defer cancel()
	count, err := tun.Observe(ctx, 10*time.Millisecond)
	if !errors.Is(err, context.DeadlineExceeded) || count.Received == 0 || count.Sent == 0 {
		t.Fatalf("%v %v", count, err)
	}
	if err = <-serverDone; err != nil {
		t.Fatal(err)
	}
}
func TestObserveCancellationUnblocksRead(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	tun := &Tunnel{Conn: a}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	_, err := tun.Observe(ctx, time.Second)
	if !errors.Is(err, context.Canceled) || time.Since(start) > time.Second {
		t.Fatal("cancellation did not unblock", err)
	}
}
func FuzzFrameDecoder(f *testing.F) {
	f.Add(assignment())
	f.Add(downFrame(ipv4()))
	f.Fuzz(func(t *testing.T, b []byte) { ReadAssignment(bytes.NewReader(b)); ReadFrame(bytes.NewReader(b)) })
}
