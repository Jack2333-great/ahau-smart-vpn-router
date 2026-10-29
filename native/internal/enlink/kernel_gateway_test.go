package enlink

import (
	"bytes"
	"campusvpn/internal/tun"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"
)

// A second isolated Linux network namespace acts as the gateway. Both sides
// use real kernel TCP/UDP stacks and TUN devices; no mock TCP/checksum logic is
// shared with the translator. Extra fd 3 carries only synthetic tunnel data.
func TestKernelLANTranslationIntegration(t *testing.T) {
	kernelLANTranslation(t, 1)
}

func TestKernelDesktopLANTranslationIntegration(t *testing.T) {
	kernelLANTranslation(t, 41)
}

func kernelLANTranslation(t *testing.T, identifier uint32) {
	t.Helper()
	if os.Getenv("CAMPUSVPN_ISOLATED_TUN_TEST") != "1" {
		t.Skip("requires isolated network namespace")
	}
	soak, _ := strconv.Atoi(os.Getenv("CAMPUSVPN_SOAK_SECONDS"))
	if soak < 0 || soak > 120 {
		t.Fatal("invalid soak duration")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(12+soak)*time.Second)
	defer cancel()
	dev, err := tun.Open("cvpn9873")
	if err != nil {
		t.Fatal(err)
	}
	defer dev.Close()
	vip := netip.MustParseAddr("10.0.0.2")
	if err = dev.Configure(ctx, vip, 1300); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"link", "set", "lo", "up"}, {"address", "add", "192.168.50.112/32", "dev", "lo"}, {"route", "add", "192.0.2.5/32", "dev", dev.Name, "src", "192.168.50.112"}} {
		if e := exec.CommandContext(ctx, "ip", args...).Run(); e != nil {
			t.Fatal(e)
		}
	}
	defer exec.Command("ip", "address", "del", "192.168.50.112/32", "dev", "lo").Run()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	parent := os.NewFile(uintptr(fds[0]), "parent-tunnel")
	child := os.NewFile(uintptr(fds[1]), "child-tunnel")
	defer parent.Close()
	defer child.Close()
	// A disposable certificate signs only this synthetic gateway. The private
	// fixture never touches the router or a production trust store.
	certSource := httptest.NewTLSServer(http.NotFoundHandler())
	certificate := certSource.TLS.Certificates[0]
	root := certSource.Certificate()
	certSource.Close()
	fixture := t.TempDir()
	key, err := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(fixture, "gateway.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Certificate[0]}), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(fixture, "gateway.key"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, "unshare", "-n", os.Args[0], "-test.run=^TestKernelGatewayHelper$", "-test.timeout="+strconv.Itoa(15+soak)+"s")
	cmd.Env = append(os.Environ(), "CAMPUSVPN_KERNEL_GATEWAY_HELPER=1", "CAMPUSVPN_TEST_DATA_IDENTIFIER="+strconv.Itoa(int(identifier)), "CAMPUSVPN_TEST_CERT_DIR="+fixture)
	cmd.ExtraFiles = []*os.File{child}
	var diagnostics bytes.Buffer
	cmd.Stdout = &diagnostics
	cmd.Stderr = &diagnostics
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cmd.Process.Kill()
		cmd.Wait()
		if t.Failed() {
			t.Log(diagnostics.String())
		}
	}()
	child.Close()
	raw, err := net.FileConn(parent)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	parent.Close()
	pool := x509.NewCertPool()
	pool.AddCert(root)
	conn := tls.Client(raw, &tls.Config{RootCAs: pool, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12})
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(4 * time.Second))
	if err = conn.HandshakeContext(ctx); err != nil {
		t.Fatal("synthetic TLS handshake", err)
	}
	conn.SetReadDeadline(time.Now().Add(4 * time.Second))
	ready := make([]byte, 1)
	if _, err = io.ReadFull(conn, ready); err != nil || ready[0] != 0x52 {
		t.Fatalf("helper startup %x %v", ready, err)
	}
	auth, _ := AuthFrame("synthetic-user", "synthetic-session")
	if err = writeAll(conn, auth); err != nil {
		t.Fatal(err)
	}
	assigned, err := ReadAssignment(conn)
	if err != nil || assigned.IP != vip {
		t.Fatal("synthetic gateway assignment", err)
	}
	conn.SetDeadline(time.Time{})
	nat, _ := NewSourceNAT(vip, []netip.Prefix{netip.MustParsePrefix("192.168.50.112/32")})
	acl, _ := CompileACL([]string{"ANY;192.0.2.5/32;12345"})
	tunnel := &Tunnel{Conn: conn, Assignment: assigned, DataIdentifier: identifier}
	done := make(chan BridgeStats, 1)
	go func() { stats, _ := tunnel.BridgeWithNAT(ctx, dev, acl, 100*time.Millisecond, nat); done <- stats }()
	dialer := net.Dialer{Timeout: 3 * time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP("192.168.50.112")}}
	tcp, err := dialer.DialContext(ctx, "tcp4", "192.0.2.5:12345")
	if err != nil {
		cancel()
		t.Logf("bridge: %+v", <-done)
		t.Fatal("real kernel TCP handshake", err)
	}
	tcp.SetDeadline(time.Now().Add(time.Duration(4+soak) * time.Second))
	defer tcp.Close()
	payload := bytes.Repeat([]byte("LAN TCP translated through Enlink framing\n"), 1500)
	written := make(chan error, 1)
	go func() { written <- writeAll(tcp, payload) }()
	reply := make([]byte, len(payload))
	if _, err = io.ReadFull(tcp, reply); err != nil || !bytes.Equal(payload, reply) {
		t.Fatal("real kernel TCP echo", err)
	}
	if err = <-written; err != nil {
		t.Fatal(err)
	}
	udp, err := net.DialUDP("udp4", &net.UDPAddr{IP: net.ParseIP("192.168.50.112")}, &net.UDPAddr{IP: net.ParseIP("192.0.2.5"), Port: 12345})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	udp.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err = udp.Write([]byte("LAN UDP odd payload")); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 128)
	size, err := udp.Read(buffer)
	if err != nil || string(buffer[:size]) != "LAN UDP odd payload" {
		t.Fatal("real kernel UDP echo", err)
	}
	if soak > 0 {
		stopAt := time.Now().Add(time.Duration(soak) * time.Second)
		tick := time.NewTicker(20 * time.Millisecond)
		defer tick.Stop()
		chunk := bytes.Repeat([]byte{0x35}, 4096)
		echo := make([]byte, len(chunk))
		udpChunk := bytes.Repeat([]byte{0x71}, 1001)
		udpEcho := make([]byte, 1400)
		rounds := 0
		for time.Now().Before(stopAt) {
			select {
			case <-ctx.Done():
				t.Fatal("soak context ended early")
			case <-tick.C:
			}
			tcp.SetDeadline(time.Now().Add(2 * time.Second))
			udp.SetDeadline(time.Now().Add(2 * time.Second))
			if err = writeAll(tcp, chunk); err != nil {
				t.Fatal("soak TCP write", err)
			}
			if _, err = io.ReadFull(tcp, echo); err != nil || !bytes.Equal(chunk, echo) {
				t.Fatal("soak TCP echo", err)
			}
			if _, err = udp.Write(udpChunk); err != nil {
				t.Fatal("soak UDP write", err)
			}
			n, e := udp.Read(udpEcho)
			if e != nil || !bytes.Equal(udpChunk, udpEcho[:n]) {
				t.Fatal("soak UDP echo", e)
			}
			rounds++
		}
		t.Logf("soak seconds=%d profile=%d TCP bytes=%d UDP datagrams=%d", soak, identifier, len(payload)+rounds*len(chunk), rounds+1)
	}
	tcp.Close()
	cancel()
	select {
	case stats := <-done:
		if stats.Sent < 5 || stats.Received < 5 {
			t.Fatalf("unexpected stats %+v", stats)
		}
		t.Logf("real kernel TCP bytes=%d, UDP echo, translated packets sent=%d received=%d", len(payload), stats.Sent, stats.Received)
	case <-time.After(time.Second):
		t.Fatal("bridge cleanup stuck")
	}
}

func TestKernelGatewayHelper(t *testing.T) {
	if os.Getenv("CAMPUSVPN_KERNEL_GATEWAY_HELPER") != "1" || os.Getenv("CAMPUSVPN_ISOLATED_TUN_TEST") != "1" {
		t.Skip("internal isolated helper")
	}
	identifier, err := strconv.Atoi(os.Getenv("CAMPUSVPN_TEST_DATA_IDENTIFIER"))
	if err != nil || (identifier != 1 && identifier != 41) {
		t.Fatal("invalid helper data profile")
	}
	soak, _ := strconv.Atoi(os.Getenv("CAMPUSVPN_SOAK_SECONDS"))
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(14+soak)*time.Second)
	defer cancel()
	dev, err := tun.Open("cvpn9874")
	if err != nil {
		t.Fatal(err)
	}
	defer dev.Close()
	if err = dev.Configure(ctx, netip.MustParseAddr("192.0.2.5"), 1300); err != nil {
		t.Fatal(err)
	}
	if err = exec.CommandContext(ctx, "ip", "route", "add", "10.0.0.2/32", "dev", dev.Name).Run(); err != nil {
		t.Fatal(err)
	}
	tcp, err := net.Listen("tcp4", "192.0.2.5:12345")
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("192.0.2.5"), Port: 12345})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	go func() {
		for {
			c, e := tcp.Accept()
			if e != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	go func() {
		b := make([]byte, 1400)
		for {
			n, a, e := udp.ReadFromUDP(b)
			if e != nil {
				return
			}
			udp.WriteToUDP(b[:n], a)
		}
	}()
	file := os.NewFile(3, "synthetic-tunnel")
	raw, err := net.FileConn(file)
	file.Close()
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	fixture := os.Getenv("CAMPUSVPN_TEST_CERT_DIR")
	certificate, err := tls.LoadX509KeyPair(filepath.Join(fixture, "gateway.crt"), filepath.Join(fixture, "gateway.key"))
	if err != nil {
		t.Fatal(err)
	}
	conn := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(4 * time.Second))
	if err = conn.HandshakeContext(ctx); err != nil {
		t.Fatal(err)
	}
	var writeMu sync.Mutex
	send := func(b []byte) error { writeMu.Lock(); defer writeMu.Unlock(); return writeAll(conn, b) }
	if err = send([]byte{0x52}); err != nil {
		t.Fatal(err)
	}
	want, _ := AuthFrame("synthetic-user", "synthetic-session")
	auth := make([]byte, len(want))
	if _, err = io.ReadFull(conn, auth); err != nil || !bytes.Equal(auth, want) {
		t.Fatal("synthetic gateway auth", err)
	}
	if err = send(assignment()); err != nil {
		t.Fatal(err)
	}
	conn.SetDeadline(time.Time{})
	go func() {
		b := make([]byte, MaxFrame-8)
		for {
			n, e := dev.Read(b)
			if e != nil {
				return
			}
			// Linux may emit IPv6 router solicitations when a TUN comes up.
			// This synthetic gateway, like this prototype, carries IPv4 only.
			if ValidateIPv4(b[:n]) != nil {
				continue
			}
			if send(downFrame(b[:n])) != nil {
				return
			}
		}
	}()
	for {
		h := make([]byte, 12)
		if _, err = io.ReadFull(conn, h); err != nil {
			return
		}
		size := int(binary.BigEndian.Uint16(h[2:4]))
		if size < 12 || size > MaxFrame {
			t.Fatal("invalid synthetic frame")
		}
		if h[1] == 1 {
			if err = send([]byte{1, 2, 0, 12, 0, 0, 0, 0, 3, 0, 0, 0}); err != nil {
				return
			}
			continue
		}
		if h[0] != 1 || h[1] != 4 || binary.BigEndian.Uint32(h[8:12]) != uint32(identifier) {
			t.Fatal("unexpected upstream data envelope")
		}
		p := make([]byte, size-12)
		if _, err = io.ReadFull(conn, p); err != nil {
			return
		}
		if _, err = dev.Write(p); err != nil {
			t.Fatal(err)
		}
	}
}
