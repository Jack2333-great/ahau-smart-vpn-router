package enlink_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
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
	"strings"
	"syscall"
	"testing"
	"time"

	"campusvpn/internal/enlink"
	"campusvpn/internal/network"
	"campusvpn/internal/tun"
)

func TestRouterAndroidEndToEndIntegration(t *testing.T) { routerKernelPath(t, 1) }
func TestRouterDesktopEndToEndIntegration(t *testing.T) { routerKernelPath(t, 41) }

// Three real Linux network namespaces exercise the complete LAN -> policy ->
// TUN -> userspace NAT -> TLS -> gateway kernel, and its reverse path. The
// existing proxy and multi-WAN rules are deliberately hostile to any packet
// which misses the scoped bypass or the higher-priority return route.
func routerKernelPath(t *testing.T, identifier uint32) {
	if os.Getenv("CAMPUSVPN_ISOLATED_TUN_TEST") != "1" {
		t.Skip("requires isolated network namespace")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	run := func(name string, args ...string) {
		t.Helper()
		if b, e := exec.CommandContext(ctx, name, args...).CombinedOutput(); e != nil {
			t.Fatalf("router fixture %s %v: %v %s", name, args, e, b)
		}
	}
	run("ip", "link", "set", "lo", "up")
	run("ip", "link", "add", "br-lan", "type", "bridge")
	run("ip", "address", "add", "192.168.50.1/24", "dev", "br-lan")
	run("ip", "link", "set", "br-lan", "up")
	run("sysctl", "-q", "-w", "net.ipv4.ip_forward=1", "net.ipv4.conf.all.rp_filter=0", "net.ipv4.conf.default.rp_filter=0")
	dev, err := tun.Open("cvpn9877")
	if err != nil {
		t.Fatal(err)
	}
	defer dev.Close()
	if err = dev.Configure(ctx, netip.MustParseAddr("10.0.0.2"), 1300); err != nil {
		t.Fatal(err)
	}
	fixture := `add table inet llgproxy
add chain inet llgproxy prerouting { type filter hook prerouting priority mangle; policy accept; }
add rule inet llgproxy prerouting iifname "br-lan" meta l4proto tcp meta mark set 0x80000000 tproxy ip to 127.0.0.1:7893 accept
add table inet fw4
add chain inet fw4 forward { type filter hook forward priority filter; policy drop; }
add table ip test_mwan
add chain ip test_mwan prerouting { type filter hook prerouting priority -149; policy accept; }
add rule ip test_mwan prerouting meta l4proto { tcp, udp } meta mark set (meta mark & 0xffffc0ff) | 0x00000100
`
	nft := exec.CommandContext(ctx, "nft", "-f", "-")
	nft.Stdin = strings.NewReader(fixture)
	if b, e := nft.CombinedOutput(); e != nil {
		t.Fatalf("router proxy fixture: %v %s", e, b)
	}
	run("ip", "route", "add", "local", "default", "dev", "lo", "table", "100")
	run("ip", "rule", "add", "pref", "100", "fwmark", "0x80000000/0x80000000", "lookup", "100")
	run("ip", "route", "add", "unreachable", "default", "table", "1")
	run("ip", "rule", "add", "pref", "2001", "fwmark", "0x100/0x3f00", "lookup", "1")
	acl, _ := enlink.CompileACL([]string{"ANY;192.0.2.5;12345"})
	plan, err := network.NewPlan(dev.Name, []netip.Prefix{netip.MustParsePrefix("192.168.50.112/32")}, acl)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := network.Apply(ctx, plan)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		if e := policy.Close(cleanup); e != nil {
			t.Error("router policy cleanup", e)
		}
	}()
	conn, assignment := routerGatewayFixture(t, ctx, identifier)
	nat, _ := enlink.NewSourceNAT(assignment.IP, []netip.Prefix{netip.MustParsePrefix("192.168.50.112/32")})
	tunnel := &enlink.Tunnel{Conn: conn, Assignment: assignment, DataIdentifier: identifier}
	bridgeDone := make(chan enlink.BridgeStats, 1)
	go func() {
		stats, _ := tunnel.BridgeWithNAT(ctx, dev, acl, 100*time.Millisecond, nat)
		bridgeDone <- stats
	}()
	defer func() {
		cancel()
		select {
		case stats := <-bridgeDone:
			if stats.Sent < 5 || stats.Received < 5 {
				t.Errorf("router path counters %+v", stats)
			}
			t.Logf("three namespaces, profile=%d: %+v", identifier, stats)
		case <-time.After(time.Second):
			t.Error("router bridge did not stop")
		}
	}()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	parent := os.NewFile(uintptr(fds[0]), "lan-parent")
	defer parent.Close()
	child := os.NewFile(uintptr(fds[1]), "lan-child")
	defer child.Close()
	client := exec.CommandContext(ctx, "unshare", "-n", os.Args[0], "-test.run=^TestRouterLANClientHelper$", "-test.timeout=10s")
	client.Env = append(os.Environ(), "CAMPUSVPN_ROUTER_LAN_HELPER=1")
	client.ExtraFiles = []*os.File{child}
	var diagnostics bytes.Buffer
	client.Stdout = &diagnostics
	client.Stderr = &diagnostics
	if err = client.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if client.ProcessState == nil {
			client.Process.Kill()
			client.Wait()
		}
		if t.Failed() {
			t.Log(diagnostics.String())
		}
	}()
	child.Close()
	if _, err = io.ReadFull(parent, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	run("ip", "link", "add", "cvpnlan", "type", "veth", "peer", "name", "cvpnpeer")
	run("ip", "link", "set", "cvpnpeer", "netns", strconv.Itoa(client.Process.Pid))
	run("ip", "link", "set", "cvpnlan", "master", "br-lan")
	run("ip", "link", "set", "cvpnlan", "up")
	parent.Write([]byte{1})
	if err = client.Wait(); err != nil {
		t.Fatalf("real LAN TCP/UDP path: %v %s", err, diagnostics.String())
	}
	if err = policy.Check(ctx); err != nil {
		t.Fatal("policy health after traffic", err)
	}
	t.Log(strings.TrimSpace(diagnostics.String()))
}

func routerGatewayFixture(t *testing.T, ctx context.Context, identifier uint32) (net.Conn, enlink.Assignment) {
	t.Helper()
	certSource := httptest.NewTLSServer(http.NotFoundHandler())
	certificate := certSource.TLS.Certificates[0]
	root := certSource.Certificate()
	certSource.Close()
	key, err := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for name, data := range map[string][]byte{"gateway.crt": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw}), "gateway.key": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})} {
		if err = os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	parent := os.NewFile(uintptr(fds[0]), "router-gateway")
	defer parent.Close()
	child := os.NewFile(uintptr(fds[1]), "gateway-router")
	defer child.Close()
	cmd := exec.CommandContext(ctx, "unshare", "-n", os.Args[0], "-test.run=^TestKernelGatewayHelper$", "-test.timeout=15s")
	cmd.Env = append(os.Environ(), "CAMPUSVPN_KERNEL_GATEWAY_HELPER=1", "CAMPUSVPN_TEST_DATA_IDENTIFIER="+strconv.Itoa(int(identifier)), "CAMPUSVPN_TEST_CERT_DIR="+dir, "CAMPUSVPN_SOAK_SECONDS=0")
	cmd.ExtraFiles = []*os.File{child}
	var diagnostics bytes.Buffer
	cmd.Stdout = &diagnostics
	cmd.Stderr = &diagnostics
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
		if t.Failed() {
			t.Log(diagnostics.String())
		}
	})
	child.Close()
	raw, err := net.FileConn(parent)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	conn := tls.Client(raw, &tls.Config{RootCAs: pool, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12})
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(4 * time.Second))
	if err = conn.HandshakeContext(ctx); err != nil {
		t.Fatal(err)
	}
	ready := make([]byte, 1)
	if _, err = io.ReadFull(conn, ready); err != nil || ready[0] != 0x52 {
		t.Fatal("gateway startup", err)
	}
	auth, _ := enlink.AuthFrame("synthetic-user", "synthetic-session")
	if _, err = conn.Write(auth); err != nil {
		t.Fatal(err)
	}
	assigned, err := enlink.ReadAssignment(conn)
	if err != nil {
		t.Fatal(err)
	}
	conn.SetDeadline(time.Time{})
	return conn, assigned
}

func TestRouterLANClientHelper(t *testing.T) {
	if os.Getenv("CAMPUSVPN_ROUTER_LAN_HELPER") != "1" {
		return
	}
	fd := os.NewFile(3, "router-control")
	defer fd.Close()
	fd.Write([]byte{1})
	if _, err := io.ReadFull(fd, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"link", "set", "lo", "up"}, {"address", "add", "192.168.50.112/24", "dev", "cvpnpeer"}, {"link", "set", "cvpnpeer", "up"}, {"route", "add", "default", "via", "192.168.50.1"}} {
		if b, e := exec.Command("ip", args...).CombinedOutput(); e != nil {
			t.Fatalf("LAN fixture %v %s", e, b)
		}
	}
	tcp, err := net.DialTimeout("tcp4", "192.0.2.5:12345", 3*time.Second)
	if err != nil {
		t.Fatal("LAN TCP handshake", err)
	}
	defer tcp.Close()
	tcp.SetDeadline(time.Now().Add(4 * time.Second))
	payload := bytes.Repeat([]byte("LAN policy NAT TLS kernel path\n"), 2100)
	written := make(chan error, 1)
	go func() { _, e := io.Copy(tcp, bytes.NewReader(payload)); written <- e }()
	got := make([]byte, len(payload))
	if _, err = io.ReadFull(tcp, got); err != nil || !bytes.Equal(payload, got) {
		t.Fatal("LAN TCP echo", err)
	}
	if err = <-written; err != nil {
		t.Fatal(err)
	}
	udp, err := net.DialTimeout("udp4", "192.0.2.5:12345", 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	udp.SetDeadline(time.Now().Add(2 * time.Second))
	message := bytes.Repeat([]byte{0x5b}, 1001)
	if _, err = udp.Write(message); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 1400)
	n, err := udp.Read(b)
	if err != nil || !bytes.Equal(message, b[:n]) {
		t.Fatal("LAN UDP echo", err)
	}
	t.Logf("real separate LAN client: TCP bytes=%d, UDP bytes=%d", len(payload), n)
}
