package network

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"campusvpn/internal/enlink"
	"campusvpn/internal/tun"
)

func TestPlanScope(t *testing.T) {
	acl, _ := enlink.CompileACL([]string{"UDP;192.0.2.5;12345", "TCP;192.0.2.5;443-444"})
	p, err := NewPlan("cvpn0", []netip.Prefix{netip.MustParsePrefix("192.168.50.112/32")}, acl)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Prefixes) != 1 || p.preRules != 2 || p.forwardRules != 4 {
		t.Fatal("incorrect resource scope")
	}
	for _, s := range []string{"0.0.0.0/0", "127.0.0.1/32", "198.18.0.0/15", "192.168.50.0/24"} {
		a, _ := enlink.CompileACL([]string{"ANY;" + s + ";ANY"})
		if _, err = NewPlan("cvpn0", []netip.Prefix{netip.MustParsePrefix("192.168.50.112/32")}, a); err == nil {
			t.Fatalf("unsafe prefix accepted: %s", s)
		}
	}
	if strings.Contains(p.NFT, "flush ruleset") || strings.Contains(p.NFT, "delete table") {
		t.Fatal("plan contains a global mutation")
	}
}

func networkFixture(t *testing.T) (context.Context, *tun.Device, Plan) {
	t.Helper()
	if os.Getenv("CAMPUSVPN_ISOLATED_TUN_TEST") != "1" {
		t.Skip("requires isolated network namespace")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	t.Cleanup(cancel)
	run := func(args ...string) {
		t.Helper()
		if b, e := exec.CommandContext(ctx, args[0], args[1:]...).CombinedOutput(); e != nil {
			t.Fatalf("fixture command %v: %v %s", args, e, b)
		}
	}
	run("ip", "link", "set", "lo", "up")
	run("ip", "link", "add", "br-lan", "type", "bridge")
	run("ip", "address", "add", "192.168.50.1/24", "dev", "br-lan")
	run("ip", "link", "set", "br-lan", "up")
	for _, setting := range []string{"net.ipv4.ip_forward=1", "net.ipv4.conf.all.rp_filter=0", "net.ipv4.conf.default.rp_filter=0"} {
		run("sysctl", "-q", "-w", setting)
	}
	dev, err := tun.Open("cvpn9876")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dev.Close() })
	if err = dev.Configure(ctx, netip.MustParseAddr("10.0.0.2"), 1300); err != nil {
		t.Fatal(err)
	}
	fixture := `add table inet llgproxy
add chain inet llgproxy prerouting { type filter hook prerouting priority mangle; policy accept; }
add rule inet llgproxy prerouting iifname "br-lan" meta l4proto udp counter drop comment "original-proxy-catch"
add table inet fw4
add chain inet fw4 forward { type filter hook forward priority filter; policy drop; }
`
	if _, err = command(ctx, fixture, "nft", "-f", "-"); err != nil {
		t.Fatal(err)
	}
	acl, _ := enlink.CompileACL([]string{"UDP;192.0.2.5;12345"})
	p, err := NewPlan(dev.Name, []netip.Prefix{netip.MustParsePrefix("192.168.50.112/32")}, acl)
	if err != nil {
		t.Fatal(err)
	}
	return ctx, dev, p
}

func TestPolicyRouteAndRollbackIntegration(t *testing.T) {
	ctx, dev, p := networkFixture(t)
	a, err := Apply(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close(context.Background())
	if err = a.Check(ctx); err != nil {
		t.Fatal(err)
	}
	for _, mark := range []string{"0x40000000", "0x40000100", "0xc0000400"} {
		b, e := command(ctx, "", "ip", "-4", "route", "get", "192.0.2.5", "from", "192.168.50.112", "iif", "br-lan", "mark", mark)
		if e != nil || !bytes.Contains(b, []byte("dev "+dev.Name)) {
			t.Fatalf("policy did not precede proxy/multi-WAN mark %s: %s %v", mark, b, e)
		}
	}
	// Simulate process/TUN death before the network cleanup runs. The table's
	// unreachable default must prevent the marked destination escaping to WAN.
	dev.Close()
	if _, e := command(ctx, "", "ip", "-4", "route", "get", "192.0.2.5", "from", "192.168.50.112", "iif", "br-lan", "mark", "0x40000000"); e == nil {
		t.Fatal("TUN loss did not fail closed")
	}
	if err = a.Close(ctx); err != nil {
		t.Fatal("cleanup after TUN destruction", err)
	}
	if err = a.Close(ctx); err != nil {
		t.Fatal("cleanup is not idempotent", err)
	}
	rules, _ := ruleRecords(ctx)
	for _, r := range rules {
		if field(r["priority"]) == "89" || field(r["priority"]) == "90" {
			t.Fatal("owned policy rule survived cleanup")
		}
	}
	routes, _ := routeRecords(ctx)
	for _, r := range routes {
		if field(r["table"]) == tableID {
			t.Fatalf("owned route survived cleanup: %+v", r)
		}
	}
	s, _ := snapshot(ctx)
	for _, o := range s.NFTables {
		if o.Chain != nil && strings.HasPrefix(o.Chain.Name, dev.Name) {
			t.Fatal("owned chain survived cleanup")
		}
	}
}

func TestPolicyFirewallLossIntegration(t *testing.T) {
	ctx, _, p := networkFixture(t)
	a, err := Apply(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close(context.Background())
	if _, err = command(ctx, "", "nft", "flush", "chain", "inet", "llgproxy", p.pre); err != nil {
		t.Fatal(err)
	}
	if a.Check(ctx) == nil {
		t.Fatal("empty managed chain was not detected")
	}
	if err = a.Close(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestPolicyCrashRecoveryIntegration(t *testing.T) {
	ctx, dev, p := networkFixture(t)
	a, err := Apply(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	if Recover(ctx, dev.Name) == nil {
		t.Fatal("recovery accepted an active TUN")
	}
	dev.Close()
	if err = Recover(ctx, dev.Name); err != nil {
		t.Fatal("crash recovery", err)
	}
	if err = Recover(ctx, dev.Name); err != nil {
		t.Fatal("idempotent crash recovery", err)
	}
	if err = a.Close(ctx); err != nil {
		t.Fatal("cleanup after recovery", err)
	}
	routes, _ := routeRecords(ctx)
	for _, r := range routes {
		if field(r["table"]) == tableID {
			t.Fatal("crash recovery left an owned route")
		}
	}
}

func TestPolicyCollisionIntegration(t *testing.T) {
	ctx, dev, p := networkFixture(t)
	if _, err := command(ctx, "", "ip", "-4", "rule", "add", "pref", "90", "lookup", "main"); err != nil {
		t.Fatal(err)
	}
	if a, err := Apply(ctx, p); err == nil {
		a.Close(ctx)
		t.Fatal("occupied priority accepted")
	}
	rules, _ := ruleRecords(ctx)
	found := false
	for _, r := range rules {
		if field(r["priority"]) == "90" && field(r["table"]) == "main" {
			found = true
		}
	}
	if !found {
		t.Fatal("existing rule was removed")
	}
	command(ctx, "", "ip", "-4", "rule", "del", "pref", "90", "lookup", "main")
	if _, err := command(ctx, "", "nft", "add", "chain", "inet", "llgproxy", p.pre); err != nil {
		t.Fatal(err)
	}
	if a, err := Apply(ctx, p); err == nil {
		a.Close(ctx)
		t.Fatal("existing chain accepted")
	}
	if _, err := command(ctx, "", "nft", "list", "chain", "inet", "llgproxy", p.pre); err != nil {
		t.Fatal("existing chain was removed")
	}
	command(ctx, "", "nft", "delete", "chain", "inet", "llgproxy", p.pre)
	// A failure after initial IP operations must remove only those operations.
	broken := p
	broken.Prefixes = append(append([]netip.Prefix{}, p.Prefixes...), netip.Prefix{})
	if a, err := Apply(ctx, broken); err == nil {
		a.Close(ctx)
		t.Fatal("induced route failure was ignored")
	}
	routes, _ := routeRecords(ctx)
	for _, r := range routes {
		if field(r["table"]) == tableID {
			t.Fatalf("partial apply leaked state %+v", r)
		}
	}
	dev.Close()
	command(ctx, "", "ip", "-4", "route", "add", "unreachable", "default", "table", tableID, "proto", "99", "metric", defaultMetric)
	if Recover(ctx, dev.Name) == nil {
		t.Fatal("recovery accepted an unowned route")
	}
	routes, _ = routeRecords(ctx)
	found = false
	for _, r := range routes {
		if field(r["table"]) == tableID && field(r["protocol"]) == "99" {
			found = true
		}
	}
	if !found {
		t.Fatal("recovery deleted an unowned route")
	}
}

func TestPolicyActualLANPacketScopeIntegration(t *testing.T) {
	ctx, dev, p := networkFixture(t)
	a, err := Apply(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close(context.Background())
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	parent := os.NewFile(uintptr(fds[0]), "parent-control")
	defer parent.Close()
	child := os.NewFile(uintptr(fds[1]), "child-control")
	defer child.Close()
	cmd := exec.CommandContext(ctx, "unshare", "-n", os.Args[0], "-test.run=^TestPolicyLANHelper$", "-test.timeout=10s")
	cmd.Env = append(os.Environ(), "CAMPUSVPN_POLICY_HELPER=1")
	cmd.ExtraFiles = []*os.File{child}
	var diagnostics bytes.Buffer
	cmd.Stdout = &diagnostics
	cmd.Stderr = &diagnostics
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if cmd.ProcessState == nil {
			cmd.Process.Kill()
			cmd.Wait()
		}
		if t.Failed() {
			t.Log(diagnostics.String())
		}
	}()
	child.Close()
	// Wait until unshare has created the child's network namespace.
	if _, err = io.ReadFull(parent, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"link", "add", "cvpnlan", "type", "veth", "peer", "name", "cvpnpeer"}, {"link", "set", "cvpnpeer", "netns", strconvPID(cmd.Process.Pid)}, {"link", "set", "cvpnlan", "master", "br-lan"}, {"link", "set", "cvpnlan", "up"}} {
		if _, err = command(ctx, "", "ip", args...); err != nil {
			t.Fatal(err)
		}
	}
	parent.Write([]byte{1})
	if err = dev.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	packet := make([]byte, 1600)
	for {
		n, e := dev.Read(packet)
		if e != nil {
			t.Fatal("selected LAN packet did not enter TUN", e)
		}
		if enlink.ValidateIPv4(packet[:n]) == nil {
			packet = packet[:n]
			break
		}
	}
	if packet[9] != 17 || netip.AddrFrom4([4]byte(packet[12:16])).String() != "192.168.50.112" || netip.AddrFrom4([4]byte(packet[16:20])).String() != "192.0.2.5" {
		t.Fatal("wrong client/resource reached TUN")
	}
	if err = cmd.Wait(); err != nil {
		t.Fatalf("LAN helper %v %s", err, diagnostics.String())
	}
	// The three nonmatching packets must continue to the existing proxy rule.
	s, err := snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var caught float64
	for _, o := range s.NFTables {
		if r := o.Rule; r != nil && r.Comment == "original-proxy-catch" {
			for _, expr := range r.Expr {
				var v map[string]map[string]float64
				json.Unmarshal(expr, &v)
				caught += v["counter"]["packets"]
			}
		}
	}
	if caught != 3 {
		t.Fatalf("existing proxy should retain 3 nonmatching packets, got %v", caught)
	}
	if err = dev.SetReadDeadline(time.Now().Add(60 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	for {
		n, e := dev.Read(make([]byte, 1600))
		if e != nil {
			break
		}
		if n > 0 {
			t.Fatal("nonmatching traffic leaked into VPN TUN")
		}
	}
}

func strconvPID(n int) string { b, _ := json.Marshal(n); return string(b) }

func TestPolicyLANHelper(t *testing.T) {
	if os.Getenv("CAMPUSVPN_POLICY_HELPER") != "1" {
		return
	}
	fd := os.NewFile(3, "parent-control")
	defer fd.Close()
	fd.Write([]byte{1})
	if _, err := io.ReadFull(fd, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"link", "set", "lo", "up"}, {"address", "add", "192.168.50.112/24", "dev", "cvpnpeer"}, {"address", "add", "192.168.50.113/24", "dev", "cvpnpeer"}, {"link", "set", "cvpnpeer", "up"}, {"route", "add", "default", "via", "192.168.50.1"}} {
		if b, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("helper setup %v %s", err, b)
		}
	}
	for _, flow := range []struct {
		source, destination string
		port                int
	}{{"192.168.50.112", "192.0.2.5", 12345}, {"192.168.50.112", "192.0.2.5", 12346}, {"192.168.50.113", "192.0.2.5", 12345}, {"192.168.50.112", "198.51.100.5", 12345}} {
		c, err := net.DialUDP("udp4", &net.UDPAddr{IP: net.ParseIP(flow.source)}, &net.UDPAddr{IP: net.ParseIP(flow.destination), Port: flow.port})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = c.Write([]byte("synthetic policy scope")); err != nil {
			t.Fatal(err)
		}
		c.Close()
	}
	time.Sleep(100 * time.Millisecond)
}
