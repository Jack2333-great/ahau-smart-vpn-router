package enlink

import (
	"bytes"
	"campusvpn/internal/tun"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"testing"
	"time"
)

// Run only through `unshare -n` as root. A real Linux UDP socket sends packets
// through a real transient TUN; the synthetic peer echoes protocol frames.
// This validates kernel integration, not live school access.
func TestKernelUDPRoundTripIntegration(t *testing.T) {
	if os.Getenv("CAMPUSVPN_ISOLATED_TUN_TEST") != "1" {
		t.Skip("requires isolated network namespace")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	dev, err := tun.Open("cvpn9875")
	if err != nil {
		t.Fatal(err)
	}
	defer dev.Close()
	ip := netip.MustParseAddr("10.0.0.2")
	if err = dev.Configure(ctx, ip, 1300); err != nil {
		t.Fatal(err)
	}
	if err = exec.CommandContext(ctx, "ip", "route", "add", "192.0.2.5/32", "dev", dev.Name, "src", ip.String()).Run(); err != nil {
		t.Fatal(err)
	}
	a, b := net.Pipe()
	defer b.Close()
	tunnel := &Tunnel{Conn: a, Assignment: Assignment{IP: ip}}
	acl, _ := CompileACL([]string{"UDP;192.0.2.5/32;12345"})
	type result struct {
		s BridgeStats
		e error
	}
	done := make(chan result, 1)
	go func() { s, e := tunnel.Bridge(ctx, dev, acl, 100*time.Millisecond); done <- result{s, e} }()
	peerDone := make(chan struct{})
	go func() {
		defer close(peerDone)
		for {
			h := make([]byte, 12)
			if _, e := io.ReadFull(b, h); e != nil {
				return
			}
			n := int(binary.BigEndian.Uint16(h[2:4]))
			if n < 12 || n > MaxFrame {
				return
			}
			if h[1] == 1 {
				if e := writeAll(b, []byte{1, 2, 0, 12, 0, 0, 0, 0, 3, 0, 0, 0}); e != nil {
					return
				}
				continue
			}
			packet := make([]byte, n-12)
			if _, e := io.ReadFull(b, packet); e != nil {
				return
			}
			if len(packet) < 28 {
				return
			}
			ihl := int(packet[0]&15) * 4
			original := bytes.Clone(packet)
			copy(packet[12:16], original[16:20])
			copy(packet[16:20], original[12:16])
			copy(packet[ihl:ihl+2], original[ihl+2:ihl+4])
			copy(packet[ihl+2:ihl+4], original[ihl:ihl+2])
			packet[ihl+6] = 0
			packet[ihl+7] = 0
			packet[10] = 0
			packet[11] = 0
			var checksum uint32
			for i := 0; i < ihl; i += 2 {
				checksum += uint32(binary.BigEndian.Uint16(packet[i : i+2]))
			}
			for checksum>>16 != 0 {
				checksum = (checksum & 65535) + (checksum >> 16)
			}
			binary.BigEndian.PutUint16(packet[10:12], ^uint16(checksum))
			if e := writeAll(b, downFrame(packet)); e != nil {
				return
			}
		}
	}()
	conn, err := net.DialUDP("udp4", &net.UDPAddr{IP: net.ParseIP(ip.String())}, &net.UDPAddr{IP: net.ParseIP("192.0.2.5"), Port: 12345})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	for _, payload := range []string{"kernel-tun-first", "kernel-tun-second", "kernel-tun-third"} {
		if _, err = conn.Write([]byte(payload)); err != nil {
			t.Fatal(err)
		}
		buffer := make([]byte, 128)
		n, e := conn.Read(buffer)
		if e != nil || string(buffer[:n]) != payload {
			t.Fatalf("UDP echo %q %v", buffer[:n], e)
		}
	}
	cancel()
	select {
	case r := <-done:
		if r.s.Sent != 3 || r.s.Received != 3 {
			t.Fatalf("%+v %v", r.s, r.e)
		}
	case <-time.After(time.Second):
		t.Fatal("bridge cleanup stuck")
	}
	b.Close()
	<-peerDone
	if _, err = net.InterfaceByName(dev.Name); err == nil {
		t.Fatal("TUN leaked")
	}
}
