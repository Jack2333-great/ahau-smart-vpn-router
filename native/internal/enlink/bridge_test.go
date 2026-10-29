package enlink

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

type packetDevice struct {
	in, out chan []byte
	done    chan struct{}
	once    sync.Once
}

func TestBridgeHeartbeatLossClosesBothEnds(t *testing.T) {
	local, remote := net.Pipe()
	defer remote.Close()
	dev := &packetDevice{make(chan []byte), make(chan []byte), make(chan struct{}), sync.Once{}}
	tunnel := &Tunnel{Conn: local, Assignment: Assignment{IP: netip.MustParseAddr("10.0.0.2")}}
	acl, _ := CompileACL([]string{"UDP;192.0.2.5;443"})
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		// Accept client heartbeats but deliberately send nothing back.
		io.Copy(io.Discard, remote)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := tunnel.Bridge(ctx, dev, acl, 20*time.Millisecond)
	var timeout net.Error
	if !errors.As(err, &timeout) || !timeout.Timeout() || ctx.Err() != nil {
		t.Fatalf("missing heartbeat did not cause a read timeout: %v", err)
	}
	select {
	case <-dev.done:
	default:
		t.Fatal("packet device remained open")
	}
	select {
	case <-serverDone:
	case <-ctx.Done():
		t.Fatal("gateway connection remained open")
	}
}

func (d *packetDevice) Read(p []byte) (int, error) {
	select {
	case <-d.done:
		return 0, io.EOF
	case b := <-d.in:
		return copy(p, b), nil
	}
}
func (d *packetDevice) Write(p []byte) (int, error) {
	select {
	case <-d.done:
		return 0, io.ErrClosedPipe
	case d.out <- bytes.Clone(p):
		return len(p), nil
	}
}
func (d *packetDevice) Close() error { d.once.Do(func() { close(d.done) }); return nil }
func TestBridgeResourceFilteringAndCleanup(t *testing.T) {
	local, remote := net.Pipe()
	defer remote.Close()
	dev := &packetDevice{make(chan []byte, 3), make(chan []byte, 3), make(chan struct{}), sync.Once{}}
	tunnel := &Tunnel{Conn: local, Assignment: Assignment{IP: netip.MustParseAddr("10.0.0.2")}}
	acl, _ := CompileACL([]string{"TCP;192.0.2.0/24;443"})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	type result struct {
		s BridgeStats
		e error
	}
	done := make(chan result, 1)
	go func() { s, e := tunnel.Bridge(ctx, dev, acl, time.Second); done <- result{s, e} }()
	allowed := ipv4()
	denied := bytes.Clone(allowed)
	denied[23] = 80
	spoof := bytes.Clone(allowed)
	spoof[12] = 192
	dev.in <- denied
	dev.in <- spoof
	dev.in <- allowed
	remote.SetDeadline(time.Now().Add(2 * time.Second))
	h := make([]byte, 12)
	if _, err := io.ReadFull(remote, h); err != nil {
		t.Fatal(err)
	}
	if h[1] != 4 || binary.BigEndian.Uint32(h[8:12]) != 1 {
		t.Fatalf("bad upstream header %x", h)
	}
	b := make([]byte, int(binary.BigEndian.Uint16(h[2:4]))-12)
	if _, err := io.ReadFull(remote, b); err != nil || !bytes.Equal(b, allowed) {
		t.Fatal("authorized data not sent", err)
	}
	reply := bytes.Clone(allowed)
	copy(reply[12:16], allowed[16:20])
	copy(reply[16:20], allowed[12:16])
	copy(reply[20:22], allowed[22:24])
	reply[22] = 0x9c
	reply[23] = 0x40
	badreply := bytes.Clone(reply)
	badreply[12] = 198
	if err := writeAll(remote, append(downFrame(badreply), downFrame(reply)...)); err != nil {
		t.Fatal(err)
	}
	select {
	case p := <-dev.out:
		if !bytes.Equal(p, reply) {
			t.Fatal("incorrect reply delivered")
		}
	case <-ctx.Done():
		t.Fatal("reply not delivered")
	}
	cancel()
	select {
	case r := <-done:
		if !errors.Is(r.e, context.Canceled) || r.s.Sent != 1 || r.s.Received != 1 || r.s.Dropped != 3 {
			t.Fatalf("stats=%+v err=%v", r.s, r.e)
		}
	case <-time.After(time.Second):
		t.Fatal("bridge workers did not stop")
	}
	select {
	case <-dev.done:
	default:
		t.Fatal("device not closed")
	}
}
