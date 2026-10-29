package enlink

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

type PacketDevice interface{ io.ReadWriteCloser }
type BridgeStats struct{ Sent, Received, Dropped uint64 }

// Bridge carries only packets sourced from the negotiated IPv4 and allowed by
// server resources. It deliberately has no LAN forwarding/NAT configuration.
// EOF, heartbeat loss, cancellation, or either write failure closes both ends.
func (t *Tunnel) Bridge(ctx context.Context, device PacketDevice, acl []ACL, interval time.Duration) (BridgeStats, error) {
	return t.BridgeWithNAT(ctx, device, acl, interval, nil)
}

func (t *Tunnel) BridgeWithNAT(ctx context.Context, device PacketDevice, acl []ACL, interval time.Duration, nat *SourceNAT) (BridgeStats, error) {
	var sent, received, dropped atomic.Uint64
	if len(acl) == 0 || interval <= 0 || !t.Assignment.IP.Is4() {
		return BridgeStats{}, errors.New("bridge requires an IPv4 assignment, resources, and heartbeat interval")
	}
	if nat != nil && nat.ip != t.Assignment.IP {
		return BridgeStats{}, errors.New("translation address differs from gateway assignment")
	}
	identifier := t.DataIdentifier
	if identifier == 0 {
		identifier = 1
	}
	if identifier != 1 && identifier != 41 {
		return BridgeStats{}, errors.New("unsupported data envelope identifier")
	}
	working, cancel := context.WithCancel(ctx)
	defer cancel()
	errorsCh := make(chan error, 3)
	var workers sync.WaitGroup
	report := func(err error) {
		select {
		case errorsCh <- err:
		case <-working.Done():
		}
	}
	stop := context.AfterFunc(ctx, func() { t.Conn.Close(); device.Close() })
	defer stop()
	workers.Add(3)
	go func() {
		defer workers.Done()
		p := make([]byte, MaxFrame-12)
		for {
			n, err := device.Read(p)
			if err != nil {
				report(err)
				return
			}
			if n == 0 {
				continue
			}
			packet := p[:n]
			ok := ValidateIPv4(packet) == nil
			if ok {
				source := netip.AddrFrom4([4]byte(packet[12:16]))
				ok = source == t.Assignment.IP
				if nat != nil {
					ok = nat.AllowsSource(source)
				}
			}
			allowed := false
			if ok {
				for _, rule := range acl {
					if rule.Allows(packet) {
						allowed = true
						break
					}
				}
			}
			if !allowed {
				dropped.Add(1)
				continue
			}
			if nat != nil {
				var err error
				packet, err = nat.Outbound(packet)
				if err != nil {
					dropped.Add(1)
					continue
				}
			}
			frame, err := DataFrame(packet, identifier)
			if err != nil {
				report(err)
				return
			}
			if err = t.Send(frame); err != nil {
				report(err)
				return
			}
			sent.Add(1)
		}
	}()
	go func() {
		defer workers.Done()
		for {
			t.Conn.SetReadDeadline(time.Now().Add(4 * interval))
			f, err := ReadFrame(t.Conn)
			if err != nil {
				report(err)
				return
			}
			if f.Heartbeat {
				continue
			}
			if netip.AddrFrom4([4]byte(f.Packet[16:20])) != t.Assignment.IP {
				dropped.Add(1)
				continue
			}
			allowed := false
			for _, rule := range acl {
				if rule.AllowsReply(f.Packet) {
					allowed = true
					break
				}
			}
			if !allowed {
				dropped.Add(1)
				continue
			}
			if nat != nil {
				f.Packet, err = nat.Inbound(f.Packet)
				if err != nil {
					dropped.Add(1)
					continue
				}
			}
			n, err := device.Write(f.Packet)
			if err != nil {
				report(err)
				return
			}
			if n != len(f.Packet) {
				report(io.ErrShortWrite)
				return
			}
			received.Add(1)
		}
	}()
	go func() {
		defer workers.Done()
		tick := time.NewTicker(interval)
		defer tick.Stop()
		for {
			select {
			case <-working.Done():
				return
			case <-tick.C:
				if err := t.Send(HeartbeatFrame()); err != nil {
					report(err)
					return
				}
			}
		}
	}()
	var err error
	select {
	case <-ctx.Done():
		err = ctx.Err()
	case err = <-errorsCh:
	}
	cancel()
	t.Conn.Close()
	device.Close()
	workers.Wait()
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	return BridgeStats{sent.Load(), received.Load(), dropped.Load()}, err
}
