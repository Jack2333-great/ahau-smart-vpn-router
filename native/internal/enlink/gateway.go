package enlink

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

type Tunnel struct {
	Conn       net.Conn
	Assignment Assignment
	// DataIdentifier is 1 for the school Android SDK or 41 for the observed
	// Windows/Linux desktop IPv4 envelope. Zero retains the Android default.
	DataIdentifier uint32
	mu             sync.Mutex
}

func DialGateway(ctx context.Context, endpoint Endpoint, config *tls.Config, login Login) (*Tunnel, error) {
	if config == nil {
		return nil, errors.New("TLS configuration required")
	}
	cfg := config.Clone()
	cfg.ServerName = endpoint.ServerName
	dial := tls.Dialer{NetDialer: &net.Dialer{Timeout: 10 * time.Second}, Config: cfg}
	conn, err := dial.DialContext(ctx, "tcp", endpoint.Address)
	if err != nil {
		return nil, errors.New("gateway TLS connection failed (address, trust, or SPA policy)")
	}
	success := false
	defer func() {
		if !success {
			conn.Close()
		}
	}()
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	// Closing on cancellation also interrupts a blocked authentication read.
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	auth, err := AuthFrame(login.Username, login.SID)
	if err != nil {
		return nil, err
	}
	defer clear(auth)
	if err = writeAll(conn, auth); err != nil {
		return nil, errors.New("gateway auth write failed")
	}
	assigned, err := ReadAssignment(conn)
	if err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	conn.SetDeadline(time.Time{})
	success = true
	return &Tunnel{Conn: conn, Assignment: assigned}, nil
}
func writeAll(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if n < 0 || n > len(b) {
			return errors.New("invalid writer count")
		}
		b = b[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}
func (t *Tunnel) Send(b []byte) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.Conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	return writeAll(t.Conn, b)
}
func (t *Tunnel) Close() error { return t.Conn.Close() }

// Observe authenticates a tunnel and exercises heartbeats without creating a
// network device or sending IP traffic. Cancellation always closes the stream.
type Heartbeats struct{ Sent, Received int }

func (t *Tunnel) Observe(ctx context.Context, interval time.Duration) (Heartbeats, error) {
	var count Heartbeats
	if interval <= 0 {
		return count, errors.New("heartbeat interval must be positive")
	}
	reading, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(ctx, func() { t.Conn.Close() })
	defer stop()
	finished := make(chan struct{})
	defer func() { cancel(); t.Conn.Close(); <-finished }()
	events := make(chan error, 1)
	go func() {
		defer close(finished)
		for {
			t.Conn.SetReadDeadline(time.Now().Add(4 * interval))
			f, err := ReadFrame(t.Conn)
			if err == nil && !f.Heartbeat {
				err = errors.New("unexpected IP data during isolated handshake test")
			}
			select {
			case events <- err:
			case <-reading.Done():
				return
			}
			if err != nil {
				return
			}
		}
	}()
	// Send immediately: a 10-second observation must not race its first
	// heartbeat against a 10-second ticker/deadline.
	if err := ctx.Err(); err != nil {
		return count, err
	}
	if err := t.Send(HeartbeatFrame()); err != nil {
		if ctx.Err() != nil {
			return count, ctx.Err()
		}
		return count, err
	}
	count.Sent++
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return count, ctx.Err()
		case err := <-events:
			if err != nil {
				if ctx.Err() != nil {
					return count, ctx.Err()
				}
				return count, err
			}
			count.Received++
		case <-tick.C:
			if err := t.Send(HeartbeatFrame()); err != nil {
				if ctx.Err() != nil {
					return count, ctx.Err()
				}
				return count, err
			}
			count.Sent++
		}
	}
}
