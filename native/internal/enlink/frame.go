package enlink

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
)

const MaxFrame = 32767 // Android's reader uses a signed Java short.
var ErrAuthRejected = errors.New("gateway rejected authentication")
var heartbeat = []byte{1, 1, 0, 12, 0, 0, 0, 0, 3, 0, 0, 0}

// AuthFrame: version, operation, BE total length, reserved, LE method,
// then (LE uint16 type, uint8 UTF-8 byte length, value), and ff terminator.
func AuthFrame(username, session string) ([]byte, error) {
	if len(username) == 0 || len(username) > 255 || len(session) == 0 || len(session) > 255 {
		return nil, errors.New("username/session must contain 1..255 UTF-8 bytes")
	}
	b := []byte{1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0}
	b = append(b, 1, 0, byte(len(username)))
	b = append(b, []byte(username)...)
	b = append(b, 2, 0, byte(len(session)))
	b = append(b, []byte(session)...)
	b = append(b, 255)
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	return b, nil
}

type Assignment struct {
	IP   netip.Addr
	Mask netip.Prefix
	DNS  []string
	WINS []string
}

// ReadAssignment consumes the entire response (including its terminator),
// preserving any following frame in the TLS stream. No unbounded reads.
func ReadAssignment(r io.Reader) (Assignment, error) {
	var a Assignment
	h := make([]byte, 12)
	if _, err := io.ReadFull(r, h); err != nil {
		return a, fmt.Errorf("gateway auth header: %w", err)
	}
	size := int(binary.BigEndian.Uint16(h[2:4]))
	if h[0] != 1 || h[1] != 2 || size < 12 || size > MaxFrame {
		return a, errors.New("invalid gateway auth header")
	}
	if h[10] != 0 || h[11] != 0 {
		return a, fmt.Errorf("%w (status 0x%02x%02x)", ErrAuthRejected, h[10], h[11])
	}
	if size == 12 {
		return a, errors.New("gateway supplied no virtual address")
	}
	body := make([]byte, size-12)
	if _, err := io.ReadFull(r, body); err != nil {
		return a, fmt.Errorf("gateway options: %w", err)
	}
	var mask netip.Addr
	done := false
	for len(body) > 0 {
		if len(body) == 1 && body[0] == 255 {
			done = true
			break
		}
		if len(body) < 2 {
			return a, errors.New("truncated gateway option type")
		}
		tag := binary.LittleEndian.Uint16(body[:2])
		body = body[2:]
		// Older fixtures end with a bare 43 (optionally followed by ff).
		// The live school gateway instead sends 43 as a one-byte TLV before
		// IPv6 options 53/54. Only ff ends that complete option sequence.
		if tag == 43 && (len(body) == 0 || len(body) == 1 && body[0] == 255) {
			done = true
			break
		}
		if len(body) < 1 {
			return a, errors.New("truncated gateway option length")
		}
		n := int(body[0])
		body = body[1:]
		if n > len(body) {
			return a, errors.New("truncated gateway option value")
		}
		value := body[:n]
		body = body[n:]
		switch tag {
		case 11:
			if n != 4 || a.IP.IsValid() {
				return a, errors.New("invalid/duplicate virtual address")
			}
			a.IP = netip.AddrFrom4([4]byte(value))
		case 12:
			if n != 4 || mask.IsValid() {
				return a, errors.New("invalid/duplicate virtual mask")
			}
			mask = netip.AddrFrom4([4]byte(value))
		case 35: // Gateway-provided name, unused.
		case 36:
			a.DNS = splitServers(value)
		case 37:
			a.WINS = splitServers(value)
		case 43:
			if n != 1 || value[0] > 1 {
				return a, errors.New("invalid gateway capability option")
			}
			// Consume the capability byte without configuring IPv6.
		case 53, 54:
			// Windows setupTun handles these as IPv6 address/DNS options.
			// Their bounded TLV values are consumed; this IPv4-only client
			// neither configures IPv6 nor installs IPv6 routes.
		default:
			return a, fmt.Errorf("unsupported gateway option %d; refusing to guess its meaning", tag)
		}
	}
	if !done || !a.IP.Is4() || !mask.Is4() || a.IP.IsUnspecified() || a.IP.IsMulticast() {
		return a, errors.New("incomplete/invalid virtual address assignment")
	}
	m := mask.As4()
	bits := 0
	zero := false
	for _, v := range m {
		for bit := 7; bit >= 0; bit-- {
			one := v&(1<<bit) != 0
			if one && zero {
				return a, errors.New("non-contiguous gateway netmask")
			}
			if one {
				bits++
			} else {
				zero = true
			}
		}
	}
	a.Mask = netip.PrefixFrom(a.IP, bits)
	return a, nil
}

func splitServers(value []byte) []string {
	value = bytes.ReplaceAll(value, []byte("；"), []byte(";"))
	var out []string
	for _, s := range bytes.Split(value, []byte(";")) {
		if a, err := netip.ParseAddr(string(bytes.TrimSpace(s))); err == nil && a.Is4() {
			out = append(out, a.String())
		}
	}
	return out
}

func DataFrame(packet []byte, tunnelID uint32) ([]byte, error) {
	if err := ValidateIPv4(packet); err != nil {
		return nil, err
	}
	if len(packet)+12 > MaxFrame {
		return nil, errors.New("packet exceeds frame limit")
	}
	b := make([]byte, 12+len(packet))
	b[0] = 1
	b[1] = 4
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	binary.BigEndian.PutUint32(b[8:12], tunnelID)
	copy(b[12:], packet)
	return b, nil
}

func HeartbeatFrame() []byte { return bytes.Clone(heartbeat) }

type Frame struct {
	Heartbeat bool
	Packet    []byte
}

func ReadFrame(r io.Reader) (Frame, error) {
	var f Frame
	h := make([]byte, 8)
	if _, err := io.ReadFull(r, h); err != nil {
		return f, err
	}
	n := int(binary.BigEndian.Uint16(h[2:4]))
	if h[0] != 1 || n < 8 || n > MaxFrame {
		return f, errors.New("invalid frame version/length")
	}
	body := make([]byte, n-8)
	if _, err := io.ReadFull(r, body); err != nil {
		return f, err
	}
	if h[1] == 2 && n == 12 && bytes.Equal(h[4:], []byte{0, 0, 0, 0}) && bytes.Equal(body, []byte{3, 0, 0, 0}) {
		f.Heartbeat = true
		return f, nil
	}
	if h[1] != 4 {
		return f, fmt.Errorf("unsupported gateway frame operation %d", h[1])
	}
	if err := ValidateIPv4(body); err != nil {
		return f, err
	}
	f.Packet = body
	return f, nil
}

func ValidateIPv4(p []byte) error {
	if len(p) < 20 || p[0]>>4 != 4 {
		return errors.New("not an IPv4 packet")
	}
	ihl := int(p[0]&15) * 4
	if ihl < 20 || ihl > len(p) || int(binary.BigEndian.Uint16(p[2:4])) != len(p) {
		return errors.New("invalid IPv4 length")
	}
	return nil
}
