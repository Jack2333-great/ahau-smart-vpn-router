package enlink

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// Reproduce the live school's 88-byte option layout with synthetic addresses.
// A capability TLV precedes IPv6 values; interpreting it as an end marker
// rejected real handshakes even though TLS and account authentication worked.
func TestAssignmentSchoolCapabilityAndIPv6Tail(t *testing.T) {
	b := bytes.Clone(assignment()[:26])
	b = append(b, 35, 0, 4, 't', 'e', 's', 't')
	b = append(b, 36, 0, 9)
	b = append(b, []byte("192.0.2.1")...)
	b = append(b, 43, 0, 1, 0, 53, 0, 16)
	b = append(b, make([]byte, 16)...)
	b = append(b, 54, 0, 16)
	b = append(b, make([]byte, 16)...)
	b = append(b, 255)
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	if len(b) != 88 {
		t.Fatal("fixture layout drift", len(b))
	}
	stream := bytes.NewReader(append(b, []byte{1, 2, 0, 12, 0, 0, 0, 0, 3, 0, 0, 0}...))
	a, err := ReadAssignment(fragmentReader{stream})
	if err != nil || a.IP.String() != "10.0.0.2" || len(a.DNS) != 1 || a.DNS[0] != "192.0.2.1" {
		t.Fatal(a, err)
	}
	f, err := ReadFrame(stream)
	if err != nil || !f.Heartbeat {
		t.Fatal("next frame consumed by assignment", err)
	}
	// Missing final ff and a truncated extension must still be rejected.
	for _, trim := range []int{1, 2, 17} {
		bad := bytes.Clone(b[:len(b)-trim])
		binary.BigEndian.PutUint16(bad[2:4], uint16(len(bad)))
		if _, err := ReadAssignment(bytes.NewReader(bad)); err == nil {
			t.Fatal("accepted truncated live layout", trim)
		}
	}
}
