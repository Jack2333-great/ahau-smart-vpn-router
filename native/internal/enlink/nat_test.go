package enlink

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

func transportPacket(protocol byte, source string, port uint16) []byte {
	size := 20
	if protocol == 17 {
		size = 8
	}
	p := make([]byte, 20+size+5)
	p[0], p[8], p[9] = 0x45, 64, protocol
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	a := netip.MustParseAddr(source).As4()
	copy(p[12:16], a[:])
	copy(p[16:20], []byte{192, 0, 2, 5})
	binary.BigEndian.PutUint16(p[20:22], port)
	binary.BigEndian.PutUint16(p[22:24], 443)
	if protocol == 6 {
		p[32] = 0x50
		p[33] = 0x18
	} else {
		binary.BigEndian.PutUint16(p[24:26], uint16(size+5))
	}
	copy(p[20+size:], []byte("hello"))
	repairChecksums(p, 20)
	return p
}
func reversePacket(p []byte) []byte {
	out := bytes.Clone(p)
	copy(out[12:16], p[16:20])
	copy(out[16:20], p[12:16])
	ihl := int(p[0]&15) * 4
	copy(out[ihl:ihl+2], p[ihl+2:ihl+4])
	copy(out[ihl+2:ihl+4], p[ihl:ihl+2])
	repairChecksums(out, ihl)
	return out
}

// Verify the complete IPv4 header and pseudo-header checksum independently
// from repairChecksums' field positioning, including an odd payload length.
func validChecksums(p []byte) bool {
	ihl := int(p[0]&15) * 4
	if checksum(p[:ihl], 0) != 0 {
		return false
	}
	pseudo := []byte{p[12], p[13], p[14], p[15], p[16], p[17], p[18], p[19], 0, p[9], byte((len(p) - ihl) >> 8), byte(len(p) - ihl)}
	return checksum(append(pseudo, p[ihl:]...), 0) == 0
}
func TestNATTwoClientsAndProtocols(t *testing.T) {
	n, err := NewSourceNAT(netip.MustParseAddr("10.0.0.2"), []netip.Prefix{netip.MustParsePrefix("192.168.50.0/24")})
	if err != nil {
		t.Fatal(err)
	}
	for _, protocol := range []byte{6, 17} {
		seen := map[uint16]bool{}
		for _, source := range []string{"192.168.50.112", "192.168.50.113", "10.0.0.2"} {
			original := transportPacket(protocol, source, 50000)
			translated, e := n.Outbound(original)
			if e != nil || !validChecksums(translated) {
				t.Fatalf("outbound %v %x", e, translated)
			}
			port := binary.BigEndian.Uint16(translated[20:22])
			if seen[port] {
				t.Fatal("two clients collided")
			}
			seen[port] = true
			if !bytes.Equal(translated[12:16], []byte{10, 0, 0, 2}) || !bytes.Equal(original, transportPacket(protocol, source, 50000)) {
				t.Fatal("wrong address or input mutated")
			}
			again, e := n.Outbound(original)
			if e != nil || !bytes.Equal(again, translated) {
				t.Fatal("flow mapping changed")
			}
			reply, e := n.Inbound(reversePacket(translated))
			if e != nil || !validChecksums(reply) || !bytes.Equal(reply, reversePacket(original)) {
				t.Fatalf("reply %v %x", e, reply)
			}
			for _, offset := range []int{12, 20, 22} {
				forged := reversePacket(translated)
				forged[offset] ^= 1
				if _, e = n.Inbound(forged); e == nil {
					t.Fatalf("forged tuple accepted offset=%d", offset)
				}
			}
		}
	}
	if _, err = n.Outbound(transportPacket(17, "192.168.7.1", 50000)); err == nil {
		t.Fatal("unauthorized LAN source translated")
	}
}
func TestNATExpiryCapacityAndMalformed(t *testing.T) {
	n, _ := NewSourceNAT(netip.MustParseAddr("10.0.0.2"), []netip.Prefix{netip.MustParsePrefix("192.168.50.112/32")})
	n.limit = 1
	now := time.Unix(1000, 0)
	n.now = func() time.Time { return now }
	p := transportPacket(17, "192.168.50.112", 50000)
	translated, e := n.Outbound(p)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = n.Outbound(transportPacket(17, "192.168.50.112", 50001)); e == nil {
		t.Fatal("table capacity ignored")
	}
	now = now.Add(91 * time.Second)
	if _, e = n.Inbound(reversePacket(translated)); e == nil {
		t.Fatal("expired reply accepted")
	}
	if _, e = n.Outbound(transportPacket(17, "192.168.50.112", 50001)); e != nil {
		t.Fatal("expired entry not reclaimed")
	}
	for _, mutate := range []func([]byte){func(p []byte) { p[6] = 0x20 }, func(p []byte) { p[25]-- }, func(p []byte) { p[20] = 0; p[21] = 0 }} {
		bad := bytes.Clone(p)
		mutate(bad)
		if _, e = n.Outbound(bad); e == nil {
			t.Fatal("malformed translation accepted")
		}
	}
	for _, source := range []string{"0.0.0.0/0", "192.168.0.0/15", "203.0.113.0/24", "::/128"} {
		if _, e := NewSourceNAT(netip.MustParseAddr("10.0.0.2"), []netip.Prefix{netip.MustParsePrefix(source)}); e == nil {
			t.Fatal("invalid LAN prefix accepted", source)
		}
	}
}

func TestAssignmentConsumesOptionalIPv6(t *testing.T) {
	b := assignment()
	b = append(bytes.Clone(b[:26]), append([]byte{53, 0, 16}, make([]byte, 16)...)...)
	b = append(b, 54, 0, 0, 43, 0, 255)
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	a, err := ReadAssignment(bytes.NewReader(b))
	if err != nil || a.IP.String() != "10.0.0.2" {
		t.Fatal(a, err)
	}
}
