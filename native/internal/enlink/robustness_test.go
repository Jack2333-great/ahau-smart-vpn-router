package enlink

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestControllerErrorDoesNotReflectResponseContent(t *testing.T) {
	for _, code := range []string{`"private-session-token"`, `{"sid":"private-session-token"}`, `"200\nprivate-session-token"`, `1234567890`, `null`} {
		err := (Response{Code: json.RawMessage(code)}).Check()
		if err == nil || strings.Contains(err.Error(), "private-session-token") || !strings.Contains(err.Error(), "unsupported") {
			t.Fatalf("response content escaped into diagnostics: %v", err)
		}
	}
	if err := (Response{Code: json.RawMessage(`"401"`)}).Check(); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatal("numeric diagnostic lost", err)
	}
}

func TestBridgeRejectsMismatchedTranslation(t *testing.T) {
	n, _ := NewSourceNAT(netip.MustParseAddr("10.0.0.3"), []netip.Prefix{netip.MustParsePrefix("192.168.50.112/32")})
	tunnel := &Tunnel{Assignment: Assignment{IP: netip.MustParseAddr("10.0.0.2")}}
	acl, _ := CompileACL([]string{"TCP;192.0.2.5;443"})
	if _, err := tunnel.BridgeWithNAT(context.Background(), nil, acl, time.Second, n); err == nil {
		t.Fatal("mismatched NAT accepted")
	}
}

func TestGatewayPolicyDoesNotIgnoreExclusions(t *testing.T) {
	for _, field := range []string{"gateway-ip", "gateway-domain", "global-ip", "global-domain"} {
		var r Rules
		g := Gateway{IPList: []string{"ANY;192.0.2.0/24;ANY"}}
		switch field {
		case "gateway-ip":
			g.OutIP = []string{"TCP;192.0.2.5;443"}
		case "gateway-domain":
			g.OutDomains = []string{"excluded.example"}
		case "global-ip":
			r.Filter.OutIP = []string{"TCP;192.0.2.5;443"}
		case "global-domain":
			r.Filter.OutDomains = []string{"excluded.example"}
		}
		if _, err := CompileGatewayACL(r, g); err == nil {
			t.Fatal("exclusion silently ignored", field)
		}
	}
}

func TestNATMSSOptionsAndChecksums(t *testing.T) {
	for _, mss := range []uint16{1200, 1460} {
		n, _ := NewSourceNAT(netip.MustParseAddr("10.0.0.2"), []netip.Prefix{netip.MustParsePrefix("192.168.50.112/32")})
		p := transportPacket(6, "192.168.50.112", 50000)
		p = append(p[:40], 1, 1, 2, 4, byte(mss>>8), byte(mss), 0, 0)
		p[32], p[33] = 0x70, 2 // SYN, 28-byte TCP header.
		binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
		repairChecksums(p, 20)
		out, err := n.Outbound(p)
		want := mss
		if want > 1260 {
			want = 1260
		}
		if err != nil || binary.BigEndian.Uint16(out[44:46]) != want || !validChecksums(out) {
			t.Fatalf("outbound MSS/checksum: %v %x", err, out)
		}
		// Independently restore a large MSS on the server SYN/ACK to exercise
		// the reverse path, rather than inheriting the outbound clamp.
		ack := reversePacket(out)
		ack[33] = 0x12
		binary.BigEndian.PutUint16(ack[44:46], 1460)
		repairChecksums(ack, 20)
		back, err := n.Inbound(ack)
		if err != nil || binary.BigEndian.Uint16(back[44:46]) != 1260 || !validChecksums(back) {
			t.Fatalf("inbound MSS/checksum: %v %x", err, back)
		}
	}
}

func FuzzTranslation(f *testing.F) {
	f.Add(transportPacket(6, "192.168.50.112", 50000))
	f.Add(transportPacket(17, "192.168.50.112", 50000))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, p []byte) {
		if len(p) > MaxFrame {
			return
		}
		n, _ := NewSourceNAT(netip.MustParseAddr("10.0.0.2"), []netip.Prefix{netip.MustParsePrefix("192.168.50.112/32")})
		original := bytes.Clone(p)
		out, err := n.Outbound(p)
		if !bytes.Equal(original, p) {
			t.Fatal("input mutated")
		}
		if err != nil {
			// The inbound parser must also be bounded for unrelated data.
			n.Inbound(p)
			return
		}
		if !validChecksums(out) {
			t.Fatal("invalid outbound checksum")
		}
		back, err := n.Inbound(reversePacket(out))
		if err != nil || !validChecksums(back) {
			t.Fatalf("round trip: %v", err)
		}
		if !bytes.Equal(back[16:20], p[12:16]) {
			t.Fatal("wrong restored destination")
		}
	})
}

func BenchmarkNATRoundTrip(b *testing.B) {
	n, _ := NewSourceNAT(netip.MustParseAddr("10.0.0.2"), []netip.Prefix{netip.MustParsePrefix("192.168.50.112/32")})
	p := transportPacket(17, "192.168.50.112", 50000)
	p = append(p, make([]byte, 1200-len(p))...)
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	binary.BigEndian.PutUint16(p[24:26], uint16(len(p)-20))
	repairChecksums(p, 20)
	out, _ := n.Outbound(p)
	reply := reversePacket(out)
	b.SetBytes(int64(2 * len(p)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := n.Outbound(p); err != nil {
			b.Fatal(err)
		}
		if _, err := n.Inbound(reply); err != nil {
			b.Fatal(err)
		}
	}
}
