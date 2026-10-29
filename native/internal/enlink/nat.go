package enlink

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"sync"
	"time"
)

type flowKey struct {
	protocol      byte
	local, remote netip.AddrPort
}
type returnKey struct {
	protocol byte
	port     uint16
	remote   netip.AddrPort
}
type translation struct {
	key  flowKey
	port uint16
	last time.Time
}

// SourceNAT is an optional in-memory TCP/UDP translator for explicitly selected
// LAN sources. It changes no kernel firewall, routing, forwarding, or DNS state.
// Every flow, including router-originated traffic, is translated, so replies
// cannot collide with the router's own ephemeral ports. Resource ACL checks
// remain the bridge's responsibility, both before translation and on replies.
type SourceNAT struct {
	mu      sync.Mutex
	ip      netip.Addr
	sources []netip.Prefix
	flows   map[flowKey]*translation
	replies map[returnKey]*translation
	next    uint16
	limit   int
	now     func() time.Time
	swept   time.Time
}

func NewSourceNAT(ip netip.Addr, sources []netip.Prefix) (*SourceNAT, error) {
	if !ip.Is4() || ip.IsUnspecified() || len(sources) == 0 {
		return nil, errors.New("LAN translation requires an assigned IPv4 and explicit private source prefixes")
	}
	for _, prefix := range sources {
		if !prefix.IsValid() || !prefix.Addr().Is4() || prefix.Bits() < 16 || !prefix.Addr().IsPrivate() || !lastAddress(prefix).IsPrivate() {
			return nil, errors.New("LAN sources must be private IPv4 prefixes of /16 or narrower")
		}
	}
	return &SourceNAT{ip: ip, sources: append([]netip.Prefix(nil), sources...), flows: make(map[flowKey]*translation), replies: make(map[returnKey]*translation), next: 40000, limit: 4096, now: time.Now}, nil
}
func lastAddress(prefix netip.Prefix) netip.Addr {
	b := prefix.Masked().Addr().As4()
	n := binary.BigEndian.Uint32(b[:]) | uint32((uint64(1)<<uint(32-prefix.Bits()))-1)
	binary.BigEndian.PutUint32(b[:], n)
	return netip.AddrFrom4(b)
}
func (n *SourceNAT) AllowsSource(ip netip.Addr) bool {
	if ip == n.ip {
		return true
	}
	for _, p := range n.sources {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}
func transport(p []byte) (flowKey, int, error) {
	var key flowKey
	if ValidateIPv4(p) != nil || p[6]&0x3f != 0 || p[7] != 0 {
		return key, 0, errors.New("invalid/fragmented translation packet")
	}
	ihl := int(p[0]&15) * 4
	key.protocol = p[9]
	switch key.protocol {
	case 6:
		if len(p) < ihl+20 {
			return key, 0, errors.New("truncated TCP")
		}
		size := int(p[ihl+12]>>4) * 4
		if size < 20 || len(p) < ihl+size {
			return key, 0, errors.New("invalid TCP header length")
		}
	case 17:
		if len(p) < ihl+8 || int(binary.BigEndian.Uint16(p[ihl+4:ihl+6])) != len(p)-ihl {
			return key, 0, errors.New("invalid UDP length")
		}
	default:
		return key, 0, errors.New("translation supports TCP/UDP only")
	}
	key.local = netip.AddrPortFrom(netip.AddrFrom4([4]byte(p[12:16])), binary.BigEndian.Uint16(p[ihl:ihl+2]))
	key.remote = netip.AddrPortFrom(netip.AddrFrom4([4]byte(p[16:20])), binary.BigEndian.Uint16(p[ihl+2:ihl+4]))
	if key.local.Port() == 0 || key.remote.Port() == 0 {
		return key, 0, errors.New("zero transport port")
	}
	return key, ihl, nil
}
func (n *SourceNAT) expire(now time.Time) {
	if !n.swept.IsZero() && now.Sub(n.swept) < time.Second {
		return
	}
	n.swept = now
	for k, f := range n.flows {
		ttl := 5 * time.Minute
		if k.protocol == 17 {
			ttl = 90 * time.Second
		}
		if now.Sub(f.last) > ttl {
			delete(n.flows, k)
			delete(n.replies, returnKey{k.protocol, f.port, k.remote})
		}
	}
}
func (n *SourceNAT) Outbound(packet []byte) ([]byte, error) {
	k, ihl, err := transport(packet)
	if err != nil {
		return nil, err
	}
	if !n.AllowsSource(k.local.Addr()) {
		return nil, errors.New("source outside configured LAN prefixes")
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	now := n.now()
	n.expire(now)
	f := n.flows[k]
	if f == nil {
		if len(n.flows) >= n.limit {
			return nil, errors.New("translation table full")
		}
		// A return key also contains the exact remote endpoint and protocol.
		// Probe boundedly; never evict a live translation to make room.
		port := uint16(0)
		for i := 0; i < 25536; i++ {
			candidate := n.next
			n.next++
			if n.next < 40000 {
				n.next = 40000
			}
			if _, exists := n.replies[returnKey{k.protocol, candidate, k.remote}]; !exists {
				port = candidate
				break
			}
		}
		if port == 0 {
			return nil, errors.New("translation ports exhausted")
		}
		f = &translation{key: k, port: port}
		n.flows[k] = f
		n.replies[returnKey{k.protocol, port, k.remote}] = f
	}
	f.last = now
	out := bytes.Clone(packet)
	address := n.ip.As4()
	copy(out[12:16], address[:])
	binary.BigEndian.PutUint16(out[ihl:ihl+2], f.port)
	clampMSS(out, ihl)
	repairChecksums(out, ihl)
	return out, nil
}
func (n *SourceNAT) Inbound(packet []byte) ([]byte, error) {
	k, ihl, err := transport(packet)
	if err != nil {
		return nil, err
	}
	if k.remote.Addr() != n.ip {
		return nil, errors.New("reply has wrong virtual destination")
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	now := n.now()
	n.expire(now)
	f := n.replies[returnKey{k.protocol, k.remote.Port(), k.local}]
	if f == nil {
		return nil, errors.New("reply has no matching outbound flow")
	}
	f.last = now
	out := bytes.Clone(packet)
	address := f.key.local.Addr().As4()
	copy(out[16:20], address[:])
	binary.BigEndian.PutUint16(out[ihl+2:ihl+4], f.key.local.Port())
	clampMSS(out, ihl)
	repairChecksums(out, ihl)
	return out, nil
}
func checksum(p []byte, sum uint32) uint16 {
	for len(p) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(p[:2]))
		p = p[2:]
	}
	if len(p) == 1 {
		sum += uint32(p[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 65535) + (sum >> 16)
	}
	return ^uint16(sum)
}
func repairChecksums(p []byte, ihl int) {
	p[10], p[11] = 0, 0
	binary.BigEndian.PutUint16(p[10:12], checksum(p[:ihl], 0))
	offset := ihl + 16
	if p[9] == 17 {
		offset = ihl + 6
	}
	p[offset], p[offset+1] = 0, 0
	var sum uint32
	for i := 12; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(p[i : i+2]))
	}
	sum += uint32(p[9]) + uint32(len(p)-ihl)
	c := checksum(p[ihl:], sum)
	if c == 0 && p[9] == 17 {
		c = 65535
	}
	binary.BigEndian.PutUint16(p[offset:offset+2], c)
}

// LAN hosts did not learn the TUN's 1300-byte MTU. Clamp both directions of
// TCP SYN exchange so their payloads fit without depending on ICMP handling.
func clampMSS(p []byte, ihl int) {
	if p[9] != 6 || p[ihl+13]&2 == 0 {
		return
	}
	end := ihl + int(p[ihl+12]>>4)*4
	for pos := ihl + 20; pos < end; {
		kind := p[pos]
		if kind == 0 {
			return
		}
		if kind == 1 {
			pos++
			continue
		}
		if pos+1 >= end {
			return
		}
		size := int(p[pos+1])
		if size < 2 || pos+size > end {
			return
		}
		if kind == 2 && size == 4 && binary.BigEndian.Uint16(p[pos+2:pos+4]) > 1260 {
			binary.BigEndian.PutUint16(p[pos+2:pos+4], 1260)
		}
		pos += size
	}
}
