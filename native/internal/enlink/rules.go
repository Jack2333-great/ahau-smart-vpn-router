package enlink

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

type Rules struct {
	Server    string    `json:"server"`
	SPAPort   string    `json:"spa_port"`
	SPAStatus bool      `json:"spa_status"`
	Gateways  []Gateway `json:"gateway_list"`
	Filter    struct {
		IP         []string `json:"in_ip_list"`
		OutIP      []string `json:"out_ip_list"`
		OutDomains []string `json:"out_domain_filter"`
	} `json:"filter_rules"`
}
type Gateway struct {
	ID         string   `json:"id"`
	IP         string   `json:"ip"`
	DNS        string   `json:"dns"`
	SPAPort    string   `json:"spaPort"`
	IPList     []string `json:"inIpList"`
	Domains    []string `json:"inDomainFilter"`
	OutIP      []string `json:"outIpList"`
	OutDomains []string `json:"outDomainFilter"`
}
type Endpoint struct{ Address, ServerName string }

// The SDK publishes "domain:port||address:port". Keep the domain as TLS
// identity while connecting to the published address; never disable trust.
func ParseEndpoint(s string) (Endpoint, error) {
	var e Endpoint
	fields := strings.Split(s, "||")
	if len(fields) < 1 || len(fields) > 3 {
		return e, errors.New("unsupported gateway endpoint")
	}
	host, port, err := net.SplitHostPort(fields[0])
	if err != nil || host == "" {
		return e, errors.New("gateway domain must contain host:port")
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return e, errors.New("invalid gateway port")
	}
	e = Endpoint{Address: fields[0], ServerName: host}
	if len(fields) > 1 && fields[1] != "" {
		h, p, err := net.SplitHostPort(fields[1])
		if err != nil {
			return Endpoint{}, errors.New("invalid gateway address")
		}
		a, err := netip.ParseAddr(h)
		if err != nil || !a.Is4() {
			return Endpoint{}, errors.New("gateway transport address must be IPv4")
		}
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return Endpoint{}, errors.New("invalid transport port")
		}
		e.Address = fields[1]
	}
	return e, nil
}
func (r Rules) SelectGateway(index int) (Gateway, Endpoint, error) {
	if index < 0 || index >= len(r.Gateways) {
		return Gateway{}, Endpoint{}, errors.New("gateway index outside server-published list")
	}
	g := r.Gateways[index]
	if g.ID == "" {
		return g, Endpoint{}, errors.New("gateway has no ID")
	}
	e, err := ParseEndpoint(g.IP)
	return g, e, err
}

type ACL struct {
	Protocol  byte
	Prefix    netip.Prefix
	Low, High uint16
}

func ParseACL(s string) (ACL, error) {
	var a ACL
	f := strings.Split(s, ";")
	if len(f) != 3 {
		return a, errors.New("expected protocol;IPv4/prefix;port")
	}
	switch f[0] {
	case "TCP":
		a.Protocol = 6
	case "UDP":
		a.Protocol = 17
	case "ANY":
		a.Protocol = 0
	default:
		return a, errors.New("unsupported ACL protocol")
	}
	if strings.Contains(f[1], ":") {
		return a, errors.New("range/mapped ACL requires further protocol verification")
	}
	ip := f[1]
	if !strings.Contains(ip, "/") {
		ip += "/32"
	}
	p, err := netip.ParsePrefix(ip)
	if err != nil || !p.Addr().Is4() {
		return a, errors.New("invalid IPv4 resource prefix")
	}
	a.Prefix = p.Masked()
	if f[2] == "ANY" {
		a.Low = 0
		a.High = 65535
		return a, nil
	}
	ports := strings.Split(f[2], "-")
	if len(ports) > 2 {
		return a, errors.New("unsupported resource port list")
	}
	low, err := strconv.Atoi(ports[0])
	if err != nil || low < 1 || low > 65535 {
		return a, errors.New("invalid resource port")
	}
	high := low
	if len(ports) == 2 {
		high, err = strconv.Atoi(ports[1])
		if err != nil || high < low || high > 65535 {
			return a, errors.New("invalid resource port range")
		}
	}
	a.Low = uint16(low)
	a.High = uint16(high)
	return a, nil
}
func CompileACL(values []string) ([]ACL, error) {
	var rules []ACL
	for i, s := range values {
		a, err := ParseACL(s)
		if err != nil {
			return nil, fmt.Errorf("resource rule %d: %w", i, err)
		}
		rules = append(rules, a)
	}
	if len(rules) == 0 {
		return nil, errors.New("no supported IP resources were assigned")
	}
	return rules, nil
}

// A partial implementation must not silently drop server-published exclusion
// policy. The SDK exposes these fields, but their precedence and mapping
// behavior have not yet been verified. Handshake-only mode remains available.
func CompileGatewayACL(r Rules, g Gateway) ([]ACL, error) {
	if len(g.OutIP)+len(g.OutDomains)+len(r.Filter.OutIP)+len(r.Filter.OutDomains) != 0 {
		return nil, errors.New("server published exclusion rules; verify their semantics before enabling data mode")
	}
	values := g.IPList
	if len(values) == 0 {
		values = r.Filter.IP
	}
	return CompileACL(values)
}

// RestrictACL intersects an already authenticated policy with operator-selected
// targets. It can narrow destinations but never add destinations or ports.
func RestrictACL(rules []ACL, targets []netip.Prefix) ([]ACL, error) {
	if len(targets) == 0 {
		return rules, nil
	}
	if len(targets) > 16 {
		return nil, errors.New("at most 16 resource targets are supported")
	}
	var out []ACL
	seen := make(map[ACL]bool)
	for _, target := range targets {
		if !target.IsValid() || !target.Addr().Is4() || target.Bits() < 8 {
			return nil, errors.New("resource target must be an explicit IPv4 /8 or narrower")
		}
		target = target.Masked()
		matched := false
		for _, rule := range rules {
			if !rule.Prefix.Overlaps(target) {
				continue
			}
			matched = true
			if target.Bits() > rule.Prefix.Bits() {
				rule.Prefix = target
			}
			if !seen[rule] {
				out = append(out, rule)
				seen[rule] = true
			}
		}
		if !matched {
			return nil, errors.New("resource target is outside the server-published IP policy")
		}
	}
	return out, nil
}
func (a ACL) Allows(p []byte) bool {
	return a.allows(p, false)
}
func (a ACL) AllowsReply(p []byte) bool { return a.allows(p, true) }
func (a ACL) allows(p []byte, reply bool) bool {
	if ValidateIPv4(p) != nil {
		return false
	}
	ihl := int(p[0]&15) * 4
	// No fragment reassembly in this prototype: reject every fragment, including
	// the first fragment with MF set, so port filtering cannot be bypassed.
	if p[6]&0x3f != 0 || p[7] != 0 {
		return false
	}
	if p[9] != 6 && p[9] != 17 {
		return false
	}
	if a.Protocol != 0 && a.Protocol != p[9] {
		return false
	}
	addressOffset, portOffset := 16, ihl+2
	if reply {
		addressOffset = 12
		portOffset = ihl
	}
	if !a.Prefix.Contains(netip.AddrFrom4([4]byte(p[addressOffset : addressOffset+4]))) {
		return false
	}
	minimum := 8
	if p[9] == 6 {
		minimum = 20
	}
	if len(p) < ihl+minimum {
		return false
	}
	port := uint16(p[portOffset])<<8 | uint16(p[portOffset+1])
	return port >= a.Low && port <= a.High
}
