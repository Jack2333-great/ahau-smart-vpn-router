// Package network implements an opt-in, transient adapter for the inspected
// dorm router. It never writes UCI, DNS, sysctls, startup files, or WAN state.
package network

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"campusvpn/internal/enlink"
	"campusvpn/internal/tun"
)

const tableID = "21900"
const marker = "0x40000000/0x40000000"
const protocol = "242"
const defaultMetric = "42760"

type Plan struct {
	TUN                    string
	Prefixes               []netip.Prefix
	NFT                    string
	owner, pre, forward    string
	preRules, forwardRules int
}

func NewPlan(name string, sources []netip.Prefix, acl []enlink.ACL) (Plan, error) {
	p := Plan{TUN: name, owner: "campusvpn:" + name, pre: name + "_pre", forward: name + "_fwd"}
	if err := tun.ValidateName(name); err != nil {
		return p, err
	}
	if len(sources) == 0 || len(sources) > 4 || len(acl) == 0 || len(acl)*len(sources) > 512 {
		return p, errors.New("policy adapter requires 1..4 LAN sources and at most 512 source/resource combinations")
	}
	for _, s := range sources {
		if !s.IsValid() || !s.Addr().Is4() || !s.Addr().IsPrivate() || s.Bits() < 24 {
			return p, errors.New("policy LAN sources must be explicit private IPv4 /24 or narrower")
		}
	}
	blocked := []netip.Prefix{netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("224.0.0.0/3")}
	unique := map[netip.Prefix]bool{}
	var pre, forward strings.Builder
	fmt.Fprintf(&pre, "add chain inet llgproxy %s { comment %q; }\n", p.pre, p.owner)
	fmt.Fprintf(&forward, "add chain inet fw4 %s { comment %q; }\n", p.forward, p.owner)
	for _, a := range acl {
		if !a.Prefix.IsValid() || !a.Prefix.Addr().Is4() || a.Prefix.Bits() < 8 || a.Low > a.High || (a.Protocol != 0 && a.Protocol != 6 && a.Protocol != 17) {
			return p, errors.New("policy adapter rejects broad, malformed, or unsupported resources")
		}
		for _, b := range blocked {
			if a.Prefix.Overlaps(b) {
				return p, errors.New("resource overlaps a reserved, local, or fake-IP prefix")
			}
		}
		for _, s := range sources {
			if a.Prefix.Overlaps(s) {
				return p, errors.New("resource overlaps a selected LAN source")
			}
		}
		unique[a.Prefix.Masked()] = true
		protocols := []string{"tcp", "udp"}
		if a.Protocol == 6 {
			protocols = protocols[:1]
		}
		if a.Protocol == 17 {
			protocols = protocols[1:]
		}
		for _, source := range sources {
			for _, proto := range protocols {
				p.preRules++
				p.forwardRules += 2
				port := fmt.Sprint(a.Low)
				if a.High != a.Low {
					port = fmt.Sprintf("%d-%d", a.Low, a.High)
				}
				dport, sport := "", ""
				if a.Low != 0 || a.High != 65535 {
					dport = " " + proto + " dport " + port
					sport = " " + proto + " sport " + port
				}
				out := fmt.Sprintf("ip saddr %s ip daddr %s meta l4proto %s%s", source, a.Prefix.Masked(), proto, dport)
				back := fmt.Sprintf("ip saddr %s ip daddr %s meta l4proto %s%s", a.Prefix.Masked(), source, proto, sport)
				fmt.Fprintf(&pre, "add rule inet llgproxy %s iifname \"br-lan\" %s meta mark set meta mark | 0x40000000 counter accept\n", p.pre, out)
				fmt.Fprintf(&forward, "add rule inet fw4 %s iifname \"br-lan\" oifname %q %s counter accept\n", p.forward, name, out)
				fmt.Fprintf(&forward, "add rule inet fw4 %s iifname %q oifname \"br-lan\" %s ct state established counter accept\n", p.forward, name, back)
			}
		}
	}
	for prefix := range unique {
		p.Prefixes = append(p.Prefixes, prefix)
	}
	sort.Slice(p.Prefixes, func(i, j int) bool { return p.Prefixes[i].String() < p.Prefixes[j].String() })
	p.NFT = pre.String() + forward.String() + fmt.Sprintf("insert rule inet llgproxy prerouting jump %s comment %q\ninsert rule inet fw4 forward jump %s comment %q\n", p.pre, p.owner, p.forward, p.owner)
	return p, nil
}

type nftChain struct {
	Family, Table, Name, Comment, Type, Hook, Policy string
	Prio                                             int
}
type nftRule struct {
	Family, Table, Chain, Comment string
	Handle                        uint64
	Expr                          []json.RawMessage
}
type nftObject struct {
	Chain *nftChain
	Rule  *nftRule
}
type nftSnapshot struct {
	NFTables []nftObject `json:"nftables"`
}

type limitedOutput struct{ bytes.Buffer }

func (b *limitedOutput) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 2*1024*1024 {
		return 0, errors.New("network command output too large")
	}
	return b.Buffer.Write(p)
}

func command(ctx context.Context, input, name string, args ...string) ([]byte, error) {
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(bounded, name, args...)
	if input != "" {
		cmd.Stdin = strings.NewReader(input)
	}
	var out limitedOutput
	cmd.Stdout = &out
	// Diagnostics may contain private rule contents. Callers receive only the
	// operation name; raw output is never included in authentication logs.
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("network command %s failed", name)
	}
	return out.Bytes(), nil
}

func snapshot(ctx context.Context) (nftSnapshot, error) {
	var s nftSnapshot
	b, err := command(ctx, "", "nft", "-j", "list", "ruleset")
	if err != nil {
		return s, err
	}
	if json.Unmarshal(b, &s) != nil {
		return s, errors.New("unsupported nft JSON")
	}
	return s, nil
}

func (p Plan) checkNFT(s nftSnapshot, active bool) error {
	bases, owned, jumps, preRules, forwardRules := 0, 0, 0, 0, 0
	for _, o := range s.NFTables {
		if c := o.Chain; c != nil {
			if c.Family == "inet" && c.Table == "llgproxy" && c.Name == "prerouting" && c.Type == "filter" && c.Hook == "prerouting" && c.Prio == -150 && c.Policy == "accept" {
				bases++
			}
			if c.Family == "inet" && c.Table == "fw4" && c.Name == "forward" && c.Type == "filter" && c.Hook == "forward" && c.Prio == 0 {
				bases++
			}
			if (c.Family == "inet" && c.Table == "llgproxy" && c.Name == p.pre) || (c.Family == "inet" && c.Table == "fw4" && c.Name == p.forward) {
				if !active || c.Comment != p.owner {
					return errors.New("network chain collision or ownership mismatch")
				}
				owned++
			}
		}
		if r := o.Rule; r != nil {
			if r.Comment == p.owner {
				jumps++
			}
			if r.Family == "inet" && r.Table == "llgproxy" && r.Chain == p.pre {
				preRules++
			}
			if r.Family == "inet" && r.Table == "fw4" && r.Chain == p.forward {
				forwardRules++
			}
			for _, expression := range r.Expr {
				if bytes.Contains(expression, []byte(`"tproxy"`)) && r.Family != "ip6" && !bytes.Contains(expression, []byte(`"family":"ip6"`)) && !(r.Family == "inet" && r.Table == "llgproxy" && r.Chain == "prerouting") {
					return errors.New("additional IPv4 TProxy chain requires a separate adapter")
				}
			}
		}
	}
	if bases != 2 {
		return errors.New("expected llgproxy prerouting and fw4 forward chains are absent or changed")
	}
	if active && (owned != 2 || jumps != 2 || preRules != p.preRules || forwardRules != p.forwardRules) {
		return errors.New("managed firewall rules disappeared; stopping data forwarding")
	}
	return nil
}

func routeRecords(ctx context.Context) ([]map[string]any, error) {
	b, err := command(ctx, "", "ip", "-4", "-N", "-j", "route", "show", "table", "all")
	if err != nil {
		return nil, err
	}
	var records []map[string]any
	if json.Unmarshal(b, &records) != nil {
		return nil, errors.New("unsupported ip route JSON")
	}
	return records, nil
}
func ruleRecords(ctx context.Context) ([]map[string]any, error) {
	b, err := command(ctx, "", "ip", "-4", "-j", "rule", "show")
	if err != nil {
		return nil, err
	}
	var records []map[string]any
	if json.Unmarshal(b, &records) != nil {
		return nil, errors.New("unsupported ip rule JSON")
	}
	return records, nil
}
func field(v any) string { return fmt.Sprint(v) }

// Inspect checks dependencies and reserved identifiers without creating a TUN
// or submitting an account. It is safe to run on the production router.
func Inspect(ctx context.Context, name string) error {
	if err := tun.ValidateName(name); err != nil {
		return err
	}
	p := Plan{TUN: name, owner: "campusvpn:" + name, pre: name + "_pre", forward: name + "_fwd"}
	s, err := snapshot(ctx)
	if err != nil {
		return err
	}
	if err = p.checkNFT(s, false); err != nil {
		return err
	}
	for _, key := range []string{"all", "default"} {
		b, e := os.ReadFile("/proc/sys/net/ipv4/conf/" + key + "/rp_filter")
		if e != nil || strings.TrimSpace(string(b)) != "0" {
			return errors.New("policy adapter requires existing rp_filter=0")
		}
	}
	b, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	if err != nil || strings.TrimSpace(string(b)) != "1" {
		return errors.New("IPv4 forwarding must already be enabled")
	}
	if _, err = net.InterfaceByName("br-lan"); err != nil {
		return errors.New("expected br-lan interface is absent")
	}
	rules, err := ruleRecords(ctx)
	if err != nil {
		return err
	}
	for _, r := range rules {
		priority, _ := strconv.Atoi(field(r["priority"]))
		mark, _ := strconv.ParseUint(strings.TrimPrefix(field(r["fwmark"]), "0x"), 16, 32)
		mask, _ := strconv.ParseUint(strings.TrimPrefix(field(r["fwmask"]), "0x"), 16, 32)
		if (priority > 0 && priority <= 90) || field(r["table"]) == tableID || mark&mask&0x40000000 != 0 {
			return errors.New("reserved policy priority, mark, or routing table is already in use")
		}
	}
	routes, err := routeRecords(ctx)
	if err != nil {
		return err
	}
	for _, r := range routes {
		if field(r["table"]) == tableID {
			return errors.New("routing table 21900 is not empty")
		}
	}
	return nil
}

type Active struct {
	Plan                 Plan
	mu                   sync.Mutex
	undos                [][]string
	nftInstalled, closed bool
}

// Apply installs IP rules first and the atomic nft batch last. Without our
// mark no existing LAN flow can enter the new routing table. A fallback
// unreachable route keeps marked packets off WAN if the process/TUN dies.
func Apply(ctx context.Context, p Plan) (*Active, error) {
	if err := Inspect(ctx, p.TUN); err != nil {
		return nil, err
	}
	s, err := snapshot(ctx)
	if err != nil {
		return nil, err
	}
	if err = p.checkNFT(s, false); err != nil {
		return nil, err
	}
	for _, key := range []string{"all", "default", p.TUN} {
		b, e := os.ReadFile("/proc/sys/net/ipv4/conf/" + key + "/rp_filter")
		if e != nil || strings.TrimSpace(string(b)) != "0" {
			return nil, errors.New("policy adapter requires existing rp_filter=0; sysctls are not changed")
		}
	}
	b, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	if err != nil || strings.TrimSpace(string(b)) != "1" {
		return nil, errors.New("IPv4 forwarding must already be enabled")
	}
	br, err := net.InterfaceByName("br-lan")
	if err != nil {
		return nil, errors.New("expected br-lan interface is absent")
	}
	addresses, err := br.Addrs()
	if err != nil {
		return nil, err
	}
	for _, address := range addresses {
		prefix, e := netip.ParsePrefix(address.String())
		if e == nil && prefix.Addr().Is4() {
			for _, resource := range p.Prefixes {
				if resource.Overlaps(prefix) {
					return nil, errors.New("resource overlaps the connected LAN network")
				}
			}
		}
	}
	rules, err := ruleRecords(ctx)
	if err != nil {
		return nil, err
	}
	for _, r := range rules {
		if field(r["priority"]) == "89" || field(r["priority"]) == "90" || field(r["table"]) == tableID {
			return nil, errors.New("policy priorities 89/90 or routing table 21900 are already in use")
		}
	}
	routes, err := routeRecords(ctx)
	if err != nil {
		return nil, err
	}
	for _, r := range routes {
		if field(r["table"]) == tableID {
			return nil, errors.New("routing table 21900 is not empty")
		}
	}
	if _, err = command(ctx, p.NFT, "nft", "-c", "-f", "-"); err != nil {
		return nil, err
	}
	a := &Active{Plan: p}
	add := func(args, undo []string) error {
		if _, err := command(ctx, "", "ip", args...); err != nil {
			return err
		}
		a.undos = append(a.undos, undo)
		return nil
	}
	failed := func(err error) (*Active, error) {
		cleanup, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		defer cancel()
		if e := a.Close(cleanup); e != nil {
			return nil, fmt.Errorf("%w; rollback also failed", err)
		}
		return nil, err
	}
	if err = add([]string{"-4", "route", "add", "unreachable", "default", "table", tableID, "proto", protocol, "metric", defaultMetric}, []string{"-4", "route", "del", "unreachable", "default", "table", tableID, "proto", protocol, "metric", defaultMetric}); err != nil {
		return failed(err)
	}
	for _, prefix := range p.Prefixes {
		args := []string{"-4", "route", "add", prefix.String(), "dev", p.TUN, "table", tableID, "proto", protocol}
		undo := append([]string(nil), args...)
		undo[2] = "del"
		if err = add(args, undo); err != nil {
			return failed(err)
		}
	}
	for _, args := range [][]string{{"-4", "rule", "add", "pref", "89", "iif", p.TUN, "lookup", "main"}, {"-4", "rule", "add", "pref", "90", "fwmark", marker, "lookup", tableID}} {
		undo := append([]string(nil), args...)
		undo[2] = "del"
		if err = add(args, undo); err != nil {
			return failed(err)
		}
	}
	if _, err = command(ctx, p.NFT, "nft", "-f", "-"); err != nil {
		return failed(err)
	}
	a.nftInstalled = true
	return a, nil
}

func (a *Active) Check(ctx context.Context) error {
	s, err := snapshot(ctx)
	if err != nil {
		return err
	}
	if err = a.Plan.checkNFT(s, true); err != nil {
		return err
	}
	rules, err := ruleRecords(ctx)
	if err != nil {
		return err
	}
	count := 0
	for _, r := range rules {
		if field(r["priority"]) == "89" && field(r["iif"]) == a.Plan.TUN && field(r["table"]) == "main" {
			count++
		}
		if field(r["priority"]) == "90" && field(r["table"]) == tableID && field(r["fwmark"]) == "0x40000000" && field(r["fwmask"]) == "0x40000000" {
			count++
		}
	}
	if count != 2 {
		return errors.New("managed routing rules disappeared; stopping data forwarding")
	}
	routes, err := routeRecords(ctx)
	if err != nil {
		return err
	}
	expected := map[string]bool{"default": true}
	for _, p := range a.Plan.Prefixes {
		expected[strings.TrimSuffix(p.String(), "/32")] = true
	}
	for _, r := range routes {
		if field(r["table"]) == tableID && field(r["protocol"]) == protocol {
			dst := strings.TrimSuffix(field(r["dst"]), "/32")
			if dst == "default" {
				if field(r["type"]) == "7" && field(r["metric"]) == defaultMetric {
					delete(expected, dst)
				}
			} else if field(r["dev"]) == a.Plan.TUN {
				delete(expected, dst)
			}
		}
	}
	if len(expected) != 0 {
		return errors.New("managed routes disappeared; stopping data forwarding")
	}
	return nil
}

// Recover removes only this adapter's identifiable transient state after an
// abnormal process exit. A live TUN or any conflicting owner stops recovery.
func Recover(ctx context.Context, name string) error {
	if err := tun.ValidateName(name); err != nil {
		return err
	}
	if _, err := net.InterfaceByName(name); err == nil {
		return errors.New("TUN is still present; disconnect the running session before recovery")
	}
	p := Plan{TUN: name, owner: "campusvpn:" + name, pre: name + "_pre", forward: name + "_fwd"}
	a := &Active{Plan: p, nftInstalled: true}
	routes, err := routeRecords(ctx)
	if err != nil {
		return err
	}
	for _, r := range routes {
		if field(r["table"]) != tableID {
			continue
		}
		if field(r["protocol"]) != protocol {
			return errors.New("recovery refused: routing table contains unowned routes")
		}
		if field(r["dst"]) == "default" && field(r["type"]) == "7" && field(r["metric"]) == defaultMetric {
			a.undos = append(a.undos, []string{"-4", "route", "del", "unreachable", "default", "table", tableID, "proto", protocol, "metric", defaultMetric})
		} else {
			return errors.New("recovery refused: unexpected owned-table route")
		}
	}
	rules, err := ruleRecords(ctx)
	if err != nil {
		return err
	}
	for _, r := range rules {
		priority := field(r["priority"])
		if priority == "89" {
			if field(r["iif"]) != name || field(r["table"]) != "main" {
				return errors.New("recovery refused: policy priority 89 has another owner")
			}
			a.undos = append(a.undos, []string{"-4", "rule", "del", "pref", "89", "iif", name, "lookup", "main"})
		} else if priority == "90" {
			if field(r["table"]) != tableID || field(r["fwmark"]) != "0x40000000" || field(r["fwmask"]) != "0x40000000" {
				return errors.New("recovery refused: policy priority 90 has another owner")
			}
			a.undos = append(a.undos, []string{"-4", "rule", "del", "pref", "90", "fwmark", marker, "lookup", tableID})
		} else if field(r["table"]) == tableID {
			return errors.New("recovery refused: routing table is referenced by another policy rule")
		}
	}
	return a.Close(ctx)
}

func (a *Active) undo(ctx context.Context, args []string, routes, rules []map[string]any) error {
	// TUN destruction automatically removes its routes. External firewall
	// reloads can also remove rules; cleanup treats only verified absence as
	// success and never flushes a shared routing table or priority.
	found := false
	if args[1] == "route" {
		for _, r := range routes {
			if field(r["table"]) != tableID || field(r["protocol"]) != protocol {
				continue
			}
			if args[3] == "unreachable" {
				if field(r["dst"]) == "default" && (field(r["type"]) == "unreachable" || field(r["type"]) == "7") && field(r["metric"]) == defaultMetric {
					found = true
				}
			} else if strings.TrimSuffix(field(r["dst"]), "/32") == strings.TrimSuffix(args[3], "/32") && field(r["dev"]) == a.Plan.TUN {
				found = true
			}
		}
	} else {
		for _, r := range rules {
			if args[4] == "89" && field(r["priority"]) == "89" && field(r["iif"]) == a.Plan.TUN && field(r["table"]) == "main" {
				found = true
			}
			if args[4] == "90" && field(r["priority"]) == "90" && field(r["fwmark"]) == "0x40000000" && field(r["fwmask"]) == "0x40000000" && field(r["table"]) == tableID {
				found = true
			}
		}
	}
	if !found {
		return nil
	}
	_, err := command(ctx, "", "ip", args...)
	return err
}

func (a *Active) Close(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return nil
	}
	if a.nftInstalled {
		s, err := snapshot(ctx)
		if err != nil {
			return err
		}
		var batch strings.Builder
		for _, o := range s.NFTables {
			if r := o.Rule; r != nil && r.Comment == a.Plan.owner {
				if r.Family != "inet" || !((r.Table == "llgproxy" && r.Chain == "prerouting") || (r.Table == "fw4" && r.Chain == "forward")) {
					return errors.New("owned rule appeared in an unexpected chain; refusing cleanup")
				}
				fmt.Fprintf(&batch, "delete rule %s %s %s handle %s\n", r.Family, r.Table, r.Chain, strconv.FormatUint(r.Handle, 10))
			}
		}
		for _, o := range s.NFTables {
			if c := o.Chain; c != nil && c.Family == "inet" && ((c.Table == "llgproxy" && c.Name == a.Plan.pre) || (c.Table == "fw4" && c.Name == a.Plan.forward)) {
				if c.Comment != a.Plan.owner {
					return errors.New("owned chain changed ownership; refusing cleanup")
				}
				fmt.Fprintf(&batch, "flush chain %s %s %s\ndelete chain %s %s %s\n", c.Family, c.Table, c.Name, c.Family, c.Table, c.Name)
			}
		}
		if batch.Len() > 0 {
			if _, err = command(ctx, batch.String(), "nft", "-f", "-"); err != nil {
				return err
			}
		}
		a.nftInstalled = false
	}
	var failures []error
	routes, err := routeRecords(ctx)
	if err != nil {
		return err
	}
	rules, err := ruleRecords(ctx)
	if err != nil {
		return err
	}
	for i := len(a.undos) - 1; i >= 0; i-- {
		if err := a.undo(ctx, a.undos[i], routes, rules); err != nil {
			failures = append(failures, err)
		}
	}
	if len(failures) != 0 {
		return errors.New("one or more owned policy routes could not be removed")
	}
	a.closed = true
	return nil
}
