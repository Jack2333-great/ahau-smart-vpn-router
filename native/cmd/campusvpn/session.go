package main

import (
	"campusvpn/internal/enlink"
	"campusvpn/internal/network"
	"campusvpn/internal/tun"
	"context"
	"errors"
	"net/netip"
	"time"
)

type eventReporter func(string, map[string]any)
type sessionOptions struct {
	Mode, TUN, SPAProfile, DataProfile string
	Gateway                            int
	Duration                           time.Duration
	LANPrefixes                        []netip.Prefix
	ResourceTargets                    []netip.Prefix
	NetworkProfile                     string
	SPAUsername                        string
}

// executeSession owns the entire authenticated lifetime. Credentials are used
// for one login only; cancellation joins data workers before clearing the
// virtual address and logging out. The optional router profile owns and removes
// its transient network state; persistent configuration is never written.
func executeSession(ctx context.Context, controller *enlink.Controller, options sessionOptions, username, password string, report eventReporter) (result error) {
	login, err := controller.Login(ctx, username, password)
	password = ""
	username = ""
	// A partially established session may already exist when extra policy is
	// requested. Attempt logout whenever a user ID was supplied.
	if login.ID != "" {
		defer func() {
			cleanup, done := context.WithTimeout(context.Background(), 10*time.Second)
			defer done()
			if e := controller.Logout(cleanup, login); e != nil {
				report("logout-failed", map[string]any{"message": e.Error()})
				if result == nil {
					result = errors.New("remote logout could not be confirmed")
				}
			} else {
				report("logout-ok", nil)
			}
		}()
	}
	if err != nil {
		if errors.Is(err, enlink.ErrAuthenticationRejected) {
			report("authentication-rejected", nil)
		}
		return err
	}
	report("login-ok", nil)
	rules, err := controller.Rules(ctx, login)
	if err != nil {
		return err
	}
	report("rules-ok", map[string]any{"gateway_count": len(rules.Gateways), "spa_required": rules.SPAStatus})
	g, endpoint, err := rules.SelectGateway(options.Gateway)
	if err != nil {
		return err
	}
	if rules.SPAStatus {
		if options.SPAProfile != "school-apk" || controller.Base.Hostname() != "myvpn.ahau.edu.cn" {
			return errors.New("SPA requires a verified school bootstrap profile")
		}
		if options.Gateway != 0 {
			return errors.New("legacy SPA selection currently supports the first published gateway only")
		}
		address, access, err := rules.SPAEndpoint(g)
		if err != nil {
			return err
		}
		packet, err := enlink.NewSPAPacket(enlink.SPAOptions{Username: options.SPAUsername, Access: access, PasswordMaterial: enlink.SchoolAPKPasswordMaterial()})
		if err != nil {
			return err
		}
		err = enlink.SendSPA(ctx, address, packet)
		clear(packet)
		if err != nil {
			return err
		}
		report("spa-sent", map[string]any{"profile": "school-apk", "server_acceptance_verified": false})
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	tunnel, err := enlink.DialGateway(ctx, endpoint, controller.TLS, login)
	if err != nil {
		return err
	}
	defer tunnel.Close()
	report("gateway-auth-ok", map[string]any{"virtual_address_assigned": true, "dns_count": len(tunnel.Assignment.DNS), "ip_resource_count": len(g.IPList), "routes_changed": false})
	acl, aclErr := inspectResources(rules, g, report)
	if options.Mode == "connect" {
		if options.DataProfile == "desktop" {
			tunnel.DataIdentifier = 41
		}
		if aclErr != nil {
			return aclErr
		}
		acl, err = enlink.RestrictACL(acl, options.ResourceTargets)
		if err != nil {
			return err
		}
		var nat *enlink.SourceNAT
		var plan network.Plan
		if options.NetworkProfile == "dorm-router" {
			plan, err = network.NewPlan(options.TUN, options.LANPrefixes, acl)
			if err != nil {
				return err
			}
		}
		if len(options.LANPrefixes) != 0 {
			nat, err = enlink.NewSourceNAT(tunnel.Assignment.IP, options.LANPrefixes)
			if err != nil {
				return err
			}
		}
		dev, err := tun.Open(options.TUN)
		if err != nil {
			return err
		}
		defer dev.Close()
		if err = dev.Configure(ctx, tunnel.Assignment.IP, 1300); err != nil {
			return err
		}
		if err = controller.UpdateIP(ctx, login, tunnel.Assignment.IP.String(), g.ID); err != nil {
			return err
		}
		defer func() {
			cleanup, done := context.WithTimeout(context.Background(), 10*time.Second)
			defer done()
			if e := controller.ClearIP(cleanup, login); e != nil {
				report("clear-address-failed", map[string]any{"message": e.Error()})
				if result == nil {
					result = errors.New("remote virtual address cleanup could not be confirmed")
				}
			}
		}()
		var policy *network.Active
		if options.NetworkProfile == "dorm-router" {
			policy, err = network.Apply(ctx, plan)
			if err != nil {
				return err
			}
			defer func() {
				cleanup, done := context.WithTimeout(context.Background(), 10*time.Second)
				defer done()
				if e := policy.Close(cleanup); e != nil {
					report("network-cleanup-failed", nil)
					if result == nil {
						result = errors.New("transient network cleanup failed; use recover-network after checking the service is stopped")
					}
				} else {
					report("network-restored", nil)
				}
			}()
			report("policy-ready", map[string]any{"profile": "dorm-router", "source_prefix_count": len(options.LANPrefixes), "resource_prefix_count": len(plan.Prefixes), "persistent_config_changed": false})
		}
		report("tun-ready", map[string]any{"name": dev.Name, "virtual_ip": tunnel.Assignment.IP.String(), "resource_rules": len(acl), "data_routes_installed": policy != nil, "firewall_changed": policy != nil, "lan_source_nat": nat != nil, "data_profile": options.DataProfile})
		working, stop := context.WithCancel(ctx)
		defer stop()
		pingDone := make(chan error, 1)
		go func() {
			tick := time.NewTicker(60 * time.Second)
			defer tick.Stop()
			health := time.NewTicker(10 * time.Second)
			defer health.Stop()
			for {
				select {
				case <-working.Done():
					pingDone <- nil
					return
				case <-tick.C:
					if e := controller.Ping(working, login); e != nil {
						pingDone <- e
						stop()
						return
					}
				case <-health.C:
					if policy != nil {
						if e := policy.Check(working); e != nil {
							pingDone <- e
							stop()
							return
						}
					}
				}
			}
		}()
		stats, e := tunnel.BridgeWithNAT(working, dev, acl, 10*time.Second, nat)
		stop()
		pingErr := <-pingDone
		report("tunnel-stopped", map[string]any{"sent": stats.Sent, "received": stats.Received, "dropped": stats.Dropped})
		if ctx.Err() != nil {
			return nil
		}
		if pingErr != nil {
			return pingErr
		}
		return e
	}
	// Do not register an active virtual address for a routing-free observation.
	// No IP payload is sent and no forwarding state is installed.
	observation, done := context.WithTimeout(ctx, options.Duration)
	defer done()
	count, err := tunnel.Observe(observation, 10*time.Second)
	if errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
		if count.Received == 0 {
			return errors.New("observation ended without a gateway heartbeat acknowledgement")
		}
		report("heartbeat-test-ok", map[string]any{"sent": count.Sent, "received": count.Received, "routes_changed": false})
		return nil
	}
	return err
}

// Report only capabilities and counts, never the account's actual resource
// addresses or domains. A handshake-only test still observes heartbeats when
// the data parser cannot support the assigned policy.
func inspectResources(rules enlink.Rules, gateway enlink.Gateway, report eventReporter) ([]enlink.ACL, error) {
	acl, err := enlink.CompileGatewayACL(rules, gateway)
	fields := map[string]any{
		"ip_acl_supported":          err == nil,
		"compiled_ip_rules":         len(acl),
		"gateway_domain_rule_count": len(gateway.Domains),
		"routes_changed":            false,
	}
	if err != nil {
		fields["message"] = err.Error()
	}
	report("resource-policy-check", fields)
	return acl, err
}
