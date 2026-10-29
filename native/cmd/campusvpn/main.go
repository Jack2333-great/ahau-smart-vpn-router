package main

import (
	"bytes"
	"campusvpn/internal/enlink"
	"campusvpn/internal/network"
	"campusvpn/internal/tun"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"net/netip"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"
)

const version = "0.5.1-research"

func emit(stage string, fields map[string]any) {
	if fields == nil {
		fields = map[string]any{}
	}
	fields["stage"] = stage
	json.NewEncoder(os.Stdout).Encode(fields)
}
func main() {
	if err := run(); err != nil {
		emit("error", map[string]any{"message": err.Error()})
		os.Exit(1)
	}
}
func run() error {
	if err := syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{Cur: 0, Max: 0}); err != nil {
		return errors.New("cannot disable credential-bearing core dumps")
	}
	mode := flag.String("mode", "preflight", "preflight | selftest | network-check | login-test | connect | serve | login | status | disconnect | recover-network")
	networkProfile := flag.String("network-profile", "none", "none | dorm-router (opt-in transient IPv4 LAN policy adapter)")
	socket := flag.String("socket", defaultSocket, "private local Unix control socket for service commands")
	credentialFile := flag.String("credential-file", "", "private credential file for bounded automatic login")
	rpcAction := flag.String("rpc-action", "", "rpcd plugin action")
	rpcMethod := flag.String("rpc-method", "", "rpcd plugin method")
	tunName := flag.String("tun", "cvpn0", "transient TUN name for connect or serve mode")
	lanSource := flag.String("lan-source", "", "optional comma-separated private IPv4 sources for in-process NAT")
	resourceTarget := flag.String("resource-target", "", "optional comma-separated IPv4 prefixes to narrow the server resource policy")
	dataProfile := flag.String("data-profile", "android", "IPv4 envelope: android (identifier 1) | desktop (identifier 41); no automatic retry")
	server := flag.String("server", "https://myvpn.ahau.edu.cn", "school HTTPS origin")
	ca := flag.String("ca", "", "additional trusted CA PEM file")
	device := flag.String("device-id", "", "stable random device ID, never copied from another device")
	gateway := flag.Int("gateway", 0, "index in the server-published gateway list")
	spaProfile := flag.String("spa-profile", "school-apk", "school-apk | disabled (only authenticated server-published destinations)")
	spaUser := flag.String("spa-user", "enlink", "SPA packet username (deployment compatibility assumption; not the campus account)")
	duration := flag.Duration("duration", 30*time.Second, "isolated tunnel observation, 10s..5m")
	flag.Parse()
	if flag.NArg() != 0 {
		return errors.New("unexpected positional arguments; credentials must be typed interactively")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if *mode == "rpc" {
		return rpcControl(ctx, *socket, *rpcAction, *rpcMethod)
	}
	if *mode == "selftest" {
		return selftest()
	}
	if *mode == "network-check" {
		if err := network.Inspect(ctx, *tunName); err != nil {
			return err
		}
		emit("network-check-ok", map[string]any{"version": version, "profile": "dorm-router", "authentication_attempted": false, "network_changed": false})
		return nil
	}
	if *mode == "recover-network" {
		if *networkProfile != "dorm-router" {
			return errors.New("network recovery requires explicit -network-profile dorm-router")
		}
		if err := network.Recover(ctx, *tunName); err != nil {
			return err
		}
		emit("network-restored", map[string]any{"persistent_config_changed": false})
		return nil
	}
	if *mode == "login" || *mode == "status" || *mode == "disconnect" {
		request := controlRequest{Action: *mode}
		if *mode == "login" {
			status, err := requestControl(ctx, *socket, controlRequest{Action: "status"})
			if err != nil {
				return err
			}
			if status.State == "connecting" || status.State == "connected" || status.State == "stopping" || status.CleanupStage == "network-cleanup-failed" {
				return errors.New("service is busy or requires network cleanup; inspect status before login")
			}
			request.Username, request.Password, err = credentials(ctx)
			if err != nil {
				return err
			}
		}
		result, err := requestControl(ctx, *socket, request)
		request = controlRequest{}
		if err != nil {
			return err
		}
		json.NewEncoder(os.Stdout).Encode(result)
		if !result.OK {
			return errors.New("local service rejected the request")
		}
		return nil
	}
	if *mode != "preflight" && *mode != "login-test" && *mode != "connect" && *mode != "serve" {
		return errors.New("unknown mode")
	}
	if *dataProfile != "android" && *dataProfile != "desktop" {
		return errors.New("data-profile must be android or desktop")
	}
	if *networkProfile != "none" && *networkProfile != "dorm-router" {
		return errors.New("network-profile must be none or dorm-router")
	}
	if *networkProfile != "none" && (*mode != "connect" && *mode != "serve") {
		return errors.New("network-profile requires connect or serve mode")
	}
	if *networkProfile == "dorm-router" && *lanSource == "" {
		return errors.New("dorm-router requires explicit -lan-source")
	}
	if *spaProfile != "school-apk" && *spaProfile != "disabled" {
		return errors.New("spa-profile must be school-apk or disabled")
	}
	if err := enlink.ValidateSPAUsername(*spaUser); err != nil {
		return err
	}
	if *gateway < 0 {
		return errors.New("gateway index must be nonnegative")
	}
	if err := tun.ValidateName(*tunName); err != nil {
		return err
	}
	if *duration < 10*time.Second || *duration > 5*time.Minute {
		return errors.New("duration must be 10s..5m")
	}
	var lanPrefixes []netip.Prefix
	var resourceTargets []netip.Prefix
	if *resourceTarget != "" {
		if *mode != "connect" && *mode != "serve" {
			return errors.New("resource-target requires connect or serve mode")
		}
		for _, value := range strings.Split(*resourceTarget, ",") {
			p, e := netip.ParsePrefix(value)
			if e != nil || !p.Addr().Is4() || p.Bits() < 8 {
				return errors.New("resource target must be an explicit IPv4 /8 or narrower")
			}
			resourceTargets = append(resourceTargets, p.Masked())
		}
		if len(resourceTargets) > 16 {
			return errors.New("at most 16 resource targets are supported")
		}
	}
	if *lanSource != "" {
		if *mode != "connect" && *mode != "serve" {
			return errors.New("lan-source requires connect or serve mode")
		}
		for _, value := range strings.Split(*lanSource, ",") {
			p, e := netip.ParsePrefix(value)
			if e != nil {
				return errors.New("invalid LAN source prefix")
			}
			lanPrefixes = append(lanPrefixes, p.Masked())
		}
		if _, e := enlink.NewSourceNAT(netip.MustParseAddr("10.0.0.2"), lanPrefixes); e != nil {
			return e
		}
	}
	if *device == "" {
		var b [16]byte
		if _, err := rand.Read(b[:]); err != nil {
			return err
		}
		*device = hex.EncodeToString(b[:])
	}
	if len(*device) < 16 || len(*device) > 128 {
		return errors.New("device ID must contain 16..128 bytes")
	}
	options := sessionOptions{
		Mode: *mode, TUN: *tunName, SPAProfile: *spaProfile, DataProfile: *dataProfile,
		Gateway: *gateway, Duration: *duration, LANPrefixes: lanPrefixes,
		NetworkProfile:  *networkProfile,
		ResourceTargets: resourceTargets,
		SPAUsername:     *spaUser,
	}
	if *mode == "serve" {
		check, err := enlink.NewController(*server, *ca, *device)
		if err != nil {
			return err
		}
		check.HTTP.CloseIdleConnections()
		options.Mode = "connect"
		// Each login receives a fresh cookie jar. Session cookies from a
		// disconnected user are never carried into the next login.
		probe := func(probeCtx context.Context) bool {
			controller, e := enlink.NewController(*server, *ca, *device)
			if e != nil {
				return false
			}
			defer controller.HTTP.CloseIdleConnections()
			_, e = controller.GenerateKey(probeCtx)
			return e == nil
		}
		return serveControlWithAuto(ctx, *socket, func(session context.Context, username, password string, report eventReporter) error {
			controller, err := enlink.NewController(*server, *ca, *device)
			if err != nil {
				return err
			}
			defer controller.HTTP.CloseIdleConnections()
			return executeSession(session, controller, options, username, password, report)
		}, func() {
			emit("service-ready", map[string]any{"version": version, "socket": *socket, "authentication_attempted": false, "routes_changed": false})
		}, *credentialFile, probe)
	}
	controller, err := enlink.NewController(*server, *ca, *device)
	if err != nil {
		return err
	}
	defer controller.HTTP.CloseIdleConnections()
	if *mode == "preflight" {
		_, err = controller.GenerateKey(ctx)
		if err != nil {
			return err
		}
		_, tunErr := os.Stat("/dev/net/tun")
		emit("preflight-ok", map[string]any{"version": version, "os": runtime.GOOS, "arch": runtime.GOARCH, "tun_device": tunErr == nil, "controller_tls": true, "authentication_attempted": false, "routes_changed": false})
		return nil
	}
	username, password, err := credentials(ctx)
	if err != nil {
		return err
	}
	return executeSession(ctx, controller, options, username, password, emit)
}

func selftest() error {
	auth, err := enlink.AuthFrame("test-user", "test-session")
	if err != nil || len(auth) != 40 {
		return errors.New("auth frame selftest failed")
	}
	// Synthetic server response. This tests executable/runtime compatibility,
	// not actual school interoperability.
	response := []byte{1, 2, 0, 29, 128, 1, 0, 4, 1, 0, 0, 0, 11, 0, 4, 10, 0, 0, 2, 12, 0, 4, 255, 255, 255, 0, 43, 0, 255}
	assigned, err := enlink.ReadAssignment(bytes.NewReader(response))
	if err != nil || assigned.IP.String() != "10.0.0.2" {
		return errors.New("assignment selftest failed")
	}
	_, err = enlink.EncryptPassword("synthetic-password", "0123456789abcdef")
	if err != nil {
		return err
	}
	emit("selftest-ok", map[string]any{"version": version, "os": runtime.GOOS, "arch": runtime.GOARCH, "synthetic_only": true, "routes_changed": false})
	return nil
}
