package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"campusvpn/internal/enlink"
	"net/netip"
)

// Test helpers execute the actual CLI with a controlling terminal. Secrets are
// typed into its PTY, never passed through argv, environment, or fixture files.
func TestCLIProcessHelper(t *testing.T) {
	if os.Getenv("CAMPUSVPN_CLI_HELPER") != "1" {
		return
	}
	var args []string
	if json.Unmarshal([]byte(os.Getenv("CAMPUSVPN_CLI_ARGUMENTS")), &args) != nil {
		os.Exit(97)
	}
	os.Args = append([]string{"campusvpn"}, args...)
	flag.CommandLine = flag.NewFlagSet("campusvpn", flag.ContinueOnError)
	main()
	os.Exit(0)
}

func openPTY(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	fd, err := syscall.Open("/dev/ptmx", syscall.O_RDWR|syscall.O_NOCTTY|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	master := os.NewFile(uintptr(fd), "ptmx")
	var unlock int32
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), 0x40045431, uintptr(unsafe.Pointer(&unlock)))
	if errno != 0 {
		master.Close()
		t.Fatal(errno)
	}
	var n uint32
	_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), 0x80045430, uintptr(unsafe.Pointer(&n)))
	if errno != 0 {
		master.Close()
		t.Fatal(errno)
	}
	// Avoid platform-specific sprintf/ioctl wrappers in the runtime binary.
	name := filepath.Join("/dev/pts", jsonNumber(n))
	slave, err := os.OpenFile(name, os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		master.Close()
		t.Fatal(err)
	}
	return master, slave
}

func jsonNumber(n uint32) string { b, _ := json.Marshal(n); return string(b) }

func runTTY(t *testing.T, args []string, username, password string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 22*time.Second)
	defer cancel()
	master, slave := openPTY(t)
	defer master.Close()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCLIProcessHelper$")
	wire, _ := json.Marshal(args)
	cmd.Env = append(os.Environ(), "CAMPUSVPN_CLI_HELPER=1", "CAMPUSVPN_CLI_ARGUMENTS="+string(wire))
	cmd.Stdin = slave
	cmd.Stdout = slave
	cmd.Stderr = slave
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := cmd.Start(); err != nil {
		slave.Close()
		t.Fatal(err)
	}
	slave.Close()
	defer func() {
		if cmd.ProcessState == nil {
			cmd.Process.Kill()
			cmd.Wait()
		}
	}()
	var mu sync.Mutex
	var output bytes.Buffer
	changed := make(chan struct{}, 1)
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		b := make([]byte, 2048)
		for {
			n, err := master.Read(b)
			if n > 0 {
				mu.Lock()
				output.Write(b[:n])
				mu.Unlock()
				select {
				case changed <- struct{}{}:
				default:
				}
			}
			if err != nil {
				return
			}
		}
	}()
	text := func() string { mu.Lock(); defer mu.Unlock(); return output.String() }
	waitPrompt := func(prompt string) {
		t.Helper()
		for !strings.Contains(text(), prompt) {
			select {
			case <-ctx.Done():
				t.Fatalf("CLI timeout waiting for %s: %s", prompt, text())
			case <-readerDone:
				t.Fatalf("CLI exited before %s: %s", prompt, text())
			case <-changed:
			}
		}
	}
	waitPrompt("Campus username: ")
	if _, err := io.WriteString(master, username+"\n"); err != nil {
		t.Fatal(err)
	}
	waitPrompt("Campus password (hidden): ")
	if _, err := io.WriteString(master, password+"\n"); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("CLI exited: %v; output: %s", err, text())
	}
	<-readerDone
	return text()
}

func TestCLIInteractiveTLSLoginLifecycle(t *testing.T) {
	cliTLSLifecycle(t, false)
}

func TestServiceAuthenticatedLifecycleIntegration(t *testing.T) {
	if os.Getenv("CAMPUSVPN_ISOLATED_TUN_TEST") != "1" {
		t.Skip("requires isolated network namespace")
	}
	cliTLSLifecycle(t, true)
}

func TestServiceManagedPolicyIntegration(t *testing.T) {
	if os.Getenv("CAMPUSVPN_ISOLATED_TUN_TEST") != "1" {
		t.Skip("requires isolated network namespace")
	}
	for _, args := range [][]string{{"ip", "link", "add", "br-lan", "type", "bridge"}, {"ip", "address", "add", "192.168.50.1/24", "dev", "br-lan"}, {"ip", "link", "set", "br-lan", "up"}, {"sysctl", "-q", "-w", "net.ipv4.ip_forward=1", "net.ipv4.conf.all.rp_filter=0", "net.ipv4.conf.default.rp_filter=0"}} {
		if b, e := exec.Command(args[0], args[1:]...).CombinedOutput(); e != nil {
			t.Fatalf("managed service fixture %v %s", e, b)
		}
	}
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader("add table inet llgproxy\nadd chain inet llgproxy prerouting { type filter hook prerouting priority mangle; policy accept; }\nadd table inet fw4\nadd chain inet fw4 forward { type filter hook forward priority filter; policy drop; }\n")
	if b, e := cmd.CombinedOutput(); e != nil {
		t.Fatalf("managed service firewall fixture %v %s", e, b)
	}
	cliTLSLifecycle(t, true)
	if b, e := exec.Command("ip", "-4", "-j", "rule", "show").CombinedOutput(); e != nil || bytes.Contains(b, []byte("21900")) {
		t.Fatalf("managed service leaked policy rule %v %s", e, b)
	}
}

func cliTLSLifecycle(t *testing.T, service bool) {
	t.Helper()
	if service {
		if err := exec.Command("ip", "link", "set", "lo", "up").Run(); err != nil {
			t.Fatal(err)
		}
	}
	var logout, login atomic.Int32
	var update, cleared atomic.Int32
	certServer := httptest.NewTLSServer(http.NotFoundHandler())
	certificate := certServer.TLS.Certificates[0]
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certServer.Certificate().Raw})
	certServer.Close()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	gatewayDone := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			gatewayDone <- err
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(18 * time.Second))
		want, _ := enlink.AuthFrame("synthetic-user", "private-test-session")
		got := make([]byte, len(want))
		if _, err = io.ReadFull(conn, got); err != nil || !bytes.Equal(got, want) {
			gatewayDone <- errors.New("invalid CLI gateway auth")
			return
		}
		assignment := []byte{1, 2, 0, 29, 128, 1, 0, 4, 1, 0, 0, 0, 11, 0, 4, 10, 0, 0, 2, 12, 0, 4, 255, 255, 255, 0, 43, 0, 255}
		if _, err = conn.Write(assignment); err != nil {
			gatewayDone <- err
			return
		}
		for {
			frame := make([]byte, 12)
			if _, err = io.ReadFull(conn, frame); err != nil {
				gatewayDone <- nil
				return
			}
			if !bytes.Equal(frame, enlink.HeartbeatFrame()) {
				gatewayDone <- errors.New("CLI sent non-heartbeat data")
				return
			}
			if _, err = conn.Write([]byte{1, 2, 0, 12, 0, 0, 0, 0, 3, 0, 0, 0}); err != nil {
				gatewayDone <- nil
				return
			}
		}
	}()
	controller := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch strings.TrimPrefix(r.URL.Path, "/enlink/api/client/") {
		case "auth/generateKey":
			http.SetCookie(w, &http.Cookie{Name: "SID", Value: "private-test-cookie", Path: "/", Secure: true})
			io.WriteString(w, `{"code":200,"data":"0123456789abcdef"}`)
		case "auth/login":
			login.Add(1)
			var fields map[string]string
			if json.NewDecoder(r.Body).Decode(&fields) != nil || fields["username"] != "synthetic-user" || fields["password"] != "SanqAingpSUVL+dRaWKxnrxfV0sxd1ed80DIX0gu14o=" {
				t.Error("CLI password encoding mismatch")
			}
			if r.Header.Get("Authorization") != "SID=private-test-cookie" {
				t.Error("CLI lost session cookie")
			}
			io.WriteString(w, `{"code":200,"data":{"id":"test-id","username":"synthetic-user","sid":"private-test-session"}}`)
		case "user/terminal/rules/test-id":
			json.NewEncoder(w).Encode(map[string]any{"code": 200, "data": map[string]any{"gateway_list": []map[string]any{{"id": "g1", "ip": ln.Addr().String(), "inIpList": []string{"TCP;192.0.2.5;443"}}}}})
		case "auth/logout":
			logout.Add(1)
			io.WriteString(w, `{"code":200,"data":null}`)
		case "user/updateUserSession":
			update.Add(1)
			var fields map[string]string
			if json.NewDecoder(r.Body).Decode(&fields) != nil || fields["sessionId"] != "private-test-session" || fields["virtualIp"] != "10.0.0.2" || fields["gateway"] != "g1" {
				t.Error("incorrect session address registration")
			}
			io.WriteString(w, `{"code":200,"data":null}`)
		case "user/clearVirtualIp":
			cleared.Add(1)
			io.WriteString(w, `{"code":200,"data":null}`)
		default:
			t.Errorf("unexpected CLI controller request %s", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	controller.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12}
	controller.StartTLS()
	defer controller.Close()
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err = os.WriteFile(caPath, caPEM, 0600); err != nil {
		t.Fatal(err)
	}
	var output string
	if service {
		path := socketPath(t)
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		ready := make(chan struct{})
		finished := make(chan error, 1)
		go func() {
			finished <- serveControl(ctx, path, func(ctx context.Context, u, p string, report eventReporter) error {
				c, err := enlink.NewController(controller.URL, caPath, "synthetic-device-123456")
				if err != nil {
					return err
				}
				defer c.HTTP.CloseIdleConnections()
				options := sessionOptions{Mode: "connect", TUN: "cvpn9875", DataProfile: "android"}
				if _, e := net.InterfaceByName("br-lan"); e == nil {
					options.NetworkProfile = "dorm-router"
					options.LANPrefixes = []netip.Prefix{netip.MustParsePrefix("192.168.50.112/32")}
				}
				return executeSession(ctx, c, options, u, p, report)
			}, func() { close(ready) })
		}()
		<-ready
		output = runTTY(t, []string{"-mode", "login", "-socket", path}, "synthetic-user", "synthetic-password")
		for {
			status, err := requestControl(ctx, path, controlRequest{Action: "status"})
			if err != nil {
				t.Fatal(err)
			}
			if status.State == "connected" {
				break
			}
			if status.State == "failed" {
				t.Fatalf("authenticated service failed %+v", status)
			}
			select {
			case <-ctx.Done():
				t.Fatal("service connection timed out")
			case <-time.After(10 * time.Millisecond):
			}
		}
		if _, err = net.InterfaceByName("cvpn9875"); err != nil {
			t.Fatal("connected status without real TUN")
		}
		status, err := requestControl(ctx, path, controlRequest{Action: "disconnect"})
		if err != nil || status.State != "idle" {
			t.Fatalf("service disconnect %+v %v", status, err)
		}
		if _, err = net.InterfaceByName("cvpn9875"); err == nil {
			t.Fatal("service leaked TUN after disconnect")
		}
		if update.Load() != 1 || cleared.Load() != 1 {
			t.Fatal("session virtual address was not registered and cleared")
		}
		cancel()
		if err = <-finished; err != nil {
			t.Fatal(err)
		}
	} else {
		output = runTTY(t, []string{"-mode", "login-test", "-server", controller.URL, "-ca", caPath, "-device-id", "synthetic-device-123456", "-duration", "10s"}, "synthetic-user", "synthetic-password")
		for _, stage := range []string{"login-ok", "rules-ok", "gateway-auth-ok", "heartbeat-test-ok", "logout-ok"} {
			if !strings.Contains(output, `"stage":"`+stage+`"`) {
				t.Errorf("CLI missing %s: %s", stage, output)
			}
		}
		if update.Load() != 0 || cleared.Load() != 0 {
			t.Fatal("observation test registered a virtual address")
		}
	}
	for _, secret := range []string{"synthetic-password", "private-test-session", "private-test-cookie"} {
		if strings.Contains(output, secret) {
			t.Error("secret appeared in terminal output")
		}
	}
	if login.Load() != 1 || logout.Load() != 1 {
		t.Fatalf("login/logout count %d/%d", login.Load(), logout.Load())
	}
	if err = <-gatewayDone; err != nil {
		t.Fatal(err)
	}
}
