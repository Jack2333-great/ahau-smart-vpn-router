package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func socketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "cvpn-control-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, "control.sock")
}

func TestControlSessionLifecycle(t *testing.T) {
	path := socketPath(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var runs, cleanups atomic.Int32
	started := make(chan struct{}, 2)
	run := func(ctx context.Context, user, password string, report eventReporter) error {
		if user != "synthetic-user" || password != "synthetic-password" {
			return errors.New("incorrect synthetic credentials")
		}
		runs.Add(1)
		report("tun-ready", nil)
		started <- struct{}{}
		<-ctx.Done()
		// Completion must not be acknowledged until cleanup actually finishes.
		time.Sleep(30 * time.Millisecond)
		cleanups.Add(1)
		report("logout-ok", nil)
		return ctx.Err()
	}
	ready := make(chan struct{})
	finished := make(chan error, 1)
	go func() { finished <- serveControl(ctx, path, run, func() { close(ready) }) }()
	select {
	case <-ready:
	case <-time.After(2 * time.Second):
		t.Fatal("service did not start")
	}
	call := func(request controlRequest) controlStatus {
		t.Helper()
		reply, err := requestControl(ctx, path, request)
		if err != nil {
			t.Fatal(err)
		}
		return reply
	}
	if r := call(controlRequest{Action: "status"}); !r.OK || r.State != "idle" {
		t.Fatalf("initial status %+v", r)
	}
	login := controlRequest{Action: "login", Username: "synthetic-user", Password: "synthetic-password"}
	if r := call(login); !r.OK || r.Generation != 1 {
		t.Fatalf("start %+v", r)
	}
	<-started
	if r := call(login); r.OK {
		t.Fatal("concurrent login accepted")
	}
	if r := call(controlRequest{Action: "status"}); r.State != "connected" {
		t.Fatalf("connected status %+v", r)
	}
	if r := call(controlRequest{Action: "disconnect"}); !r.OK || r.State != "idle" || cleanups.Load() != 1 {
		t.Fatalf("disconnect did not join cleanup %+v", r)
	}
	if r := call(login); !r.OK || r.Generation != 2 {
		t.Fatalf("fresh login %+v", r)
	}
	<-started
	cancel()
	select {
	case err := <-finished:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown stalled")
	}
	if runs.Load() != 2 || cleanups.Load() != 2 {
		t.Fatal("shutdown failed to join active session")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("socket survived service shutdown")
	}
}

func TestSupervisorFailureAndConcurrentDisconnect(t *testing.T) {
	s := newSupervisor(context.Background(), func(context.Context, string, string, eventReporter) error {
		return errors.New("never-export-this-secret")
	})
	r := s.start("user", "password")
	if !r.OK {
		t.Fatal(r)
	}
	deadline := time.After(2 * time.Second)
	for s.snapshot().State != "failed" {
		select {
		case <-deadline:
			t.Fatal("failure not reported")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	b, _ := json.Marshal(s.snapshot())
	if strings.Contains(string(b), "never-export-this-secret") {
		t.Fatal("runner error leaked")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	s = newSupervisor(ctx, func(ctx context.Context, _ string, _ string, _ eventReporter) error { <-ctx.Done(); return ctx.Err() })
	s.start("user", "password")
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if r := s.stop(ctx); r.State != "idle" {
				t.Errorf("stop %+v", r)
			}
		}()
	}
	wg.Wait()
}

func TestControlRefusesUnsafePathsAndDuplicateDaemon(t *testing.T) {
	path := socketPath(t)
	ln, lock, err := listenControl(path)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	defer ln.Close()
	if info, _ := os.Lstat(path); info.Mode().Perm() != 0600 {
		t.Fatal("socket is not private")
	}
	if second, secondLock, err := listenControl(path); err == nil {
		second.Close()
		secondLock.Close()
		t.Fatal("second daemon replaced live socket")
	}
	if conn, err := net.Dial("unix", path); err != nil {
		t.Fatal("original socket was damaged")
	} else {
		conn.Close()
	}
	other := socketPath(t)
	target := filepath.Join(filepath.Dir(other), "keep")
	if err = os.WriteFile(target, []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(target, other); err != nil {
		t.Fatal(err)
	}
	if l, k, e := listenControl(other); e == nil {
		l.Close()
		k.Close()
		t.Fatal("symlink accepted")
	}
	if b, _ := os.ReadFile(target); string(b) != "preserve" {
		t.Fatal("symlink target changed")
	}
	os.Remove(other)
	os.Chmod(filepath.Dir(other), 0777)
	if l, k, e := listenControl(other); e == nil {
		l.Close()
		k.Close()
		t.Fatal("public control directory accepted")
	}
}

func TestControlMalformedMessages(t *testing.T) {
	for _, wire := range []string{"{}", strings.Repeat("x", 8192) + "\n", "{\"action\":\"status\",\"extra\":1}\n", "{}{}\n"} {
		var request controlRequest
		if err := decodeControl(strings.NewReader(wire), &request); err == nil {
			t.Fatal("malformed request accepted")
		}
	}
}

func TestSupervisorReportsCleanupFailureAfterCancellation(t *testing.T) {
	for _, stage := range []string{"logout-failed", "clear-address-failed", "network-cleanup-failed"} {
		t.Run(stage, func(t *testing.T) {
			started := make(chan struct{})
			s := newSupervisor(context.Background(), func(ctx context.Context, _, _ string, report eventReporter) error {
				report("tun-ready", nil)
				close(started)
				<-ctx.Done()
				report(stage, map[string]any{"message": "synthetic-secret-not-for-status"})
				report("logout-ok", nil)
				return nil
			})
			if r := s.start("user", "password"); !r.OK {
				t.Fatal(r)
			}
			<-started
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			r := s.stop(ctx)
			if r.OK || r.State != "failed" || !r.CleanupFailed || r.CleanupStage != stage || r.Stage != "tun-ready" {
				t.Fatalf("cleanup failure hidden: %+v", r)
			}
			data, _ := json.Marshal(r)
			if strings.Contains(string(data), "synthetic-secret") {
				t.Fatal("cleanup diagnostic leaked")
			}
			if stage == "network-cleanup-failed" && s.start("user", "password").OK {
				t.Fatal("new login accepted before failed network cleanup was addressed")
			}
		})
	}
}
