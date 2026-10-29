package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func waitState(t *testing.T, s *supervisor, want string) {
	t.Helper()
	for i := 0; i < 500; i++ {
		if s.snapshot().State == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("expected %s: %+v", want, s.snapshot())
}
func TestAutoOfflineBoundedAndCredentialPermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	path := filepath.Join(dir, "credentials")
	var calls atomic.Int32
	online := false
	s := newSupervisor(context.Background(), func(ctx context.Context, u, p string, report eventReporter) error {
		calls.Add(1)
		return errors.New("temporary failure")
	})
	a := newAutoManager(context.Background(), s, path, func(context.Context) bool { return online })
	if e := a.write(savedLogin{"test-user", "test-secret", true}); e != nil {
		t.Fatal(e)
	}
	if info, e := os.Stat(path); e != nil || info.Mode().Perm() != 0600 {
		t.Fatal("credentials are not private", e)
	}
	for i := 0; i < 20; i++ {
		a.step()
	}
	if calls.Load() != 0 || a.status() != "offline" {
		t.Fatal("offline login attempt")
	}
	online = true
	for i := 0; i < 3; i++ {
		a.step()
		waitState(t, s, "failed")
	}
	a.step()
	if calls.Load() != 3 || a.status() != "retry-limit" {
		t.Fatalf("attempts %d mode %s", calls.Load(), a.status())
	}
	a.pause()
	x, e := a.read()
	if e != nil || x.Enabled {
		t.Fatal("manual pause not persisted")
	}
}
func TestAutoAuthenticationRejectedStops(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "credentials")
	var calls atomic.Int32
	s := newSupervisor(context.Background(), func(ctx context.Context, u, p string, report eventReporter) error {
		calls.Add(1)
		report("authentication-rejected", nil)
		return errors.New("rejected")
	})
	a := newAutoManager(context.Background(), s, path, func(context.Context) bool { return true })
	if !a.saveAndStart("test-user", "test-secret").OK {
		t.Fatal("start failed")
	}
	waitState(t, s, "failed")
	for i := 0; i < 10; i++ {
		a.step()
	}
	if calls.Load() != 1 || a.status() != "authentication-paused" {
		t.Fatal("rejected login retried")
	}
}
func TestAutoRejectsUnsafeCredentialFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "credentials")
	a := newAutoManager(context.Background(), newSupervisor(context.Background(), nil), path, nil)
	if e := a.write(savedLogin{"u", "p", true}); e != nil {
		t.Fatal(e)
	}
	if e := os.Chmod(path, 0644); e != nil {
		t.Fatal(e)
	}
	if _, e := a.read(); e == nil {
		t.Fatal("accepted exposed credentials")
	}
}
