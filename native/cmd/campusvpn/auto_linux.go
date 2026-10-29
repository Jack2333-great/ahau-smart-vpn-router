package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

type savedLogin struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Enabled  bool   `json:"enabled"`
}
type autoManager struct {
	mu       sync.Mutex
	ctx      context.Context
	s        *supervisor
	path     string
	probe    func(context.Context) bool
	attempts int
	mode     string
}

func newAutoManager(ctx context.Context, s *supervisor, path string, probe func(context.Context) bool) *autoManager {
	return &autoManager{ctx: ctx, s: s, path: path, probe: probe, mode: "disabled"}
}
func (a *autoManager) read() (savedLogin, error) {
	var x savedLogin
	if a.path == "" {
		return x, errors.New("automatic login unavailable")
	}
	dir, e := os.Lstat(filepath.Dir(a.path))
	if e != nil || !dir.IsDir() || !ownedPrivate(dir, false) {
		return x, errors.New("unsafe credential directory")
	}
	fd, e := syscall.Open(a.path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if e != nil {
		return x, e
	}
	f := os.NewFile(uintptr(fd), a.path)
	defer f.Close()
	info, e := f.Stat()
	if e != nil || !ownedPrivate(info, true) || info.Size() > 4096 {
		return x, errors.New("unsafe credential file")
	}
	e = json.NewDecoder(f).Decode(&x)
	return x, e
}
func (a *autoManager) write(x savedLogin) error {
	if a.path == "" || !filepath.IsAbs(a.path) {
		return errors.New("automatic login unavailable")
	}
	dir := filepath.Dir(a.path)
	if e := os.Mkdir(dir, 0700); e != nil && !os.IsExist(e) {
		return e
	}
	info, e := os.Lstat(dir)
	if e != nil || !info.IsDir() || !ownedPrivate(info, false) {
		return errors.New("unsafe credential directory")
	}
	b, e := json.Marshal(x)
	if e != nil {
		return e
	}
	defer clear(b)
	f, e := os.CreateTemp(dir, ".credentials-")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(b)
	}
	if e == nil {
		e = f.Sync()
	}
	if closeErr := f.Close(); e == nil {
		e = closeErr
	}
	if e != nil {
		return e
	}
	return os.Rename(name, a.path)
}
func (a *autoManager) saveAndStart(u, p string) controlStatus {
	a.mu.Lock()
	defer a.mu.Unlock()
	r := a.s.snapshot()
	if r.State == "connecting" || r.State == "connected" || r.State == "stopping" || r.CleanupStage == "network-cleanup-failed" {
		r.OK = false
		r.Message = "disconnect the existing session first"
		return r
	}
	if u == "" || len(u) > 255 || p == "" || len(p) > 1024 || strings.ContainsAny(u+p, "\x00\r\n") {
		r.OK = false
		r.Message = "invalid credentials"
		return r
	}
	if e := a.write(savedLogin{u, p, true}); e != nil {
		r.OK = false
		r.Message = "unable to store credentials securely"
		return r
	}
	a.attempts = 1
	a.mode = "trying"
	return a.s.start(u, p)
}
func (a *autoManager) pause() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if x, e := a.read(); e == nil {
		x.Enabled = false
		if a.write(x) != nil {
			a.mode = "error"
			return
		}
	}
	a.mode = "paused"
}
func (a *autoManager) resume() controlStatus {
	a.mu.Lock()
	defer a.mu.Unlock()
	r := a.s.snapshot()
	x, e := a.read()
	if e != nil {
		r.OK = false
		r.Message = "no saved credentials"
		return r
	}
	if r.State == "connected" || r.State == "connecting" || r.State == "stopping" || r.CleanupStage == "network-cleanup-failed" {
		r.OK = false
		r.Message = "service is busy or needs cleanup"
		return r
	}
	x.Enabled = true
	if a.write(x) != nil {
		r.OK = false
		r.Message = "unable to update saved credentials"
		return r
	}
	a.attempts = 1
	a.mode = "trying"
	return a.s.start(x.Username, x.Password)
}
func (a *autoManager) status() string { a.mu.Lock(); defer a.mu.Unlock(); return a.mode }
func (a *autoManager) step() {
	a.mu.Lock()
	defer a.mu.Unlock()
	x, e := a.read()
	if e != nil {
		a.mode = "disabled"
		return
	}
	if !x.Enabled {
		a.mode = "paused"
		return
	}
	r := a.s.snapshot()
	if r.State == "connecting" || r.State == "stopping" {
		a.mode = "trying"
		return
	}
	if r.State == "connected" {
		if t, err := time.Parse(time.RFC3339, r.ConnectedSince); err == nil && time.Since(t) >= 10*time.Minute {
			a.attempts = 0
		}
		a.mode = "connected"
		return
	}
	if r.CleanupStage == "network-cleanup-failed" {
		a.mode = "cleanup-required"
		return
	}
	if a.attempts > 0 && r.State == "failed" && r.Stage == "authentication-rejected" {
		a.mode = "authentication-paused"
		return
	}
	if a.attempts >= 3 {
		a.mode = "retry-limit"
		return
	}
	if a.probe == nil {
		a.mode = "offline"
		return
	}
	ctx, cancel := context.WithTimeout(a.ctx, 8*time.Second)
	ok := a.probe(ctx)
	cancel()
	if !ok {
		a.mode = "offline"
		return
	}
	a.attempts++
	a.mode = "trying"
	a.s.start(x.Username, x.Password)
}
func (a *autoManager) loop() {
	a.step()
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-a.ctx.Done():
			return
		case <-t.C:
			a.step()
		}
	}
}
