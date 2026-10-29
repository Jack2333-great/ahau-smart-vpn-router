package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

const defaultSocket = "/var/run/campusvpn/control.sock"

type controlRequest struct {
	Action   string `json:"action"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

type controlStatus struct {
	OK             bool   `json:"ok"`
	Version        string `json:"version"`
	State          string `json:"state"`
	Stage          string `json:"stage,omitempty"`
	LastEvent      string `json:"last_event,omitempty"`
	CleanupFailed  bool   `json:"cleanup_failed,omitempty"`
	CleanupStage   string `json:"cleanup_stage,omitempty"`
	Message        string `json:"message,omitempty"`
	Generation     uint64 `json:"generation"`
	Updated        string `json:"updated"`
	ConnectedSince string `json:"connected_since,omitempty"`
	AutoState      string `json:"auto_state,omitempty"`
}

type sessionRunner func(context.Context, string, string, eventReporter) error

// The supervisor owns exactly one session. Session callbacks and completion
// belong to a generation, so an old worker can never overwrite a newer status.
type supervisor struct {
	mu     sync.Mutex
	status controlStatus
	cancel context.CancelFunc
	done   chan struct{}
	run    sessionRunner
	ctx    context.Context
}

func newSupervisor(ctx context.Context, run sessionRunner) *supervisor {
	return &supervisor{ctx: ctx, run: run, status: controlStatus{OK: true, Version: version, State: "idle", Updated: time.Now().UTC().Format(time.RFC3339)}}
}

func (s *supervisor) snapshot() controlStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.status
}

func (s *supervisor) start(username, password string) controlStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := s.status
	if s.ctx.Err() != nil {
		result.OK = false
		result.Message = "service is stopping"
		return result
	}
	if s.done != nil {
		result.OK = false
		result.Message = "a session is already active; disconnect it first"
		return result
	}
	if s.status.CleanupStage == "network-cleanup-failed" {
		result.OK = false
		result.Message = "previous network cleanup failed; stop the service and inspect recover-network first"
		return result
	}
	if len(username) == 0 || len(username) > 255 || len(password) == 0 || len(password) > 1024 || strings.ContainsAny(username+password, "\x00\r\n") {
		result.OK = false
		result.Message = "invalid credential length or characters"
		return result
	}
	s.status.Generation++
	generation := s.status.Generation
	s.status.State = "connecting"
	s.status.Stage = "login-starting"
	s.status.Message = ""
	s.status.CleanupFailed = false
	s.status.CleanupStage = ""
	s.status.LastEvent = ""
	s.status.ConnectedSince = ""
	s.status.Updated = time.Now().UTC().Format(time.RFC3339)
	ctx, cancel := context.WithCancel(s.ctx)
	done := make(chan struct{})
	s.cancel = cancel
	s.done = done
	go func() {
		err := s.run(ctx, username, password, func(stage string, _ map[string]any) {
			s.mu.Lock()
			defer s.mu.Unlock()
			if s.status.Generation != generation {
				return
			}
			s.status.LastEvent = stage
			if stage == "logout-failed" || stage == "clear-address-failed" || stage == "network-cleanup-failed" {
				s.status.CleanupFailed = true
				if s.status.CleanupStage != "network-cleanup-failed" {
					s.status.CleanupStage = stage
				}
			}
			if stage != "logout-ok" && stage != "logout-failed" && stage != "clear-address-failed" && stage != "tunnel-stopped" && stage != "network-restored" && stage != "network-cleanup-failed" {
				s.status.Stage = stage
			}
			if stage == "tun-ready" && s.status.State != "stopping" {
				s.status.State = "connected"
				s.status.ConnectedSince = time.Now().UTC().Format(time.RFC3339)
			}
			s.status.Updated = time.Now().UTC().Format(time.RFC3339)
		})
		wasCanceled := errors.Is(ctx.Err(), context.Canceled)
		cancel()
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.status.Generation == generation {
			s.status.State = "idle"
			s.status.ConnectedSince = ""
			s.status.Message = ""
			if err != nil && !wasCanceled {
				s.status.State = "failed"
				// Do not reflect arbitrary server/runner errors into the control
				// socket: stage is sufficient for a secret-free service status.
				s.status.Message = "session failed; run the interactive diagnostic test for details"
			}
			if s.status.CleanupFailed {
				s.status.State = "failed"
				s.status.Message = "session cleanup could not be confirmed; inspect cleanup_stage before starting again"
			}
			s.status.Updated = time.Now().UTC().Format(time.RFC3339)
			s.done = nil
			s.cancel = nil
		}
		close(done)
	}()
	return s.status
}

func (s *supervisor) stop(ctx context.Context) controlStatus {
	s.mu.Lock()
	done := s.done
	if done != nil {
		s.status.State = "stopping"
		s.status.Updated = time.Now().UTC().Format(time.RFC3339)
		s.cancel()
	}
	s.mu.Unlock()
	if done != nil {
		select {
		case <-done:
		case <-ctx.Done():
			r := s.snapshot()
			r.OK = false
			r.Message = "session cleanup is still running"
			return r
		}
	}
	result := s.snapshot()
	if result.CleanupFailed {
		result.OK = false
	}
	return result
}

func ownedPrivate(info os.FileInfo, regular bool) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st.Uid == uint32(os.Geteuid()) && info.Mode().Perm()&0077 == 0 && (!regular || info.Mode().IsRegular())
}

// Never unlink an unverified path. The persistent flock file prevents a second
// daemon from removing a live socket; it is deliberately not unlinked on exit.
func listenControl(path string) (*net.UnixListener, *os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 100 {
		return nil, nil, errors.New("control socket must be a short absolute clean path")
	}
	dir := filepath.Dir(path)
	if err := os.Mkdir(dir, 0700); err != nil && !os.IsExist(err) {
		return nil, nil, err
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || !ownedPrivate(info, false) {
		return nil, nil, errors.New("control directory must be owned by this user with mode 0700")
	}
	fd, err := syscall.Open(path+".lock", syscall.O_CREAT|syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, nil, errors.New("cannot open control lock")
	}
	lock := os.NewFile(uintptr(fd), path+".lock")
	fail := func(e error) (*net.UnixListener, *os.File, error) { lock.Close(); return nil, nil, e }
	info, err = lock.Stat()
	if err != nil || !ownedPrivate(info, true) {
		return fail(errors.New("control lock must be a private owned regular file"))
	}
	if syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		return fail(errors.New("another service owns this control socket"))
	}
	if info, err = os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 || !ownedPrivate(info, false) {
			return fail(errors.New("refusing to replace an untrusted control path"))
		}
		if err = os.Remove(path); err != nil {
			return fail(err)
		}
	} else if !os.IsNotExist(err) {
		return fail(err)
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return fail(err)
	}
	if err = os.Chmod(path, 0600); err != nil {
		listener.Close()
		return fail(err)
	}
	return listener, lock, nil
}

func decodeControl(r io.Reader, value any) error {
	line, err := bufio.NewReaderSize(r, 8192).ReadSlice('\n')
	if err != nil {
		return errors.New("invalid or oversized control message")
	}
	dec := json.NewDecoder(strings.NewReader(string(line)))
	dec.DisallowUnknownFields()
	if err = dec.Decode(value); err != nil {
		return errors.New("invalid control message")
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return errors.New("multiple control messages are not allowed")
	}
	return nil
}

func serveControl(ctx context.Context, path string, run sessionRunner, ready func()) error {
	return serveControlWithAuto(ctx, path, run, ready, "", nil)
}

func serveControlWithAuto(ctx context.Context, path string, run sessionRunner, ready func(), credentialPath string, probe func(context.Context) bool) error {
	ctx, cancelService := context.WithCancel(ctx)
	defer cancelService()
	ln, lock, err := listenControl(path)
	if err != nil {
		return err
	}
	defer lock.Close()
	defer ln.Close()
	s := newSupervisor(ctx, run)
	auto := newAutoManager(ctx, s, credentialPath, probe)
	if credentialPath != "" {
		go auto.loop()
	}
	stop := context.AfterFunc(ctx, func() { ln.Close() })
	defer stop()
	var handlers sync.WaitGroup
	slots := make(chan struct{}, 8)
	defer handlers.Wait()
	defer func() {
		cancelService()
		ln.Close()
		cleanup, cancel := context.WithTimeout(context.Background(), 40*time.Second)
		defer cancel()
		s.stop(cleanup)
	}()
	ready()
	for {
		conn, e := ln.AcceptUnix()
		if e != nil {
			if ctx.Err() != nil {
				return nil
			}
			return e
		}
		select {
		case slots <- struct{}{}:
		default:
			conn.Close()
			continue
		}
		handlers.Add(1)
		go func() {
			defer handlers.Done()
			defer func() { <-slots }()
			defer conn.Close()
			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			var request controlRequest
			result := s.snapshot()
			if decodeControl(conn, &request) != nil {
				result.OK = false
				result.Message = "invalid control request"
			} else {
				switch request.Action {
				case "login":
					result = s.start(request.Username, request.Password)
				case "save-login":
					result = auto.saveAndStart(request.Username, request.Password)
				case "reconnect":
					result = auto.resume()
				case "status", "disconnect":
					if request.Username != "" || request.Password != "" {
						result.OK = false
						result.Message = "unexpected credential fields"
						break
					}
					if request.Action == "disconnect" {
						auto.pause()
						wait, cancel := context.WithTimeout(context.Background(), 40*time.Second)
						result = s.stop(wait)
						cancel()
					}
				default:
					result.OK = false
					result.Message = "unknown control action"
				}
			}
			request = controlRequest{}
			result.AutoState = auto.status()
			conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
			json.NewEncoder(conn).Encode(result)
		}()
	}
}

func requestControl(ctx context.Context, path string, request controlRequest) (controlStatus, error) {
	var result controlStatus
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSocket == 0 || !ownedPrivate(info, false) {
		return result, errors.New("control socket is missing or is not private and owned")
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", path)
	if err != nil {
		return result, errors.New("cannot connect to local service")
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	conn.SetDeadline(time.Now().Add(45 * time.Second))
	if err = json.NewEncoder(conn).Encode(request); err != nil {
		return result, errors.New("cannot send control request")
	}
	request = controlRequest{}
	if err = decodeControl(conn, &result); err != nil {
		return result, err
	}
	return result, nil
}
