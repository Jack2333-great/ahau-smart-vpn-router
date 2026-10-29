package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"
)

func credentials(ctx context.Context) (string, string, error) {
	fd := os.Stdin.Fd()
	var original syscall.Termios
	if _, _, errno := syscall.Syscall6(syscall.SYS_IOCTL, fd, syscall.TCGETS, uintptr(unsafe.Pointer(&original)), 0, 0, 0); errno != 0 {
		return "", "", errors.New("credentials require an interactive TTY; never supply passwords on the command line")
	}
	reader := bufio.NewReaderSize(os.Stdin, 4096)
	read := func() (string, error) {
		type result struct {
			s string
			e error
		}
		ch := make(chan result, 1)
		go func() {
			b, e := reader.ReadSlice('\n')
			if errors.Is(e, bufio.ErrBufferFull) {
				ch <- result{"", errors.New("credential input exceeds terminal buffer")}
				return
			}
			ch <- result{string(b), e}
		}()
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case r := <-ch:
			return strings.TrimSuffix(strings.TrimSuffix(r.s, "\n"), "\r"), r.e
		}
	}
	fmt.Fprint(os.Stderr, "Campus username: ")
	username, err := read()
	if err != nil {
		return "", "", err
	}
	if username == "" || len(username) > 255 {
		return "", "", errors.New("username must contain 1..255 bytes")
	}
	hidden := original
	hidden.Lflag &^= syscall.ECHO | syscall.ECHONL
	if _, _, errno := syscall.Syscall6(syscall.SYS_IOCTL, fd, syscall.TCSETS, uintptr(unsafe.Pointer(&hidden)), 0, 0, 0); errno != 0 {
		return "", "", errno
	}
	defer func() {
		syscall.Syscall6(syscall.SYS_IOCTL, fd, syscall.TCSETS, uintptr(unsafe.Pointer(&original)), 0, 0, 0)
		fmt.Fprintln(os.Stderr)
	}()
	fmt.Fprint(os.Stderr, "Campus password (hidden): ")
	password, err := read()
	if err != nil {
		return "", "", err
	}
	if password == "" || len(password) > 1024 {
		return "", "", errors.New("password must contain 1..1024 bytes")
	}
	return username, password, nil
}
