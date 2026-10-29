package tun

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"syscall"
	"time"
	"unsafe"
)

// Only a transient, non-persistent TUN is created. Closing its descriptor
// destroys it, including associated addresses and routes. No firewall or DNS.
const tunsetiff = 0x400454ca

var validName = regexp.MustCompile(`^cvpn[0-9]{1,4}$`)

type Device struct {
	*os.File
	Name string
}

func ValidateName(name string) error {
	if !validName.MatchString(name) {
		return errors.New("TUN name must be cvpn followed by 1..4 digits")
	}
	return nil
}

func Open(name string) (*Device, error) {
	if err := ValidateName(name); err != nil {
		return nil, err
	}
	if _, err := net.InterfaceByName(name); err == nil {
		return nil, errors.New("refusing to attach an existing interface")
	}
	fd, err := syscall.Open("/dev/net/tun", syscall.O_RDWR|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	// struct ifreq is 40 bytes on 64-bit Linux; flags at offset IFNAMSIZ.
	var request [40]byte
	copy(request[:16], name)
	*(*uint16)(unsafe.Pointer(&request[16])) = 0x0001 | 0x1000 | 0x8000 // TUN | NO_PI | TUN_EXCL
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), tunsetiff, uintptr(unsafe.Pointer(&request[0])))
	if errno != 0 {
		syscall.Close(fd)
		return nil, errno
	}
	// Initialize Go's poller after TUNSETIFF. Opening the unconfigured character
	// device with os.OpenFile can leave reads blocking in the kernel; Close
	// then cannot interrupt them, leaking bridge workers on disconnect.
	f := os.NewFile(uintptr(fd), "/dev/net/tun")
	return &Device{File: f, Name: name}, nil
}
func (d *Device) Configure(ctx context.Context, address netip.Addr, mtu int) error {
	if !address.Is4() || address.IsUnspecified() || mtu < 576 || mtu > 1400 {
		return errors.New("invalid TUN IPv4/MTU")
	}
	// An assigned /32 avoids adding a connected subnet route. There is still
	// a local host route while the transient interface exists.
	if err := ip(ctx, "address", "add", address.String()+"/32", "dev", d.Name, "noprefixroute"); err != nil {
		return err
	}
	return ip(ctx, "link", "set", "dev", d.Name, "mtu", fmt.Sprint(mtu), "up")
}
func ip(ctx context.Context, args ...string) error {
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := exec.CommandContext(bounded, "ip", args...).Run(); err != nil {
		return fmt.Errorf("ip configuration failed: %w", err)
	}
	return nil
}
