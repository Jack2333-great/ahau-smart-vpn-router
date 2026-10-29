package tun

import (
	"context"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"
)

func TestRejectInvalidName(t *testing.T) {
	for _, name := range []string{"tun0", "eth0", "cvpn", "cvpn0;reboot", "cvpn12345"} {
		if _, err := Open(name); err == nil {
			t.Fatal("invalid name accepted")
		}
	}
}
func TestTransientDeviceIntegration(t *testing.T) {
	if os.Getenv("CAMPUSVPN_ISOLATED_TUN_TEST") != "1" {
		t.Skip("requires root inside an isolated network namespace")
	}
	d, err := Open("cvpn9876")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err = d.Configure(ctx, netip.MustParseAddr("192.0.2.2"), 1300); err != nil {
		t.Fatal(err)
	}
	iface, err := net.InterfaceByName(d.Name)
	if err != nil || iface.MTU != 1300 || iface.Flags&net.FlagUp == 0 {
		t.Fatalf("%v %v", iface, err)
	}
	if other, err := Open(d.Name); err == nil {
		other.Close()
		t.Fatal("attached an existing interface")
	}
	readDone := make(chan error, 1)
	go func() {
		b := make([]byte, 1500)
		for {
			_, err := d.Read(b)
			if err != nil {
				readDone <- err
				return
			}
		}
	}()
	time.Sleep(20 * time.Millisecond)
	if err = d.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-readDone:
		if err == nil {
			t.Fatal("blocked read returned without error")
		}
	case <-time.After(time.Second):
		t.Fatal("close failed to unblock TUN read")
	}
	if _, err = net.InterfaceByName(d.Name); err == nil {
		t.Fatal("transient interface survived close")
	}
}
