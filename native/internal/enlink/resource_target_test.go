package enlink

import (
	"net/netip"
	"testing"
)

func TestResourceTargetsNeverExpandServerPolicy(t *testing.T) {
	rules, err := CompileACL([]string{"TCP;192.0.2.0/24;443", "UDP;198.51.100.7;53"})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ target, want string }{
		{"192.0.2.5/32", "192.0.2.5/32"},
		{"192.0.0.0/16", "192.0.2.0/24"},
	} {
		got, err := RestrictACL(rules, []netip.Prefix{netip.MustParsePrefix(tc.target)})
		if err != nil || len(got) != 1 || got[0].Prefix.String() != tc.want || got[0].Protocol != 6 || got[0].Low != 443 || got[0].High != 443 {
			t.Fatal(tc, got, err)
		}
	}
	for _, target := range []string{"203.0.113.1/32", "0.0.0.0/0", "::/0"} {
		if _, err := RestrictACL(rules, []netip.Prefix{netip.MustParsePrefix(target)}); err == nil {
			t.Fatal("unsupported target accepted", target)
		}
	}
	got, err := RestrictACL(rules, []netip.Prefix{netip.MustParsePrefix("192.0.2.5/32"), netip.MustParsePrefix("192.0.2.5/32")})
	if err != nil || len(got) != 1 {
		t.Fatal("duplicate target", got, err)
	}
}
