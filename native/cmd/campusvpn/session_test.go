package main

import (
	"campusvpn/internal/enlink"
	"encoding/json"
	"strings"
	"testing"
)

func TestResourceDiagnosticsPreservePolicyAndPrivacy(t *testing.T) {
	for _, unsupported := range []bool{false, true} {
		gateway := enlink.Gateway{IPList: []string{"TCP;192.0.2.99;443"}, Domains: []string{"private-synthetic-resource.example"}}
		if unsupported {
			gateway.OutIP = []string{"private-synthetic-exclusion"}
		}
		called := false
		_, err := inspectResources(enlink.Rules{}, gateway, func(stage string, fields map[string]any) {
			called = true
			if stage != "resource-policy-check" || fields["ip_acl_supported"] != !unsupported || fields["gateway_domain_rule_count"] != 1 || fields["routes_changed"] != false {
				t.Fatalf("incorrect capability diagnostic: %s %+v", stage, fields)
			}
			wire, _ := json.Marshal(fields)
			if strings.Contains(string(wire), "192.0.2.99") || strings.Contains(string(wire), "private-synthetic") {
				t.Fatal("private resource contents leaked")
			}
		})
		if !called || (err != nil) != unsupported {
			t.Fatal("diagnostic changed policy rejection")
		}
	}
}
