#!/bin/sh
# Run on a local development machine, never on the production router.
# Root is used only to create disposable network namespaces and TUN devices.
set -eu
if [ "$(id -u)" != 0 ]; then
    echo 'Run as root on the development machine (isolated network namespaces).' >&2
    exit 1
fi
root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
go_cmd=${GO_BINARY:-go}
export GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off CGO_ENABLED=0
build_dir=$(mktemp -d /tmp/campusvpn-test.XXXXXX)
trap 'rm -f "$build_dir/enlink.test" "$build_dir/tun.test" "$build_dir/cli.test" "$build_dir/network.test"; rmdir "$build_dir"' EXIT HUP INT TERM
cd "$root/native"
"$go_cmd" test -c -o "$build_dir/enlink.test" ./internal/enlink
"$go_cmd" test -c -o "$build_dir/tun.test" ./internal/tun
"$go_cmd" test -c -o "$build_dir/cli.test" ./cmd/campusvpn
"$go_cmd" test -c -o "$build_dir/network.test" ./internal/network
soak=${CAMPUSVPN_SOAK_SECONDS:-0}
case "$soak" in ''|*[!0-9]*) echo 'Invalid soak duration' >&2; exit 1;; esac
[ "$soak" -le 120 ] || { echo 'Soak duration must be <= 120 seconds per profile' >&2; exit 1; }
unshare -n env CAMPUSVPN_ISOLATED_TUN_TEST=1 CAMPUSVPN_SOAK_SECONDS="$soak" "$build_dir/enlink.test" -test.run '^Test(KernelLANTranslation|KernelDesktopLANTranslation|KernelUDPRoundTrip)Integration$' -test.v -test.timeout="$((30 + 2 * soak))s"
for test in TestRouterAndroidEndToEndIntegration TestRouterDesktopEndToEndIntegration; do
    unshare -n env CAMPUSVPN_ISOLATED_TUN_TEST=1 "$build_dir/enlink.test" -test.run "^${test}\$" -test.v -test.timeout=20s
done
unshare -n env CAMPUSVPN_ISOLATED_TUN_TEST=1 "$build_dir/tun.test" -test.run Integration -test.v -test.timeout=15s
for test in TestServiceAuthenticatedLifecycleIntegration TestServiceManagedPolicyIntegration; do
    unshare -n env CAMPUSVPN_ISOLATED_TUN_TEST=1 "$build_dir/cli.test" -test.run "^${test}\$" -test.v -test.timeout=20s
done
for test in TestPolicyRouteAndRollbackIntegration TestPolicyFirewallLossIntegration TestPolicyActualLANPacketScopeIntegration TestPolicyCrashRecoveryIntegration TestPolicyCollisionIntegration; do
    unshare -n env CAMPUSVPN_ISOLATED_TUN_TEST=1 "$build_dir/network.test" -test.run "^${test}\$" -test.v -test.timeout=20s
done
