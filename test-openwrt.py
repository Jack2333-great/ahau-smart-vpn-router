"""Exercise the actual init script with isolated procd/UCI stubs, no install."""
from pathlib import Path
import os
import subprocess

ROOT = Path(__file__).resolve().parent
STUBS = r'''
config_load() { [ "$1" = campusvpn ]; }
config_get_bool() { eval "$1=\$CASE_ENABLED"; }
config_get() {
    case "$3" in
        device_id) eval "$1=\$CASE_DEVICE";;
        lan_source) eval "$1=\$CASE_LAN";;
        ca_file) eval "$1=\$CASE_CA";;
        *) eval "$1=\${4-}";;
    esac
}
record() { printf '%s\000' "$@"; printf '\n'; }
procd_open_instance() { record open "$@"; }
procd_set_param() { record set "$@"; }
procd_append_param() { record append "$@"; }
procd_close_instance() { record close; }
procd_add_reload_trigger() { record trigger "$@"; }
logger() { record logger "$@"; }
. "$1"
start_service
result=$?
service_triggers
exit "$result"
'''


def run(enabled, device, lan="", ca=""):
    env = dict(os.environ, CASE_ENABLED=enabled, CASE_DEVICE=device,
               CASE_LAN=lan, CASE_CA=ca)
    result = subprocess.run(["sh", "-s", "--", str(ROOT / "openwrt/campusvpn.init")],
                            input=STUBS.encode(), capture_output=True, env=env, check=False)
    records = [line.rstrip(b"\0").decode().split("\0") for line in result.stdout.splitlines()]
    assert not result.stderr, result.stderr
    return result.returncode, records


def main():
    subprocess.run(["sh", "-n", str(ROOT / "openwrt/campusvpn.init")], check=True)
    config = (ROOT / "openwrt/campusvpn.config").read_text()
    assert "option enabled '0'" in config
    code, records = run("0", "")
    assert code == 0 and records == [["trigger", "campusvpn"]], records
    code, records = run("1", "")
    assert code == 1 and not any(r[0] == "open" for r in records), records
    device = "synthetic stable id; no shell interpretation"
    ca = "/tmp/synthetic CA file.pem"
    lan = "192.168.50.112/32,192.168.50.113/32"
    code, records = run("1", device, lan, ca)
    assert code == 0, records
    command = next(r[2:] for r in records if r[:2] == ["set", "command"])
    assert command == ["/usr/sbin/campusvpn", "-mode", "serve", "-server",
                       "https://myvpn.ahau.edu.cn", "-device-id", device,
                       "-tun", "cvpn0", "-network-profile", "none", "-data-profile",
                       "android", "-spa-profile", "school-apk", "-spa-user", "enlink"], command
    assert ["append", "command", "-lan-source", lan] in records
    assert ["append", "command", "-ca", ca] in records
    for record in [["set", "term_timeout", "50"], ["set", "respawn", "3600", "5", "5"],
                   ["set", "limits", "core=0"], ["set", "file", "/etc/config/campusvpn"]]:
        assert record in records, (record, records)
    assert records.count(["open", "main"]) == records.count(["close"]) == 1
    print("OpenWrt init: syntax, disabled default, device ID, quoted arguments and cleanup timeout passed; not installed.")


if __name__ == "__main__":
    main()
