"""Build and inspect an offline opkg archive; never installs anything."""
from pathlib import Path
import gzip
import hashlib
import io
import re
import tarfile

ROOT = Path(__file__).resolve().parent


def tar_gz(files):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, data, mode in files:
            item = tarfile.TarInfo(name)
            item.size, item.mode, item.mtime = len(data), mode, 0
            item.uid = item.gid = 0
            item.uname = item.gname = "root"
            archive.addfile(item, io.BytesIO(data))
    return gzip.compress(stream.getvalue(), mtime=0)


def ar_member(name, data):
    header = f"{name + '/':<16}{0:<12}{0:<6}{0:<6}{'100644':<8}{len(data):<10}`\n"
    if len(header) != 60:
        raise RuntimeError("invalid ar header")
    return header.encode("ascii") + data + (b"\n" if len(data) % 2 else b"")


def main():
    version = re.search(r'const version = "([0-9.]+-research)"',
                        (ROOT / "native/cmd/campusvpn/main.go").read_text(encoding="utf-8")).group(1)
    binary = (ROOT / "dist/campusvpn-linux-arm64").read_bytes()
    if version.encode("ascii") not in binary:
        raise RuntimeError("binary does not contain the expected release version; rebuild first")
    digest = hashlib.sha256(binary).hexdigest()
    if f"{digest}  campusvpn-linux-arm64" not in (ROOT / "dist/SHA256SUMS").read_text():
        raise RuntimeError("binary checksum mismatch")
    if binary[:5] != b"\x7fELF\x02" or int.from_bytes(binary[18:20], "little") != 183:
        raise RuntimeError("binary is not AArch64 ELF64")
    control = (f"Package: campusvpn-research\nVersion: {version}-1\n"
               "Architecture: aarch64_cortex-a53\n"
               "Maintainer: Local campusvpn research\nSection: net\nPriority: optional\n"
               "Depends: ca-bundle, ip, kmod-tun, nftables-json\n"
               "Description: Native Enlink compatibility research client.\n"
               " Disabled by default. Credentials are entered interactively.\n").encode("utf-8")
    controls = [("./control", control, 0o644),
                ("./conffiles", b"/etc/config/campusvpn\n", 0o644)]
    payload = [("./usr/sbin/campusvpn", binary, 0o755),
               ("./etc/init.d/campusvpn", (ROOT / "openwrt/campusvpn.init").read_bytes(), 0o755),
               ("./etc/config/campusvpn", (ROOT / "openwrt/campusvpn.config").read_bytes(), 0o600),
               ("./usr/libexec/rpcd/luci.campusvpn", (ROOT / "openwrt/luci/rpcd").read_bytes(), 0o755),
               ("./usr/share/luci/menu.d/luci-app-campusvpn.json", (ROOT / "openwrt/luci/menu.json").read_bytes(), 0o644),
               ("./usr/share/rpcd/acl.d/luci-app-campusvpn.json", (ROOT / "openwrt/luci/acl.json").read_bytes(), 0o644),
               ("./www/luci-static/resources/view/campusvpn-ui-v2.js", (ROOT / "openwrt/luci/status.js").read_bytes(), 0o644)]
    parts = [("debian-binary", b"2.0\n"), ("control.tar.gz", tar_gz(controls)),
             ("data.tar.gz", tar_gz(payload))]
    archive = tar_gz([(f"./{name}", data, 0o644) for name, data in parts])
    # Validate the outer OpenWrt tar archive and each nested tar entry by exact whitelist,
    # content, type, uid/gid, and permissions without extracting or executing.
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as outer:
        if outer.getnames() != [f"./{name}" for name, _ in parts]:
            raise RuntimeError("outer archive member mismatch")
        for name, expected in parts:
            item = outer.getmember(f"./{name}")
            if not item.isfile() or outer.extractfile(item).read() != expected:
                raise RuntimeError("outer archive content mismatch")
    for (_, data), entries in zip(parts[1:], (controls, payload)):
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as check:
            if check.getnames() != [name for name, _, _ in entries]:
                raise RuntimeError("unexpected tar member")
            for name, content, mode in entries:
                item = check.getmember(name)
                if not item.isfile() or item.uid or item.gid or item.mode != mode or check.extractfile(item).read() != content:
                    raise RuntimeError("tar validation failed")
    destination = ROOT / "releases" / f"campusvpn-research_{version}-1_aarch64_cortex-a53.ipk"
    destination.parent.mkdir(exist_ok=True)
    destination.write_bytes(archive)
    digest = hashlib.sha256(archive).hexdigest()
    destination.with_suffix(".ipk.sha256").write_text(f"{digest}  {destination.name}\n", encoding="ascii")
    print(f"{destination}\nSHA-256: {digest}\nArchive validated; not installed or started.")


if __name__ == "__main__":
    main()
