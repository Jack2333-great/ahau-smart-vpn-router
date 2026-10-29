#!/bin/sh
# Pure standard-library build. No downloads, router access, or configuration changes.
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
go_cmd=${GO_BINARY:-go}
export GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off CGO_ENABLED=0
cd "$root/native"
"$go_cmd" vet ./...
"$go_cmd" test ./...
mkdir -p "$root/dist"
for arch in arm64 amd64; do
    GOOS=linux GOARCH=$arch "$go_cmd" build -trimpath -buildvcs=false -ldflags='-s -w' -o "$root/dist/campusvpn-linux-$arch" ./cmd/campusvpn
    # Some ZIP extractors discard Unix mode bits. Go may reuse an identical
    # existing output without restoring them, so make the result executable.
    chmod 755 "$root/dist/campusvpn-linux-$arch"
done
cd "$root/dist"
sha256sum campusvpn-linux-arm64 campusvpn-linux-amd64 > SHA256SUMS
cat SHA256SUMS
