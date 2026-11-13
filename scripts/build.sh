#!/bin/sh
# Test and build. Runs in Docker (golang image, no local Go needed) unless
# NATIVE=1 is set (CI).
# usage: scripts/build.sh [version] [arch...]
#   arch: arm64 (default), mipsle, mips, or "all"
# Output: bin/kdnsfilter-linux-<arch>; with "all" also the release archives
# bin/kdnsfilter_linux_<arch>.tar.gz (binary, init script, ndm hook) and
# bin/SHA256SUMS.
set -e
cd "$(dirname "$0")/.."
VERSION=${1:-$(date +%Y.%m.%d)}
[ $# -gt 0 ] && shift
ARCHS=${*:-arm64}

if [ "${NATIVE:-}" != 1 ]; then
	# shellcheck disable=SC2086
	exec docker run --rm --user "$(id -u):$(id -g)" -v "$PWD":/src -w /src \
		-e GOCACHE=/tmp/gocache -e GOPATH=/tmp/gopath -e HOME=/tmp -e NATIVE=1 \
		golang:1.26 sh scripts/build.sh "$VERSION" $ARCHS
fi

PACKAGE=
[ "$ARCHS" = all ] && ARCHS="arm64 mipsle mips" PACKAGE=1
export GOFLAGS=-buildvcs=false
test -z "$(gofmt -l .)" || { gofmt -l .; echo "run gofmt"; exit 1; }
go vet ./...
go test ./...
for arch in $ARCHS; do
	# Keenetic's MIPS SoCs have no FPU.
	CGO_ENABLED=0 GOOS=linux GOARCH=$arch GOMIPS=softfloat go build -trimpath \
		-ldflags="-s -w -X main.version=$VERSION" -o "bin/kdnsfilter-linux-$arch" ./cmd/kdnsfilter
done
if [ -n "$PACKAGE" ]; then
	cd bin
	for arch in $ARCHS; do
		rm -rf pkg && mkdir pkg
		cp "kdnsfilter-linux-$arch" pkg/kdnsfilter
		cp ../dist/S80kdnsfilter ../dist/50-kdnsfilter.sh pkg/
		echo "$VERSION" > pkg/VERSION
		# Deterministic bytes: gzip -n drops the timestamp, tar sorts and
		# zeroes metadata, so a rebuilt release hashes identically.
		tar --sort=name --mtime='@0' --owner=0 --group=0 -cf - -C pkg . | gzip -n > "kdnsfilter_linux_$arch.tar.gz"
	done
	rm -rf pkg
	sha256sum kdnsfilter_linux_*.tar.gz > SHA256SUMS
	cd ..
fi
ls -la bin/
