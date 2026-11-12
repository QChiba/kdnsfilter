#!/bin/sh
# Build and test in Docker (no local Go needed). Output: bin/kdnsfilter (linux/arm64).
# usage: scripts/build.sh [version]
set -e
cd "$(dirname "$0")/.."
VERSION=${1:-$(date +%Y.%m.%d)}
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD":/src -w /src \
	-e GOCACHE=/tmp/gocache -e GOPATH=/tmp/gopath -e HOME=/tmp -e GOFLAGS=-buildvcs=false \
	golang:1.26 sh -c "
		test -z \"\$(gofmt -l .)\" || { gofmt -l .; echo 'run gofmt'; exit 1; }
		go vet ./... && go test ./... &&
		CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath \
			-ldflags='-s -w -X main.version=$VERSION' -o bin/kdnsfilter ./cmd/kdnsfilter"
ls -la bin/kdnsfilter
