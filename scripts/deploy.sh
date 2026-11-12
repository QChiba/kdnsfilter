#!/bin/sh
# Developer deploy: copy a locally built binary, init script and ndm hook to
# a router over SSH (see scripts/build.sh). Does not start the service and
# never touches the config. Users install with scripts/install.sh instead.
# usage: scripts/deploy.sh <ssh-host> [arch]   (arch: arm64, mipsle, mips)
set -e
HOST=${1:?usage: $0 <ssh-host> [arch]}
ARCH=${2:-arm64}
cd "$(dirname "$0")/.."
scp -O "bin/kdnsfilter-linux-$ARCH" "$HOST":/opt/sbin/kdnsfilter.new
scp -O dist/S80kdnsfilter "$HOST":/opt/etc/init.d/S80kdnsfilter
scp -O dist/50-kdnsfilter.sh "$HOST":/opt/etc/ndm/netfilter.d/50-kdnsfilter.sh
ssh "$HOST" 'chmod +x /opt/sbin/kdnsfilter.new /opt/etc/init.d/S80kdnsfilter /opt/etc/ndm/netfilter.d/50-kdnsfilter.sh &&
	mv /opt/sbin/kdnsfilter.new /opt/sbin/kdnsfilter &&
	mkdir -p /opt/etc/kdnsfilter /opt/var/kdnsfilter &&
	/opt/sbin/kdnsfilter -version'
echo "Deployed. Restart with: ssh $HOST /opt/etc/init.d/S80kdnsfilter restart"
