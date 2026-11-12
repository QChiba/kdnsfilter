#!/bin/sh
# Copy the binary, init script and ndm hook to a Keenetic router over SSH.
# Does not start the service and never overwrites an existing config.
# usage: scripts/install.sh <ssh-host>
set -e
HOST=${1:?usage: $0 <ssh-host>}
cd "$(dirname "$0")/.."
scp -O bin/kdnsfilter "$HOST":/opt/sbin/kdnsfilter.new
scp -O dist/S80kdnsfilter "$HOST":/opt/etc/init.d/S80kdnsfilter
scp -O dist/50-kdnsfilter.sh "$HOST":/opt/etc/ndm/netfilter.d/50-kdnsfilter.sh
ssh "$HOST" 'chmod +x /opt/sbin/kdnsfilter.new /opt/etc/init.d/S80kdnsfilter /opt/etc/ndm/netfilter.d/50-kdnsfilter.sh &&
	mv /opt/sbin/kdnsfilter.new /opt/sbin/kdnsfilter &&
	mkdir -p /opt/etc/kdnsfilter /opt/var/kdnsfilter &&
	/opt/sbin/kdnsfilter -version'
echo "Installed. Create /opt/etc/kdnsfilter/kdnsfilter.yaml (e.g. with -import-adguard), then: /opt/etc/init.d/S80kdnsfilter start"
