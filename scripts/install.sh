#!/bin/sh
# kdnsfilter installer for Keenetic routers with Entware. Run it on the
# router as root:
#
#   curl -fsSL https://raw.githubusercontent.com/QChiba/kdnsfilter/main/scripts/install.sh | sh
#   curl -fsSL https://raw.githubusercontent.com/QChiba/kdnsfilter/main/scripts/install.sh | sh -s -- --tproxy-port 12345
#
# It installs the Entware packages kdnsfilter needs, downloads the release
# for the router's CPU, installs the binary, the init script and the ndm
# netfilter.d hook, and starts the service. Running it again updates
# kdnsfilter and keeps the config.
#
# Options:
#   --tproxy-port N  route the "bypass" list to a proxy listening with TPROXY
#                    on port N (the port can also be set later in the UI)
#   --version V      install release V (e.g. v0.6.0) instead of the latest
#   --file PATH      install from a downloaded kdnsfilter_linux_<arch>.tar.gz
#   --no-start       don't start the service
#   --uninstall      stop kdnsfilter, remove its firewall rules and files;
#                    the config and data stay unless --purge is added too
set -e

REPO=${KDNSFILTER_REPO:-QChiba/kdnsfilter}
BIN=/opt/sbin/kdnsfilter
INIT=/opt/etc/init.d/S80kdnsfilter
HOOK=/opt/etc/ndm/netfilter.d/50-kdnsfilter.sh
CONF_DIR=/opt/etc/kdnsfilter
CONF=$CONF_DIR/kdnsfilter.yaml
DATA=/opt/var/kdnsfilter
LOG=/opt/var/log/kdnsfilter.log
export PATH=/opt/sbin:/opt/bin:/opt/usr/sbin:/opt/usr/bin:/usr/sbin:/usr/bin:/sbin:/bin

say() { printf 'kdnsfilter: %s\n' "$*"; }
die() { printf 'kdnsfilter: error: %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

TPROXY_PORT='' VERSION='' FILE='' START=1 UNINSTALL='' PURGE=''
while [ $# -gt 0 ]; do
	case "$1" in
	--tproxy-port) TPROXY_PORT=$2; shift ;;
	--version) VERSION=$2; shift ;;
	--file) FILE=$2; shift ;;
	--no-start) START= ;;
	--uninstall) UNINSTALL=1 ;;
	--purge) PURGE=1 ;;
	-h | --help)
		if [ -f "$0" ]; then sed -n '2,/^set -e/p' "$0" | sed 's/^# \{0,1\}//; /^set -e/d'; else echo "see https://github.com/$REPO#install"; fi
		exit 0 ;;
	*) die "unknown option $1 (see --help)" ;;
	esac
	shift
done

[ -x /opt/bin/opkg ] || die "Entware is not installed: install the OPKG component in KeeneticOS and Entware on a USB drive or the internal storage first"
[ -w /opt ] || die "run me as root"
if [ -n "$TPROXY_PORT" ]; then
	case "$TPROXY_PORT" in *[!0-9]* | '') die "--tproxy-port wants a number" ;; esac
	[ "$TPROXY_PORT" -ge 1 ] && [ "$TPROXY_PORT" -le 65535 ] || die "--tproxy-port wants 1-65535"
fi

stop_service() {
	[ -x "$INIT" ] && "$INIT" stop || true
}

if [ -n "$UNINSTALL" ]; then
	stop_service
	# Routing rules, TPROXY chains and ip rules stay when the service stops
	# (so routing survives restarts); take them out too.
	[ -x "$BIN" ] && [ -f "$CONF" ] && "$BIN" -c "$CONF" -firewall remove-all || true
	if have ipset; then
		for s in $(ipset list -n 2>/dev/null | grep '^kdf_'); do ipset destroy "$s" 2>/dev/null || true; done
	fi
	rm -f "$BIN" "$INIT" "$HOOK"
	if [ -n "$PURGE" ]; then
		rm -rf "$CONF_DIR" "$DATA" "$LOG" "$LOG.1"
		say "removed, including the config and data"
	else
		say "removed; the config ($CONF_DIR) and data ($DATA) are kept, --purge removes them"
	fi
	exit 0
fi

# --- CPU architecture: Entware's own (aarch64-3.10, mipselsf-k3.4, mipssf-k3.4) ---
ENTWARE_ARCH=$(opkg print-architecture 2>/dev/null | awk '$2 != "all" && $2 !~ /_kn$/ { a = $2 } END { print a }')
case "$ENTWARE_ARCH" in
aarch64*) ARCH=arm64 ;;
mipsel*) ARCH=mipsle ;;
mips*) ARCH=mips ;;
*)
	case "$(uname -m)" in
	aarch64) ARCH=arm64 ;;
	*) die "unsupported CPU: Entware arch '$ENTWARE_ARCH', uname -m '$(uname -m)'; kdnsfilter is built for aarch64, mipsel and mips" ;;
	esac
	;;
esac
say "router CPU: $ARCH (Entware $ENTWARE_ARCH)"

# --- Entware packages: iptables/ip6tables and ip for the firewall rules,
# CA certificates for downloading filter lists, curl for this script ---
PKGS=
have iptables || PKGS="$PKGS iptables"
[ -x /opt/sbin/ip ] || have ip || PKGS="$PKGS ip-full"
have insmod || PKGS="$PKGS busybox"
[ -f /opt/etc/ssl/certs/ca-certificates.crt ] || PKGS="$PKGS ca-certificates"
[ -n "$FILE" ] || have curl || PKGS="$PKGS curl"
if [ -n "$PKGS" ]; then
	say "installing Entware packages:$PKGS"
	opkg update >/dev/null || die "opkg update failed"
	# shellcheck disable=SC2086
	opkg install $PKGS || die "opkg install$PKGS failed"
fi
have iptables || die "iptables is missing (opkg install iptables)"
# Most Entware builds ship ip6tables in the iptables package.
if ! have ip6tables; then
	opkg install ip6tables >/dev/null 2>&1 || true
	have ip6tables || say "warning: ip6tables is missing, IPv6 DNS replies won't be filtered"
fi

# --- kernel modules: KeeneticOS ships them as the "Netfilter subsystem
# kernel modules" component and loads them on demand ---
MODDIR=/lib/modules/$(uname -r)
for m in xt_NFQUEUE nfnetlink_queue; do
	grep -q "^$m " /proc/modules || [ -f "$MODDIR/$m.ko" ] ||
		die "kernel module $m is missing: add the \"Netfilter subsystem kernel modules\" component in KeeneticOS (General settings → Component options) and reboot"
done
if [ -n "$TPROXY_PORT" ]; then
	for m in xt_TPROXY xt_socket; do
		grep -q "^$m " /proc/modules || [ -f "$MODDIR/$m.ko" ] ||
			say "warning: kernel module $m is missing, TPROXY routing will not work"
	done
fi

# --- download ---
TMP=/opt/tmp/kdnsfilter-install.$$
rm -rf "$TMP" && mkdir -p "$TMP"
trap 'rm -rf "$TMP"' EXIT
ASSET=kdnsfilter_linux_$ARCH.tar.gz
if [ -n "$FILE" ]; then
	cp "$FILE" "$TMP/$ASSET"
else
	if [ -n "$VERSION" ]; then
		URL=https://github.com/$REPO/releases/download/$VERSION
	else
		URL=https://github.com/$REPO/releases/latest/download
	fi
	say "downloading $URL/$ASSET"
	curl -fL --retry 3 --connect-timeout 20 -o "$TMP/$ASSET" "$URL/$ASSET" || die "download failed"
	if curl -fsL --retry 3 --connect-timeout 20 -o "$TMP/SHA256SUMS" "$URL/SHA256SUMS" && have sha256sum; then
		(cd "$TMP" && grep " $ASSET\$" SHA256SUMS | sha256sum -c - >/dev/null 2>&1) || die "checksum mismatch for $ASSET"
		say "checksum ok"
	else
		say "warning: checksum not verified"
	fi
fi
mkdir "$TMP/pkg"
tar -xzf "$TMP/$ASSET" -C "$TMP/pkg" || die "can't unpack $ASSET"
[ -f "$TMP/pkg/kdnsfilter" ] || die "$ASSET has no kdnsfilter binary"
chmod +x "$TMP/pkg/kdnsfilter"
NEW_VERSION=$("$TMP/pkg/kdnsfilter" -version) || die "the downloaded binary doesn't run on this router"

# --- install ---
OLD_VERSION=
[ -x "$BIN" ] && OLD_VERSION=$("$BIN" -version 2>/dev/null || true)
stop_service
mkdir -p /opt/sbin /opt/etc/init.d /opt/etc/ndm/netfilter.d "$CONF_DIR" "$DATA" /opt/var/log /opt/var/run
cp "$TMP/pkg/kdnsfilter" "$BIN.new" && mv "$BIN.new" "$BIN"
cp "$TMP/pkg/S80kdnsfilter" "$INIT"
cp "$TMP/pkg/50-kdnsfilter.sh" "$HOOK"
chmod +x "$BIN" "$INIT" "$HOOK"
if [ -n "$OLD_VERSION" ]; then
	say "updated $OLD_VERSION → $NEW_VERSION"
else
	say "installed $NEW_VERSION"
fi

# The config is created with defaults on the first start; -tproxy-port
# creates it now if needed and only changes the routing list.
if [ -n "$TPROXY_PORT" ]; then
	"$BIN" -c "$CONF" -tproxy-port "$TPROXY_PORT" -list bypass
fi

if [ -n "$START" ]; then
	"$INIT" start
fi

LAN_IP=$(ip -4 addr show br0 2>/dev/null | awk '/inet /{ sub(/\/.*/, "", $2); print $2; exit }')
cat <<EOT

Web UI:  http://${LAN_IP:-<router address>}:8190  (no login, LAN only)
Config:  $CONF
Log:     $LOG

Next: pick filter lists on the Filters page. To route domains through a
proxy, add them to a list on the Routing page and set its TPROXY port there
(or run this script again with --tproxy-port N).
EOT
