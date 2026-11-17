#!/bin/sh
# Keenetic ndm netfilter.d hook: re-add kdnsfilter's rules after ndm rebuilds
# the mangle table. ndm passes $type (iptables/ip6tables) and $table.
# While kdnsfilter is down only the routing rules are restored: the NFQUEUE
# rules need the running filter, the routing sets keep working without it.
# shellcheck disable=SC2154 # set by ndm
[ "$table" = "mangle" ] || exit 0
op=ensure
# ndm's environment doesn't necessarily have /opt/bin in PATH, so don't
# rely on bare pidof; the init script's pidfile is checked instead.
PIDFILE=/opt/var/run/kdnsfilter.pid
pid=$(cat "$PIDFILE" 2>/dev/null) && [ -d "/proc/$pid" ] || op=ensure-routing
/opt/sbin/kdnsfilter -c /opt/etc/kdnsfilter/kdnsfilter.yaml -firewall $op -family "$type"
