#!/bin/sh
# Keenetic ndm netfilter.d hook: re-add kdnsfilter's rules after ndm rebuilds
# the mangle table. ndm passes $type (iptables/ip6tables) and $table.
# While kdnsfilter is down only the routing rules are restored: the NFQUEUE
# rules need the running filter, the routing sets keep working without it.
[ "$table" = "mangle" ] || exit 0
op=ensure
pidof kdnsfilter >/dev/null 2>&1 || op=ensure-routing
/opt/sbin/kdnsfilter -c /opt/etc/kdnsfilter/kdnsfilter.yaml -firewall $op -family "$type"
