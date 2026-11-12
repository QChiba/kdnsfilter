# kdnsfilter

Ad/tracker filtering for Keenetic routers **without replacing the router's DNS**.
KeeneticOS keeps serving DNS on :53 — so its own per-domain upstreams, DoT/DoH,
static hosts and **DNS-based routes** (`object-group fqdn` + `dns-proxy route`)
keep working — while kdnsfilter inspects DNS replies leaving the router via
netfilter NFQUEUE and rewrites the ones it must block.

```
client ─query─► Keenetic DNS (ndnproxy :53) ─► DoT/DoH upstreams
                      │ reply (udp sport 53, mangle POSTROUTING)
                      ▼
       NFQUEUE --queue-bypass ─► kdnsfilter
                      │  allowed   → unchanged
                      │  blocked   → NXDOMAIN / 0.0.0.0 / REFUSED
                      │  safe search → CNAME to the engine's safe host
                      │  routed    → addresses into ipsets, then unchanged
                      ▼
                    client
```

## Features

- AdGuard rule syntax via AdGuard's own `urlfilter` engine: `||host^`, `@@`
  exceptions, hosts-file lists, `$important`, `$client`, `$dnstype`, regexps.
- Filter list subscriptions with periodic updates; custom rules; one-click
  block/unblock from the query log.
- Per-client settings: filtering on/off, safe search, blocked services
  (AdGuard's catalog, with AdGuard's weekly *pause* schedules).
- Clients follow their devices: addresses are mapped to MACs through
  Keenetic's host map (`/var/ndnproxyhostmap.conf`, re-read every 10 s), and a
  client bound by MAC wins over address ids — so DHCP lease changes and IPv6
  privacy addresses don't break per-client rules, and a stale IP id can't
  capture another device. Address/CIDR ids remain as a fallback for hosts the
  router doesn't list (VPN peers). The UI shows each client's current
  addresses and suggests MACs for IP-only clients (same name / similar name /
  currently holds the IP), with one-click and bulk binding.
- Safe search for Google, YouTube, Bing, DuckDuckGo, Yandex, Pixabay, Ecosia
  (same targets as AdGuard Home).
- CNAME cloaking: an allowed name whose CNAME target is blocked is blocked.
- DNS rewrites (as in AdGuard Home): `filtering.rewrites` entries answer a
  name (`example.com`, or `*.example.com` for its subdomains) with an IP
  address, a CNAME (followed through other rewrites, otherwise resolved via
  the router), or `A`/`AAAA` to keep the real records of that type; other
  record types get an empty NOERROR so e.g. HTTPS hints can't leak real
  addresses. They apply to every client, even with protection off. Custom
  rules and lists may also use `$dnsrewrite` (A/AAAA, CNAME, response codes;
  per client with `$client`) and hosts lines with real addresses
  (`192.168.1.5 media.home`). Keenetic's domain lists still see only the upstream
  answer, so don't rewrite names the router routes by.
- Firefox's DoH canary `use-application-dns.net` gets NXDOMAIN for every
  client (as in AdGuard Home), so Firefox keeps using the router's DNS and
  Keenetic domain lists still see its lookups.
- Query log and statistics that survive restarts, kept for a period set in
  Settings (like AdGuard Home): the log in daily JSON-lines files with the
  newest entries in memory, statistics as hourly totals plus per-day top
  domains/clients/services (finished days keep their top 100).
- Web UI (no external assets, CSP `self`) without a login — it is meant for
  the router's LAN only. Requests must address the router by IP, a
  single-label name, a `.local`/`.lan`/`.home` name or `http.allowed_hosts`
  (blocks DNS rebinding), and changes must be JSON (blocks cross-site posts).
- `-import-adguard` turns an `AdGuardHome.yaml` into a config: lists, user
  rules, clients, blocked services, safe search, query log and statistics
  retention.
- Routing by domain: the addresses that listed domains (and their
  subdomains, or CNAME targets) resolve to go into `hash:ip` ipsets *before*
  the reply is released, so a device's first connection already takes the
  route; the sets go to a proxy's TPROXY port (kdnsfilter sets up the
  chains, mark and routing table) or to your own firewall chains. Lists
  are edited in the UI and apply at once — removed domains leave the sets,
  added ones are filled from the answers devices got recently (query log).
  See [Routing by domain](#routing-by-domain).
- Fail-open: `--queue-bypass` plus `NfQaCfgFlagFailOpen`; if kdnsfilter isn't
  running, DNS keeps working unfiltered.

Not included on purpose — Keenetic does these natively: upstream servers and
per-domain upstreams (`ip name-server <ip> <domain>`, `dns-proxy tls|https
upstream … domain <d>`), rewrites (`ip host`).

## Measured on a Keenetic Ultra KN-1811 (KeeneticOS 5.1.8, 2× Cortex-A53)

With the AdGuard DNS filter (190 258 rules):

| | |
|---|---|
| RSS | 42–55 MB, 48 MB peak at rule rebuild (AdGuard Home: 87 MB) |
| Processing per reply | ~155 µs median |
| UI/API request | 0.5–3 ms CPU, no GC (the GC scans the ~35 MB rule index, so request paths must not allocate much) |
| Added query latency | +0.5–0.65 ms median (A/B on the same client) |
| Safe search rewrite | first lookup 30–50 ms (target resolved, then cached 1–10 min) |

## Install

On a Keenetic router with Entware (aarch64, mipsel or mips), as root:

```sh
opkg update && opkg install curl
curl -fsSL https://raw.githubusercontent.com/QChiba/kdnsfilter/main/scripts/install.sh | sh
```

With a transparent proxy on the router (hysteria, sing-box, xray, mihomo, …)
listening with TPROXY, add its port to route the domains of the `bypass` list
through it:

```sh
curl -fsSL https://raw.githubusercontent.com/QChiba/kdnsfilter/main/scripts/install.sh | sh -s -- --tproxy-port 12345
```

Then open `http://<router>:8190` (no login; LAN only — Keenetic's firewall
keeps it off the WAN). The step-by-step guide, with the KeeneticOS components
it needs, proxy examples, updating and removal, is in
**[docs/install.md](docs/install.md)**.

Files: binary `/opt/sbin/kdnsfilter`, init script
`/opt/etc/init.d/S80kdnsfilter`, ndm hook
`/opt/etc/ndm/netfilter.d/50-kdnsfilter.sh`, config
`/opt/etc/kdnsfilter/kdnsfilter.yaml`; lists, services cache, `stats.json`,
`routing.json` and `querylog/YYYY-MM-DD.jsonl` under `/opt/var/kdnsfilter/`;
log `/opt/var/log/kdnsfilter.log`.

### Trying it on one device first

Set `nfqueue.destinations` to one client (e.g. `[192.168.1.10]`): only replies
to that client are inspected. This also works while AdGuard Home still answers
DNS, since its replies leave the router the same way.

### Switching from AdGuard Home (DNS outage of a few seconds)

1. Move AdGuard's upstreams to Keenetic: default `dns-proxy https|tls upstream …`,
   per-domain ones with `… domain <d>` or `ip name-server <ip> <d>`.
2. Move AdGuard rewrites to `ip host <name> <ip>` (or kdnsfilter's DNS rewrites).
3. Check `dns-proxy filter assign …` presets — once Keenetic DNS is live they
   send those hosts/segments to the preset's (e.g. Yandex) DNS.
4. `kdnsfilter -import-adguard /opt/etc/AdGuardHome/AdGuardHome.yaml`, then on
   the Clients page bind IP-only clients to their devices (AdGuard ids are
   often stale DHCP addresses).
5. Stop AdGuard Home, `no opkg dns-override`, `system configuration save`,
   start kdnsfilter. Rollback: stop kdnsfilter, `opkg dns-override`, start AdGuard.

## Config

Created with defaults on the first start; most of it is edited in the UI.

```yaml
http:
  address: 0.0.0.0:8190
  allowed_hosts: [my.keenetic.net]  # extra names the UI answers to (besides IPs, single-label, .local/.lan/.home)
nfqueue:
  queue: 4242
  destinations: []        # empty = all DNS replies leaving the router
  manage_firewall: true   # add rules at start, remove at stop
filtering:
  protection_enabled: true
  blocking_mode: nxdomain # nxdomain | null_ip | refused
  blocked_response_ttl: 10
  safe_search: {enabled: false, google: true, youtube: true, …}
  blocked_services: {ids: [], schedule: {time_zone: Europe/Berlin, mon: {start: 9h, end: 21h}}}
  update_interval: 24h
filters: [{id: 1, name: AdGuard DNS filter, url: https://…/filter_1.txt, enabled: true}]
user_rules: ['||example.com^']
clients: []               # AdGuard Home's persistent client shape
querylog:
  enabled: true
  size: 5000              # newest entries kept in memory
  interval: 7d            # kept on disk; 0 = memory only (accepts 30d, 2160h, …)
statistics:
  interval: 7d            # 1h … 365d; hourly buckets up to 48h, daily beyond
routing:
  enabled: false
  min_timeout: 3h         # an address stays at least this long (or its TTL), refreshed by every answer
  tproxy:                 # for lists with a tproxy_port
    mark: 0x2dd           # fwmark of packets bound for the proxy
    table: 733            # routing table delivering them locally; also the ip rule priority
    router: false         # also proxy the router's own traffic (needs proxy_group or proxy_mark)
    proxy_group: ''       # group the proxy runs as: its packets are never sent back to it
    proxy_mark: 0         # or: the mark the proxy puts on its outgoing sockets
  lists:
    - name: bypass        # ipsets kdf_bypass4 / kdf_bypass6 unless set4/set6 are given
      tproxy_port: 12345  # the proxy's TPROXY port (set on the Routing page)
      domains: [youtube.com, googlevideo.com, '!music.youtube.com']
    - name: custom
      chain: MY_PROXY         # instead of tproxy_port: jump to your own mangle chain from PREROUTING
      output_chain: MY_PROXY_OUT  # … and from OUTPUT, for the router's own traffic
      domains: [example.org]
hostmap: /var/ndnproxyhostmap.conf
resolver: 127.0.0.1:53    # for safe search targets and routing prefill
data_dir: /opt/var/kdnsfilter
domain_info: ''           # optional domain info service, see below
```

The firewall rule (one per family, appended so no other mangle rule is skipped):

```
iptables -t mangle -A POSTROUTING -p udp --sport 53 ! -o lo -j NFQUEUE --queue-num 4242 --queue-bypass
```

ndm rebuilds its tables on many events; `dist/50-kdnsfilter.sh` (installed to
`/opt/etc/ndm/netfilter.d/`) re-adds kdnsfilter's rules. kdnsfilter loads the
kernel modules it needs (`nfnetlink_queue`, `xt_NFQUEUE`, and for TPROXY
`xt_socket`, `xt_TPROXY`) itself.

Command line, for scripts: `-version`, `-import-adguard <AdGuardHome.yaml>`,
`-tproxy-port <port> [-list <name>]` (sets a list's TPROXY port and enables
routing; stop the service first), `-firewall ensure|ensure-routing|remove|remove-all`.

## Routing by domain

Keenetic's own domain lists (`object-group fqdn` + `opkg object-group fqdn
… enable`) make ndm re-resolve every name a client ever looked up and resync
the whole ipset each time; with a few hundred CDN-heavy domains that keeps a
Cortex-A53 core busy, and an address only lands in the set some time after
the client got it. kdnsfilter instead adds the addresses of the reply it is
already holding:

- Matching like Keenetic: a domain covers all its subdomains; `!name`
  excludes a subtree; a reply also counts when one of its CNAME targets is
  listed. A/AAAA records and HTTPS/SVCB address hints are added; blocked,
  private and loopback addresses never are.
- Sets: `hash:ip`, `maxelem 65536`, per-entry timeout = max(TTL,
  `min_timeout`). An answer only costs a netlink call when the address is new
  or past half its lifetime. The sets live in the kernel, so routing goes on
  while kdnsfilter restarts; `data_dir/routing.json` restores them after a
  reboot.
- Lists are edited on the Routing page (or `PUT /api/routing/lists/<name>
  {"domains": [...], "tproxy_port": 12345}`) and kept sorted; "Export .txt"
  (`GET /api/routing/lists/<name>/export`) downloads one domain per line for
  backup — paste it back into the editor to restore.

How the sets are routed, per list:

- **TPROXY port** (`tproxy_port`, on the Routing page): for a proxy running on
  the router that accepts TPROXY connections. kdnsfilter builds everything:

  ```
  PREROUTING -m set --match-set kdf_bypass4 dst -j KDF_TPROXY_<port>
  KDF_TPROXY_<port>:  -m socket --transparent → MARK <mark>  (packets of connections the proxy holds)
                      -m socket → RETURN
                      -p tcp|udp → TPROXY --on-port <port> --on-ip 127.0.0.1 (::1) --tproxy-mark <mark>
  ip rule fwmark <mark> lookup main suppress_prefixlength 0 priority <table-1>
  ip rule fwmark <mark> lookup <table> priority <table>;  ip route local default dev lo table <table>
  ```

  The first ip rule keeps marked packets on the main table's LAN routes:
  KeeneticOS sets `tcp_fwmark_accept`, so the proxy's replies to LAN devices
  carry the mark as well.

  With `tproxy.router: true` also `OUTPUT … -j KDF_TPROXY_OUT_<port>`, which
  marks the router's own packets (except the proxy's, by `proxy_group` /
  `proxy_mark`) so they loop back through PREROUTING. The ip rule's priority
  must come before KeeneticOS's own rules (they start around 1000).
  Several lists may use different ports (proxies).
- **Own chains** (`chain` / `output_chain`, YAML only): kdnsfilter only adds
  `-m set --match-set <set> dst -j <chain>` to PREROUTING / OUTPUT; the
  chains and routing (TPROXY, marks, tables, a VPN interface) are yours.
- **Neither**: the sets are only filled; use them in your own rules.

With `manage_firewall`, these rules stay when kdnsfilter stops (the sets go
on routing), and the ndm hook re-adds them after a rebuild even while it is
down. Changes in the UI apply at once: a changed port replaces the chains,
removing a list's port removes them. `kdnsfilter -firewall remove-all` (or
uninstalling) takes everything out.

Moving a Keenetic list over (no outage; both sets route meanwhile):

1. Create the list on the Routing page, set its TPROXY port (or the chains in
   the YAML), paste the domains of the Keenetic list, enable routing.
2. Compare for a while: the query log marks routed lookups `→ bypass`.
3. `no opkg object-group fqdn domain-list0 enable`, `system configuration
   save`, then `ipset flush` the `_NDM_OGDN_*` sets: a disabled group keeps
   its last entries, which would go on routing. The Keenetic list stays in
   the config; re-enabling it is the rollback.

Lookups kdnsfilter doesn't see aren't routed: DNS over TCP, the router's own
lookups (they don't leave through POSTROUTING) and clients using their own
DoH/DoT.

## Domain info (optional)

Settings → Domain info takes the address of an HTTP service that knows which
company or app a domain belongs to; the query log then shows an "About"
section for each entry. kdnsfilter calls `GET <service>/api/info?host=<name>`
(`&page=0` for blocked names: don't fetch the site) and shows the JSON object
it returns: `domain`, `company` (`{name, …}`), `app`, `app_category`,
`tracker`, `note`, `facts`, and `pending: true` while the service is still
collecting. No such service ships with kdnsfilter; leave the field empty to
turn this off.

## Build

Needs only Docker (or Go with `NATIVE=1`):

```sh
scripts/build.sh 0.6.0            # gofmt check, vet, tests, bin/kdnsfilter-linux-arm64
scripts/build.sh 0.6.0 all        # arm64, mipsle, mips + release archives and SHA256SUMS
scripts/deploy.sh <ssh-host> arm64   # developer deploy over SSH (doesn't restart)
```

Releases are built by GitHub Actions when a `v*` tag is pushed.

## Limitations

- DNS over TCP and fragmented UDP replies pass unfiltered (can't be rewritten
  in place); clients with their own DoH/DoT bypass it, as with any DNS filter.
- Blocked names are still resolved upstream once by Keenetic before the reply
  is rewritten.
- `$dnsrewrite` rules and hosts entries with real addresses are not applied
  (only blocking entries are).
- Top lists for finished days keep their top 100 entries, so long-period top
  lists are approximate below that; totals are exact.
- The MIPS (mipsel / mips) builds are compiled like the aarch64 one but have
  not been tried on a real router yet; reports are welcome.

## License

GPL-3.0, as required by the AdGuard `urlfilter` library it links.
