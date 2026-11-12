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
  route; the firewall routes the sets (e.g. TPROXY to a VPN client). Lists
  are edited in the UI and apply at once — removed domains leave the sets,
  added ones are filled from the answers devices got recently (query log).
  See [Routing by domain](#routing-by-domain).
- Fail-open: `--queue-bypass` plus `NfQaCfgFlagFailOpen`; if kdnsfilter isn't
  running, DNS keeps working unfiltered.

Not included on purpose — Keenetic does these natively: upstream servers and
per-domain upstreams (`ip name-server <ip> <domain>`, `dns-proxy tls|https
upstream … domain <d>`), rewrites (`ip host`).

## Measured on Keenetic Ultra KN-1811 (KeeneticOS 5.1.8, 2× Cortex-A53)

With the AdGuard DNS filter (190 258 rules):

| | |
|---|---|
| RSS | 42–55 MB, 48 MB peak at rule rebuild (AdGuard Home: 87 MB) |
| Processing per reply | ~155 µs median |
| UI/API request | 0.5–3 ms CPU, no GC (the GC scans the ~35 MB rule index, so request paths must not allocate much) |
| Added query latency | +0.5–0.65 ms median (A/B on the same client) |
| Safe search rewrite | first lookup 30–50 ms (target resolved, then cached 1–10 min) |

## Build

Needs only Docker:

```sh
scripts/build.sh 0.2.0        # gofmt check, vet, tests, linux/arm64 binary in bin/
```

## Install on the router

```sh
scripts/install.sh router     # binary, init script, ndm netfilter hook; does not start
ssh router
/opt/sbin/kdnsfilter -import-adguard /opt/etc/AdGuardHome/AdGuardHome.yaml   # or start with defaults
vi /opt/etc/kdnsfilter/kdnsfilter.yaml
/opt/etc/init.d/S80kdnsfilter start
```

UI: `http://<router>:8190` (no login; LAN only — Keenetic's firewall keeps
it off the WAN).

Files: config `/opt/etc/kdnsfilter/kdnsfilter.yaml`; lists, services cache,
`stats.json` and `querylog/YYYY-MM-DD.jsonl` under `/opt/var/kdnsfilter/`;
log `/opt/var/log/kdnsfilter.log`.

### Trying it without switching DNS

Set `nfqueue.destinations` to one client (e.g. `[192.168.1.10]`): only replies
to that client are inspected. This also works while AdGuard Home still answers
DNS, since its replies leave the router the same way.

### Switching from AdGuard Home (DNS outage of a few seconds)

1. Move AdGuard's upstreams to Keenetic: default `dns-proxy https|tls upstream …`,
   per-domain ones with `… domain <d>` or `ip name-server <ip> <d>`.
2. Move AdGuard rewrites to `ip host <name> <ip>`.
3. Check `dns-proxy filter assign …` presets — once Keenetic DNS is live they
   send those hosts/segments to the preset's (e.g. Yandex) DNS.
4. `kdnsfilter -import-adguard …`, then on the Clients page bind IP-only
   clients to their devices (AdGuard ids are often stale DHCP addresses).
5. Stop AdGuard Home, `no opkg dns-override`, `system configuration save`,
   start kdnsfilter. Rollback: stop kdnsfilter, `opkg dns-override`, start AdGuard.

## Config

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
  blocked_services: {ids: [], schedule: {time_zone: Europe/Moscow, mon: {start: 9h, end: 21h}}}
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
  lists:
    - name: bypass        # ipsets kdf_bypass4 / kdf_bypass6 unless set4/set6 are given
      chain: MY_PROXY        # PREROUTING jumps here for packets to the sets (empty: route them yourself)
      output_chain: MY_PROXY_OUT   # the same from OUTPUT, for the router's own traffic
      domains: [youtube.com, googlevideo.com, '!music.youtube.com']
hostmap: /var/ndnproxyhostmap.conf
resolver: 127.0.0.1:53    # for safe search targets and routing prefill
data_dir: /opt/var/kdnsfilter
```

The firewall rule (one per family, appended so no other mangle rule is skipped):

```
iptables -t mangle -A POSTROUTING -p udp --sport 53 ! -o lo -j NFQUEUE --queue-num 4242 --queue-bypass
```

ndm rebuilds its tables on many events; `dist/50-kdnsfilter.sh` (installed to
`/opt/etc/ndm/netfilter.d/`) re-adds the rule.

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
- Firewall: with `manage_firewall`, kdnsfilter adds
  `-m set --match-set <set> dst -j <chain>` to mangle PREROUTING (and OUTPUT
  with `output_chain`) for each family. These rules stay when it stops; the
  ndm hook re-adds them after a rebuild even while kdnsfilter is down
  (`-firewall ensure-routing`). The chains themselves (TPROXY, marks, routing
  tables) stay with whatever routes the traffic, e.g. your proxy's hooks.
- Lists are edited on the Routing page (or `PUT /api/routing/lists/<name>
  {"domains": [...]}`) and kept sorted; "Export .txt"
  (`GET /api/routing/lists/<name>/export`) downloads one domain per line for
  backup — paste it back into the editor to restore. Set names and chains are
  set up once in the YAML, not in the UI. (PREROUTING covers the LAN's
  traffic, OUTPUT the router's own; TCP and UDP are both handled by the chain
  they jump to.)

Moving a Keenetic list over (no outage; both sets route meanwhile):

1. Add the list with its chains to the YAML (or create it on the Routing page
   and add the chains), paste the domains of the Keenetic list, enable routing.
2. Compare for a while: the query log marks routed lookups `→ bypass`.
3. `no opkg object-group fqdn domain-list0 enable`, `system configuration
   save`, then `ipset flush` the `_NDM_OGDN_*` sets: a disabled group keeps
   its last entries, which would go on routing. The Keenetic list stays in
   the config; re-enabling it is the rollback.

Lookups kdnsfilter doesn't see aren't routed: DNS over TCP, the router's own
lookups (they don't leave through POSTROUTING) and clients using their own
DoH/DoT.

## Limitations

- DNS over TCP and fragmented UDP replies pass unfiltered (can't be rewritten
  in place); clients with their own DoH/DoT bypass it, as with any DNS filter.
- Blocked names are still resolved upstream once by Keenetic before the reply
  is rewritten.
- `$dnsrewrite` rules and hosts entries with real addresses are not applied
  (only blocking entries are).
- Top lists for finished days keep their top 100 entries, so long-period top
  lists are approximate below that; totals are exact.

## License

GPL-3.0, as required by the AdGuard `urlfilter` library it links.
