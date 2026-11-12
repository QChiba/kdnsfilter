# Installing kdnsfilter on a Keenetic router

kdnsfilter runs on the router itself, next to KeeneticOS's own DNS server: the
router keeps answering DNS, kdnsfilter rewrites the replies it must block and,
if you want, routes listed domains through a proxy. This guide takes you from
a stock router to a working setup.

- [1. What you need](#1-what-you-need)
- [2. KeeneticOS components](#2-keeneticos-components)
- [3. Entware](#3-entware)
- [4. Install kdnsfilter](#4-install-kdnsfilter)
- [5. First steps in the web UI](#5-first-steps-in-the-web-ui)
- [6. Routing domains through a proxy (TPROXY)](#6-routing-domains-through-a-proxy-tproxy)
- [7. Updating](#7-updating)
- [8. Removing](#8-removing)
- [9. Troubleshooting](#9-troubleshooting)

## 1. What you need

- A Keenetic router with KeeneticOS 4 or 5 and an **aarch64** (e.g. Ultra
  KN-1811) or **MIPS** (mipsel / mips) CPU — the installer finds out which. kdnsfilter
  is developed and measured on an Ultra KN-1811 with KeeneticOS 5.1; the MIPS
  builds are compiled the same way but have not been tried on a real router
  yet.
- Storage for Entware: a USB drive, or the internal storage on models that
  offer it.
- RAM: kdnsfilter takes about 50 MB with the AdGuard DNS filter (~190 000
  rules), about half of what AdGuard Home needs. On a 128 MB router keep to
  one or two lists.
- Devices must use the router as their DNS server (the KeeneticOS default).

## 2. KeeneticOS components

In the web interface open **Management → General settings → Component
options** (*Управление → Общие настройки → Изменить набор компонентов*) and
install:

| Component | Why |
|---|---|
| **Open Package support** / OPKG (*Поддержка открытых пакетов*) | runs Entware and its `netfilter.d` hooks |
| **Netfilter subsystem kernel modules** (*Модули ядра подсистемы Netfilter*) | NFQUEUE (DNS filtering), TPROXY and socket matching (routing) |
| **IPv6 protocol** (*Протокол IPv6*) | optional: filtering DNS replies sent over IPv6 |

The router reboots to apply them.

Don't turn on `opkg dns-override`: kdnsfilter needs KeeneticOS to keep serving
DNS. (If you run AdGuard Home with dns-override today, see *Switching from
AdGuard Home* in the [README](../README.md#switching-from-adguard-home-dns-outage-of-a-few-seconds).)

## 3. Entware

Install Entware on the storage as described in Keenetic's help article
*"Installing the Entware repository package system on a USB drive"*. When
it's done, log in to Entware's shell over SSH (the Keenetic Entware image runs
its SSH server on port **222**; the router's own CLI keeps port 22):

```sh
ssh root@192.168.1.1 -p 222      # your router's address
passwd                           # if you haven't changed the default password yet
```

## 4. Install kdnsfilter

In the Entware shell:

```sh
opkg update && opkg install curl
curl -fsSL https://raw.githubusercontent.com/QChiba/kdnsfilter/main/scripts/install.sh | sh
```

The installer:

1. checks for Entware and the kernel modules (it stops with a hint if the
   Netfilter component is missing);
2. installs the Entware packages kdnsfilter uses: `iptables`, `ip-full`,
   `ca-certificates` (and `curl`), only those not already present;
3. downloads the latest release for the router's CPU from GitHub and checks
   its SHA-256;
4. installs `/opt/sbin/kdnsfilter`, the init script
   `/opt/etc/init.d/S80kdnsfilter` (Entware starts it at boot) and the ndm hook
   `/opt/etc/ndm/netfilter.d/50-kdnsfilter.sh`, which restores kdnsfilter's
   firewall rules whenever KeeneticOS rebuilds its firewall;
5. starts the service; the config `/opt/etc/kdnsfilter/kdnsfilter.yaml` is
   created with defaults on the first start.

Options (after `sh -s --`, e.g. `… | sh -s -- --tproxy-port 12345`):

| Option | |
|---|---|
| `--tproxy-port N` | route the `bypass` list through a proxy listening with TPROXY on port N (see [section 6](#6-routing-domains-through-a-proxy-tproxy)) |
| `--version vX.Y.Z` | install that release instead of the latest |
| `--file PATH` | install from a release archive you copied to the router (no download from GitHub) |
| `--no-start` | install only |
| `--uninstall [--purge]` | see [section 8](#8-removing) |

No direct access to GitHub from the router? Download
`kdnsfilter_linux_<arch>.tar.gz` (`arm64`, `mipsle` or `mips`, as the
installer reports) and `scripts/install.sh` on another machine, copy both to
the router (e.g. `scp -O -P 222 … root@192.168.1.1:/opt/tmp/`) and run
`sh /opt/tmp/install.sh --file /opt/tmp/kdnsfilter_linux_arm64.tar.gz`. It
still needs Entware's package feed for the packages above.

## 5. First steps in the web UI

Open `http://192.168.1.1:8190` (your router's address) from a device in the
LAN. There is no login: the UI is reachable only from the LAN, and it refuses
requests that don't address the router by its IP or a local name.

1. **Dashboard** — the counters should start moving within seconds. Open a
   few sites, then the **Query log**: each lookup appears with its client.
2. **Filters** — the AdGuard DNS filter is on by default; add other lists
   (any AdGuard or hosts-format URL) and custom rules (`||example.com^`
   blocks, `@@||example.com^` allows) and DNS rewrites (answer a name with
   your own address).
3. **Clients** — devices appear with the names KeeneticOS knows. Add clients
   for per-device settings (safe search, blocked services with schedules,
   filtering off); bind them by MAC address so DHCP changes don't matter.
4. **Settings** — blocking mode, blocked services for everyone, how long the
   query log and statistics are kept.

To test a block: `nslookup doubleclick.net 192.168.1.1` from a computer in the
LAN answers *Non-existent domain*.

## 6. Routing domains through a proxy (TPROXY)

kdnsfilter can send the traffic of chosen domains (and their subdomains)
through a proxy running on the router, e.g. to reach sites your ISP blocks or
to use a VPN only for some services. It puts the addresses those domains
resolve to into ipsets **before** the device gets the DNS reply, so even the
first connection takes the proxy. Any proxy that accepts TPROXY connections
works; kdnsfilter sets up the iptables chains, the fwmark and the routing
table, so all you choose is the port.

### 6.1 Make the proxy listen with TPROXY

Pick a free port (`12345` below) and add a TPROXY listener for TCP and UDP to
your proxy's config. Listen on all addresses (or on `127.0.0.1` and `::1`).

hysteria 2 (client `config.yaml`):

```yaml
tcpTProxy:
  listen: :12345
udpTProxy:
  listen: :12345
```

sing-box (`inbounds`):

```json
{ "type": "tproxy", "tag": "tproxy-in", "listen": "::", "listen_port": 12345 }
```

xray (`inbounds`):

```json
{
  "tag": "tproxy-in", "port": 12345, "protocol": "dokodemo-door",
  "settings": { "network": "tcp,udp", "followRedirect": true },
  "streamSettings": { "sockopt": { "tproxy": "tproxy" } },
  "sniffing": { "enabled": true, "destOverride": ["http", "tls", "quic"] }
}
```

mihomo / Clash Meta: `tproxy-port: 12345`.

Restart the proxy and check that it listens: `netstat -lnp | grep 12345`
should show TCP and UDP sockets.

### 6.2 Tell kdnsfilter the port

On the **Routing** page: create a list (e.g. `bypass`), enter `12345` as its
**TPROXY port**, paste the domains (one per line; `!sub.example.com` excludes a
subdomain), **Save list**, then tick **Routing enabled** and **Save**.

Or from the shell (the installer does the same with `--tproxy-port`):

```sh
/opt/etc/init.d/S80kdnsfilter stop
/opt/sbin/kdnsfilter -tproxy-port 12345 -list bypass
/opt/etc/init.d/S80kdnsfilter start
```

The changes apply at once. Each list can have its own port, so different
domains can go to different proxies.

### 6.3 Check it

- The query log marks routed lookups with `→ bypass`; the Routing page counts
  the routed addresses.
- From a device in the LAN, a site from the list sees the proxy's address
  (e.g. open an "what is my IP" site you added to the list).
- On the router:

  ```sh
  ipset list kdf_bypass4 | head                  # addresses of listed domains
  iptables -t mangle -S KDF_TPROXY_12345         # the TPROXY chain
  ip rule | grep 733                             # fwmark 0x2dd lookup 733
  ```

### 6.4 The router's own traffic

By default only LAN devices are routed. To route the router's own
connections too (e.g. Entware programs), set in the YAML config:

```yaml
routing:
  tproxy:
    router: true
    proxy_group: proxy     # the group the proxy runs as, or:
    proxy_mark: 0xff       # the mark it puts on its sockets (sing-box routing_mark, xray sockopt.mark)
```

One of them is required: otherwise the proxy's own connections to listed
addresses (e.g. when it sends some traffic directly) would loop back into it.

### 6.5 Routing with your own rules

If you already have chains that route traffic (a VPN, your own TPROXY setup),
leave the TPROXY port empty and set `chain` / `output_chain` for the list in
the YAML: kdnsfilter then only adds `-m set --match-set kdf_<list>4 dst -j
<chain>` to PREROUTING / OUTPUT. With neither, the sets `kdf_<list>4` and
`kdf_<list>6` are only filled and you can use them in any rule.

The mark (`0x2dd`) and table (`733`) can be changed under `routing.tproxy` if
they clash with something else; the table number is also the ip rule's
priority and must stay below KeeneticOS's own rules (they start around 1000).

## 7. Updating

Run the installer again; it keeps the config and data and restarts the
service:

```sh
curl -fsSL https://raw.githubusercontent.com/QChiba/kdnsfilter/main/scripts/install.sh | sh
```

## 8. Removing

```sh
curl -fsSL https://raw.githubusercontent.com/QChiba/kdnsfilter/main/scripts/install.sh | sh -s -- --uninstall
```

This stops kdnsfilter, removes its firewall rules, TPROXY chains, ip rules
and ipsets, the binary, the init script and the hook. The config
(`/opt/etc/kdnsfilter`) and data (`/opt/var/kdnsfilter`) stay; add `--purge`
to remove them too. DNS keeps working throughout: the router never depended on
kdnsfilter to answer.

## 9. Troubleshooting

| Symptom | What to check |
|---|---|
| Nothing in the query log | `/opt/etc/init.d/S80kdnsfilter status`, the log `/opt/var/log/kdnsfilter.log`; `iptables -t mangle -S POSTROUTING \| grep NFQUEUE` shows the rule; the devices use the router as DNS server |
| `kernel module xt_NFQUEUE is missing` | install the *Netfilter subsystem kernel modules* component (section 2) |
| Some devices aren't filtered | they use their own DNS: browser "secure DNS" / DoH (Chrome, Edge), iCloud Private Relay, a hard-coded DNS server; or IPv6 DNS from the ISP — let the router advertise itself |
| A site breaks | find its lookups in the query log and unblock them with one click |
| Routed sites don't open | the proxy listens on the port for both TCP and UDP (`netstat -lnp`); `lsmod \| grep -E 'TPROXY\|socket'`; the log for `firewall:` errors; the Routing page shows an error if the sets couldn't be filled |
| Rules gone after KeeneticOS changes | the hook `/opt/etc/ndm/netfilter.d/50-kdnsfilter.sh` exists and is executable; `kdnsfilter -firewall ensure` re-adds everything by hand |

DNS over TCP and replies too big for one UDP packet are not filtered, and
the router's own lookups are not routed (they don't pass through the rules).
