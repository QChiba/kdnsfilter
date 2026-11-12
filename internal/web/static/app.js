'use strict';

// ---------- helpers ----------

// el builds DOM nodes; children that are strings become text nodes, so data
// is never interpreted as HTML.
function el(tag, attrs, ...children) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k.startsWith('on')) n.addEventListener(k.slice(2), v);
    else if (k === 'class') n.className = v;
    else if (k === 'value') n.value = v;
    else if (k === 'checked') n.checked = !!v;
    else n.setAttribute(k, v === true ? '' : v);
  }
  for (const c of children.flat(Infinity)) {
    if (c === undefined || c === null || c === false) continue;
    n.append(c instanceof Node ? c : String(c));
  }
  return n;
}

// render replaces a container's content, skipping empty (null/false) parts.
function render(container, ...nodes) {
  container.replaceChildren(...nodes.flat(Infinity).filter(n => n !== null && n !== undefined && n !== false));
}

async function api(method, path, body) {
  const opts = { method, headers: {} };
  if (body !== undefined) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  const r = await fetch(path, opts);
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || r.statusText);
  return data;
}

function toast(msg, isErr) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.className = 'toast' + (isErr ? ' err' : '');
  t.hidden = false;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => { t.hidden = true; }, isErr ? 6000 : 2500);
}

// run wraps an async action with error reporting.
async function run(fn, okMsg) {
  try { await fn(); if (okMsg) toast(okMsg); } catch (e) { toast(e.message, true); }
}

// pref/setPref keep per-browser UI choices; storage may be unavailable.
function pref(key, def) {
  try {
    const v = localStorage.getItem('kdnsfilter.' + key);
    return v === null ? def : JSON.parse(v);
  } catch { return def; }
}
function setPref(key, v) {
  try { localStorage.setItem('kdnsfilter.' + key, JSON.stringify(v)); } catch { /* not remembered */ }
}

const fmtNum = n => (n || 0).toLocaleString();
const pct = (a, b) => b ? (100 * a / b).toFixed(1) + '%' : '—';
function fmtTime(s) {
  const d = new Date(s);
  return isNaN(d) || d.getFullYear() < 2000 ? '—' : d.toLocaleString();
}
function fmtAgo(s) {
  const sec = (Date.now() - new Date(s)) / 1000;
  if (!(sec >= 0)) return '—';
  if (sec < 90) return Math.round(sec) + ' s';
  if (sec < 5400) return Math.round(sec / 60) + ' min';
  if (sec < 172800) return Math.round(sec / 3600) + ' h';
  return Math.round(sec / 86400) + ' d';
}
// listNames maps filter list ids to names for display; filled by views that show reasons.
let listNames = {};
async function loadListNames() {
  const d = await api('GET', '/api/filters');
  listNames = Object.fromEntries(d.filters.map(f => [f.id, f.name]));
}
const reasonText = e => ({
  filter: e.list_id ? (listNames[e.list_id] || 'filter list #' + e.list_id) : 'user rule',
  allowlist: 'allowlisted',
  service: 'service: ' + e.service,
  safe_search: 'safe search',
  doh_canary: 'Firefox DoH canary',
  rewrite: 'DNS rewrite',
  dnsrewrite: 'rewrite rule' + (e.list_id ? ' in ' + (listNames[e.list_id] || 'filter list #' + e.list_id) : ''),
}[e.reason] || e.reason || '');

// rewriteText describes a rewrite's answer (from /api/check).
const RCODES = { 2: 'SERVFAIL', 3: 'NXDOMAIN', 5: 'REFUSED' };
function rewriteText(rw) {
  if (rw.rcode) return RCODES[rw.rcode] || 'response code ' + rw.rcode;
  const parts = [...(rw.cnames || []), ...(rw.addrs || [])];
  if (rw.resolve) parts.push(`addresses of ${rw.resolve}`);
  return parts.length ? parts.join(' → ') : 'no records';
}

// rewriteKind says what a rewrite answer is.
function rewriteKind(answer) {
  if (answer === 'A' || answer === 'AAAA') return `keeps the real ${answer} records`;
  if (/^\d+\.\d+\.\d+\.\d+$/.test(answer)) return 'IPv4 address';
  if (answer.includes(':')) return 'IPv6 address';
  return 'domain name (CNAME)';
}

// focusRewrite is a rewrite domain for the Filters view to show when it opens.
let focusRewrite = null;

// ---------- details popover ----------

// One shared popover: hover shows it (on devices with a mouse), click or
// Enter pins it until Escape or a click elsewhere.
const pop = { box: null, anchor: null, pinned: false, timer: 0 };

function popBox() {
  if (pop.box) return pop.box;
  pop.box = el('div', { class: 'popover', role: 'dialog', hidden: true,
    onmouseenter: () => clearTimeout(pop.timer),
    onmouseleave: () => { if (!pop.pinned) hideDetailsSoon(); } });
  document.body.append(pop.box);
  document.addEventListener('click', ev => {
    if (pop.anchor && !pop.box.contains(ev.target) && !pop.anchor.contains(ev.target)) hideDetails();
  });
  document.addEventListener('keydown', ev => { if (ev.key === 'Escape') hideDetails(); });
  window.addEventListener('scroll', ev => {
    if (pop.box.contains(ev.target)) return; // scrolling a tall popover
    if (pop.pinned) placeDetails(); else hideDetails();
  }, true);
  window.addEventListener('resize', placeDetails);
  window.addEventListener('hashchange', hideDetails);
  return pop.box;
}

function showDetails(anchor, build, pin) {
  const box = popBox();
  clearTimeout(pop.timer);
  if (pop.anchor !== anchor) {
    pop.anchor?.setAttribute('aria-expanded', 'false');
    pop.anchor = anchor;
    pop.pinned = false;
    render(box, build());
  }
  if (pin) pop.pinned = true;
  anchor.setAttribute('aria-expanded', 'true');
  box.hidden = false;
  placeDetails();
}

function hideDetails() {
  clearTimeout(pop.timer);
  if (!pop.anchor) return;
  pop.anchor.setAttribute('aria-expanded', 'false');
  pop.box.hidden = true;
  pop.anchor = null;
  pop.pinned = false;
}

function hideDetailsSoon() {
  clearTimeout(pop.timer);
  pop.timer = setTimeout(hideDetails, 200);
}

// placeDetails puts the popover under its anchor, or above it when there is
// no room below, and keeps it inside the window.
function placeDetails() {
  const box = pop.box, a = pop.anchor;
  if (!a) return;
  if (!a.isConnected) return hideDetails();
  // Measure at the origin, where the width isn't squeezed by the window edge.
  box.style.top = box.style.left = '0px';
  const r = a.getBoundingClientRect(), m = 8, w = box.offsetWidth, h = box.offsetHeight;
  const vw = document.documentElement.clientWidth, vh = document.documentElement.clientHeight;
  let top = r.bottom + 6;
  if (top + h > vh - m) top = r.top - 6 - h >= m ? r.top - 6 - h : Math.max(m, vh - m - h);
  const left = Math.max(m, Math.min(r.left, vw - m - w));
  box.style.top = top + 'px';
  box.style.left = left + 'px';
}

const canHover = matchMedia('(hover: hover)');

function bindDetails(anchor, build) {
  anchor.addEventListener('mouseenter', () => {
    if (!canHover.matches || pop.pinned) return;
    clearTimeout(pop.timer);
    pop.timer = setTimeout(() => showDetails(anchor, build), 150);
  });
  anchor.addEventListener('mouseleave', () => { if (!pop.pinned) hideDetailsSoon(); });
  anchor.addEventListener('click', () => {
    if (pop.anchor === anchor && pop.pinned) hideDetails(); else showDetails(anchor, build, true);
  });
  anchor.addEventListener('keydown', ev => {
    if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); anchor.click(); }
  });
}

// focusRule is a custom rule for the Filters view to select when it opens.
let focusRule = null;

// explain describes why a group of query log entries (one client, domain
// and result; newest first) got its result.
function explain(entries) {
  const e = entries[0];
  const listed = e.reason === 'filter' || e.reason === 'allowlist' || e.reason === 'dnsrewrite';
  const custom = listed && !e.list_id;
  const list = listNames[e.list_id] || 'filter list #' + e.list_id;
  const title = {
    filter: custom ? 'Blocked by a custom rule' : 'Blocked by ' + list,
    allowlist: custom ? 'Allowed by a custom allow rule' : 'Allowed by an allow rule in ' + list,
    service: 'Blocked service: ' + e.service,
    safe_search: 'Rewritten to the safe search address',
    doh_canary: 'Blocked for every client, so Firefox keeps using the router\'s DNS instead of its built-in DoH',
    rewrite: 'Rewritten by a DNS rewrite',
    dnsrewrite: custom ? 'Rewritten by a custom rule' : 'Rewritten by a rule in ' + list,
    rewrite_error: 'Allowed: the rewrite target could not be resolved, so the original answer was sent',
    safe_search_error: 'Allowed: the safe search address could not be resolved, so the original answer was sent',
    pack_error: 'Allowed: the block reply could not be built, so the original answer was sent',
  }[e.reason] || (e.action === 'pass' ? 'Allowed: no rule matched' : e.reason);
  const item = (k, ...v) => [el('dt', {}, k), el('dd', {}, ...v)];
  const about = el('div', { class: 'about' }, el('p', { class: 'small' }, 'Looking up ', e.host, '…'));
  loadAbout(about, e);
  const from = fmtTime(entries[entries.length - 1].time), to = fmtTime(e.time);
  const when = from === to ? to : `${from} – ${new Date(e.time).toLocaleTimeString()}`;
  const addrs = clientAddrs(entries);
  const ms = us => (us / 1000).toFixed(us < 10000 ? 2 : 0);
  const took = entries.map(x => x.elapsed_us || 0), lo = Math.min(...took), hi = Math.max(...took);
  return [
    el('h4', {}, title),
    e.cname ? el('p', {}, `${e.host} points (CNAME) to ${e.cname}, and the rule matched ${e.cname}.`) : null,
    el('dl', {},
      item('Time', when),
      e.rule ? item('Rule', el('code', {}, e.rule)) : null,
      listed ? item('Source', custom ? 'Custom rules' : list) : null,
      e.reason === 'service' ? item('Source', 'Blocked services') : null,
      e.reason === 'rewrite' ? item('Source', 'DNS rewrites') : null,
      e.route ? item('Routed', `list ${e.route}: the answer's addresses were added to its sets before the reply was sent`,
        e.route_entry ? el('div', { class: 'small' }, e.route_via
          ? `Matched through the CNAME ${e.route_via}, which is covered by the list entry ${e.route_entry}. Add !${e.host} to the list to keep this domain out.`
          : `Matched by the list entry ${e.route_entry}.`) : null) : null,
      hi ? item('Filter time', lo === hi ? ms(hi) + ' ms' : `${ms(lo)}–${ms(hi)} ms`) : null),
    el('table', { class: 'queries' },
      el('thead', {}, el('tr', {}, el('th', {}, 'Type'), addrs.length > 1 ? el('th', {}, 'From') : null,
        el('th', {}, 'Response'), el('th', {}, 'Answers'))),
      el('tbody', {}, [...entries].reverse().map(x => el('tr', {},
        el('td', {}, x.qtype), addrs.length > 1 ? el('td', {}, x.client_ip) : null, el('td', {}, x.rcode || '—'),
        el('td', {}, x.answers && x.answers.length ? x.answers.map(a => el('div', {}, a)) : '—'))))),
    about,
    custom && e.rule ? el('div', { class: 'actions' },
      el('button', { class: 'small', onclick: () => { focusRule = e.rule; hideDetails(); location.hash = '#filters'; } }, 'Show in custom rules')) : null,
    e.reason === 'rewrite' && e.rule ? el('div', { class: 'actions' },
      el('button', { class: 'small', onclick: () => { focusRewrite = e.rule.split(' →')[0]; hideDetails(); location.hash = '#filters'; } }, 'Show in DNS rewrites')) : null,
  ];
}

// Queries from one client (a named device counts once across its IPv4 and
// IPv6 addresses) for one domain with the same result that arrive within
// GROUP_WINDOW_MS of the group's newest query share a row: a browser asks
// for A, AAAA and HTTPS at once.
const GROUP_WINDOW_MS = 5000;

// groupEntries groups newest-first entries; each group is newest first.
function groupEntries(entries) {
  const groups = [], open = new Map();
  for (const e of entries) {
    const k = [e.client_name || e.client_ip, e.host, e.action, e.reason, e.rule, e.cname].join('\n');
    const g = open.get(k);
    if (g && Date.parse(g[0].time) - Date.parse(e.time) <= GROUP_WINDOW_MS) {
      g.push(e);
      continue;
    }
    const ng = [e];
    open.set(k, ng);
    groups.push(ng);
  }
  return groups;
}

// clientAddrs lists a group's distinct client addresses.
const clientAddrs = entries => [...new Set(entries.map(x => x.client_ip))];

// typeCounts lists a group's query types (A, AAAA, HTTPS first) with counts.
const TYPE_ORDER = ['A', 'AAAA', 'HTTPS'];
function typeCounts(entries) {
  const n = new Map();
  for (const x of entries) n.set(x.qtype, (n.get(x.qtype) || 0) + 1);
  const rank = t => TYPE_ORDER.includes(t) ? TYPE_ORDER.indexOf(t) : TYPE_ORDER.length;
  return [...n].sort(([a], [b]) => rank(a) - rank(b) || a.localeCompare(b));
}

// ---------- domain info (popover "About" section) ----------

// aboutCache keeps finished answers for the session; pending ones are asked again.
const aboutCache = new Map();

// loadAbout fills a popover's "About" box from the domain info service.
async function loadAbout(box, e) {
  let info = aboutCache.get(e.host);
  if (!info) {
    try {
      info = await api('GET', '/api/domaininfo?' + new URLSearchParams({ host: e.host, page: e.action === 'block' ? '0' : '1' }));
    } catch (err) {
      render(box, el('p', { class: 'small' }, "Couldn't reach the domain info service."));
      return placeDetails();
    }
    if (!info.enabled) {
      box.remove();
      return placeDetails();
    }
    if (!info.pending) aboutCache.set(e.host, info);
  }
  render(box, aboutView(info));
  placeDetails();
  if (info.pending && !box.dataset.retried) {
    box.dataset.retried = '1';
    setTimeout(() => { if (box.isConnected) loadAbout(box, e); }, 4000);
  }
}

function aboutView(info) {
  const c = info.company, f = info.facts || {};
  const item = (k, ...v) => [el('dt', {}, k), el('dd', {}, ...v)];
  const rows = [
    c ? item('Company', c.name, c.country ? ` · ${c.country}` : '',
      c.industry ? el('div', { class: 'small' }, c.industry) : null,
      c.description ? el('div', { class: 'small' }, c.description) : null) : null,
    info.app ? item('App', info.app, info.app_category ? ` · ${info.app_category}` : '') : null,
    info.tracker ? item('Tracker', el('span', { class: 'badge block' }, info.tracker)) : null,
    info.note ? item('Your note', info.note) : null,
    // Collected facts matter most when no company is known.
    !c && (f.site_name || f.title) ? item('Website', f.site_name || f.title,
      f.description ? el('div', { class: 'small' }, f.description) : null) : null,
    !c && f.network ? item('Network', f.network) : null,
    !c && f.ns && f.ns.length ? item('Name servers', f.ns.join(', ')) : null,
  ].filter(Boolean);
  return [
    el('h5', {}, 'About ', info.domain || info.host),
    rows.length ? el('dl', {}, rows) : el('p', { class: 'small' }, info.pending ? 'Collecting details…' : 'Nothing known yet.'),
    info.pending && rows.length ? el('p', { class: 'small' }, 'Collecting more details…') : null,
    el('a', { href: info.editor, target: '_blank', rel: 'noopener', class: 'small' }, 'Edit in domain info ↗'),
  ];
}

// selectRule scrolls the rules editor to a rule and selects it.
function selectRule(ta, rule) {
  const lines = ta.value.split('\n');
  const n = lines.findIndex(l => l.trim() === rule.trim());
  if (n < 0) return;
  const start = lines.slice(0, n).reduce((s, l) => s + l.length + 1, 0);
  ta.scrollIntoView({ block: 'center' });
  ta.focus({ preventScroll: true });
  ta.setSelectionRange(start, start + lines[n].length);
  ta.scrollTop = n * (parseFloat(getComputedStyle(ta).lineHeight) || 18) - ta.clientHeight / 3;
}

// Go durations ("9h30m0s") <-> "09:30".
function durToTime(d) {
  if (!d) return '';
  const h = +(/(\d+)h/.exec(d) || [0, 0])[1], m = +(/(\d+)m(?!s)/.exec(d) || [0, 0])[1];
  if (h >= 24) return '23:59';
  return String(h).padStart(2, '0') + ':' + String(m).padStart(2, '0');
}
function timeToDur(t) {
  const [h, m] = t.split(':').map(Number);
  if (h === 23 && m === 59) return '24h';
  return h + 'h' + m + 'm';
}

// ---------- shell ----------

const views = { dashboard, log: queryLog, filters, routing, clients, settings };
let current = null;
let refreshTimer = null;

function route() {
  const name = (location.hash || '#dashboard').slice(1);
  const view = views[name] ? name : 'dashboard';
  document.querySelectorAll('#nav a').forEach(a => a.classList.toggle('active', a.hash === '#' + view));
  clearInterval(refreshTimer);
  current = view;
  const main = document.getElementById('view');
  render(main, el('p', { class: 'muted' }, 'Loading…'));
  run(() => views[view](main));
}

async function loadStatus() {
  const s = await api('GET', '/api/status');
  document.getElementById('version').textContent = s.version;
  document.getElementById('protection').checked = s.protection_enabled;
  document.getElementById('protection-label').textContent = s.protection_enabled ? 'Protection on' : 'Protection off';
  return s;
}

document.addEventListener('DOMContentLoaded', () => {
  window.addEventListener('hashchange', route);
  document.getElementById('protection').addEventListener('change', e => run(async () => {
    await api('POST', '/api/protection', { enabled: e.target.checked });
    await loadStatus();
  }, e.target.checked ? 'Protection enabled' : 'Protection disabled'));
  run(async () => { await loadStatus(); route(); });
});

// Retention choices offered in Settings (Go duration strings, "0" = memory only).
const RETENTION = [['6h', '6 hours'], ['24h', '24 hours'], ['7d', '7 days'], ['30d', '30 days'], ['90d', '90 days']];
function retentionSelect(value, extra) {
  const opts = (extra || []).concat(RETENTION);
  if (!opts.some(([v]) => v === value)) opts.push([value, value]); // keep a custom value from the config file
  const s = el('select', {}, opts.map(([v, l]) => el('option', { value: v }, l)));
  s.value = value;
  return s;
}

// ---------- dashboard ----------

// dashboard draws the view and refreshes it every 15 s. The timer is armed
// here only: re-arming it from each refresh would double the timers every
// period, until the tab runs out of memory.
async function dashboard(main) {
  await drawDashboard(main);
  if (current !== 'dashboard') return; // navigated away while loading
  clearInterval(refreshTimer);
  let busy = false;
  refreshTimer = setInterval(() => {
    if (current !== 'dashboard' || document.hidden || busy) return;
    busy = true;
    run(() => drawDashboard(main)).finally(() => { busy = false; });
  }, 15000);
}

async function drawDashboard(main) {
  const [s, st] = await Promise.all([loadStatus(), api('GET', '/api/stats')]);
  const maxH = Math.max(1, ...st.buckets.map(h => h.total));
  const byDay = st.bucket_size === 'day';
  const bucketLabel = b => byDay ? new Date(b.time).toLocaleDateString()
    : new Date(b.time).toLocaleString([], { weekday: 'short', hour: '2-digit', minute: '2-digit' });

  const tile = (v, k) => el('div', { class: 'tile' }, el('div', { class: 'v' }, v), el('div', { class: 'k' }, k));
  const top = (title, items) => el('div', { class: 'card' }, el('h3', {}, title),
    items.length ? el('ul', { class: 'top-list' }, items.map(i => el('li', {}, el('span', { title: i.name }, i.name), el('span', {}, fmtNum(i.count)))))
      : el('p', { class: 'muted' }, 'No data yet'));

  render(main, 
    el('div', { class: 'tiles' },
      tile(fmtNum(st.total), `Queries, ${st.interval}`),
      tile(fmtNum(st.blocked), `Blocked, ${st.interval}`),
      tile(pct(st.blocked, st.total), 'Blocked share'),
      tile(fmtNum(s.rules), 'Rules loaded'),
      tile(Math.round(s.rss_kb / 1024) + ' MB', 'Memory (RSS)'),
      tile(fmtAgo(s.started), 'Uptime'),
    ),
    s.warnings && s.warnings.length ? el('div', { class: 'card error' }, s.warnings.map(w => el('div', {}, w))) : null,
    !s.manage_firewall ? el('div', { class: 'card' }, 'UI-only mode: manage_firewall is off, so no DNS traffic is intercepted and the log stays empty. Settings, clients and the domain check work.')
      : s.destinations && s.destinations.length ? el('div', { class: 'card' }, 'Test mode: only replies to ', s.destinations.join(', '), ' are filtered.') : null,
    el('div', { class: 'card' },
      el('h3', {}, `Queries per ${st.bucket_size} `, el('span', { class: 'muted small' }, '(red: blocked)')),
      el('div', { class: 'chart' }, st.buckets.map(b => el('div', {
        class: 'bar', style: `height:${100 * b.total / maxH}%`,
        title: `${bucketLabel(b)}: ${fmtNum(b.total)} queries, ${fmtNum(b.blocked)} blocked`,
      }, el('i', { style: `height:${b.total ? 100 * b.blocked / b.total : 0}%` })))),
      el('div', { class: 'chart-axis' }, el('span', {}, fmtTime(st.since)), el('span', {}, 'now')),
    ),
    el('p', { class: 'small' }, `Statistics for the last ${st.interval} (change in Settings); they are kept across restarts.`),
    el('div', { class: 'grid' },
      top('Top queried', st.top_queried),
      top('Top blocked', st.top_blocked),
      top('Top clients', st.top_clients),
      top('Blocked services', st.top_services),
    ),
  );
}

// ---------- query log ----------

// Auto-refresh periods in seconds (0 = off); any other value is custom.
const REFRESH_CHOICES = [[0, 'Off'], [10, '10 s'], [15, '15 s'], [30, '30 s'], [60, '1 min']];

async function queryLog(main) {
  // before: time of the oldest entry shown, the cursor for "Load more";
  // entries: everything shown, newest first.
  const state = { search: '', action: '', route: '', before: '', paged: false, entries: [], every: pref('logRefresh', 10) };
  if (!(state.every === 0 || state.every >= 5 && state.every <= 3600)) state.every = 10;
  const tbody = el('tbody');
  const more = el('button', { onclick: () => run(() => load(true)) }, 'Load more');
  const scanNote = el('p', { class: 'small' });

  const search = el('input', { type: 'search', placeholder: 'Domain, client IP or name', oninput: debounce(() => { state.search = search.value; run(() => load()); }, 300) });
  const action = el('select', { onchange: () => { state.action = action.value; run(() => load()); } },
    el('option', { value: '' }, 'All'), el('option', { value: 'filtered' }, 'Blocked + rewritten'),
    el('option', { value: 'block' }, 'Blocked'), el('option', { value: 'rewrite' }, 'Rewritten'), el('option', { value: 'pass' }, 'Allowed'));
  // Routing lists, filled once the log view has loaded them; hidden without lists.
  const route = el('select', { id: 'route-filter', 'aria-label': 'Route', hidden: true,
    onchange: () => { state.route = route.value; run(() => load()); } });

  const preset = REFRESH_CHOICES.some(([sec]) => sec === state.every);
  const secs = el('input', { type: 'number', id: 'refresh-secs', class: 'secs', min: 5, max: 3600, step: 1,
    value: preset ? '' : state.every, 'aria-label': 'Refresh every, seconds',
    onchange: () => {
      secs.value = Math.min(3600, Math.max(5, Math.round(+secs.value) || 20));
      setEvery(+secs.value);
    } });
  const custom = el('span', { class: 'small', hidden: preset }, secs, ' s');
  const every = el('select', { id: 'refresh-every', onchange: () => {
    custom.hidden = every.value !== 'custom';
    if (every.value !== 'custom') return setEvery(+every.value);
    if (!secs.value) secs.value = state.every || 20;
    setEvery(+secs.value);
    secs.focus();
  } }, REFRESH_CHOICES.map(([sec, label]) => el('option', { value: sec }, label)), el('option', { value: 'custom' }, 'Custom…'));
  every.value = preset ? String(state.every) : 'custom';

  function setEvery(sec) {
    state.every = sec;
    setPref('logRefresh', sec);
    schedule();
  }

  function schedule() {
    clearInterval(refreshTimer);
    if (!state.every) return;
    refreshTimer = setInterval(() => {
      // Don't refresh away older pages the user loaded, nor rows whose
      // details are open.
      if (current === 'log' && !document.hidden && !state.paged && !pop.anchor) run(() => load());
    }, state.every * 1000);
  }

  async function load(append) {
    if (!append) state.before = '';
    state.paged = !!append;
    const q = new URLSearchParams({ search: state.search, action: state.action, route: state.route, limit: 100 });
    if (state.before) q.set('before', state.before);
    const res = await api('GET', '/api/querylog?' + q);
    state.before = res.next_before || '';
    state.entries = append ? state.entries.concat(res.entries) : res.entries;
    tbody.replaceChildren(...groupEntries(state.entries).map(row));
    if (pop.anchor && !pop.anchor.isConnected) hideDetails();
    more.hidden = !res.more;
    // A rare search stops after a slice of the log to keep the router responsive.
    scanNote.textContent = res.more && res.entries.length < 100
      ? `Searched back to ${fmtTime(res.next_before)}. Press Load more to search older entries.` : '';
  }

  function row(g) {
    const e = g[0];
    const blocked = e.action !== 'pass';
    const btn = e.reason === 'rewrite' || e.reason === 'dnsrewrite' ? null : blocked
      ? el('button', { class: 'small', onclick: () => quick(e.cname || e.host, 'allow') }, 'Unblock')
      : el('button', { class: 'small danger', onclick: () => quick(e.host, 'block') }, 'Block');
    const t = new Date(e.time);
    return el('tr', { class: e.action },
      el('td', { class: 'nowrap small', title: t.toLocaleString() },
        t.toDateString() === new Date().toDateString() ? t.toLocaleTimeString() : t.toLocaleString()),
      el('td', {}, e.client_name || e.client_ip,
        e.client_name ? clientAddrs(g).map(a => el('div', { class: 'small addr' }, a)) : null),
      el('td', { class: 'host' }, e.host,
        el('div', { class: 'small qtypes' }, typeCounts(g).map(([type, n]) => n > 1 ? `${type} ×${n}` : type).join(' · ')),
        e.cname ? el('div', { class: 'small' }, 'via CNAME ', e.cname) : null,
        e.route ? el('span', { class: 'badge route', title: 'Addresses added to the sets of routing list ' + e.route }, '→ ' + e.route) : null),
      el('td', {}, why(g)),
      el('td', { class: 'nowrap' }, btn));
  }

  function why(g) {
    const e = g[0];
    const t = el('div', { class: 'why', tabindex: 0, role: 'button', 'aria-haspopup': 'dialog', 'aria-expanded': 'false' },
      el('span', { class: 'badge ' + e.action }, e.action),
      reasonText(e) ? el('div', { class: 'small reason' }, reasonText(e)) : null);
    bindDetails(t, () => explain(g));
    return t;
  }

  function quick(host, act) {
    run(async () => {
      await api('POST', '/api/user_rules/quick', { host, action: act });
    }, (act === 'block' ? 'Blocked ' : 'Allowed ') + host + '. New lookups use the rule; cached answers expire on their own.');
  }

  render(main,
    el('div', { class: 'card' },
      el('div', { class: 'toolbar' }, search, action, route,
        el('span', { class: 'refresh' }, el('label', { class: 'small', for: 'refresh-every' }, 'Auto-refresh'), every, custom),
        el('button', { onclick: () => run(() => load()) }, 'Refresh')),
      el('div', { class: 'table-wrap' }, el('table', {},
        el('thead', {}, el('tr', {}, el('th', {}, 'Time'), el('th', {}, 'Client'), el('th', {}, 'Domain'),
          el('th', {}, 'Result'), el('th', {}))),
        tbody)),
      scanNote, more));
  await loadListNames();
  const lists = await api('GET', '/api/routing').then(r => r.lists.map(l => l.name)).catch(() => []);
  if (lists.length) {
    render(route, el('option', { value: '' }, 'All routes'),
      lists.length > 1 ? el('option', { value: '*' }, 'Routed by any list') : null,
      lists.map(n => el('option', { value: n }, 'Routed by ' + n)));
    route.hidden = false;
  }
  await load();
  schedule();
}

function debounce(fn, ms) {
  let t;
  return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); };
}

// ---------- filters ----------

async function filters(main) {
  const data = await api('GET', '/api/filters');
  listNames = Object.fromEntries(data.filters.map(f => [f.id, f.name]));
  const reload = () => run(() => filters(main));

  const rows = data.filters.map(f => el('tr', {},
    el('td', {}, el('input', { type: 'checkbox', checked: f.enabled, onchange: e => run(async () => {
      await api('PUT', '/api/filters/' + f.id, { name: f.name, url: f.url, enabled: e.target.checked });
      reload();
    }, 'Saved') })),
    el('td', {}, f.name, el('div', { class: 'small host' }, f.url)),
    el('td', { class: 'nowrap' }, fmtNum(f.rules)),
    el('td', { class: 'nowrap small' }, f.updated && !f.updated.startsWith('0001') ? fmtAgo(f.updated) + ' ago' : 'never',
      f.error ? el('div', { class: 'error' }, f.error) : null),
    el('td', {}, el('button', { class: 'small danger', onclick: () => confirmDo(`Remove list "${f.name}"?`, async () => {
      await api('DELETE', '/api/filters/' + f.id);
      reload();
    }) }, 'Remove'))));

  const name = el('input', { placeholder: 'Name' });
  const url = el('input', { placeholder: 'https://… list URL', size: 50 });
  const rules = el('textarea', { spellcheck: 'false' }, data.user_rules.join('\n'));

  // Rewrites are saved as a whole list; the view reloads either way, so a
  // rejected change doesn't leave the table showing it.
  const saveRewrites = (change, msg) => run(async () => {
    const list = data.rewrites.map(r => ({ ...r }));
    change(list);
    try { await api('PUT', '/api/rewrites', list); } finally { reload(); }
  }, msg);
  const rwRows = data.rewrites.length ? data.rewrites.map((r, i) => el('tr', { 'data-domain': r.domain },
    el('td', {}, el('input', { type: 'checkbox', checked: r.enabled, 'aria-label': 'Rewrite on',
      onchange: e => saveRewrites(list => { list[i].enabled = e.target.checked; }, e.target.checked ? 'Rewrite on' : 'Rewrite off') })),
    el('td', { class: 'host' }, r.domain),
    el('td', { class: 'host' }, r.answer, el('div', { class: 'small' }, rewriteKind(r.answer))),
    el('td', {}, el('button', { class: 'small danger', onclick: () => saveRewrites(list => { list.splice(i, 1); }, 'Rewrite removed') }, 'Remove'))))
    : el('tr', {}, el('td', { colspan: 4, class: 'muted' }, 'No rewrites yet. Add one below, e.g. media.home → 192.168.1.5.'));
  const rwDomain = el('input', { id: 'rewrite-domain', size: 26, placeholder: 'media.home or *.example.com', 'aria-label': 'Domain' });
  const rwAnswer = el('input', { id: 'rewrite-answer', size: 30, placeholder: '192.168.1.5, a domain, A or AAAA', 'aria-label': 'Answer' });

  const checkHost = el('input', { placeholder: 'example.com' });
  const checkClient = el('input', { placeholder: 'client IP (optional)', size: 16 });
  const checkOut = el('div', { class: 'small' });

  render(main, 
    el('div', { class: 'card' },
      el('div', { class: 'toolbar' }, el('h3', {}, 'Filter lists'), el('span', { class: 'small' }, `updated every ${data.update_interval}`),
        el('button', { onclick: () => run(async () => { await api('POST', '/api/filters/refresh', {}); reload(); }, 'Lists updated') }, 'Update now')),
      el('div', { class: 'table-wrap' }, el('table', {},
        el('thead', {}, el('tr', {}, el('th', {}, 'On'), el('th', {}, 'List'), el('th', {}, 'Rules'), el('th', {}, 'Updated'), el('th', {}))),
        el('tbody', {}, rows))),
      el('div', { class: 'toolbar', style: 'margin-top:12px' }, name, url,
        el('button', { class: 'primary', onclick: () => run(async () => {
          await api('POST', '/api/filters', { name: name.value, url: url.value, enabled: true });
          setTimeout(reload, 3000);
          reload();
        }, 'List added; downloading…') }, 'Add list'))),
    el('div', { class: 'card' },
      el('h3', {}, 'Custom rules ', el('span', { class: 'muted small' }, 'AdGuard syntax: ||example.com^ blocks, @@||example.com^ allows, ||example.com^$dnsrewrite=192.168.1.5 rewrites, ! comments')),
      rules,
      el('div', { class: 'toolbar', style: 'margin-top:8px' },
        el('button', { class: 'primary', onclick: () => run(() => api('PUT', '/api/user_rules', { rules: rules.value.split('\n') }), 'Rules saved') }, 'Save rules'))),
    el('div', { class: 'card', id: 'rewrites' },
      el('h3', {}, 'DNS rewrites'),
      el('p', { class: 'small' }, 'Answer a domain with your own records on every device, even with protection off. ',
        'Domain: example.com, or *.example.com for its subdomains. Answer: an IP address, a domain name (sent as a CNAME), ',
        'or A / AAAA to keep the real records of that type. Other record types for a rewritten domain get an empty answer.'),
      el('div', { class: 'table-wrap' }, el('table', {},
        el('thead', {}, el('tr', {}, el('th', {}, 'On'), el('th', {}, 'Domain'), el('th', {}, 'Answer'), el('th', {}))),
        el('tbody', {}, rwRows))),
      el('form', { class: 'toolbar', style: 'margin-top:12px', onsubmit: ev => {
        ev.preventDefault();
        saveRewrites(list => { list.push({ domain: rwDomain.value, answer: rwAnswer.value, enabled: true }); },
          'Rewrite added');
      } }, rwDomain, rwAnswer, el('button', { class: 'primary' }, 'Add rewrite'))),
    el('div', { class: 'card' },
      el('h3', {}, 'Check a domain'),
      el('div', { class: 'toolbar' }, checkHost, checkClient,
        el('button', { onclick: () => run(async () => {
          const r = await api('GET', '/api/check?' + new URLSearchParams({ host: checkHost.value, client: checkClient.value }));
          render(checkOut, el('span', { class: 'badge ' + r.action }, r.action), ' ',
            reasonText(r), r.rule ? ` — ${r.rule}` : '', r.safe_target ? ` → ${r.safe_target}` : '',
            r.rewrite ? ` (A query answered with ${rewriteText(r.rewrite)})` : '',
            r.client ? ` (client ${r.client})` : '',
            r.route ? el('span', {}, ' ', el('span', { class: 'badge route' }, '→ ' + r.route), ' routed by list ' + r.route) : '');
        }) }, 'Check')),
      checkOut),
  );
  if (focusRule) {
    selectRule(rules, focusRule);
    focusRule = null;
  }
  if (focusRewrite) {
    const tr = [...main.querySelectorAll('#rewrites tr[data-domain]')].find(r => r.dataset.domain === focusRewrite);
    (tr || main.querySelector('#rewrites')).scrollIntoView({ block: 'center' });
    if (tr) tr.classList.add('hl');
    focusRewrite = null;
  }
}

// ---------- routing ----------

// Lifetime units offered for the minimum lifetime, largest first.
const LIFETIME_UNITS = [['h', 3600], ['m', 60], ['s', 1]];

// lifetimeEditor edits a duration in seconds as a number and a unit.
function lifetimeEditor(seconds) {
  const [unit, size] = LIFETIME_UNITS.find(([, n]) => seconds % n === 0);
  const num = el('input', { type: 'number', min: 1, step: 1, value: seconds / size, style: 'width:80px', 'aria-label': 'Minimum lifetime' });
  const sel = el('select', { 'aria-label': 'Unit' }, LIFETIME_UNITS.map(([u]) => el('option', { value: u }, u)));
  sel.value = unit;
  const box = el('span', { class: 'nowrap' }, num, ' ', sel);
  box.value = () => `${Math.round(+num.value)}${sel.value}`;
  return box;
}

async function routing(main) {
  const data = await api('GET', '/api/routing');
  const reload = () => run(() => routing(main));
  const enabled = el('input', { type: 'checkbox', checked: data.enabled });
  const minTimeout = lifetimeEditor(data.min_timeout_s);
  const tp = data.tproxy;
  const routerToo = el('input', { type: 'checkbox', checked: tp.router });
  const proxyGroup = el('input', { id: 'proxy-group', value: tp.proxy_group || '', size: 12, placeholder: 'e.g. hysteria',
    autocapitalize: 'none', spellcheck: 'false' });
  const proxyMark = el('input', { id: 'proxy-mark', value: tp.proxy_mark || '', size: 8, placeholder: 'e.g. 0xff',
    autocapitalize: 'none', spellcheck: 'false' });
  const newName = el('input', { value: data.lists.length ? '' : 'bypass', size: 14, placeholder: 'name, e.g. vpn',
    autocapitalize: 'none', spellcheck: 'false', 'aria-label': 'New list name' });
  const newPort = el('input', { type: 'number', min: 1, max: 65535, step: 1, placeholder: 'TPROXY port', style: 'width:120px',
    'aria-label': 'TPROXY port of the new list' });
  const create = ev => {
    ev.preventDefault();
    run(async () => {
      const name = newName.value.trim().toLowerCase();
      if (!/^[a-z0-9][a-z0-9_-]{0,23}$/.test(name)) throw new Error('List name: 1-24 of a-z, 0-9, _ and -, starting with a letter or digit');
      if (data.lists.some(l => l.name === name)) throw new Error(`List ${name} already exists`);
      const port = newPort.value.trim() === '' ? 0 : Number(newPort.value);
      if (!Number.isInteger(port) || port < 0 || port > 65535) throw new Error('TPROXY port must be 1-65535 or empty');
      await api('PUT', '/api/routing/lists/' + encodeURIComponent(name), { domains: [], tproxy_port: port });
      reload();
    }, 'List created');
  };

  render(main,
    el('div', { class: 'card' },
      el('h3', {}, 'Routing by domain'),
      el('p', { class: 'small' },
        'Addresses that listed domains resolve to are put into ipsets before the DNS reply reaches the device, so even its ',
        'first connection takes the route the firewall gives the sets (e.g. a VPN). Each answer keeps an address for its TTL, ',
        'but at least the minimum lifetime, since devices and browsers keep using cached answers.'),
      data.error ? el('p', { class: 'error small' }, data.error) : null,
      el('div', { class: 'form-row' }, el('label', {}, enabled, ' Routing enabled'),
        el('label', {}, 'Minimum lifetime ', minTimeout),
        el('span', { class: 'small' }, 'from 1 minute to 7 days (168 h); e.g. 3600 s = 60 m = 1 h')),
      el('h4', {}, 'Lists with a TPROXY port'),
      el('div', { class: 'form-row' }, el('label', {}, routerToo, ' Also route the router\'s own traffic'),
        el('label', { for: proxyGroup.id }, 'proxy runs as group ', proxyGroup),
        el('label', { for: proxyMark.id }, 'or marks its sockets with ', proxyMark)),
      el('p', { class: 'small' }, 'Devices in the LAN are always routed. For the router\'s own connections kdnsfilter must recognise the ',
        'proxy\'s traffic, or it would be sent back into the proxy: give the group the proxy process runs as, or the mark it sets ',
        '(sing-box routing_mark, xray sockopt.mark). ',
        `Packets for the proxy get mark ${tp.mark} and routing table ${tp.table} (change them in the YAML config if they clash).`),
      el('div', { class: 'toolbar' }, el('button', { class: 'primary', onclick: () => run(async () => {
        await api('PUT', '/api/routing', { enabled: enabled.checked, min_timeout: minTimeout.value(),
          tproxy: { router: routerToo.checked, proxy_group: proxyGroup.value.trim(), proxy_mark: proxyMark.value.trim() } });
        reload();
      }, 'Routing settings saved') }, 'Save'))),
    data.lists.map(l => routeListCard(l, data, reload)),
    el('div', { class: 'card' },
      el('h3', {}, 'New list'),
      el('p', { class: 'small' }, 'Each list has its own domains and its own route: give a TPROXY port to send it through ',
        'a proxy on the router (another port, another proxy), or leave it empty to only fill its ipsets.'),
      el('form', { class: 'toolbar', onsubmit: create }, newName, newPort, el('button', { class: 'primary' }, 'Create'))));
}

// normalizeRouteDomain mirrors config.NormalizeDomain; a pasted link gives its host.
function normalizeRouteDomain(s) {
  s = s.trim().toLowerCase();
  const except = s.startsWith('!');
  s = s.replace(/^!\s*/, '');
  if (/^[a-z][a-z0-9+.-]*:\/\//.test(s)) {
    try { s = new URL(s).hostname; } catch { /* not a URL after all */ }
  }
  s = s.replace(/^\*/, '').replace(/^\.+|\.+$/g, '');
  return (except ? '!' : '') + s;
}

// sortRouteDomains cleans and orders list lines the way saving does: no
// blanks, comments or duplicates, sorted by name with "!name" right after name.
function sortRouteDomains(lines) {
  const out = [...new Set(lines.filter(l => l.trim() && !l.trim().startsWith('#')).map(normalizeRouteDomain))];
  const name = d => d.replace(/^!/, '');
  return out.sort((a, b) => name(a) < name(b) ? -1 : name(a) > name(b) ? 1 : a.startsWith('!') - b.startsWith('!'));
}

// scrollToLine shows a line of a textarea without focusing it (which would
// open the on-screen keyboard on phones).
function scrollToLine(ta, line) {
  const n = ta.value.split('\n').indexOf(line);
  if (n < 0) return;
  const cs = getComputedStyle(ta);
  const lh = parseFloat(cs.lineHeight) || parseFloat(cs.fontSize) * 1.2;
  ta.scrollTop = Math.max(0, n * lh - ta.clientHeight / 3);
}

// routeVia shows how a list's sets are routed: a TPROXY port kdnsfilter
// wires up itself, or the user's own chains from the YAML config (which a
// port replaces).
function routeVia(l, data, markUnsaved) {
  const ownChains = !!(l.chain || l.output_chain);
  const port = el('input', { id: 'route-port-' + l.name, type: 'number', min: 1, max: 65535, step: 1,
    value: l.tproxy_port || '', placeholder: 'e.g. 12345', style: 'width:110px', 'aria-label': 'TPROXY port of ' + l.name });
  port.addEventListener('input', markUnsaved);
  const tp = data.tproxy;
  const status = ownChains
    ? el('span', { class: 'small' }, 'now routed by your own chains: ',
      l.chain ? el('code', {}, 'PREROUTING → ' + l.chain) : null, l.chain && l.output_chain ? ', ' : null,
      l.output_chain ? el('code', {}, 'OUTPUT → ' + l.output_chain) : null, '; a port replaces them')
    : el('span', { class: 'small' }, l.tproxy_port
      ? `TCP and UDP to the sets go to 127.0.0.1:${l.tproxy_port} / [::1]:${l.tproxy_port}` +
        (tp.router ? ', the router\'s own traffic too' : ' (devices in the LAN)')
      : 'not set: the sets ' + l.set4 + ' / ' + l.set6 + ' are only filled, route them yourself');
  const box = el('div', {},
    el('div', { class: 'form-row' }, el('label', { for: port.id }, 'TPROXY port '), port, status),
    data.manage_firewall ? null : el('p', { class: 'error small' }, 'nfqueue.manage_firewall is off: kdnsfilter adds no firewall rules.'));
  // value returns the fields to save with the list, or throws.
  box.value = () => {
    const v = port.value.trim();
    const n = v === '' ? 0 : Number(v);
    if (!Number.isInteger(n) || n < 0 || n > 65535) throw new Error('TPROXY port must be 1-65535 or empty');
    if (ownChains && n === 0) return {}; // keep the chains
    return ownChains ? { tproxy_port: n, chain: '', output_chain: '' } : { tproxy_port: n };
  };
  return box;
}

function deleteRouteList(l, reload) {
  confirmDo(`Delete list ${l.name}? Its ${fmtNum(l.domains.filter(d => !d.startsWith('!')).length)} domains stop being routed ` +
    'at once. Export it first to keep a copy.', async () => {
    await api('DELETE', '/api/routing/lists/' + encodeURIComponent(l.name));
    toast(`List ${l.name} deleted`);
    reload();
  });
}

function routeListCard(l, data, reload) {
  const domains = el('textarea', { spellcheck: 'false', 'aria-label': 'Domains of ' + l.name }, l.domains.join('\n'));
  const routed = l.domains.filter(d => !d.startsWith('!')).length;
  const unsaved = el('span', { class: 'small', hidden: true }, 'Not saved yet');
  domains.addEventListener('input', () => { unsaved.hidden = false; });
  const via = routeVia(l, data, () => { unsaved.hidden = false; });
  // A field for phones and tablets, where editing the textarea is awkward;
  // it changes the editor only, Save list still applies.
  const addInput = el('input', { id: 'route-add-' + l.name, type: 'text', inputmode: 'url', size: 30,
    style: 'flex:1 1 12em;min-width:0;max-width:24em', // keeps Add on the same row on phones
    placeholder: 'example.com or !sub.example.com', autocapitalize: 'none', autocorrect: 'off',
    spellcheck: 'false', enterkeyhint: 'done', 'aria-label': 'Domain to add to ' + l.name });
  const add = ev => {
    ev.preventDefault();
    const items = addInput.value.split(/[\s,]+/).map(normalizeRouteDomain).filter(d => d && d !== '!');
    if (!items.length) return;
    const bad = items.find(d => !/^!?[a-z0-9_-]+(\.[a-z0-9_-]+)+$/.test(d));
    if (bad) return toast(`"${bad}" doesn't look like a domain`, true);
    const had = new Set(sortRouteDomains(domains.value.split('\n')));
    const fresh = items.filter(d => !had.has(d));
    domains.value = sortRouteDomains([...domains.value.split('\n'), ...items]).join('\n');
    addInput.value = '';
    scrollToLine(domains, fresh[0] || items[0]);
    if (!fresh.length) return toast(`${items.join(', ')} ${items.length > 1 ? 'are' : 'is'} already in the list`);
    unsaved.hidden = false;
    toast(`Added ${fresh.join(', ')}. Press Save list to apply.`);
  };
  const save = () => run(async () => {
    const route = via.value(); // throws before anything is sent or reloaded
    try {
      await api('PUT', '/api/routing/lists/' + encodeURIComponent(l.name), { domains: domains.value.split('\n'), ...route });
    } finally { reload(); }
  }, `List ${l.name} saved; addresses devices already have are being added`);
  return el('div', { class: 'card' },
    el('div', { class: 'toolbar' }, el('h3', {}, 'List ', l.name),
      el('span', { class: 'small' }, `${fmtNum(routed)} domains · ${fmtNum(l.count4)} IPv4 and ${fmtNum(l.count6)} IPv6 addresses routed`)),
    el('p', { class: 'small' }, 'One domain per line; it covers all its subdomains. ',
      el('code', {}, '!sub.example.com'), ' excludes a subdomain. The list is sorted when saved. ',
      'Saving applies at once: removed domains stop being routed, added ones are routed from the answers devices already have.'),
    via,
    el('form', { class: 'toolbar', onsubmit: add }, addInput, el('button', {}, 'Add')),
    domains,
    el('div', { class: 'toolbar', style: 'margin-top:8px' },
      el('button', { class: 'primary', onclick: save }, 'Save list'), unsaved,
      el('button', { title: 'Download the saved list as a text file, one domain per line',
        onclick: () => location.assign(`/api/routing/lists/${encodeURIComponent(l.name)}/export`) }, 'Export .txt'),
      // The last list stays: the page always has one to edit.
      data.lists.length > 1 ? el('button', { class: 'danger', style: 'margin-left:auto', onclick: () => deleteRouteList(l, reload) }, 'Delete list') : null));
}

function confirmDo(question, fn) {
  const d = document.getElementById('dialog');
  const f = document.getElementById('dialog-form');
  f.replaceChildren(el('div', {}, question), el('div', { class: 'actions' },
    el('button', { value: 'cancel' }, 'Cancel'),
    el('button', { value: 'ok', class: 'primary' }, 'Confirm')));
  d.onclose = () => { if (d.returnValue === 'ok') run(fn); };
  d.showModal();
}

// ---------- services & schedule editors ----------

let servicesCache = null;
async function servicesList() {
  if (!servicesCache) servicesCache = await api('GET', '/api/services');
  return servicesCache;
}

function servicesEditor(selected, catalog) {
  const sel = new Set(selected || []);
  const groups = {};
  for (const s of catalog) (groups[s.group || 'other'] ||= []).push(s);
  const filter = el('input', { type: 'search', placeholder: 'Filter services' });
  const boxes = [];
  const body = el('div', { class: 'services-scroll' }, Object.keys(groups).sort().map(g => el('div', {},
    el('div', { class: 'small', style: 'margin-top:6px;text-transform:capitalize' }, g.replace(/_/g, ' ')),
    el('div', { class: 'services' }, groups[g].map(s => {
      const cb = el('input', { type: 'checkbox', value: s.id, checked: sel.has(s.id) });
      const lbl = el('label', { title: s.id }, cb, s.name);
      boxes.push([cb, lbl, s.name.toLowerCase() + ' ' + s.id]);
      return lbl;
    })))));
  filter.addEventListener('input', () => {
    const q = filter.value.toLowerCase();
    for (const [, lbl, key] of boxes) lbl.hidden = q !== '' && !key.includes(q);
  });
  const node = el('div', {}, filter, body);
  node.value = () => boxes.filter(([cb]) => cb.checked).map(([cb]) => cb.value);
  return node;
}

const DAYS = [['mon', 'Mon'], ['tue', 'Tue'], ['wed', 'Wed'], ['thu', 'Thu'], ['fri', 'Fri'], ['sat', 'Sat'], ['sun', 'Sun']];

function scheduleEditor(sched) {
  sched = sched || {};
  const tz = el('input', { value: sched.time_zone || Intl.DateTimeFormat().resolvedOptions().timeZone, size: 18 });
  const rows = DAYS.map(([k, label]) => {
    const r = sched[k];
    const on = el('input', { type: 'checkbox', checked: !!r });
    const start = el('input', { type: 'time', value: r ? durToTime(r.start) : '09:00' });
    const end = el('input', { type: 'time', value: r ? durToTime(r.end) : '21:00' });
    return { k, nodes: [el('label', {}, on, ' ', label), start, end], on, start, end };
  });
  const node = el('div', {},
    el('div', { class: 'small' }, 'Blocking is paused (services allowed) during these hours. Days left unticked stay blocked all day.'),
    el('div', { class: 'form-row' }, el('label', {}, 'Time zone ', tz)),
    el('div', { class: 'sched' }, el('span', { class: 'small' }, 'Day'), el('span', { class: 'small' }, 'From'), el('span', { class: 'small' }, 'To'),
      rows.map(r => r.nodes)));
  node.value = () => {
    const out = { time_zone: tz.value.trim() };
    for (const r of rows) if (r.on.checked) out[r.k] = { start: timeToDur(r.start.value), end: timeToDur(r.end.value) };
    return out;
  };
  return node;
}

const ENGINES = [['google', 'Google'], ['youtube', 'YouTube'], ['bing', 'Bing'], ['duckduckgo', 'DuckDuckGo'], ['yandex', 'Yandex'], ['pixabay', 'Pixabay'], ['ecosia', 'Ecosia']];

function safeSearchEditor(ss) {
  ss = ss || {};
  const enabled = el('input', { type: 'checkbox', checked: ss.enabled });
  const boxes = ENGINES.map(([k, label]) => [k, el('input', { type: 'checkbox', checked: ss[k] }), label]);
  const engines = el('div', { class: 'form-row' }, boxes.map(([, cb, label]) => el('label', {}, cb, label)));
  // Engines only matter while safe search is enforced; keep their ticks but grey them out.
  const sync = () => {
    for (const [, cb] of boxes) cb.disabled = !enabled.checked;
    engines.classList.toggle('disabled', !enabled.checked);
  };
  enabled.addEventListener('change', sync);
  sync();
  const node = el('div', {},
    el('label', {}, enabled, ' Enforce safe search'),
    engines);
  node.value = () => {
    const out = { enabled: enabled.checked };
    for (const [k, cb] of boxes) out[k] = cb.checked;
    return out;
  };
  return node;
}

// ---------- clients ----------

async function clients(main) {
  const data = await api('GET', '/api/clients');
  const list = data.clients;
  const save = async () => { await api('PUT', '/api/clients', list); await clients(main); };

  const summary = c => {
    const parts = [];
    if (c.use_global_settings) parts.push('global settings');
    else {
      parts.push(c.filtering_enabled ? 'filtering on' : 'filtering OFF');
      if (c.safe_search && c.safe_search.enabled) parts.push('safe search');
    }
    if (!c.use_global_blocked_services) {
      const n = (c.blocked_services.ids || []).length;
      parts.push(n ? `${n} services blocked` : 'own services: none');
    }
    return parts.join(' · ');
  };

  // bindTo replaces a client's single-address ids with the device's MAC, so
  // it follows the device across DHCP leases; prefixes are kept.
  const bindTo = (c, mac) => {
    c.ids = (c.ids || []).filter(id => isMAC(id) || id.includes('/')).concat(mac);
  };
  const strong = list.filter(c => c.ip_only && c.suggestions.length && c.suggestions[0].strong);
  const bindAll = () => confirmDo(
    el('div', {}, 'Bind these clients to their devices by MAC?',
      el('ul', {}, strong.map(c => el('li', {}, c.name, ' → ', c.suggestions[0].name, ' (', c.suggestions[0].mac, ')')))),
    async () => { strong.forEach(c => bindTo(c, c.suggestions[0].mac)); await save(); });

  const rows = list.map((c, i) => el('tr', {},
    el('td', {}, c.name, c.ip_only ? el('div', {}, el('span', { class: 'badge rewrite', title: 'DHCP may give this address to another device' }, 'IP only')) : null),
    el('td', { class: 'small' }, (c.ids || []).join(', '),
      c.addresses.length && c.addresses.join() !== (c.ids || []).join() ? el('div', { class: 'muted' }, 'now: ', fmtAddrs(c.addresses)) : null,
      c.suggestions.map(s => el('div', { style: 'margin-top:4px' },
        el('button', { class: 'small', title: s.reasons.join(', '), onclick: () => run(async () => { bindTo(c, s.mac); await save(); }, `${c.name} bound to ${s.mac}`) },
          'Bind to ', s.name || s.mac), ' ', el('span', { class: 'muted' }, s.reasons.join(', '))))),
    el('td', { class: 'small' }, summary(c)),
    el('td', { class: 'nowrap' },
      el('button', { class: 'small', onclick: () => editClient(c, v => { list[i] = v; run(save, 'Client saved'); }) }, 'Edit'), ' ',
      el('button', { class: 'small danger', onclick: () => confirmDo(`Delete client "${c.name}"?`, async () => { list.splice(i, 1); await save(); }) }, 'Delete'))));

  const known = data.known.map(h => el('tr', {},
    el('td', {}, h.name || '—'),
    el('td', { class: 'small' }, fmtAddrs(h.ips)),
    el('td', { class: 'small nowrap' }, h.mac),
    el('td', {}, h.client ? el('span', { class: 'small' }, '→ ', h.client)
      : el('button', { class: 'small', onclick: () => editClient(
        { name: h.name || h.mac, ids: [h.mac], use_global_settings: true, filtering_enabled: true, use_global_blocked_services: true, safe_search: {}, blocked_services: { ids: [] } },
        v => { list.push(v); run(save, 'Client added'); }) }, 'Add as client'))));

  render(main,
    el('div', { class: 'card' },
      el('div', { class: 'toolbar' }, el('h3', {}, 'Clients'),
        el('button', { class: 'primary', onclick: () => editClient(
          { name: '', ids: [], use_global_settings: true, filtering_enabled: true, use_global_blocked_services: true, safe_search: {}, blocked_services: { ids: [] } },
          v => { list.push(v); run(save, 'Client added'); }) }, 'Add client'),
        strong.length ? el('button', { onclick: bindAll }, `Bind ${strong.length} clear match${strong.length > 1 ? 'es' : ''} by MAC`) : null),
      el('p', { class: 'small' }, 'Clients bound by MAC follow their device when DHCP changes its address, and cover all its IPv6 addresses. Addresses are fallbacks for devices the router doesn’t list (e.g. VPN peers).'),
      list.length ? el('div', { class: 'table-wrap' }, el('table', {},
        el('thead', {}, el('tr', {}, el('th', {}, 'Name'), el('th', {}, 'Identifiers'), el('th', {}, 'Settings'), el('th', {}))),
        el('tbody', {}, rows))) : el('p', { class: 'muted' }, 'No clients configured; everyone uses the global settings.')),
    el('div', { class: 'card' },
      el('h3', {}, 'Devices known to the router'),
      el('div', { class: 'table-wrap' }, el('table', {},
        el('thead', {}, el('tr', {}, el('th', {}, 'Name'), el('th', {}, 'Addresses'), el('th', {}, 'MAC'), el('th', {}))),
        el('tbody', {}, known)))));
}

const isMAC = id => /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(id);

// fmtAddrs shows IPv4 addresses and a count of IPv6 ones (devices often have many).
function fmtAddrs(addrs) {
  const v4 = addrs.filter(a => !a.includes(':'));
  const v6 = addrs.length - v4.length;
  return [v4.join(', '), v6 ? `+${v6} IPv6` : ''].filter(Boolean).join(' ') || '—';
}

async function editClient(c, onSave) {
  const catalog = await servicesList();
  const d = document.getElementById('dialog');
  const f = document.getElementById('dialog-form');
  const name = el('input', { value: c.name, required: true });
  const ids = el('input', { value: (c.ids || []).join(', '), size: 40, placeholder: '192.168.1.16, aa:bb:cc:dd:ee:ff, 192.168.1.0/24' });
  const useGlobal = el('input', { type: 'checkbox', checked: c.use_global_settings });
  const filtering = el('input', { type: 'checkbox', checked: c.filtering_enabled });
  const ss = safeSearchEditor(c.safe_search);
  const own = el('fieldset', {}, el('legend', {}, 'Own settings'),
    el('label', {}, filtering, ' Filtering enabled'), ss);
  const useGlobalSvc = el('input', { type: 'checkbox', checked: c.use_global_blocked_services });
  const svc = servicesEditor(c.blocked_services && c.blocked_services.ids, catalog);
  const sched = scheduleEditor(c.blocked_services && c.blocked_services.schedule);
  const ownSvc = el('fieldset', {}, el('legend', {}, 'Blocked services'), svc, el('details', {}, el('summary', {}, 'Pause schedule'), sched));
  const sync = () => { own.hidden = useGlobal.checked; ownSvc.hidden = useGlobalSvc.checked; };
  useGlobal.addEventListener('change', sync);
  useGlobalSvc.addEventListener('change', sync);
  sync();

  f.replaceChildren(
    el('h3', {}, c.name ? 'Edit client' : 'New client'),
    el('div', { class: 'form-row' }, el('label', {}, 'Name ', name)),
    el('div', { class: 'form-row' }, el('label', {}, 'IPs, prefixes or MACs ', ids)),
    el('div', { class: 'form-row' }, el('label', {}, useGlobal, ' Use global settings (filtered, global safe search)')), own,
    el('div', { class: 'form-row' }, el('label', {}, useGlobalSvc, ' Use global blocked services')), ownSvc,
    el('div', { class: 'actions' }, el('button', { value: 'cancel', formnovalidate: true }, 'Cancel'), el('button', { value: 'ok', class: 'primary' }, 'Save')));
  d.onclose = () => {
    if (d.returnValue !== 'ok') return;
    onSave({
      name: name.value.trim(),
      ids: ids.value.split(/[,\s]+/).filter(Boolean),
      use_global_settings: useGlobal.checked,
      filtering_enabled: filtering.checked,
      safe_search: ss.value(),
      use_global_blocked_services: useGlobalSvc.checked,
      blocked_services: { ids: svc.value(), schedule: sched.value() },
    });
  };
  d.showModal();
}

// ---------- settings ----------

async function settings(main) {
  const [s, catalog] = await Promise.all([api('GET', '/api/settings'), servicesList()]);
  const protection = el('input', { type: 'checkbox', checked: s.protection_enabled });
  const mode = el('select', {},
    [['nxdomain', 'NXDOMAIN'], ['null_ip', '0.0.0.0 / ::'], ['refused', 'REFUSED']].map(([v, l]) => el('option', { value: v }, l)));
  mode.value = s.blocking_mode;
  const ttl = el('input', { type: 'number', min: 0, max: 86400, value: s.blocked_response_ttl, style: 'width:90px' });
  const interval = el('input', { value: s.update_interval, size: 8 });
  const qlEnabled = el('input', { type: 'checkbox', checked: s.querylog_enabled });
  const qlSize = el('input', { type: 'number', min: 100, max: 100000, value: s.querylog_size, style: 'width:100px' });
  const qlKeep = retentionSelect(s.querylog_interval, [['0', 'memory only']]);
  const stKeep = retentionSelect(s.stats_interval);
  const domainInfo = el('input', { id: 'domain-info', value: s.domain_info || '', size: 30, placeholder: 'http://host:port' });
  const ss = safeSearchEditor(s.safe_search);
  const svc = servicesEditor(s.blocked_services.ids, catalog);
  const sched = scheduleEditor(s.blocked_services.schedule);

  render(main, 
    el('div', { class: 'card' },
      el('h3', {}, 'Filtering'),
      el('div', { class: 'form-row' }, el('label', {}, protection, ' Protection enabled'),
        el('span', { class: 'small' }, 'Master switch for all clients; a client can opt out of filtering in its own settings.')),
      el('div', { class: 'form-row' }, el('label', {}, 'Blocked domains answer with ', mode), el('label', {}, 'TTL, s ', ttl)),
      el('div', { class: 'form-row' }, el('label', {}, 'Update lists every ', interval)),
      el('fieldset', {}, el('legend', {}, 'Safe search (default for clients)'), ss)),
    el('div', { class: 'card' },
      el('h3', {}, 'Blocked services (default for clients)'), svc,
      el('details', {}, el('summary', {}, 'Pause schedule'), sched),
      el('div', { class: 'toolbar', style: 'margin-top:8px' },
        el('button', { onclick: () => run(async () => { await api('POST', '/api/services/refresh', {}); servicesCache = null; }, 'Service catalog updated') }, 'Update service catalog'))),
    el('div', { class: 'card' },
      el('h3', {}, 'Query log'),
      el('div', { class: 'form-row' }, el('label', {}, qlEnabled, ' Keep query log'), el('label', {}, 'Keep on disk for ', qlKeep),
        el('label', {}, 'Newest entries in memory ', qlSize)),
      el('div', { class: 'toolbar' },
        el('button', { class: 'danger', onclick: () => confirmDo('Delete the whole query log (memory and disk)?',
          async () => { await api('POST', '/api/querylog/clear', {}); toast('Query log cleared'); }) }, 'Clear query log'))),
    el('div', { class: 'card' },
      el('h3', {}, 'Statistics'),
      el('div', { class: 'form-row' }, el('label', {}, 'Keep statistics for ', stKeep)),
      el('p', { class: 'small' }, 'Statistics and the query log are stored under the data directory and survive restarts. Shortening a period deletes older data.'),
      el('div', { class: 'toolbar' },
        el('button', { class: 'danger', onclick: () => confirmDo('Reset all statistics?',
          async () => { await api('POST', '/api/stats/reset', {}); toast('Statistics reset'); }) }, 'Reset statistics'))),
    el('div', { class: 'card' },
      el('h3', {}, 'Domain info'),
      el('div', { class: 'form-row' }, el('label', { for: 'domain-info' }, 'Domain info service '), domainInfo),
      el('p', { class: 'small' }, 'Optional: an HTTP service answering GET /api/info?host=… (see the README) that the query log asks which company and app a domain belongs to. Leave empty to turn it off.')),
    el('button', { class: 'primary', onclick: () => run(async () => {
      await api('PUT', '/api/settings', {
        protection_enabled: protection.checked,
        blocking_mode: mode.value, blocked_response_ttl: +ttl.value,
        safe_search: ss.value(), blocked_services: { ids: svc.value(), schedule: sched.value() },
        update_interval: interval.value.trim(), querylog_enabled: qlEnabled.checked, querylog_size: +qlSize.value,
        querylog_interval: qlKeep.value, stats_interval: stKeep.value, domain_info: domainInfo.value.trim(),
      });
      aboutCache.clear();
      await loadStatus();
    }, 'Settings saved') }, 'Save settings'));
}
