import http from 'node:http';
import { execFile } from 'node:child_process';
import { readFile, readdir, statfs } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import crypto from 'node:crypto';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.dirname(fileURLToPath(import.meta.url));
const port = Number(process.env.PORT || 8788);
const AUTH_FILE = path.join(root, 'auth.json');
// Prefer the dedicated install, which survives node upgrades; the unit's CCUSAGE_BIN may be stale.
const CCU = [path.join(os.homedir(), 'opt/ccusage/node_modules/.bin/ccusage'), process.env.CCUSAGE_BIN]
  .find(p => p && existsSync(p)) || 'ccusage';
const STACK_DIR = process.env.STACK_DIR || path.dirname(root);

const HOST_MS = 2000;
const PROBES_MS = 30_000;
const USAGE_MS = 10 * 60_000;
const USAGE_STALE_MS = 2 * 60_000;
const AGENT_MS = 5000;

async function readToken(file) {
  return existsSync(file) ? (await readFile(file, 'utf8')).trim() : '';
}
const agentConfigs = [
  {
    id: 'netcup',
    url: process.env.NETCUP_STATS_URL || 'http://127.0.0.1:8789/stats',
    token: await readToken(path.join(os.homedir(), '.config/stats-agent/token')),
  },
  {
    id: 'oracle',
    url: process.env.ORACLE_STATS_URL || 'http://100.73.232.54:3788/stats',
    token: await readToken(path.join(root, 'oracle-agent.token')),
  },
];

// Friendly names for known hosts; anything else shows its hostname.
const prettyNames = {
  'chinmoy.site': 'Peaceful Planet',
  'warden.chinmoy.site': 'Vaultwarden',
  'zen.chinmoy.site': 'Zen Learn',
  'music.chinmoy.site': 'Navidrome',
  'slskd.chinmoy.site': 'Soulseek',
  'rec.chinmoy.site': 'Re-command',
  'mira.chinmoy.site': 'Mira',
  'russel.chinmoy.site': 'Russel',
  'timbre.chinmoy.site': 'Timbre',
  'ops.chinmoy.site': 'Ops',
};

// ---------- auth ----------
if (!existsSync(AUTH_FILE)) {
  console.error(`FATAL: ${AUTH_FILE} missing. Create it with:  node reset-password.mjs '<password>'`);
  process.exit(1);
}
const AUTH = JSON.parse(await readFile(AUTH_FILE, 'utf8'));
const SECRET = Buffer.from(AUTH.secret, 'hex');
const USERNAME = AUTH.user || 'crimxnhaze';
const SESSION_TTL_MS = 7 * 24 * 3600 * 1000;

function verifyPassword(pw) {
  const h = crypto.scryptSync(pw, Buffer.from(AUTH.salt, 'hex'), 64);
  return crypto.timingSafeEqual(h, Buffer.from(AUTH.hash, 'hex'));
}
function hmac(expiry) {
  return crypto.createHmac('sha256', SECRET).update(String(expiry)).digest('hex');
}
function makeToken() {
  const exp = Date.now() + SESSION_TTL_MS;
  return `${exp}.${hmac(exp)}`;
}
function checkToken(tok) {
  if (!tok) return false;
  const dot = tok.indexOf('.');
  if (dot < 1) return false;
  const exp = Number(tok.slice(0, dot));
  if (!Number.isFinite(exp) || Date.now() > exp) return false;
  const want = Buffer.from(hmac(exp), 'hex');
  let got;
  try { got = Buffer.from(tok.slice(dot + 1), 'hex'); } catch { return false; }
  return got.length === want.length && crypto.timingSafeEqual(got, want);
}

const fails = new Map();
function clientIp(req) {
  const xff = req.headers['x-forwarded-for'];
  if (xff) return String(xff).split(',')[0].trim();
  const real = req.headers['x-real-ip'];
  if (real) return String(real).trim();
  return req.socket.remoteAddress || 'unknown';
}
function tooManyFails(ip) {
  const cutoff = Date.now() - 15 * 60 * 1000;
  const arr = (fails.get(ip) || []).filter(t => t > cutoff);
  fails.set(ip, arr);
  return arr.length >= 5;
}
function recordFail(ip) {
  const cutoff = Date.now() - 15 * 60 * 1000;
  const arr = (fails.get(ip) || []).filter(t => t > cutoff);
  arr.push(Date.now());
  fails.set(ip, arr);
}

function parseCookies(req) {
  const out = {};
  for (const part of String(req.headers.cookie || '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  }
  return out;
}
function sessionCookie(token, secure) {
  return `ops_session=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${SESSION_TTL_MS / 1000}${secure ? '; Secure' : ''}`;
}

function readBody(req, limit = 10_000) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', c => {
      size += c.length;
      if (size > limit) { reject(new Error('body too large')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString()));
    req.on('error', reject);
  });
}

// ---------- helpers ----------
const execEnv = {
  ...process.env,
  PATH: [
    path.join(os.homedir(), 'opt/node/bin'),
    '/usr/local/bin',
    '/usr/bin',
    '/bin',
    process.env.PATH || '',
  ].filter(Boolean).join(':'),
};

function exec(command, args, timeout = 15000) {
  return new Promise(resolve => execFile(command, args, { timeout, env: execEnv }, (error, stdout, stderr) => resolve({ ok: !error, stdout, stderr })));
}

function humanBytes(n) {
  const u = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let v = Number(n) || 0, i = 0;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(v >= 10 || i === 0 ? 0 : 1)} ${u[i]}`;
}

function humanRate(bps) {
  if (bps == null || !Number.isFinite(bps)) return '—';
  return `${humanBytes(bps)}/s`;
}

function humanUptime(sec) {
  const s = Math.floor(Number(sec) || 0);
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

// ---------- collectors ----------
let knownTargets = [];

// Every Host(`...`) rule Traefik is configured with, re-read on each probe cycle.
async function discoverTargets() {
  const files = [path.join(STACK_DIR, 'compose.yml')];
  for (const entry of await readdir(STACK_DIR, { withFileTypes: true }).catch(() => [])) {
    if (entry.isDirectory()) files.push(path.join(STACK_DIR, entry.name, 'compose.yml'));
  }
  const dynamic = path.join(STACK_DIR, 'traefik/dynamic');
  for (const name of await readdir(dynamic).catch(() => [])) {
    if (/\.(ya?ml|toml)$/.test(name)) files.push(path.join(dynamic, name));
  }
  const hosts = new Set();
  for (const file of files) {
    const text = await readFile(file, 'utf8').catch(() => '');
    for (const line of text.split('\n')) {
      if (/^\s*#/.test(line)) continue;
      for (const m of line.matchAll(/Host\(\s*`([a-z0-9.-]+)`\s*\)/gi)) {
        const host = m[1].toLowerCase();
        if (!host.startsWith('www.')) hosts.add(host);
      }
    }
  }
  if (hosts.size) {
    knownTargets = [...hosts]
      .sort((a, b) => a.split('.').length - b.split('.').length || a.localeCompare(b))
      .map(host => [prettyNames[host] || host, `https://${host}`]);
  }
  return knownTargets;
}

async function serviceProbes() {
  const targets = await discoverTargets();
  return Promise.all(targets.map(async ([name, url]) => {
    const started = Date.now();
    try {
      const response = await fetch(url, { signal: AbortSignal.timeout(8000), redirect: 'manual' });
      return { name, url, status: response.status, ok: response.status > 0 && response.status < 500, latency: Date.now() - started };
    } catch (error) {
      return { name, url, status: 0, ok: false, latency: Date.now() - started, error: error.message };
    }
  }));
}

async function usage() {
  const r = await exec(CCU, ['daily', '--json'], 90000);
  if (!r.ok) return { error: r.stderr.trim().split('\n')[0] || 'ccusage failed' };
  let j;
  try { j = JSON.parse(r.stdout); } catch { return { error: 'Invalid ccusage JSON' }; }
  const num = v => Number(v || 0);
  const days = (j.daily || []).map(d => ({
    period: d.period,
    cost: num(d.totalCost),
    in: num(d.inputTokens),
    out: num(d.outputTokens),
    cacheRead: num(d.cacheReadTokens),
    cacheCreate: num(d.cacheCreationTokens),
    models: (d.modelBreakdowns || [])
      .map(m => ({
        model: m.modelName || 'unknown',
        cost: num(m.cost),
        in: num(m.inputTokens),
        out: num(m.outputTokens),
        cacheRead: num(m.cacheReadTokens),
      }))
      .sort((a, b) => b.cost - a.cost),
  }));
  const models = {};
  for (const d of days) {
    for (const m of d.models) {
      const e = models[m.model] ??= { model: m.model, cost: 0, in: 0, out: 0, cacheRead: 0 };
      e.cost += m.cost;
      e.in += m.in;
      e.out += m.out;
      e.cacheRead += m.cacheRead;
    }
  }
  const today = new Date().toISOString().slice(0, 10);
  const todayRow = days.find(d => d.period === today) || null;
  return {
    days: days.slice(-30),
    models: Object.values(models).sort((a, b) => b.cost - a.cost),
    totalCost: days.reduce((a, b) => a + b.cost, 0),
    today,
    todayRow,
  };
}

async function readCpuSample() {
  const text = await readFile('/proc/stat', 'utf8');
  const line = text.split('\n').find(l => l.startsWith('cpu '));
  if (!line) return null;
  const parts = line.trim().split(/\s+/).slice(1).map(Number);
  const idle = (parts[3] || 0) + (parts[4] || 0);
  const total = parts.reduce((a, b) => a + b, 0);
  return { idle, total };
}

async function memInfo() {
  const text = await readFile('/proc/meminfo', 'utf8');
  const get = key => {
    const m = text.match(new RegExp(`^${key}:\\s+(\\d+)`, 'm'));
    return m ? Number(m[1]) * 1024 : 0;
  };
  const total = get('MemTotal');
  const available = get('MemAvailable') || get('MemFree');
  const used = Math.max(0, total - available);
  return { total, used, available, pct: total ? (used / total) * 100 : 0 };
}

async function diskInfo(mount = '/') {
  const s = await statfs(mount);
  const total = Number(s.blocks) * Number(s.bsize);
  const available = Number(s.bavail) * Number(s.bsize);
  const used = Math.max(0, Number(s.blocks - s.bfree) * Number(s.bsize));
  const denom = used + available;
  return { mount, total, used, available, pct: denom ? (used / denom) * 100 : 0 };
}

async function netInfo() {
  const text = await readFile('/proc/net/dev', 'utf8');
  const skip = new Set(['lo', 'docker0']);
  let best = null;
  for (const line of text.split('\n').slice(2)) {
    if (!line.includes(':')) continue;
    const [rawName, rest] = line.split(':');
    const name = rawName.trim();
    if (!name || skip.has(name) || name.startsWith('veth') || name.startsWith('br-') || name.startsWith('podman')) continue;
    const parts = rest.trim().split(/\s+/).map(Number);
    if (parts.length < 9) continue;
    const row = { iface: name, rx: parts[0], tx: parts[8], at: Date.now() };
    if (name === 'eth0' || name.startsWith('en')) return row;
    if (!best) best = row;
  }
  return best;
}

// ---------- cache + SSE ----------
const cache = {
  services: [],
  usage: { warming: true },
  host: null,
  agents: {},
  meta: { hostAt: null, probesAt: null, usageAt: null },
};

const sseClients = new Set();
let cachedCpuPct = null;
let prevCpuSample = null;
let prevNet = null;
let probesRunning = false;
let usageRunning = false;
const agentsRunning = new Set();
let lastViewerAt = 0;

function viewersActive() {
  return sseClients.size > 0 || (Date.now() - lastViewerAt) < 60_000;
}

function snapshot() {
  return {
    at: new Date().toISOString(),
    services: cache.services,
    usage: cache.usage,
    host: cache.host,
    agents: cache.agents,
    meta: { ...cache.meta, viewers: sseClients.size },
  };
}

function broadcast(event, data) {
  if (!sseClients.size) return;
  const payload = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const res of [...sseClients]) {
    try { res.write(payload); }
    catch { sseClients.delete(res); try { res.end(); } catch {} }
  }
}

async function refreshHost() {
  try {
    const curCpu = await readCpuSample();
    if (curCpu) {
      if (prevCpuSample) {
        const idle = curCpu.idle - prevCpuSample.idle;
        const total = curCpu.total - prevCpuSample.total;
        if (total > 0) cachedCpuPct = Math.max(0, Math.min(100, (1 - idle / total) * 100));
      }
      prevCpuSample = curCpu;
    }

    const [mem, disk, net] = await Promise.all([memInfo(), diskInfo('/'), netInfo()]);
    let rxRate = null, txRate = null;
    if (net && prevNet && prevNet.iface === net.iface && net.at > prevNet.at) {
      const dt = (net.at - prevNet.at) / 1000;
      if (dt > 0) {
        rxRate = Math.max(0, (net.rx - prevNet.rx) / dt);
        txRate = Math.max(0, (net.tx - prevNet.tx) / dt);
      }
    }
    if (net) prevNet = net;

    const load = os.loadavg();
    const cpus = os.cpus()?.length || 1;
    cache.host = {
      hostname: os.hostname(),
      platform: `${os.type()} ${os.release()} · ${os.arch()}`,
      uptimeSec: os.uptime(),
      uptime: humanUptime(os.uptime()),
      cpus,
      load: { m1: load[0], m5: load[1], m15: load[2] },
      cpu: { pct: cachedCpuPct == null ? null : Number(cachedCpuPct.toFixed(1)), cores: cpus },
      mem: {
        total: mem.total,
        used: mem.used,
        available: mem.available,
        pct: Number(mem.pct.toFixed(1)),
        totalLabel: humanBytes(mem.total),
        usedLabel: humanBytes(mem.used),
        availableLabel: humanBytes(mem.available),
      },
      disk: {
        mount: disk.mount,
        total: disk.total,
        used: disk.used,
        available: disk.available,
        pct: Number(disk.pct.toFixed(1)),
        totalLabel: humanBytes(disk.total),
        usedLabel: humanBytes(disk.used),
        availableLabel: humanBytes(disk.available),
      },
      net: net ? {
        iface: net.iface,
        rx: net.rx,
        tx: net.tx,
        rxLabel: humanBytes(net.rx),
        txLabel: humanBytes(net.tx),
        rxRate,
        txRate,
        rxRateLabel: humanRate(rxRate),
        txRateLabel: humanRate(txRate),
      } : null,
    };
    cache.meta.hostAt = new Date().toISOString();
    broadcast('host', cache.host);
  } catch (e) {
    console.error('host refresh failed:', e.message);
  }
}

function labelHost(raw) {
  const { mem, disk, net } = raw;
  return {
    ...raw,
    uptime: humanUptime(raw.uptimeSec),
    mem: { ...mem, totalLabel: humanBytes(mem.total), usedLabel: humanBytes(mem.used), availableLabel: humanBytes(mem.available) },
    disk: { ...disk, totalLabel: humanBytes(disk.total), usedLabel: humanBytes(disk.used), availableLabel: humanBytes(disk.available) },
    net: net ? {
      ...net,
      rxLabel: humanBytes(net.rx),
      txLabel: humanBytes(net.tx),
      rxRateLabel: humanRate(net.rxRate),
      txRateLabel: humanRate(net.txRate),
    } : null,
  };
}

async function refreshAgent({ id, url, token }) {
  if (agentsRunning.has(id)) return;
  agentsRunning.add(id);
  try {
    if (!token) throw new Error('agent token file missing');
    const r = await fetch(url, {
      headers: { authorization: `Bearer ${token}` },
      signal: AbortSignal.timeout(4000),
    });
    if (!r.ok) throw new Error(`agent returned HTTP ${r.status}`);
    cache.agents[id] = { ok: true, host: labelHost(await r.json()), lastSeen: new Date().toISOString() };
  } catch (e) {
    cache.agents[id] = { ok: false, error: e.message, lastSeen: cache.agents[id]?.lastSeen || null };
  } finally {
    agentsRunning.delete(id);
  }
  broadcast('agent', { id, agent: cache.agents[id] });
}

function refreshAgents() {
  for (const config of agentConfigs) refreshAgent(config);
}

async function refreshProbes() {
  if (probesRunning) return;
  probesRunning = true;
  try {
    cache.services = await serviceProbes();
    cache.meta.probesAt = new Date().toISOString();
    broadcast('probes', { services: cache.services, probesAt: cache.meta.probesAt });
  } catch (e) {
    console.error('probes refresh failed:', e.message);
  } finally {
    probesRunning = false;
  }
}

async function refreshUsage(force = false) {
  if (usageRunning) return;
  const age = cache.meta.usageAt ? Date.now() - Date.parse(cache.meta.usageAt) : Infinity;
  if (!force && age < USAGE_MS * 0.9) return;
  usageRunning = true;
  try {
    cache.usage = await usage();
    cache.meta.usageAt = new Date().toISOString();
    broadcast('usage', { usage: cache.usage, usageAt: cache.meta.usageAt });
  } catch (e) {
    console.error('usage refresh failed:', e.message);
    if (!cache.usage || cache.usage.warming) cache.usage = { error: e.message };
  } finally {
    usageRunning = false;
  }
}

function schedule(fn, ms) {
  const id = setInterval(fn, ms);
  id.unref?.();
  return id;
}

// Warm cache immediately, then keep it fresh in the background.
await refreshHost();
refreshAgents();
refreshProbes();
refreshUsage(true);

schedule(refreshHost, HOST_MS);
schedule(() => {
  if (!viewersActive() && Object.keys(cache.agents).length) return;
  refreshAgents();
}, AGENT_MS);
schedule(() => {
  // Skip probe cycles when nobody has viewed recently (still keep host sampling).
  if (!viewersActive() && cache.meta.probesAt) return;
  refreshProbes();
}, PROBES_MS);
schedule(() => {
  if (!viewersActive() && cache.meta.usageAt) return;
  refreshUsage(false);
}, 60_000);

// ---------- http ----------
const loginHtml = await readFile(path.join(root, 'login.html'), 'utf8');
const dashHtml = await readFile(path.join(root, 'index.html'), 'utf8');

const server = http.createServer(async (req, res) => {
  try {
    const secure = String(req.headers['x-forwarded-proto'] || '').includes('https')
      || String(req.headers['cf-visitor'] || '').includes('https');
    res.setHeader('x-frame-options', 'DENY');
    res.setHeader('x-content-type-options', 'nosniff');
    res.setHeader('referrer-policy', 'no-referrer');
    if (secure) res.setHeader('strict-transport-security', 'max-age=31536000');
    const cookies = parseCookies(req);
    const authed = checkToken(cookies.ops_session);
    const url = new URL(req.url, 'http://localhost');

    if (req.method === 'POST' && url.pathname === '/api/login') {
      const ip = clientIp(req);
      const deny = () => { res.writeHead(429, { 'content-type': 'application/json' }); res.end(JSON.stringify({ error: 'Too many attempts — locked for ~15 minutes.' })); };
      if (tooManyFails(ip)) return deny();
      const body = await readBody(req);
      let password = '', username = '';
      try { const b = JSON.parse(body); password = String(b.password || ''); username = String(b.username || ''); } catch {}
      if (username && username === USERNAME && password && verifyPassword(password)) {
        res.setHeader('Set-Cookie', sessionCookie(makeToken(), secure));
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ ok: true }));
        console.log(`login OK from ${ip}`);
      } else {
        recordFail(ip);
        await new Promise(r => setTimeout(r, 300));
        res.writeHead(401, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'Wrong password.' }));
        console.log(`login FAIL from ${ip}`);
      }
      return;
    }

    if (req.method === 'POST' && url.pathname === '/api/logout') {
      res.setHeader('Set-Cookie', 'ops_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0');
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ ok: true }));
      return;
    }

    if (!authed) {
      if (url.pathname.startsWith('/api/')) {
        res.writeHead(401, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'unauthorized' }));
      } else {
        res.writeHead(200, { 'content-type': 'text/html' });
        res.end(loginHtml);
      }
      return;
    }

    lastViewerAt = Date.now();

    // Instant cache read — never triggers collectors.
    if (url.pathname === '/api/snapshot') {
      res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' });
      res.end(JSON.stringify(snapshot()));
      return;
    }

    if (url.pathname === '/api/stream') {
      res.writeHead(200, {
        'content-type': 'text/event-stream',
        'cache-control': 'no-cache, no-transform',
        connection: 'keep-alive',
        'x-accel-buffering': 'no',
      });
      if (typeof res.flushHeaders === 'function') res.flushHeaders();
      res.write(': connected\n\n');
      res.write(`event: snapshot\ndata: ${JSON.stringify(snapshot())}\n\n`);
      sseClients.add(res);
      // If usage is stale and a viewer just connected, refresh in background.
      const usageAge = cache.meta.usageAt ? Date.now() - Date.parse(cache.meta.usageAt) : Infinity;
      if (usageAge > USAGE_STALE_MS) refreshUsage(true);
      if (!cache.meta.probesAt) refreshProbes();
      refreshAgents();

      const heartbeat = setInterval(() => {
        try { res.write(': ping\n\n'); } catch { clearInterval(heartbeat); }
      }, 25000);
      heartbeat.unref?.();

      req.on('close', () => {
        clearInterval(heartbeat);
        sseClients.delete(res);
      });
      return;
    }

    if (url.pathname === '/' || url.pathname === '/index.html') {
      res.writeHead(200, { 'content-type': 'text/html' });
      res.end(dashHtml);
      return;
    }
    res.writeHead(404);
    res.end('not found');
  } catch (error) {
    res.writeHead(500, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ error: error.message }));
  }
});

server.keepAliveTimeout = 65_000;
server.headersTimeout = 70_000;
const bindHost = process.env.HOST || '127.0.0.1';
server.listen(port, bindHost, () => console.log(`observability dashboard listening on http://${bindHost}:${port}`));
