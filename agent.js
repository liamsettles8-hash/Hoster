#!/usr/bin/env node
// MCHost agent - run with:  node agent.js   (Node 18 or newer)
// Runs and manages Minecraft servers on this PC: downloads Java and the server jar,
// starts and stops servers. Create servers from the web panel; this does the rest.

const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const net = require('net');
const { spawn, execFileSync } = require('child_process');
const { pipeline } = require('stream/promises');
const { Readable } = require('stream');

const DB = 'https://mchost-9516b-default-rtdb.firebaseio.com';
const API_KEY = 'AIzaSyAew9fVw91DarhE9mUUIy2VZ2sCVxrAX44';
const HOME = __dirname;
const SERVERS = path.join(HOME, 'servers');
const RUNTIME = path.join(HOME, 'runtime');
const CFG_FILE = path.join(HOME, 'agent.json');
fs.mkdirSync(SERVERS, { recursive: true });
fs.mkdirSync(RUNTIME, { recursive: true });

// ---------- config ----------
let cfg = { aid: '', uid: '', refreshToken: '', owner: '', ownerEmail: '', users: {}, servers: {} };
try { Object.assign(cfg, JSON.parse(fs.readFileSync(CFG_FILE, 'utf8'))); } catch {}
if (!cfg.servers) cfg.servers = {};
if (!cfg.users) cfg.users = {};
// limits for everyone except the admin (you). Edit agent.json to change them.
cfg.limits = Object.assign({ maxServersPerUser: 3, maxRamMb: 4096 }, cfg.limits || {});
// There is exactly one host and it always has this ID. The web panel uses the same ID.
const AID = cfg.aid = 'main';
cfg.ports = Object.assign({ min: 25565, max: 25700 }, cfg.ports || {});
const saveCfg = () => fs.writeFileSync(CFG_FILE, JSON.stringify(cfg, null, 2));

const sleep = ms => new Promise(r => setTimeout(r, ms));
const UA = { 'User-Agent': 'mchost-agent/2.0' };
const getJson = async u => {
  const r = await fetch(u, { headers: UA });
  if (!r.ok) throw new Error(`${u} -> HTTP ${r.status}`);
  return r.json();
};

// ---------- Firebase sign-in ----------
let UID = cfg.uid, idToken = '', tokenExp = 0, refreshing = null;
async function authCall(url, body, form) {
  const r = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': form ? 'application/x-www-form-urlencoded' : 'application/json' },
    body: form ? new URLSearchParams(body).toString() : JSON.stringify(body)
  });
  const j = await r.json();
  if (!r.ok) throw new Error((j.error && j.error.message) || 'Sign-in failed');
  return j;
}
function applyToken(tok, refresh, uid, expires) {
  idToken = tok; tokenExp = Date.now() + Number(expires) * 1000;
  if (refresh) cfg.refreshToken = refresh;
  if (uid) UID = cfg.uid = uid;
  saveCfg();
}
// The agent has no account. It gets its own anonymous Firebase identity, which is
// only used to prove to the database that "this is the agent for this host".
async function anonSignUp() {
  const j = await authCall(`https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=${API_KEY}`, { returnSecureToken: true });
  applyToken(j.idToken, j.refreshToken, j.localId, j.expiresIn);
}
async function refreshToken() {
  const j = await authCall(`https://securetoken.googleapis.com/v1/token?key=${API_KEY}`,
    { grant_type: 'refresh_token', refresh_token: cfg.refreshToken }, true);
  applyToken(j.id_token, j.refresh_token, j.user_id, j.expires_in);
}
async function token() {
  if (Date.now() > tokenExp - 300000) {
    refreshing = refreshing || refreshToken().catch(e => console.log('  [!] Could not refresh login: ' + e.message)).finally(() => { refreshing = null; });
    await refreshing;
  }
  return idToken;
}
async function login() {
  if (cfg.refreshToken) {
    try { await refreshToken(); return; } catch (e) { console.log('  Saved agent identity expired: ' + e.message); }
  }
  try { await anonSignUp(); }
  catch (e) {
    console.log('\n  [!] Could not create the agent identity: ' + e.message);
    console.log('      In the Firebase console open Authentication > Sign-in method and enable "Anonymous".\n');
    process.exit(1);
  }
}

// ---------- database helpers (REST, acts as the signed-in owner) ----------
let warned = false;
async function db(method, p, body) {
  try {
    const r = await fetch(`${DB}/${p}.json?auth=${await token()}`, { method, body: body === undefined ? undefined : JSON.stringify(body) });
    if (!r.ok) {
      if (!warned) {
        warned = true;
        console.log(`\n  [!] Firebase refused ${method} ${p} (HTTP ${r.status}): ${(await r.text()).slice(0, 160)}`);
        console.log('      Check the database rules from the setup notes.\n');
      }
      return null;
    }
    warned = false;
    return method === 'GET' ? r.json() : true;
  } catch (e) {
    if (!warned) { warned = true; console.log('\n  [!] Cannot reach Firebase: ' + e.message + '\n'); }
    return null;
  }
}
const h = p => `agents/${AID}/${p}`;
const put = (p, v) => db('PUT', h(p), v);
const del = p => db('DELETE', h(p));
const get = p => db('GET', h(p));

// ---------- RAM allocation ----------
const S = {}; // running state per server id
const totalMb = () => Math.floor(os.totalmem() / 1048576);
const committedMb = () => Object.values(S).reduce((a, s) => a + (s.proc ? s.xmx : 0), 0);
const freeMb = () => process.platform === 'darwin' ? totalMb() - 2048 - committedMb() : Math.floor(os.freemem() / 1048576);
// what a new server can get: never more than total - reserve - already promised, and never more than what is really free
const availMb = () => Math.min(totalMb() - 1024 - committedMb(), freeMb() - 1024);
function allocate(c) {
  const avail = availMb(), q = n => Math.floor(n / 64) * 64;
  if (c.mode === 'auto') {
    if (avail < c.minRam) throw new Error(`Not enough free RAM. This server needs at least ${c.minRam} MB and only ${Math.max(avail, 0)} MB is available right now.`);
    return q(Math.min(c.maxRam, avail));
  }
  if (avail < c.maxRam) throw new Error(`Not enough free RAM. This server is set to ${c.maxRam} MB and only ${Math.max(avail, 0)} MB is available right now.`);
  return c.maxRam;
}

// ---------- per-server state ----------
const cs = s => cfg.servers[s.id];
function mkServer(id) {
  const s = { id, dir: path.join(SERVERS, id), proc: null, state: 'offline', task: '', xmx: 0, lines: [], dirty: false, seen: new Set() };
  fs.mkdirSync(s.dir, { recursive: true });
  return (S[id] = s);
}
function pushMeta(id) {
  const c = cfg.servers[id];
  put(`servers/${id}/meta`, { name: c.name, kind: c.kind, version: c.version, mode: c.mode, minRam: c.minRam, maxRam: c.maxRam, port: c.port, ownerEmail: c.ownerEmail || '' });
  put(`index/${id}`, c.name);
}
function pushStatus(s) { put(`servers/${s.id}/status`, { state: s.state, task: s.task, xmx: s.proc ? s.xmx : 0 }); }
function setState(s, st, t = '') { s.state = st; s.task = t; pushStatus(s); }
function setTask(s, t) { s.task = t; pushStatus(s); }
function log(s, text) {
  for (const l of String(text).split(/\r?\n/)) if (l.length) s.lines.push(l);
  if (s.lines.length > 150) s.lines = s.lines.slice(-150);
  s.dirty = true;
}
setInterval(() => {
  for (const s of Object.values(S)) if (s.dirty) { s.dirty = false; put(`servers/${s.id}/console`, { t: Date.now(), text: s.lines.join('\n') }); }
}, 700);
function heartbeat() {
  put('info', { name: os.hostname(), owner: cfg.ownerEmail || '', platform: `${os.platform()} ${os.arch()}`, ts: { '.sv': 'timestamp' } });
  put('stats', { totalMb: totalMb(), freeMb: Math.max(0, freeMb()), committedMb: committedMb(), availMb: Math.max(0, availMb()) });
}

// ---------- downloading ----------
async function download(s, url, dest, label) {
  const r = await fetch(url, { headers: UA });
  if (!r.ok) throw new Error(`Download failed (HTTP ${r.status})`);
  const total = Number(r.headers.get('content-length')) || 0;
  let got = 0, last = 0;
  const body = Readable.fromWeb(r.body);
  body.on('data', c => {
    got += c.length;
    if (Date.now() - last > 800) {
      last = Date.now();
      setTask(s, total ? `${label} ${Math.round(got / total * 100)}%` : `${label} ${(got / 1048576).toFixed(0)} MB`);
    }
  });
  await pipeline(body, fs.createWriteStream(dest));
}

// ---------- Java ----------
function javaFor(version) {
  const p = String(version || '').split('.').map(Number);
  const minor = p[1] || 21, patch = p[2] || 0;
  if (minor <= 16) return 8;
  if (minor <= 19) return 17;
  if (minor === 20) return patch >= 5 ? 21 : 17;
  return 21;
}
// Mojang publishes the Java version each release needs in its official version data.
async function mojangJava(version) {
  const m = await getJson('https://launchermeta.mojang.com/mc/game/version_manifest_v2.json');
  const e = m.versions.find(x => x.id === version);
  if (!e) return null;
  const j = await getJson(e.url);
  return (j.javaVersion && j.javaVersion.majorVersion) || 8;
}
async function resolveJava(s) {
  const c = cs(s);
  setTask(s, `Checking which Java Minecraft ${c.version || ''} needs`);
  let major = null;
  try { major = await mojangJava(c.version); } catch {}
  if (!major) { major = javaFor(c.version); log(s, `[agent] Could not look up Java online, guessing Java ${major}`); }
  if (major === 16) major = 17;
  if (c.javaMin && c.javaMin > major) major = c.javaMin;
  log(s, `[agent] Minecraft ${c.version || '?'} needs Java ${major}`);
  return major;
}
function findJava(dir) {
  const exe = process.platform === 'win32' ? 'java.exe' : 'java';
  const walk = (d, depth) => {
    if (depth > 4 || !fs.existsSync(d)) return null;
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      if (!e.isDirectory()) continue;
      const p = path.join(d, e.name);
      if (e.name === 'bin' && fs.existsSync(path.join(p, exe))) return path.join(p, exe);
      const r = walk(p, depth + 1);
      if (r) return r;
    }
    return null;
  };
  return walk(dir, 0);
}
async function ensureJava(s, major) {
  const dir = path.join(RUNTIME, 'java' + major);
  let bin = findJava(dir);
  if (bin) return bin;
  const plat = { win32: 'windows', linux: 'linux', darwin: 'mac' }[process.platform];
  if (!plat) throw new Error('Unsupported operating system');
  const arch = process.arch === 'arm64' ? 'aarch64' : 'x64';
  const ext = plat === 'windows' ? 'zip' : 'tar.gz';
  fs.rmSync(dir, { recursive: true, force: true });
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(RUNTIME, `java${major}.${ext}`);
  await download(s, `https://api.adoptium.net/v3/binary/latest/${major}/ga/${plat}/${arch}/jre/hotspot/normal/eclipse`, file, `Downloading Java ${major}`);
  setTask(s, `Extracting Java ${major}`);
  execFileSync('tar', ['-xf', file, '-C', dir]);
  fs.rmSync(file, { force: true });
  bin = findJava(dir);
  if (!bin) throw new Error('Java was downloaded but the java binary was not found');
  if (process.platform !== 'win32') fs.chmodSync(bin, 0o755);
  return bin;
}

// ---------- versions ----------
const cmpVer = (a, b) => {
  const x = a.split('.').map(Number), y = b.split('.').map(Number);
  for (let i = 0; i < 3; i++) if ((x[i] || 0) !== (y[i] || 0)) return (y[i] || 0) - (x[i] || 0);
  return 0;
};
async function listVersions(kind) {
  if (kind === 'vanilla') {
    const m = await getJson('https://launchermeta.mojang.com/mc/game/version_manifest_v2.json');
    return m.versions.filter(v => v.type === 'release').map(v => v.id);
  }
  let arr;
  try {
    const j = await getJson('https://fill.papermc.io/v3/projects/paper');
    arr = Array.isArray(j.versions) ? j.versions : Object.values(j.versions).flat();
  } catch { arr = (await getJson('https://api.papermc.io/v2/projects/paper')).versions; }
  return arr.filter(v => /^\d+\.\d+(\.\d+)?$/.test(v)).sort(cmpVer);
}
async function jarUrl(kind, v) {
  if (kind === 'vanilla') {
    const m = await getJson('https://launchermeta.mojang.com/mc/game/version_manifest_v2.json');
    const e = m.versions.find(x => x.id === v);
    if (!e) throw new Error('Unknown version ' + v);
    return (await getJson(e.url)).downloads.server.url;
  }
  try {
    const b = await getJson(`https://fill.papermc.io/v3/projects/paper/versions/${v}/builds/latest`);
    const u = b.downloads && b.downloads['server:default'] && b.downloads['server:default'].url;
    if (u) return u;
  } catch {}
  const j = await getJson(`https://api.papermc.io/v2/projects/paper/versions/${v}`);
  const b = Math.max(...j.builds);
  return `https://api.papermc.io/v2/projects/paper/versions/${v}/builds/${b}/downloads/paper-${v}-${b}.jar`;
}

// ---------- install ----------
async function install(s, kind, version) {
  if (s.proc) throw new Error('Stop the server before installing a version');
  const c = cs(s);
  setState(s, 'installing', 'Preparing');
  try {
    fs.rmSync(path.join(s.dir, 'server.jar'), { force: true });          // delete old server.jar
    const plugins = path.join(s.dir, 'plugins');
    if (fs.existsSync(plugins)) {                                        // plugins -> old_plugins
      let target = path.join(s.dir, 'old_plugins'), n = 2;
      while (fs.existsSync(target)) target = path.join(s.dir, `old_plugins_${n++}`);
      fs.renameSync(plugins, target);
      log(s, `[agent] plugins renamed to ${path.basename(target)}`);
    }
    const url = await jarUrl(kind, version);
    await download(s, url, path.join(s.dir, 'server.jar'), `Downloading ${kind} ${version}`);
    fs.writeFileSync(path.join(s.dir, 'eula.txt'), 'eula=true\n');
    const pf = path.join(s.dir, 'server.properties');
    if (!fs.existsSync(pf)) fs.writeFileSync(pf, `server-port=${c.port}\nquery.port=${c.port}\n`);
    c.kind = kind; c.version = version; c.javaMin = 0; saveCfg(); pushMeta(s.id);
    await ensureJava(s, await resolveJava(s));
    log(s, `[agent] Installed ${kind} ${version}`);
  } finally { setState(s, 'offline'); }
}

// ---------- process control ----------
async function start(s) {
  if (s.proc) throw new Error('Server is already running');
  const c = cs(s);
  if (!fs.existsSync(path.join(s.dir, 'server.jar'))) throw new Error('No server installed yet. Open Versions and install one.');
  setState(s, 'starting', 'Preparing Java');
  let java;
  try { java = await ensureJava(s, await resolveJava(s)); } catch (e) { setState(s, 'offline'); throw e; }
  let xmx;
  try { xmx = allocate(c); } catch (e) { setState(s, 'offline'); throw e; }
  try {
    if (!(await portFree(c.port))) {
      const np = await allocPort(s.id);
      log(s, `[agent] Port ${c.port} is in use on this PC, moving this server to ${np}`);
      c.port = np; saveCfg(); pushMeta(s.id);
    }
    applyPort(s, c.port);
  } catch (e) { setState(s, 'offline'); throw e; }
  log(s, `[agent] Using port ${c.port}`);
  log(s, `[agent] RAM: giving this server ${xmx} MB (${c.mode}, host has ${Math.max(0, availMb())} MB available)`);
  s.xmx = xmx;
  s.proc = spawn(java, [`-Xms${Math.min(xmx, 512)}M`, `-Xmx${xmx}M`, '-jar', 'server.jar', 'nogui'], { cwd: s.dir });
  setState(s, 'starting');
  const onData = d => {
    const t = d.toString();
    log(s, t);
    const need = /(?:class file|major\.minor) version (\d+)/.exec(t);
    if (need && Number(need[1]) > 52) {
      c.javaMin = Number(need[1]) - 44; saveCfg();
      log(s, `[agent] This server needs Java ${c.javaMin} or newer. Start it again and the right Java will be installed.`);
    }
    if (s.state === 'starting' && /Done \(.*\)! For help/.test(t)) setState(s, 'online');
  };
  s.proc.stdout.on('data', onData);
  s.proc.stderr.on('data', onData);
  s.proc.on('error', e => { log(s, '[agent] ' + e.message); s.proc = null; setState(s, 'offline'); });
  s.proc.on('exit', code => { log(s, `[agent] Server process exited (code ${code})`); s.proc = null; setState(s, 'offline'); });
}
const stop = s => { if (!s.proc) throw new Error('Server is not running'); setState(s, 'stopping'); s.proc.stdin.write('stop\n'); };
const kill = s => { if (!s.proc) throw new Error('Server is not running'); s.proc.kill('SIGKILL'); };

// ---------- Modrinth plugins ----------
const LOADERS = {
  paper: ['paper', 'spigot', 'bukkit'], spigot: ['spigot', 'bukkit'], bukkit: ['bukkit'],
  purpur: ['purpur', 'paper', 'spigot', 'bukkit'], folia: ['folia']
};
async function modrinthInstall(s, project, kind, mc) {
  const c = cs(s);
  kind = kind || c.kind; mc = mc || c.version;
  if (!mc) throw new Error('No Minecraft version known. Install a server version first.');
  const loaders = LOADERS[kind];
  if (!loaders) throw new Error(`${kind || 'This server type'} does not support plugins. Install Paper from the Versions tab.`);
  const q = `loaders=${encodeURIComponent(JSON.stringify(loaders))}&game_versions=${encodeURIComponent(JSON.stringify([mc]))}`;
  const vs = await getJson(`https://api.modrinth.com/v2/project/${encodeURIComponent(project)}/version?${q}`);
  if (!vs.length) throw new Error(`No version of this plugin supports ${kind} ${mc}`);
  const v = vs.find(x => x.version_type === 'release') || vs[0];
  const file = v.files.find(f => f.primary) || v.files[0];
  if (!file || !/\.jar$/i.test(file.filename)) throw new Error('This plugin has no .jar download');
  const dir = path.join(s.dir, 'plugins');
  fs.mkdirSync(dir, { recursive: true });
  try { await download(s, file.url, path.join(dir, path.basename(file.filename)), `Downloading ${file.filename}`); }
  finally { setTask(s, ''); }
  let required = [];
  const ids = [...new Set((v.dependencies || []).filter(d => d.dependency_type === 'required' && d.project_id).map(d => d.project_id))];
  if (ids.length) {
    try { required = (await getJson(`https://api.modrinth.com/v2/projects?ids=${encodeURIComponent(JSON.stringify(ids))}`)).map(p => p.title); } catch {}
  }
  log(s, `[agent] Installed plugin ${file.filename} (${v.version_number}) from Modrinth`);
  return { file: file.filename, version: v.version_number, required };
}

// ---------- files ----------
function safe(s, p) {
  const root = path.resolve(s.dir);
  const full = path.resolve(path.join(root, p || ''));
  if (full !== root && !full.startsWith(root + path.sep)) throw new Error('Path is outside the server folder');
  return full;
}

const ramCap = uid => Math.max(512, Math.min(totalMb() - 512, uid === cfg.owner ? Infinity : cfg.limits.maxRamMb));

// ---------- server commands ----------
// who may run what: control / files / versions are permissions a subuser can be given, owner = account owner only
const NEED = {
  start: 'control', stop: 'control', kill: 'control', input: 'control', clear: 'control',
  ls: 'files', read: 'files', write: 'files', mkdir: 'files', delete: 'files', rename: 'files', upload: 'files', modrinth: 'files',
  versions: 'versions', install: 'versions', setconfig: 'owner'
};
async function run(s, c) {
  switch (c.t) {
    case 'start': start(s).catch(e => { log(s, '[agent] ' + e.message); }); return;
    case 'stop': return stop(s);
    case 'kill': return kill(s);
    case 'input':
      if (!s.proc) throw new Error('Server is not running');
      s.proc.stdin.write(String(c.text) + '\n');
      return;
    case 'clear': s.lines = []; s.dirty = true; return;
    case 'setconfig': {
      const k = cs(s);
      const mode = c.mode === 'fixed' ? 'fixed' : 'auto';
      const cap = ramCap(c.uid);
      const max = Math.min(Math.max(512, Math.floor(Number(c.maxRam)) || 2048), cap);
      const min = mode === 'fixed' ? max : Math.min(Math.max(512, Math.floor(Number(c.minRam)) || 1024), max);
      if (c.name && String(c.name).trim()) k.name = String(c.name).trim().slice(0, 40);
      Object.assign(k, { mode, minRam: min, maxRam: max }); saveCfg(); pushMeta(s.id);
      return;
    }
    case 'versions': return listVersions(c.kind);
    case 'install': await install(s, c.kind, c.version); return;
    case 'modrinth': return modrinthInstall(s, c.project, c.kind, c.mc);
    case 'ls': {
      const dir = safe(s, c.path);
      return fs.readdirSync(dir, { withFileTypes: true }).map(e => {
        const st = fs.statSync(path.join(dir, e.name));
        return { name: e.name, dir: e.isDirectory(), size: st.size, mtime: st.mtimeMs };
      }).sort((a, b) => b.dir - a.dir || a.name.localeCompare(b.name));
    }
    case 'read': {
      const f = safe(s, c.path);
      if (fs.statSync(f).size > 1.5 * 1048576) throw new Error('File is too large to edit here (limit 1.5 MB)');
      return fs.readFileSync(f, 'utf8');
    }
    case 'upload': {
      const f = safe(s, c.path);
      fs.mkdirSync(path.dirname(f), { recursive: true });
      fs.writeFileSync(f, Buffer.from([].concat(c.chunks || []).join(''), 'base64'));
      return;
    }
    case 'write': fs.writeFileSync(safe(s, c.path), c.content || ''); return;
    case 'mkdir': fs.mkdirSync(safe(s, c.path), { recursive: true }); return;
    case 'delete': fs.rmSync(safe(s, c.path), { recursive: true, force: true }); return;
    case 'rename': fs.renameSync(safe(s, c.from), safe(s, c.to)); return;
    default: throw new Error('Unknown command ' + c.t);
  }
}
async function authorize(s, c) {
  if (!c.uid) throw new Error('Not signed in');
  if (c.uid === cfg.owner) return;                       // admin: everything
  const k = cs(s);
  if (k && k.owner === c.uid) return;                    // owner of this server: everything on it
  const need = NEED[c.t];
  if (!need || need === 'owner') throw new Error('Only the server owner can do that');
  const p = cfg.users[c.uid] && cfg.users[c.uid].servers && cfg.users[c.uid].servers[s.id];
  if (!p || !p[need]) throw new Error('You do not have permission to do that');
}
async function handle(s, id, c) {
  if (s.seen.has(id) || !c || typeof c !== 'object') return;
  s.seen.add(id);
  let out;
  try { await authorize(s, c); const d = await run(s, c); out = { ok: true, d: d === undefined ? null : d }; }
  catch (e) { out = { ok: false, e: String(e.message || e) }; }
  await put(`servers/${s.id}/res/${id}`, out);
  await del(`servers/${s.id}/cmd/${id}`);
}

// ---------- access list (owner + subusers) ----------
let indexed = new Set();
async function mirrorAcl() {
  // copy of the access list into the database so its security rules can use it
  const acl = {};
  if (cfg.owner) acl[cfg.owner] = { owner: true, email: cfg.ownerEmail || '' };
  for (const [uid, u] of Object.entries(cfg.users)) acl[uid] = { email: u.email || '', servers: u.servers || {} };
  await put('acl', acl);
  const now = new Set(Object.keys(acl));
  for (const uid of now) await db('PUT', `userIndex/${uid}/${AID}`, true);
  for (const uid of indexed) if (!now.has(uid)) await db('DELETE', `userIndex/${uid}/${AID}`);
  indexed = now;
}
// ---------- owner setup ----------
// No claim codes: the person running the agent types their web-account email once.
// The agent looks the account up and makes it the owner. The host then shows up
// by itself in that account's server list.
const ekey = e => e.toLowerCase().replace(/[.#$\[\]\/]/g, ',');
const ask = q => new Promise(res => {
  const rl = require('readline').createInterface({ input: process.stdin, output: process.stdout });
  rl.question(q, a => { rl.close(); res(a.trim()); });
});
async function setupOwner() {
  console.log('  First run: choose the admin account for this host (that is you).');
  console.log('  Create your account on the web panel first, then enter the same email here.\n');
  for (;;) {
    const email = await ask('  Your account email: ');
    if (!email) continue;
    let told = false;
    for (let i = 0; i < 60; i++) {
      const uid = await db('GET', 'emailIndex/' + ekey(email));
      if (uid) {
        cfg.owner = uid; cfg.ownerEmail = email; saveCfg();
        console.log(`\n  Admin is ${email}. Everyone who signs in on the web panel can now create servers that run on this PC.\n`);
        return;
      }
      if (!told) { told = true; console.log('  No account with that email yet. Waiting for you to create it on the web panel (Ctrl+C to quit)...'); }
      await sleep(5000);
    }
  }
}

// ---------- host commands (owner only): servers and users ----------
// Every server gets its own port from cfg.ports (default 25565-25700). A port is skipped if another
// server already has it or if something else on this PC is listening on it.
const portFree = p => new Promise(res => {
  const t = net.createServer();
  t.once('error', () => res(false));
  t.once('listening', () => t.close(() => res(true)));
  t.listen(p, '0.0.0.0');
});
async function allocPort(except) {
  const used = new Set(Object.entries(cfg.servers).filter(([id]) => id !== except).map(([, c]) => c.port));
  for (let p = cfg.ports.min; p <= cfg.ports.max; p++) if (!used.has(p) && await portFree(p)) return p;
  throw new Error(`No free ports left (${cfg.ports.min}-${cfg.ports.max}). Ask the host admin.`);
}
// make server.properties match the port we assigned (it is rewritten on every start)
function applyPort(s, port) {
  const f = path.join(s.dir, 'server.properties');
  let t = fs.existsSync(f) ? fs.readFileSync(f, 'utf8') : '';
  for (const k of ['server-port', 'query.port']) {
    const re = new RegExp(`^${k.replace('.', '\\.')}=.*$`, 'm');
    t = re.test(t) ? t.replace(re, `${k}=${port}`) : (t && !t.endsWith('\n') ? t + '\n' : t) + `${k}=${port}\n`;
  }
  fs.writeFileSync(f, t);
}
async function hostRun(c) {
  const actor = c.uid;
  if (!actor) throw new Error('Not signed in');
  const admin = actor === cfg.owner;
  const manage = sid => {
    const k = cfg.servers[sid];
    if (!k || !S[sid]) throw new Error('Unknown server');
    if (!admin && k.owner !== actor) throw new Error('Only the server owner can do that');
    return k;
  };
  switch (c.t) {
    case 'versions': return listVersions(c.kind);
    case 'create': {
      const name = String(c.name || '').trim().slice(0, 40);
      if (!name) throw new Error('Give the server a name');
      if (!['paper', 'vanilla'].includes(c.kind) || !c.version) throw new Error('Pick a server type and version');
      const count = Object.values(cfg.servers).filter(k => k.owner === actor).length;
      if (!admin && count >= cfg.limits.maxServersPerUser) throw new Error(`You can have at most ${cfg.limits.maxServersPerUser} servers on this host`);
      const cap = ramCap(actor);
      const mode = c.mode === 'fixed' ? 'fixed' : 'auto';
      const max = Math.min(Math.max(512, Math.floor(Number(c.maxRam)) || 2048), cap);
      const min = mode === 'fixed' ? max : Math.min(Math.max(512, Math.floor(Number(c.minRam)) || 1024), max);
      const email = admin ? cfg.ownerEmail : String(c.email || '').slice(0, 120);
      const id = 's' + crypto.randomBytes(5).toString('hex');
      cfg.servers[id] = { name, kind: '', version: '', mode, minRam: min, maxRam: max, port: await allocPort(), javaMin: 0, owner: actor, ownerEmail: email };
      if (!admin) {
        const u = cfg.users[actor] = cfg.users[actor] || { email, servers: {} };
        u.email = email || u.email;
        u.servers[id] = { view: true, control: true, files: true, versions: true, owner: true };
      }
      saveCfg();
      const s = mkServer(id);
      pushMeta(id); pushStatus(s); watchServer(s);
      await mirrorAcl();
      // the agent does the rest: Java, the server jar, then start it
      install(s, c.kind, c.version)
        .then(() => start(s))
        .catch(e => { log(s, '[agent] ' + e.message); });
      return { id };
    }
    case 'members': {
      manage(c.sid);
      return Object.entries(cfg.users)
        .filter(([, u]) => u.servers && u.servers[c.sid] && !u.servers[c.sid].owner)
        .map(([uid, u]) => ({ uid, email: u.email || '', perms: u.servers[c.sid] }));
    }
    case 'adduser': {
      const k = manage(c.sid), t = c.target;
      if (!t) throw new Error('Unknown user');
      if (t === cfg.owner || t === k.owner) throw new Error('That account already owns this server');
      const u = cfg.users[t] = cfg.users[t] || { email: '', servers: {} };
      u.email = String(c.email || u.email || '');
      const p = c.perms || {};
      u.servers[c.sid] = { view: true, control: !!p.control, files: !!p.files, versions: !!p.versions };
      saveCfg(); await mirrorAcl(); return;
    }
    case 'setperm': {
      manage(c.sid);
      const u = cfg.users[c.target];
      if (!u || !u.servers[c.sid] || u.servers[c.sid].owner || !['control', 'files', 'versions'].includes(c.key)) throw new Error('Unknown user or permission');
      u.servers[c.sid][c.key] = !!c.value; saveCfg(); await mirrorAcl(); return;
    }
    case 'removeuser': {
      manage(c.sid);
      const u = cfg.users[c.target];
      if (u && u.servers[c.sid] && !u.servers[c.sid].owner) {
        delete u.servers[c.sid];
        if (!Object.keys(u.servers).length) delete cfg.users[c.target];
        saveCfg(); await mirrorAcl();
      }
      return;
    }
    case 'delete': {
      manage(c.id);
      const s = S[c.id];
      if (s.proc) { s.proc.kill('SIGKILL'); await sleep(500); }
      delete S[c.id]; delete cfg.servers[c.id];
      for (const [uid, u] of Object.entries(cfg.users)) {
        if (u.servers) delete u.servers[c.id];
        if (!Object.keys(u.servers || {}).length) delete cfg.users[uid];
      }
      saveCfg();
      fs.rmSync(s.dir, { recursive: true, force: true });
      await del(`servers/${c.id}`); await del(`index/${c.id}`);
      await mirrorAcl();
      return;
    }
    default: throw new Error('Unknown command ' + c.t);
  }
}
const hseen = new Set();
async function hostHandle(id, c) {
  if (hseen.has(id) || !c || typeof c !== 'object') return;
  hseen.add(id);
  let out;
  try { const d = await hostRun(c); out = { ok: true, d: d === undefined ? null : d }; }
  catch (e) { out = { ok: false, e: String(e.message || e) }; }
  await put('hres/' + id, out);
  await del('hcmd/' + id);
}

// ---------- listening to Firebase (server-sent events) ----------
function watch(p, alive, onItem) {
  (async () => {
    while (alive()) {
      const ac = new AbortController();
      let timer;
      const bump = () => { clearTimeout(timer); timer = setTimeout(() => ac.abort(), 70000); };
      const renew = setTimeout(() => ac.abort(), 45 * 60 * 1000); // reconnect before the login token expires
      try {
        bump();
        const r = await fetch(`${DB}/${p}.json?auth=${await token()}`, { headers: { Accept: 'text/event-stream' }, signal: ac.signal });
        const dec = new TextDecoder();
        let buf = '';
        for await (const chunk of r.body) {
          bump();
          buf += dec.decode(chunk, { stream: true });
          let i;
          while ((i = buf.indexOf('\n\n')) >= 0) {
            const block = buf.slice(0, i); buf = buf.slice(i + 2);
            const ev = (/^event: (.+)$/m.exec(block) || [])[1];
            const raw = (/^data: (.+)$/m.exec(block) || [])[1];
            if (ev === 'auth_revoked' || ev === 'cancel') { ac.abort(); continue; }
            if ((ev !== 'put' && ev !== 'patch') || !raw) continue;
            const { path: pp, data } = JSON.parse(raw);
            if (!data) continue;
            if (pp === '/') for (const [id, c] of Object.entries(data)) onItem(id, c);
            else if (/^\/[^/]+$/.test(pp)) onItem(pp.slice(1), data);
          }
        }
      } catch {}
      clearTimeout(timer); clearTimeout(renew);
      if (alive()) await sleep(3000);
    }
  })();
}
async function watchServer(s) {
  await del(`servers/${s.id}/cmd`); await del(`servers/${s.id}/res`);
  watch(h(`servers/${s.id}/cmd`), () => S[s.id] === s, (id, c) => handle(s, id, c));
}

// ---------- boot ----------
async function main() {
  console.log('\n  MCHost agent');
  if (process.argv.includes('--reset-owner')) { cfg.owner = ''; cfg.ownerEmail = ''; console.log('  Owner cleared.'); }
  saveCfg();
  await login();
  // only one agent may run: refuse to start if another one owns this host or is already online
  const other = await get('agentUid'), beat = await get('info/ts');
  const force = process.argv.includes('--takeover');
  if (!force && other && other !== UID) { console.log('\n  [!] Another agent already owns this host. If that is an old install of yours, run: node agent.js --takeover\n'); process.exit(1); }
  if (!force && typeof beat === 'number' && Date.now() - beat < 15000) { console.log('\n  [!] An agent is already running for this host (or stopped less than 15 s ago). Wait a moment, or run --takeover.\n'); process.exit(1); }
  await put('agentUid', UID);
  if (!cfg.owner) await setupOwner();
  console.log('');
  console.log(`  Admin:       ${cfg.ownerEmail}  (can see and manage every server)`);
  console.log(`  Ports:       ${cfg.ports.min}-${cfg.ports.max}, one per server (forward them on your router)`);
  console.log(`  Limits:      ${cfg.limits.maxServersPerUser} servers and ${cfg.limits.maxRamMb} MB per server for other users (edit agent.json)`);
  console.log(`  Servers in:  ${SERVERS}\n`);
  for (const id of Object.keys(cfg.servers)) {
    const s = mkServer(id);
    pushMeta(id); pushStatus(s);
    log(s, '[agent] Connected.');
    watchServer(s);
  }
  await mirrorAcl();
  await del('hcmd'); await del('hres');
  heartbeat(); setInterval(heartbeat, 5000);
  watch(h('hcmd'), () => true, hostHandle);
}
main().catch(e => { console.log('Fatal: ' + e.message); process.exit(1); });

async function shutdown() {
  console.log('\nShutting down...');
  const running = Object.values(S).filter(s => s.proc);
  running.forEach(s => s.proc.stdin.write('stop\n'));
  await Promise.race([Promise.all(running.map(s => new Promise(r => s.proc ? s.proc.on('exit', r) : r()))), sleep(25000)]);
  running.forEach(s => s.proc && s.proc.kill('SIGKILL'));
  await put('info', { name: os.hostname(), ts: 0 });
  process.exit(0);
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
