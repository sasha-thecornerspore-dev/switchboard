// Switchboard — Tailscale Share Manager
// Single-file Node.js app. Run: node switchboard.js
// Opens UI at http://127.0.0.1:18800/

const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { spawn, exec, execFile } = require("child_process");
const os = require("os");
const { CloudflareTunnel, installCloudflared } = require("./cloudflare");
const { OpnsenseClient } = require("./opnsense");

const PORT = process.env.SWITCHBOARD_PORT ? parseInt(process.env.SWITCHBOARD_PORT, 10) : 18800;
const HERE = __dirname;
// DATA_DIR holds writable state (config, users, logs). Defaults to the code
// directory for a standalone `node switchboard.js` run, but the packaged
// Electron app points it at the per-user app-data folder via env, because the
// code itself lives in a read-only resources directory once installed.
const DATA_DIR = process.env.SWITCHBOARD_DATA_DIR || HERE;
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
const CONFIG_PATH = path.join(DATA_DIR, "switchboard-config.json");
const USERS_PATH = path.join(DATA_DIR, "switchboard-users.json");
const SETTINGS_PATH = path.join(DATA_DIR, "switchboard-settings.json");
const FIRSTRUN_PW_PATH = path.join(DATA_DIR, "FIRST-RUN-ADMIN-PASSWORD.txt");
const SHARE_SERVER = path.join(HERE, "share-server.js");
const LOG_DIR = path.join(DATA_DIR, "logs");
if (!fs.existsSync(LOG_DIR)) fs.mkdirSync(LOG_DIR, { recursive: true });

// Tailscale CLI differs by OS. Windows ships it under Program Files; macOS/Linux
// expose `tailscale` on PATH (or the standard macOS app bundle path).
const TAILSCALE = process.platform === "win32"
  ? `"${process.env.PROGRAMFILES}\\Tailscale\\tailscale.exe"`
  : (fs.existsSync("/Applications/Tailscale.app/Contents/MacOS/Tailscale")
      ? `"/Applications/Tailscale.app/Contents/MacOS/Tailscale"`
      : "tailscale");

// ============================== STATE ==============================
let state = {
  tailnetHost: null,           // e.g. my-host.tailXXXX.ts.net
  tailnetIPv4: null,           // e.g. 100.x.x.x
  backendState: "Unknown",     // Tailscale BackendState: Running | Stopped | Starting | NeedsLogin | Unreachable
  lanIPv4: null,               // best-guess LAN address of this machine (for proxy origins)
  shares: [],                  // [{id, name, root, localPort, tailscalePort, mode, method, bind, proxyHost, pid, logFile, createdAt}]
  recentHits: [],              // last 50 hits across all shares
};

// ============================== PUBLISH METHODS ==============================
// Each share is published one of three ways:
//   tailscale — tailscale serve/funnel fronts the local share-server (the
//               original behaviour; `mode` picks tailnet-only vs public Funnel)
//   proxy     — Switchboard only runs the share-server; YOUR reverse proxy
//               (nginx / Apache / OPNsense os-nginx) fronts it. The dashboard
//               hands you ready-to-paste config for the origin it's listening on.
//   cloudflare — a Cloudflare Tunnel fronts the share-server. With an API token
//               configured in Settings it's a stable hostname on your zone via
//               one managed named tunnel; without one it's a throwaway
//               https://*.trycloudflare.com quick tunnel.
//   local     — just the share-server on localhost/LAN, nothing published.
// `bind` is the share-server listen address: 127.0.0.1 (same-machine proxy or
// Tailscale) or 0.0.0.0 (LAN — required for a proxy on another box).
const METHODS = ["tailscale", "proxy", "cloudflare", "local"];
const BIND_LOCAL = "127.0.0.1";
const BIND_LAN = "0.0.0.0";
function normalizeShare(s) {
  if (!METHODS.includes(s.method)) s.method = "tailscale";   // pre-method configs are Tailscale shares
  s.bind = s.bind === BIND_LAN ? BIND_LAN : BIND_LOCAL;
  if (typeof s.proxyHost !== "string") s.proxyHost = "";
  if (!["public", "tailnet"].includes(s.mode)) s.mode = "tailnet";
  return s;
}
function usesTailscale(s) { return s.method === "tailscale"; }
function usesCloudflare(s) { return s.method === "cloudflare"; }

// ============================== SETTINGS ==============================
// Integration credentials (Cloudflare API token, OPNsense API key) live in
// switchboard-settings.json — gitignored, admin-only, never sent to the UI in
// full (see settingsForUi).
let settings = { cloudflare: {}, opnsense: {} };
function loadSettings() {
  try {
    const raw = JSON.parse(fs.readFileSync(SETTINGS_PATH, "utf8"));
    settings = { cloudflare: raw.cloudflare || {}, opnsense: raw.opnsense || {} };
  } catch { settings = { cloudflare: {}, opnsense: {} }; }
}
function saveSettings() { fs.writeFileSync(SETTINGS_PATH, JSON.stringify(settings, null, 2)); }
function hint(secret) { return secret ? "…" + String(secret).slice(-4) : null; }
function settingsForUi() {
  const c = settings.cloudflare || {}, o = settings.opnsense || {};
  return {
    cloudflare: { accountId: c.accountId || "", zoneName: c.zoneName || "", zoneId: c.zoneId || null, apiTokenSet: !!c.apiToken, apiTokenHint: hint(c.apiToken), tunnelId: c.tunnelId || null, tunnelName: c.tunnelName || null },
    opnsense: { url: o.url || "", key: o.key || "", secretSet: !!o.secret, secretHint: hint(o.secret), insecure: o.insecure !== false, certs: o.certs || [], version: o.version || null, lastTestAt: o.lastTestAt || null },
  };
}
const cf = new CloudflareTunnel({ getSettings: () => settings.cloudflare, saveSettings, log: console.log });
function opnsenseClient() { const o = settings.opnsense || {}; return new OpnsenseClient({ url: o.url, key: o.key, secret: o.secret, insecure: o.insecure !== false }); }

// Interfaces that carry an IPv4 but are useless as a proxy origin: Hyper-V /
// WSL virtual switches, VM host adapters, Docker bridges, Tailscale itself.
const VIRTUAL_IFACE = /vEthernet|WSL|Hyper-V|Default Switch|VirtualBox|VMware|vmnet|docker|^br-|^veth|Loopback|Tailscale|ZeroTier|Npcap|Bluetooth|utun|tun\d|tap\d/i;
function detectLanIPv4() {
  const cands = [];
  for (const [name, addrs] of Object.entries(os.networkInterfaces())) {
    for (const a of addrs || []) {
      if (a.family !== "IPv4" && a.family !== 4) continue;
      if (a.internal) continue;
      const ip = a.address;
      if (ip.startsWith("169.254.")) continue;                                   // link-local
      if (/^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./.test(ip)) continue;        // CGNAT = Tailscale
      const virt = VIRTUAL_IFACE.test(name);
      const priv = /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(ip);
      cands.push({ ip, score: (virt ? 0 : 10) + (priv ? 5 : 0) });
    }
  }
  cands.sort((a, b) => b.score - a.score);
  return cands.length ? cands[0].ip : null;
}
// The exact http://HOST:PORT a reverse proxy must point at for this share.
function originFor(s) {
  const host = s.bind === BIND_LAN ? (state.lanIPv4 || "<this-machine-LAN-IP>") : "127.0.0.1";
  return `http://${host}:${s.localPort}`;
}

const PORT_RANGE = { local: { start: 18650, end: 18799 }, tailscale: { public: [443], private: [8443, 10000] } };

function nextLocalPort() {
  const used = new Set(state.shares.map(s => s.localPort));
  for (let p = PORT_RANGE.local.start; p <= PORT_RANGE.local.end; p++) if (!used.has(p)) return p;
  throw new Error("No free local ports");
}

function nextTailscalePort(mode, hasPathToken = false) {
  const used = new Set(state.shares.map(s => s.tailscalePort));
  const pool = mode === "public" ? PORT_RANGE.tailscale.public : PORT_RANGE.tailscale.private;
  // Path-tokened shares can co-host on the same port as another path-tokened share.
  if (hasPathToken) return pool[0];
  for (const p of pool) if (!used.has(p)) return p;
  // If all ports are in use, allow co-hosting on the primary port (path prefix will distinguish).
  return pool[0];
}

// ============================== PERSISTENCE ==============================
function loadConfig() {
  try {
    const cfg = JSON.parse(fs.readFileSync(CONFIG_PATH, "utf8"));
    state.shares = (cfg.shares || []).map(normalizeShare);
    console.log(`Loaded ${state.shares.length} share(s) from config`);
  } catch { /* fresh start */ }
}
function saveConfig() {
  const cfg = { shares: state.shares.map(s => ({ ...s, pid: undefined, lastError: undefined, cfQuickUrl: undefined })) };
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(cfg, null, 2));
}

// ============================== USERS / AUTH ==============================
// Dashboard users live in switchboard-users.json. Passwords are NEVER stored
// in plaintext — we keep a per-user random salt + scrypt hash and verify with
// a timing-safe comparison.
//
// user = {
//   id, username, salt (hex), passHash (hex),
//   role: "admin" | "user",
//   grants: "all" | { [shareId]: "view" | "manage" },
//   createdAt
// }
let users = [];
const sessions = new Map(); // token -> { userId, expires }
const SESSION_TTL_MS = 1000 * 60 * 60 * 24 * 14; // 14 days

function hashPassword(password, salt) {
  // scryptSync is CPU-hard; 64-byte derived key. salt is a hex string.
  return crypto.scryptSync(String(password), Buffer.from(salt, "hex"), 64).toString("hex");
}
function makeUser({ username, password, role = "user", grants = {} }) {
  const salt = crypto.randomBytes(16).toString("hex");
  return {
    id: "u" + crypto.randomBytes(6).toString("hex"),
    username: String(username).trim(),
    salt,
    passHash: hashPassword(password, salt),
    role: role === "admin" ? "admin" : "user",
    grants: grants === "all" ? "all" : (grants || {}),
    createdAt: new Date().toISOString(),
  };
}
function verifyPassword(user, password) {
  if (!user) return false;
  const candidate = Buffer.from(hashPassword(password, user.salt), "hex");
  const actual = Buffer.from(user.passHash, "hex");
  return candidate.length === actual.length && crypto.timingSafeEqual(candidate, actual);
}
function genReadablePassword(n = 18) {
  const alpha = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const buf = crypto.randomBytes(n);
  let out = ""; for (let i = 0; i < n; i++) out += alpha[buf[i] % alpha.length];
  return out;
}
function loadUsers() {
  try {
    const data = JSON.parse(fs.readFileSync(USERS_PATH, "utf8"));
    users = data.users || [];
  } catch { users = []; }
}
function saveUsers() {
  fs.writeFileSync(USERS_PATH, JSON.stringify({ users }, null, 2));
}
// First-run bootstrap: if there are no users, create an admin so the owner is
// never locked out of their own dashboard. The generated password is written
// to FIRST-RUN-ADMIN-PASSWORD.txt (and logged) for one-time retrieval.
function bootstrapUsersIfNeeded() {
  loadUsers();
  if (users.length > 0) return;
  const password = genReadablePassword(18);
  const admin = makeUser({ username: "admin", password, role: "admin", grants: "all" });
  users = [admin];
  saveUsers();
  const banner =
    "Switchboard first-run admin account created\n" +
    "------------------------------------------\n" +
    "  Username: admin\n" +
    "  Password: " + password + "\n\n" +
    "Log in at http://127.0.0.1:" + PORT + "/ and change this from the Users panel.\n" +
    "You can delete this file once you've saved the password.\n";
  try { fs.writeFileSync(FIRSTRUN_PW_PATH, banner); } catch {}
  console.log("\n" + banner);
}

// ----- sessions / cookies -----
function parseCookies(req) {
  const out = {};
  const raw = req.headers.cookie || "";
  raw.split(";").forEach(p => {
    const i = p.indexOf("=");
    if (i > -1) out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim());
  });
  return out;
}
function createSession(userId) {
  const token = crypto.randomBytes(32).toString("hex");
  sessions.set(token, { userId, expires: Date.now() + SESSION_TTL_MS });
  return token;
}
function destroySession(token) { if (token) sessions.delete(token); }
function userForRequest(req) {
  const token = parseCookies(req).sb_session;
  if (!token) return null;
  const sess = sessions.get(token);
  if (!sess) return null;
  if (sess.expires < Date.now()) { sessions.delete(token); return null; }
  return users.find(u => u.id === sess.userId) || null;
}
function sessionCookie(token) {
  // Lax so following a link into the dashboard keeps the session; HttpOnly so
  // page JS can't read it. Not marked Secure because it's also served over
  // plain http on localhost (Tailscale terminates TLS upstream when shared).
  return `sb_session=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${Math.floor(SESSION_TTL_MS / 1000)}`;
}
function clearCookie() {
  return "sb_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0";
}

// ----- authorization helpers -----
function isAdmin(u) { return u && u.role === "admin"; }
// Returns "manage" | "view" | null for a given user+share.
function grantFor(u, shareId) {
  if (!u) return null;
  if (u.role === "admin" || u.grants === "all") return "manage";
  const g = u.grants && u.grants[shareId];
  return g === "manage" || g === "view" ? g : null;
}
function canViewShare(u, shareId) { return grantFor(u, shareId) !== null; }
function canManageShare(u, shareId) { return grantFor(u, shareId) === "manage"; }
// Public-facing user shape (never leak salt/passHash).
function publicUser(u) {
  return { id: u.id, username: u.username, role: u.role, grants: u.grants, createdAt: u.createdAt };
}

// ============================== TAILSCALE ==============================
function ts(args) {
  return new Promise((resolve, reject) => {
    exec(`${TAILSCALE} ${args}`, { windowsHide: true, maxBuffer: 4 * 1024 * 1024 }, (err, stdout, stderr) => {
      if (err && !stdout) reject(stderr || err.message); else resolve(stdout);
    });
  });
}

// Is the Tailscale CLI/app actually present on this machine? Distinct from
// "installed but stopped/signed-out" so the UI can offer to INSTALL vs CONNECT.
function detectTailscaleInstalled() {
  if (process.platform === "win32") {
    return fs.existsSync(`${process.env.PROGRAMFILES}\\Tailscale\\tailscale.exe`)
        || fs.existsSync(`${process.env["ProgramFiles(x86)"] || ""}\\Tailscale\\tailscale.exe`);
  }
  if (fs.existsSync("/Applications/Tailscale.app/Contents/MacOS/Tailscale")) return true;
  try { require("child_process").execSync("command -v tailscale", { stdio: "ignore" }); return true; }
  catch { return false; }
}

async function refreshTailscale() {
  state.lanIPv4 = detectLanIPv4();
  state.tailscaleInstalled = detectTailscaleInstalled();
  if (!state.tailscaleInstalled) {
    state.backendState = "NotInstalled";
    return;
  }
  try {
    const j = JSON.parse(await ts("status --json"));
    state.backendState = j.BackendState || "Unknown";
    state.tailnetHost = (j.Self.DNSName || "").replace(/\.$/, "") || state.tailnetHost;
    state.tailnetIPv4 = (j.Self.TailscaleIPs || []).find(ip => ip.includes(".")) || state.tailnetIPv4;
  } catch (e) {
    // Only log on state CHANGE — a down tailscaled used to flood the err log
    // with an identical line every 30s.
    if (state.backendState !== "Unreachable") console.error("Tailscale status failed:", String(e).slice(0, 200));
    state.backendState = "Unreachable";
  }
}

// Install Tailscale via the OS package manager. Windows → winget (official
// Tailscale.Tailscale package); macOS → Homebrew cask. Returns the command
// output, or a typed error with a manual-download URL when no package manager
// is available. May surface a UAC/elevation prompt to the user.
const TAILSCALE_DOWNLOAD = "https://tailscale.com/download";
function hasCmd(cmd) {
  try { require("child_process").execSync(process.platform === "win32" ? `where ${cmd}` : `command -v ${cmd}`, { stdio: "ignore" }); return true; }
  catch { return false; }
}
function installTailscale() {
  return new Promise((resolve, reject) => {
    let cmd, manual = TAILSCALE_DOWNLOAD;
    if (process.platform === "win32") {
      if (!hasCmd("winget")) return reject(Object.assign(new Error("winget isn't available on this PC. Install Tailscale manually."), { manualUrl: manual + "/windows" }));
      cmd = `winget install --id Tailscale.Tailscale -e --silent --accept-package-agreements --accept-source-agreements`;
    } else if (process.platform === "darwin") {
      if (!hasCmd("brew")) return reject(Object.assign(new Error("Homebrew isn't installed. Install Tailscale manually."), { manualUrl: manual + "/mac" }));
      cmd = `brew install --cask tailscale`;
    } else {
      return reject(Object.assign(new Error("Auto-install is only supported on Windows and macOS."), { manualUrl: manual }));
    }
    exec(cmd, { windowsHide: true, timeout: 5 * 60 * 1000, maxBuffer: 8 * 1024 * 1024 }, async (err, stdout, stderr) => {
      if (err) {
        const msg = (stderr || stdout || err.message || "").toString().slice(0, 400);
        return reject(Object.assign(new Error("Install failed: " + msg), { manualUrl: manual }));
      }
      await refreshTailscale();
      resolve((stdout || "").toString().slice(-400));
    });
  });
}

// Bring the Tailscale backend up. Plain `up` first; if stored prefs are
// inconsistent (the "must mention all non-default flags" error), retry --reset.
async function tailscaleUp() {
  try { await ts("up --timeout=30s"); }
  catch (e) {
    const msg = String(e);
    if (/mentioning all|non-default/i.test(msg)) await ts("up --reset --timeout=30s");
    else throw new Error(msg.slice(0, 300));
  }
  await refreshTailscale();
}

// Self-healing: any share that should be live but has no running server
// (e.g. it failed to start because Tailscale was down at boot) gets retried
// whenever the tailnet is healthy. Guarded so ticks never overlap.
let reconciling = false;
async function reconcileShares() {
  if (reconciling) return;
  reconciling = true;
  try {
    for (const s of state.shares) {
      if (s.paused || s.pid) continue;
      // Tailscale shares can only come back once the tailnet is healthy; proxy
      // and local shares don't depend on it at all.
      if (usesTailscale(s) && state.backendState !== "Running") continue;
      // Cloudflare shares need the binary; without it they'd just fail every tick.
      if (usesCloudflare(s) && !cf.refreshBinary()) { s.lastError = "cloudflared is not installed"; continue; }
      try {
        await startShare(s);
        s.lastError = null;
        console.log(`Recovered share: ${s.name}`);
      } catch (e) { s.lastError = e.message; }
    }
  } finally { reconciling = false; }
}

async function applyTailscaleForShare(s) {
  // Throw on failure so callers (startShare, /resume, /auth, /mode) can surface
  // the error to the UI instead of leaving the share "running" with no actual
  // public/tailnet route. Previously this swallowed errors via .catch(console.error)
  // which is exactly how Funnel paths ended up pointing at dead ports silently.
  if (!usesTailscale(s)) return;   // proxy/local shares have no Tailscale route
  const target = `http://localhost:${s.localPort}`;
  const pathArg = s.pathToken ? `--set-path=/${s.pathToken}` : "";
  const cmd = s.mode === "public"
    ? `funnel --bg --https=${s.tailscalePort} ${pathArg} ${target}`
    : `serve --bg --https=${s.tailscalePort} ${pathArg} ${target}`;
  try {
    await ts(cmd);
  } catch (e) {
    const msg = typeof e === "string" ? e : (e && e.message) || String(e);
    console.error(`tailscale ${s.mode} apply failed for ${s.name}:`, msg);
    throw new Error(`tailscale ${s.mode} failed: ${msg.slice(0, 240)}`);
  }
}

async function removeTailscaleForShare(s) {
  // We don't blanket-disable the port because other shares may use it via different paths.
  // tailscale serve reset would nuke everything; instead just remove our specific entry.
  if (!usesTailscale(s)) return;
  const pathArg = s.pathToken ? `--set-path=/${s.pathToken}` : "";
  if (s.mode === "public") {
    await ts(`funnel --https=${s.tailscalePort} ${pathArg} off`).catch(()=>{});
  }
  await ts(`serve --https=${s.tailscalePort} ${pathArg} off`).catch(()=>{});
}

// ============================== CLOUDFLARE ==============================
// Named mode (API configured + hostname on the zone) or quick mode (anything
// else). Named: every cloudflare share becomes one ingress rule on the single
// managed tunnel, plus a CNAME; one cloudflared process serves them all.
function cloudflareModeFor(s) {
  return cf.configured() && s.proxyHost && cf.hostnameInZone(s.proxyHost) ? "named" : "quick";
}
// `include` is the share being published right now — a brand-new share isn't
// in state.shares until startShare succeeds, so it has to be added explicitly.
function cloudflareIngressRules(exceptId, include) {
  const list = state.shares.slice();
  if (include && !list.some(x => x.id === include.id)) list.push(include);
  return list
    .filter(x => usesCloudflare(x) && !x.paused && x.id !== exceptId && x.proxyHost && cf.hostnameInZone(x.proxyHost))
    .map(x => ({ hostname: x.proxyHost.toLowerCase(), service: `http://127.0.0.1:${x.localPort}` }));
}
async function applyCloudflareForShare(s) {
  if (!usesCloudflare(s)) return;
  if (!cf.refreshBinary()) throw Object.assign(new Error("cloudflared is not installed — use the Install button on the share card"), { needsInstall: true });
  if (cf.configured() && s.proxyHost && !cf.hostnameInZone(s.proxyHost)) {
    throw new Error(`Hostname ${s.proxyHost} isn't on your Cloudflare zone ${cf.zoneName()} — use a name under it, or clear it for a quick tunnel`);
  }
  if (cloudflareModeFor(s) === "named") {
    cf.stopQuick(s.id); s.cfQuickUrl = null;
    await cf.applyIngress(cloudflareIngressRules(null, s));
    await cf.upsertDns(s.proxyHost.toLowerCase());
    cf.ensureRunning();
  } else {
    const q = await cf.startQuick(s.id, s.localPort);
    s.cfQuickUrl = q.url;
  }
}
async function removeCloudflareForShare(s, { deleteDns = false } = {}) {
  if (!usesCloudflare(s)) return;
  cf.stopQuick(s.id); s.cfQuickUrl = null;
  if (!cf.configured()) return;
  const remaining = cloudflareIngressRules(s.id);
  try {
    if (settings.cloudflare.tunnelId) await cf.applyIngress(remaining);
    if (deleteDns && s.proxyHost) await cf.deleteDns(s.proxyHost.toLowerCase());
  } catch (e) { console.error("cloudflare teardown:", e.message); }
  if (!remaining.length) cf.stopNamed();
}

// Method-agnostic publish/unpublish used by the share lifecycle.
async function publishShare(s) {
  if (usesTailscale(s)) return applyTailscaleForShare(s);
  if (usesCloudflare(s)) return applyCloudflareForShare(s);
}
async function unpublishShare(s, opts) {
  if (usesTailscale(s)) return removeTailscaleForShare(s);
  if (usesCloudflare(s)) return removeCloudflareForShare(s, opts);
}

// ============================== SHARE LIFECYCLE ==============================
// Badge + footer the share-server shows on its directory listing, so a share
// never claims "tailnet-only" when it's actually on the LAN or behind a proxy.
function shareLabels(s) {
  if (s.method === "proxy") return { badge: "VIA REVERSE PROXY", footer: `Hosted via Switchboard behind ${s.proxyHost || "your reverse proxy"}` };
  if (s.method === "cloudflare") return { badge: "PUBLIC · CLOUDFLARE TUNNEL", footer: "Hosted via Switchboard through a Cloudflare Tunnel" };
  if (s.method === "local") return s.bind === BIND_LAN
    ? { badge: "LOCAL NETWORK", footer: "Hosted via Switchboard · Visible only on your local network" }
    : { badge: "THIS MACHINE ONLY", footer: "Hosted via Switchboard · Visible only on this machine" };
  if (s.mode === "public") return { badge: "PUBLIC · TAILSCALE FUNNEL", footer: "Hosted via Tailscale Funnel" };
  return { badge: "PRIVATE · TAILNET-ONLY", footer: "Hosted via Tailscale Serve · Visible only to your tailnet" };
}

function spawnShareServer(s) {
  const env = { ...process.env };
  env.SHARE_BIND = s.bind || BIND_LOCAL;
  const labels = shareLabels(s);
  env.SHARE_BADGE = labels.badge;
  env.SHARE_FOOTER = labels.footer;
  if (s.auth && s.auth.user && s.auth.pass) {
    env.SHARE_AUTH_USER = s.auth.user;
    env.SHARE_AUTH_PASS = s.auth.pass;
    env.SHARE_AUTH_REALM = s.name;
  } else {
    delete env.SHARE_AUTH_USER; delete env.SHARE_AUTH_PASS; delete env.SHARE_AUTH_REALM;
  }
  const child = spawn(process.execPath, [SHARE_SERVER, String(s.localPort), s.root, s.logFile, s.name],
    { cwd: HERE, windowsHide: true, detached: false, stdio: ["ignore", "ignore", "pipe"], env });
  const myPid = child.pid;
  s.pid = myPid;
  if (child.stderr) child.stderr.on("data", d => console.error(`[share:${s.name}] ${String(d).trim()}`));
  // Only clear s.pid if it still matches THIS child's pid. Otherwise a quickly
  // re-spawned share (mode switch, auth change, /restart) would have its NEW
  // pid blanked by the OLD child's late-arriving exit/error event.
  child.on("error", (e) => {
    console.error(`Share ${s.name} spawn error:`, e.message);
    if (s.pid === myPid) s.pid = null;
  });
  child.on("exit", (code) => {
    console.log(`Share ${s.name} (pid=${myPid}) exited code=${code}`);
    if (s.pid === myPid) s.pid = null;
  });
  return child;
}

function genToken(n = 10) {
  const alpha = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let out = ""; const buf = require("crypto").randomBytes(n);
  for (let i = 0; i < n; i++) out += alpha[buf[i] % alpha.length];
  return out;
}
function genPassword(n = 16) {
  const alpha = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let out = ""; const buf = require("crypto").randomBytes(n);
  for (let i = 0; i < n; i++) out += alpha[buf[i] % alpha.length];
  return out;
}

function killShareServer(s) {
  if (s.pid) { try { process.kill(s.pid, "SIGTERM"); } catch {} s.pid = null; }
}

// Kill any share-server.js processes orphaned by a previously crashed
// Switchboard instance so their squatted ports (18650+) are freed. This targets
// ONLY share-server.js — the standalone deliverables server.js is left alone.
function sweepOrphanShareServers() {
  // Windows-only best-effort cleanup; on other platforms a fresh port bind
  // failure is handled by waitForLocalPort instead.
  if (process.platform !== "win32") return Promise.resolve();
  return new Promise((resolve) => {
    const ps = `Get-CimInstance Win32_Process -Filter "Name='node.exe'" | Where-Object { $_.CommandLine -like '*share-server.js*' } | ForEach-Object { $_.ProcessId }`;
    execFile("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", ps], { windowsHide: true, timeout: 8000 }, (err, stdout) => {
      if (!err && stdout) {
        // Never sweep a share-server THIS instance already owns — a share
        // created in the seconds between UI bind and this sweep used to get
        // killed by its own cleanup.
        const ours = new Set(state.shares.map(s => s.pid).filter(Boolean));
        for (const pid of stdout.trim().split(/\s+/).filter(Boolean)) {
          const n = parseInt(pid, 10);
          if (ours.has(n)) continue;
          try { process.kill(n); console.log(`Swept orphan share-server pid=${pid}`); } catch {}
        }
      }
      resolve();
    });
  });
}

// Wait for a local TCP port to actually accept connections. Without this,
// startShare would proceed to publish the Funnel mapping before share-server.js
// had bound (or after it died with EADDRINUSE), leaving a Funnel path pointing
// at a dead port. Returns true if it came up, false if it didn't.
function waitForLocalPort(port, timeoutMs = 4000) {
  const net = require("net");
  const deadline = Date.now() + timeoutMs;
  return new Promise((resolve) => {
    const tryOnce = () => {
      const s = net.createConnection({ host: "127.0.0.1", port, timeout: 400 });
      let done = false;
      const finish = (ok) => {
        if (done) return; done = true;
        try { s.destroy(); } catch {}
        if (ok) return resolve(true);
        if (Date.now() >= deadline) return resolve(false);
        setTimeout(tryOnce, 150);
      };
      s.once("connect", () => finish(true));
      s.once("error", () => finish(false));
      s.once("timeout", () => finish(false));
    };
    tryOnce();
  });
}

async function startShare(s) {
  if (!fs.existsSync(s.root)) throw new Error("Folder not found: " + s.root);
  spawnShareServer(s);
  const up = await waitForLocalPort(s.localPort, 4000);
  if (!up) {
    // share-server failed to bind (e.g. EADDRINUSE from an orphan, or root is
    // unreachable). Don't publish a dead Funnel mapping.
    killShareServer(s);
    throw new Error(`share-server for "${s.name}" did not come up on 127.0.0.1:${s.localPort} within 4s`);
  }
  try {
    await publishShare(s);
  } catch (e) {
    // Publish failed — don't leave the share-server orphaned without a route.
    // Caller treats this as "start failed".
    killShareServer(s);
    throw e;
  }
}

// Wait until 127.0.0.1:port stops accepting connections, so a subsequent
// spawn can rebind cleanly. Returns even if it never frees (best-effort).
function waitForLocalPortFree(port, timeoutMs = 2500) {
  const net = require("net");
  const deadline = Date.now() + timeoutMs;
  return new Promise((resolve) => {
    const tryOnce = () => {
      const s = net.createConnection({ host: "127.0.0.1", port, timeout: 300 });
      let done = false;
      const finish = (stillBound) => {
        if (done) return; done = true;
        try { s.destroy(); } catch {}
        if (!stillBound) return resolve(true);
        if (Date.now() >= deadline) return resolve(false);
        setTimeout(tryOnce, 120);
      };
      s.once("connect", () => finish(true));
      s.once("error", () => finish(false));
      s.once("timeout", () => finish(false));
    };
    tryOnce();
  });
}

// Stop + start the share-server only (no Tailscale changes) so it picks up new
// env (bind address, auth, labels). Throws if it doesn't come back up.
async function respawnShareServer(s) {
  killShareServer(s);
  await waitForLocalPortFree(s.localPort, 2500);
  spawnShareServer(s);
  const up = await waitForLocalPort(s.localPort, 4000);
  if (!up) { killShareServer(s); throw new Error(`share-server for "${s.name}" did not come up on :${s.localPort}`); }
}

async function stopShare(s, opts) {
  killShareServer(s);
  // Best-effort wait for the child to release its port before tailscale teardown
  // and any subsequent restart. Without this, a quick stop+start (mode switch,
  // auth change, /restart) can EADDRINUSE because the SIGTERMed child hasn't
  // released 127.0.0.1:s.localPort yet.
  await waitForLocalPortFree(s.localPort, 2500);
  await unpublishShare(s, opts);
}

// ============================== STATS ==============================
function readLog(file, max = 200) {
  if (!fs.existsSync(file)) return [];
  try {
    const lines = fs.readFileSync(file, "utf8").trim().split("\n").slice(-max);
    return lines.map(l => { try { return JSON.parse(l); } catch { return null; }}).filter(Boolean);
  } catch { return []; }
}

function statsFor(s) {
  const hits = readLog(s.logFile, 5000);
  const totalHits = hits.length;
  const totalBytes = hits.reduce((a, h) => a + (h.bytes || 0), 0);
  const uniqueIps = new Set(hits.map(h => h.ip).filter(Boolean)).size;
  const last = hits.length ? hits[hits.length - 1].t : null;
  // Time series: hits per minute, last 60 min
  const now = Date.now();
  const series = Array(60).fill(0);
  hits.forEach(h => {
    const t = new Date(h.t).getTime();
    const minsAgo = Math.floor((now - t) / 60000);
    if (minsAgo >= 0 && minsAgo < 60) series[59 - minsAgo]++;
  });
  // Top files
  const fileMap = {};
  hits.forEach(h => { if (h.path && h.kind !== "listing") fileMap[h.path] = (fileMap[h.path] || 0) + 1; });
  const topFiles = Object.entries(fileMap).sort((a, b) => b[1] - a[1]).slice(0, 5);
  return { totalHits, totalBytes, uniqueIps, last, series, topFiles, recent: hits.slice(-10).reverse() };
}

// ============================== HTTP API ==============================
function send(res, status, body, headers = {}) {
  res.writeHead(status, { "Content-Type": "application/json", "Cache-Control": "no-store", ...headers });
  res.end(typeof body === "string" ? body : JSON.stringify(body));
}

function readBody(req) {
  return new Promise((resolve) => {
    let data = ""; req.on("data", c => data += c); req.on("end", () => { try { resolve(JSON.parse(data || "{}")); } catch { resolve({}); }});
  });
}

async function handleApi(req, res, parsed, me) {
  const m = parsed.pathname.match(/^\/api\/(.+)$/); if (!m) return send(res, 404, { error: "not found" });
  const route = m[1];

  if (route === "state" && req.method === "GET") {
    // Non-admins only see shares they've been granted.
    const visible = state.shares.filter(s => canViewShare(me, s.id));
    const sharesOut = visible.map(s => ({
      ...s,
      running: !!s.pid,
      perm: grantFor(me, s.id),          // "view" | "manage"
      stats: statsFor(s),
      urls: buildUrls(s),
      origin: originFor(s),
      proxyConfigs: s.method === "proxy" ? proxyConfigsFor(s) : undefined,
      cfMode: usesCloudflare(s) ? cloudflareModeFor(s) : undefined,
      cfQuickUrl: usesCloudflare(s) ? (cf.quickUrl(s.id) || null) : undefined,
    }));
    const ui = settingsForUi();
    return send(res, 200, {
      tailnetHost: state.tailnetHost, tailnetIPv4: state.tailnetIPv4, lanIPv4: state.lanIPv4,
      backendState: state.backendState, tailscaleInstalled: state.tailscaleInstalled !== false,
      cloudflare: cf.status(),
      opnsense: { configured: opnsenseClient().configured(), url: ui.opnsense.url, certs: ui.opnsense.certs },
      me: publicUser(me), isAdmin: isAdmin(me),
      shares: sharesOut
    });
  }

  // ---- settings (admin only): Cloudflare + OPNsense credentials ----
  if (route === "settings" && req.method === "GET") {
    if (!isAdmin(me)) return send(res, 403, { error: "admin only" });
    return send(res, 200, { settings: settingsForUi(), cloudflare: cf.status() });
  }
  if (route === "settings" && req.method === "POST") {
    if (!isAdmin(me)) return send(res, 403, { error: "admin only" });
    const b = await readBody(req);
    const c = settings.cloudflare, o = settings.opnsense;
    if (b.cloudflare) {
      const inp = b.cloudflare;
      if (typeof inp.apiToken === "string" && inp.apiToken.trim()) { c.apiToken = inp.apiToken.trim(); }
      if (inp.clearApiToken) { delete c.apiToken; delete c.tunnelToken; delete c.tunnelId; }
      if (typeof inp.accountId === "string") c.accountId = inp.accountId.trim();
      if (typeof inp.zoneName === "string") {
        const z = inp.zoneName.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
        if (z !== (c.zoneName || "")) { c.zoneName = z; delete c.zoneId; }
      }
    }
    if (b.opnsense) {
      const inp = b.opnsense;
      if (typeof inp.url === "string") o.url = inp.url.trim();
      if (typeof inp.key === "string") o.key = inp.key.trim();
      if (typeof inp.secret === "string" && inp.secret.trim()) o.secret = inp.secret.trim();
      if (inp.clearSecret) delete o.secret;
      if (typeof inp.insecure === "boolean") o.insecure = inp.insecure;
    }
    saveSettings();
    return send(res, 200, { ok: true, settings: settingsForUi(), cloudflare: cf.status() });
  }
  if (route === "cloudflare/test" && req.method === "POST") {
    if (!isAdmin(me)) return send(res, 403, { error: "admin only" });
    try { return send(res, 200, { ok: true, result: await cf.verify(), settings: settingsForUi() }); }
    catch (e) { return send(res, 500, { error: e.message }); }
  }
  if (route === "cloudflare/install" && req.method === "POST") {
    if (!isAdmin(me)) return send(res, 403, { error: "admin only" });
    if (cf.refreshBinary()) return send(res, 200, { ok: true, alreadyInstalled: true, cloudflare: cf.status() });
    try {
      const out = await installCloudflared();
      cf.refreshBinary();
      reconcileShares();
      return send(res, 200, { ok: true, output: out, cloudflare: cf.status() });
    } catch (e) { return send(res, 500, { error: e.message, manualUrl: e.manualUrl }); }
  }
  if (route === "opnsense/test" && req.method === "POST") {
    if (!isAdmin(me)) return send(res, 403, { error: "admin only" });
    try {
      const r = await opnsenseClient().test();
      settings.opnsense.certs = r.certs; settings.opnsense.version = r.version; settings.opnsense.lastTestAt = new Date().toISOString();
      saveSettings();
      return send(res, 200, { ok: true, certs: r.certs, version: r.version });
    } catch (e) { return send(res, 500, { error: e.message }); }
  }

  // ---- user management (admin only) ----
  if (route === "users" && req.method === "GET") {
    if (!isAdmin(me)) return send(res, 403, { error: "admin only" });
    return send(res, 200, { users: users.map(publicUser) });
  }
  if (route === "users" && req.method === "POST") {
    if (!isAdmin(me)) return send(res, 403, { error: "admin only" });
    const b = await readBody(req);
    const username = String(b.username || "").trim();
    if (!username) return send(res, 400, { error: "username required" });
    if (users.some(u => u.username.toLowerCase() === username.toLowerCase()))
      return send(res, 409, { error: "username already exists" });
    const autoPw = !(b.password && String(b.password).length);
    const password = autoPw ? genReadablePassword(14) : String(b.password);
    const u = makeUser({ username, password, role: b.role, grants: b.grants });
    users.push(u); saveUsers();
    return send(res, 200, { ok: true, user: publicUser(u), generatedPassword: autoPw ? password : undefined });
  }
  const userMatch = route.match(/^users\/([^\/]+)$/);
  if (userMatch) {
    if (!isAdmin(me)) return send(res, 403, { error: "admin only" });
    const u = users.find(x => x.id === userMatch[1]);
    if (!u) return send(res, 404, { error: "user not found" });
    const adminCount = users.filter(x => x.role === "admin").length;
    if (req.method === "DELETE") {
      if (u.role === "admin" && adminCount <= 1) return send(res, 400, { error: "can't delete the last admin" });
      users = users.filter(x => x.id !== u.id); saveUsers();
      return send(res, 200, { ok: true });
    }
    if (req.method === "POST") {
      const b = await readBody(req);
      if (typeof b.role === "string") {
        if (u.role === "admin" && b.role !== "admin" && adminCount <= 1)
          return send(res, 400, { error: "can't demote the last admin" });
        u.role = b.role === "admin" ? "admin" : "user";
      }
      if (b.grants !== undefined) u.grants = b.grants === "all" ? "all" : (b.grants || {});
      if (b.username) {
        const nn = String(b.username).trim();
        if (nn && !users.some(x => x.id !== u.id && x.username.toLowerCase() === nn.toLowerCase())) u.username = nn;
      }
      if (b.password) { u.salt = crypto.randomBytes(16).toString("hex"); u.passHash = hashPassword(b.password, u.salt); }
      saveUsers();
      return send(res, 200, { ok: true, user: publicUser(u) });
    }
  }

  if (route === "tailscale/up" && req.method === "POST") {
    if (!isAdmin(me)) return send(res, 403, { error: "admin only" });
    try {
      await tailscaleUp();
      reconcileShares(); // fire-and-forget — UI polls /api/state for progress
      return send(res, 200, { ok: true, backendState: state.backendState });
    } catch (e) { return send(res, 500, { error: e.message }); }
  }

  if (route === "tailscale/install" && req.method === "POST") {
    if (!isAdmin(me)) return send(res, 403, { error: "admin only" });
    if (state.tailscaleInstalled) return send(res, 200, { ok: true, alreadyInstalled: true, backendState: state.backendState });
    try {
      const out = await installTailscale();
      return send(res, 200, { ok: true, backendState: state.backendState, tailscaleInstalled: state.tailscaleInstalled, output: out });
    } catch (e) {
      return send(res, 500, { error: e.message, manualUrl: e.manualUrl });
    }
  }

  if (route === "shares" && req.method === "POST") {
    if (!isAdmin(me)) return send(res, 403, { error: "admin only — only admins can create shares" });
    const body = await readBody(req);
    if (!body.name || !body.root) return send(res, 400, { error: "name + root required" });
    const id = "s" + Date.now().toString(36);
    const s = normalizeShare({
      id, name: body.name, root: body.root,
      localPort: nextLocalPort(),
      tailscalePort: nextTailscalePort(body.mode || "tailnet"),
      mode: body.mode || "tailnet",
      method: body.method,
      bind: body.bind,
      proxyHost: body.proxyHost,
      pid: null,
      logFile: path.join(LOG_DIR, `${id}.jsonl`),
      createdAt: new Date().toISOString()
    });
    // A share published through a proxy on another box must listen on the LAN.
    if (s.method === "proxy" && body.bind === undefined) s.bind = BIND_LAN;
    if (s.proxyHost) s.proxyHost = s.proxyHost.trim().replace(/^https?:\/\//i, "").replace(/[\/:].*$/, "").toLowerCase();
    try {
      await startShare(s);
      state.shares.push(s); saveConfig();
      return send(res, 200, { ok: true, share: s });
    } catch (e) { return send(res, 500, { error: e.message }); }
  }

  const idMatch = route.match(/^shares\/([^\/]+)(\/(.+))?$/);
  if (idMatch) {
    const id = idMatch[1]; const sub = idMatch[3];
    const s = state.shares.find(x => x.id === id);
    if (!s) return send(res, 404, { error: "share not found" });
    // Hide existence of shares the user can't see; every branch below mutates,
    // so require "manage" — "view" users get a clear 403.
    if (!canViewShare(me, id)) return send(res, 404, { error: "share not found" });
    if (!canManageShare(me, id)) return send(res, 403, { error: "you have view-only access to this share" });

    // Bare DELETE /api/shares/:id removes the share. The `!sub` guard matters:
    // without it, DELETE …/auth and DELETE …/opnsense deleted the whole share.
    if (req.method === "DELETE" && !sub) {
      await stopShare(s, { deleteDns: true });
      state.shares = state.shares.filter(x => x.id !== id); saveConfig();
      return send(res, 200, { ok: true });
    }

    // ---- OPNsense: push / remove this share's reverse-proxy objects ----
    if (sub === "opnsense" && req.method === "POST") {
      if (!isAdmin(me)) return send(res, 403, { error: "admin only" });
      const b = await readBody(req);
      if (typeof b.certificate === "string") s.opnsenseCert = b.certificate;
      const client = opnsenseClient();
      if (!client.configured()) return send(res, 400, { error: "OPNsense isn't configured — open ⚙ Settings first" });
      const originHost = s.bind === BIND_LAN ? state.lanIPv4 : "127.0.0.1";
      try {
        const r = await client.pushShare({ name: s.name, originHost, originPort: s.localPort, hostname: s.proxyHost, certificate: s.opnsenseCert || "" });
        s.opnsense = { uuids: r.uuids, tag: r.tag, pushedAt: r.pushedAt, hostname: s.proxyHost, origin: `${originHost}:${s.localPort}` };
        saveConfig();
        return send(res, 200, { ok: true, opnsense: s.opnsense, steps: r.steps });
      } catch (e) { return send(res, 500, { error: e.message }); }
    }
    if (sub === "opnsense" && req.method === "DELETE") {
      if (!isAdmin(me)) return send(res, 403, { error: "admin only" });
      if (!s.opnsense) return send(res, 200, { ok: true, removed: {} });
      try {
        const removed = await opnsenseClient().removeShare(s.opnsense.uuids);
        s.opnsense = null; saveConfig();
        return send(res, 200, { ok: true, removed });
      } catch (e) { return send(res, 500, { error: e.message }); }
    }

    // Publish method: tailscale | proxy | local, plus the share-server bind
    // address and (for proxy) the public hostname your proxy answers on.
    // Any subset of {method, bind, proxyHost} may be sent.
    if (sub === "publish" && req.method === "POST") {
      const b = await readBody(req);
      const prev = { method: s.method, bind: s.bind, proxyHost: s.proxyHost, tailscalePort: s.tailscalePort, pathToken: s.pathToken };
      const next = { method: s.method, bind: s.bind, proxyHost: s.proxyHost };
      if (b.method !== undefined) {
        if (!METHODS.includes(b.method)) return send(res, 400, { error: "bad method — use tailscale, proxy or local" });
        next.method = b.method;
      }
      if (b.bind !== undefined) next.bind = (b.bind === BIND_LAN || b.bind === "lan") ? BIND_LAN : BIND_LOCAL;
      if (b.proxyHost !== undefined) {
        next.proxyHost = String(b.proxyHost).trim().replace(/^https?:\/\//i, "").replace(/[\/:].*$/, "").toLowerCase();
      }
      // OPNsense certificate choice rides along (no publish side effects).
      if (typeof b.opnsenseCert === "string") s.opnsenseCert = b.opnsenseCert;
      // Switching TO proxy without an explicit bind: a proxy on another box
      // (OPNsense) can only reach a LAN-bound origin, so enable LAN.
      if (next.method === "proxy" && prev.method !== "proxy" && b.bind === undefined) next.bind = BIND_LAN;

      const methodChanged = next.method !== prev.method;
      const bindChanged = next.bind !== prev.bind;
      const hostChanged = next.proxyHost !== prev.proxyHost;
      if (!methodChanged && !bindChanged) {
        if (hostChanged && usesCloudflare(s) && !s.paused) {
          // Hostname is the Cloudflare ingress/DNS key — tear down the old
          // route (dropping our CNAME) and publish under the new name.
          try { await removeCloudflareForShare(s, { deleteDns: true }); } catch (e) { console.error("cloudflare rename teardown:", e.message); }
          s.proxyHost = next.proxyHost;
          try { await applyCloudflareForShare(s); }
          catch (e) { s.proxyHost = prev.proxyHost; try { await applyCloudflareForShare(s); } catch {} return send(res, 500, { error: e.message }); }
          s.lastError = null; saveConfig();
          return send(res, 200, { ok: true, share: s });
        }
        s.proxyHost = next.proxyHost;
        if (hostChanged && !s.paused && s.pid && s.method === "proxy") {
          // Footer text names the proxy host — refresh it, best-effort.
          try { await respawnShareServer(s); } catch (e) { s.lastError = e.message; }
        }
        saveConfig();
        return send(res, 200, { ok: true, share: s });
      }

      // Leaving a published method: drop its route first (uses OLD fields).
      if (methodChanged) { try { await unpublishShare(s, { deleteDns: true }); } catch (e) { console.error("unpublish on method change:", e.message); } }
      Object.assign(s, next);
      const rollback = async (err) => {
        Object.assign(s, { method: prev.method, bind: prev.bind, proxyHost: prev.proxyHost, tailscalePort: prev.tailscalePort, pathToken: prev.pathToken });
        if (!s.paused) {
          try { await respawnShareServer(s); await publishShare(s); } catch (e2) { s.lastError = e2.message; }
        }
        return send(res, 500, { error: err.message, needsInstall: !!err.needsInstall });
      };
      if (!s.paused) {
        if (bindChanged || !s.pid) {
          try { await respawnShareServer(s); } catch (e) { return rollback(e); }
        }
        if (methodChanged && s.method === "tailscale") {
          if (s.mode === "public" && s.auth && !s.pathToken) s.pathToken = genToken(10);
          s.tailscalePort = nextTailscalePort(s.mode, !!s.pathToken);
        }
        if (methodChanged) {
          try { await publishShare(s); } catch (e) { return rollback(e); }
        }
      }
      s.lastError = null;
      saveConfig();
      return send(res, 200, { ok: true, share: s });
    }

    if (sub === "mode" && req.method === "POST") {
      const { mode } = await readBody(req);
      if (!["public", "tailnet"].includes(mode)) return send(res, 400, { error: "bad mode" });
      if (!usesTailscale(s)) return send(res, 400, { error: "Public/Tailnet only applies to Tailscale-published shares — switch the publish method first" });
      if (mode === s.mode) return send(res, 200, { ok: true });
      const prevMode = s.mode;
      const prevPort = s.tailscalePort;
      // Remove the OLD mapping (still using prev mode/port). Then mutate, then publish.
      await removeTailscaleForShare(s);
      s.mode = mode;
      // For public+auth, ensure a path token exists for URL obscurity
      if (mode === "public" && s.auth && !s.pathToken) s.pathToken = genToken(10);
      s.tailscalePort = nextTailscalePort(mode, !!s.pathToken);
      try {
        await applyTailscaleForShare(s);
      } catch (e) {
        // Roll back in-memory so /api/state reflects what's actually live
        s.mode = prevMode;
        s.tailscalePort = prevPort;
        return send(res, 500, { error: e.message });
      }
      saveConfig();
      return send(res, 200, { ok: true, share: s });
    }

    if (sub === "restart" && req.method === "POST") {
      killShareServer(s);
      await waitForLocalPortFree(s.localPort, 2500);
      spawnShareServer(s);
      const up = await waitForLocalPort(s.localPort, 4000);
      if (!up) return send(res, 500, { error: `share-server "${s.name}" did not come up on :${s.localPort}` });
      return send(res, 200, { ok: true });
    }

    if (sub === "pause" && req.method === "POST") {
      if (!s.paused) { await stopShare(s); s.paused = true; saveConfig(); }
      return send(res, 200, { ok: true, share: s });
    }

    if (sub === "resume" && req.method === "POST") {
      if (s.paused) {
        s.paused = false;
        try { await startShare(s); }
        catch (e) { s.paused = true; return send(res, 500, { error: e.message }); }
        saveConfig();
      }
      return send(res, 200, { ok: true, share: s });
    }

    if (sub === "auth" && req.method === "POST") {
      const body = await readBody(req);
      const user = body.user || "guest";
      const pass = body.pass || genPassword(16);
      // If no path token yet, generate one (path obscurity for public shares)
      if (!s.pathToken && s.mode === "public") s.pathToken = genToken(10);
      // Re-apply tailscale (path may have changed)
      await removeTailscaleForShare(s);
      s.auth = { user, pass };
      // Restart share-server to pick up new env vars
      killShareServer(s);
      await waitForLocalPortFree(s.localPort, 2500);
      spawnShareServer(s);
      const up = await waitForLocalPort(s.localPort, 4000);
      if (!up) { saveConfig(); return send(res, 500, { error: `share-server for "${s.name}" did not come up after auth update` }); }
      try { await applyTailscaleForShare(s); }
      catch (e) { saveConfig(); return send(res, 500, { error: e.message }); }
      saveConfig();
      return send(res, 200, { ok: true, share: s });
    }

    if (sub === "auth" && req.method === "DELETE") {
      await removeTailscaleForShare(s);
      s.auth = null;
      killShareServer(s);
      await waitForLocalPortFree(s.localPort, 2500);
      spawnShareServer(s);
      const up = await waitForLocalPort(s.localPort, 4000);
      if (!up) { saveConfig(); return send(res, 500, { error: `share-server for "${s.name}" did not come up after auth removal` }); }
      try { await applyTailscaleForShare(s); }
      catch (e) { saveConfig(); return send(res, 500, { error: e.message }); }
      saveConfig();
      return send(res, 200, { ok: true });
    }
  }

  if (route === "pickfolder" && req.method === "GET") {
    if (!isAdmin(me)) return send(res, 403, { error: "admin only" });
    // Native folder picker. Only Windows has the PowerShell WinForms path; on
    // macOS/Linux the UI falls back to typing/pasting a path (and the packaged
    // Electron app exposes its own native dialog via preload).
    if (process.platform !== "win32") {
      return send(res, 501, { error: "Native folder picker is Windows-only here — type or paste the folder path instead." });
    }
    // A bare FolderBrowserDialog opens BEHIND whatever window invoked it
    // (Electron/browser), which looks like "the button doesn't do anything". We
    // create a hidden TopMost owner Form and pass it to ShowDialog so the picker
    // reliably comes to front. -STA is required for WinForms.
    const ps = [
      "Add-Type -AssemblyName System.Windows.Forms",
      "Add-Type -AssemblyName System.Drawing",
      "$owner = New-Object System.Windows.Forms.Form",
      "$owner.TopMost = $true",
      "$owner.ShowInTaskbar = $false",
      "$owner.FormBorderStyle = 'None'",
      "$owner.StartPosition = 'Manual'",
      "$owner.Location = New-Object System.Drawing.Point(-32000, -32000)",
      "$owner.Size = New-Object System.Drawing.Size(1,1)",
      "$owner.Opacity = 0",
      "$owner.Show()",
      "$owner.Activate()",
      "$f = New-Object System.Windows.Forms.FolderBrowserDialog",
      "$f.ShowNewFolderButton = $false",
      "$f.Description = 'Select a folder to share'",
      "$f.UseDescriptionForTitle = $true",
      "$r = $f.ShowDialog($owner)",
      "$owner.Close(); $owner.Dispose()",
      "if ($r -eq [System.Windows.Forms.DialogResult]::OK) { Write-Output $f.SelectedPath }",
    ].join("; ");
    execFile("powershell.exe", ["-NoProfile", "-STA", "-Command", ps], { windowsHide: true, maxBuffer: 1024 * 1024 }, (err, stdout, stderr) => {
      if (err) { console.error("pickfolder error:", err.message, stderr); return send(res, 500, { error: err.message }); }
      const folder = (stdout || "").trim();
      send(res, 200, { folder });
    });
    return;
  }

  send(res, 404, { error: "unknown route" });
}

function buildUrls(s) {
  const urls = [];
  if (s.method === "proxy") {
    if (s.proxyHost) urls.push({ label: "Public (via proxy)", url: `https://${s.proxyHost}/`, primary: true });
    urls.push({ label: "Origin", url: originFor(s) + "/", primary: !s.proxyHost,
      note: s.bind === BIND_LAN ? "Point your reverse proxy here" : "Same-machine proxy only — flip to LAN for OPNsense" });
    return urls;
  }
  if (s.method === "cloudflare") {
    if (cloudflareModeFor(s) === "named") {
      urls.push({ label: "Public (Cloudflare)", url: `https://${s.proxyHost.toLowerCase()}/`, primary: true });
    } else {
      const q = cf.quickUrl(s.id);
      urls.push({ label: "Public (quick tunnel)", url: q ? q + "/" : "https://…starting….trycloudflare.com/", primary: true,
        note: q ? "Random trycloudflare.com URL — changes every restart" : "Waiting for cloudflared to hand back a URL" });
    }
    urls.push({ label: "Origin", url: `http://127.0.0.1:${s.localPort}/`, note: "What the tunnel forwards to" });
    return urls;
  }
  if (s.method === "local") {
    urls.push({ label: "This machine", url: `http://127.0.0.1:${s.localPort}/`, primary: true });
    if (s.bind === BIND_LAN) urls.push({ label: "LAN", url: originFor(s) + "/", note: "Other devices on your network" });
    return urls;
  }
  const host = state.tailnetHost || "your-tailnet.ts.net";
  const ip = state.tailnetIPv4 || "100.x.x.x";
  const portSeg = s.tailscalePort === 443 ? "" : `:${s.tailscalePort}`;
  const pathSeg = s.pathToken ? `/${s.pathToken}/` : "/";
  if (s.mode === "public") {
    urls.push({ label: "Public (internet)", url: `https://${host}${portSeg}${pathSeg}`, primary: true });
  } else {
    urls.push({ label: "Tailnet · short", url: `https://${host.split(".")[0]}${portSeg}${pathSeg}`, primary: true });
    urls.push({ label: "Tailnet · DNS", url: `https://${host}${portSeg}${pathSeg}` });
    urls.push({ label: "Tailnet · IPv4", url: `https://${ip}${portSeg}${pathSeg}`, note: "Use if MagicDNS is flaky" });
  }
  return urls;
}

// Ready-to-paste reverse-proxy config for a proxy-published share. Built with
// plain string joins (not template literals) because nginx/Apache syntax is
// full of $variables. Basic auth is enforced by the share-server itself, so the
// proxy only has to pass the Authorization header through — all three do by
// default; the nginx/Apache snippets make it explicit.
function proxyConfigsFor(s) {
  const host = s.proxyHost || "files.example.com";
  const origin = originFor(s);
  const originHost = s.bind === BIND_LAN ? (state.lanIPv4 || "<this-machine-LAN-IP>") : "127.0.0.1";
  const slug = (s.name || "share").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/(^-|-$)/g, "") || "share";
  const nginx = [
    "# nginx — reverse proxy for Switchboard share \"" + s.name + "\"",
    "# Origin: " + origin + "   (share-server bound to " + s.bind + ")",
    "server {",
    "    listen 443 ssl http2;",
    "    server_name " + host + ";",
    "",
    "    # TLS — e.g. certbot/acme output for " + host,
    "    ssl_certificate     /etc/letsencrypt/live/" + host + "/fullchain.pem;",
    "    ssl_certificate_key /etc/letsencrypt/live/" + host + "/privkey.pem;",
    "",
    "    location / {",
    "        proxy_pass " + origin + ";",
    "        proxy_http_version 1.1;",
    "        proxy_set_header Host              $host;",
    "        proxy_set_header X-Real-IP         $remote_addr;",
    "        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;",
    "        proxy_set_header X-Forwarded-Proto $scheme;",
    "        # Switchboard enforces its own Basic auth — pass it straight through",
    "        proxy_set_header Authorization     $http_authorization;",
    "        proxy_pass_header WWW-Authenticate;",
    "        client_max_body_size 0;",
    "        proxy_buffering off;",
    "    }",
    "}",
    "",
    "server {",
    "    listen 80;",
    "    server_name " + host + ";",
    "    return 301 https://$host$request_uri;",
    "}",
  ].join("\n");

  const apache = [
    "# Apache — reverse proxy for Switchboard share \"" + s.name + "\"",
    "# Origin: " + origin + "   (share-server bound to " + s.bind + ")",
    "# Requires: a2enmod proxy proxy_http ssl headers rewrite",
    "<VirtualHost *:443>",
    "    ServerName " + host,
    "",
    "    SSLEngine on",
    "    SSLCertificateFile    /etc/letsencrypt/live/" + host + "/fullchain.pem",
    "    SSLCertificateKeyFile /etc/letsencrypt/live/" + host + "/privkey.pem",
    "",
    "    ProxyPreserveHost On",
    "    ProxyRequests Off",
    "    ProxyPass        / " + origin + "/",
    "    ProxyPassReverse / " + origin + "/",
    "    RequestHeader set X-Forwarded-Proto \"https\"",
    "    # Switchboard enforces its own Basic auth — mod_proxy forwards the",
    "    # Authorization header by default; nothing to add here.",
    "</VirtualHost>",
    "",
    "<VirtualHost *:80>",
    "    ServerName " + host,
    "    RewriteEngine On",
    "    RewriteRule ^(.*)$ https://" + host + "$1 [R=301,L]",
    "</VirtualHost>",
  ].join("\n");

  const opnsense = [
    "OPNsense → Services → Nginx  (os-nginx plugin, form-based — fill these in order)",
    "Share: " + s.name + "   Origin: " + origin,
    (s.bind === BIND_LAN ? "" : "⚠ Origin is on 127.0.0.1 — OPNsense can't reach it. Flip the origin pill to LAN first.\n"),
    "1. HTTP(S) → Upstream Server → +",
    "     Description:  sb-" + slug,
    "     Server:       " + originHost,
    "     Port:         " + s.localPort,
    "     Priority:     1",
    "",
    "2. HTTP(S) → Upstream → +",
    "     Description:    sb-" + slug,
    "     Server Entries: sb-" + slug,
    "     (leave TLS: Enable off — the origin is plain http)",
    "",
    "3. HTTP(S) → Location → +",
    "     Description:      sb-" + slug + "-root",
    "     URL Pattern:      /",
    "     Upstream Servers: sb-" + slug,
    "     Force HTTPS:      on",
    "     (no Basic-auth settings here — the share enforces its own; the",
    "      Authorization header is proxied through untouched)",
    "",
    "4. HTTP(S) → HTTP Server → +",
    "     HTTP Listen Address:   80",
    "     HTTPS Listen Address:  443",
    "     Server Name:           " + host,
    "     Locations:             sb-" + slug + "-root",
    "     TLS Certificate:       certificate for " + host + " (ACME plugin or imported)",
    "     HTTPS Only:            on",
    "",
    "5. Services → Nginx → Configuration → Apply.",
    "   Then: public DNS A record " + host + " → your WAN IP, and Firewall → NAT →",
    "   Port Forward WAN 443 (and 80) → OPNsense itself (or a WAN pass rule if",
    "   nginx binds the WAN address directly).",
  ].join("\n");

  return { nginx, apache, opnsense };
}

// ============================== UI ==============================
const LOGIN_HTML = `<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in · Switchboard</title>
<style>
:root{--navy:#0A1733;--navy-2:#142647;--amber:#F4B33C;--amber-deep:#E09B1A;--line:rgba(255,255,255,.1);--red:#E14F4F;}
*{box-sizing:border-box;margin:0;padding:0;}
body{font-family:-apple-system,BlinkMacSystemFont,"Inter","Segoe UI",sans-serif;background:linear-gradient(180deg,var(--navy),var(--navy-2));color:#fff;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px;}
.card{width:100%;max-width:380px;background:rgba(255,255,255,.05);border:1px solid var(--line);border-radius:18px;padding:32px;}
.brand{display:flex;align-items:center;gap:12px;margin-bottom:22px;}
.logo{width:42px;height:42px;border-radius:50%;background:radial-gradient(circle at 30% 30%,var(--amber),var(--amber-deep) 60%,#5a3c0a);box-shadow:0 0 28px rgba(244,179,60,.5);}
.brand h1{font-size:22px;font-weight:800;letter-spacing:-.02em;}
.brand .sub{font-size:12px;color:var(--amber);font-style:italic;}
label{display:block;font-size:11px;letter-spacing:.07em;text-transform:uppercase;color:rgba(255,255,255,.6);margin:16px 0 6px;font-weight:600;}
input{width:100%;background:rgba(0,0,0,.28);border:1px solid var(--line);color:#fff;padding:12px 14px;border-radius:10px;font-size:15px;font-family:inherit;}
input:focus{outline:none;border-color:var(--amber);}
button{width:100%;margin-top:22px;background:var(--amber);color:var(--navy);border:none;border-radius:999px;padding:13px;font-weight:700;font-size:15px;cursor:pointer;font-family:inherit;}
button:hover{background:var(--amber-deep);}
button:disabled{opacity:.6;cursor:default;}
.err{margin-top:16px;background:rgba(225,79,79,.14);border:1px solid rgba(225,79,79,.4);color:#ffb3b3;border-radius:10px;padding:10px 12px;font-size:13px;display:none;}
.err.show{display:block;}
.hint{margin-top:18px;font-size:11px;color:rgba(255,255,255,.4);line-height:1.5;text-align:center;}
</style></head><body>
<div class="card">
  <div class="brand"><div class="logo"></div><div><h1>Switchboard</h1><div class="sub">Operator sign-in</div></div></div>
  <form id="f" onsubmit="return doLogin(event)">
    <label for="u">Username</label>
    <input id="u" type="text" autocomplete="username" autofocus>
    <label for="p">Password</label>
    <input id="p" type="password" autocomplete="current-password">
    <button id="btn" type="submit">Sign in</button>
    <div class="err" id="err"></div>
  </form>
  <div class="hint">First time? The admin password was written to<br><code>FIRST-RUN-ADMIN-PASSWORD.txt</code> in the install folder.</div>
</div>
<script>
async function doLogin(e){
  e.preventDefault();
  const btn=document.getElementById('btn'), err=document.getElementById('err');
  btn.disabled=true; btn.textContent='Signing in…'; err.classList.remove('show');
  try{
    const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:document.getElementById('u').value,password:document.getElementById('p').value})});
    const d=await r.json();
    if(r.ok&&d.ok){ location.href='/'; return false; }
    err.textContent=d.error||'Sign-in failed'; err.classList.add('show');
  }catch(ex){ err.textContent='Network error: '+(ex&&ex.message||ex); err.classList.add('show'); }
  btn.disabled=false; btn.textContent='Sign in';
  return false;
}
</script>
</body></html>`;

const UI_HTML = `<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Switchboard · Tailscale share manager</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/qrcode-generator/1.4.4/qrcode.min.js"></script>
<style>
:root{--navy:#0A1733;--navy-2:#142647;--amber:#F4B33C;--amber-deep:#E09B1A;--cream:#F7F4ED;--ink:#0E0E0E;--gray:#6B7280;--gray-2:#A8A8A8;--green:#2BAE66;--red:#E14F4F;--line:rgba(255,255,255,.1);}
*{box-sizing:border-box;margin:0;padding:0;-webkit-font-smoothing:antialiased;}
body{font-family:-apple-system,BlinkMacSystemFont,"Inter","Segoe UI",sans-serif;background:linear-gradient(180deg,var(--navy) 0%,var(--navy-2) 100%);color:white;min-height:100vh;padding:32px 24px 60px;}
.wrap{max-width:1280px;margin:0 auto;}
.head{display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:16px;margin-bottom:32px;}
.brand{display:flex;align-items:center;gap:14px;}
.logo{width:46px;height:46px;border-radius:50%;background:radial-gradient(circle at 30% 30%,var(--amber) 0%,var(--amber-deep) 60%,#5a3c0a 100%);box-shadow:0 0 32px rgba(244,179,60,.5);position:relative;animation:logoBreathe 4s ease-in-out infinite;}
.logo::after{content:'';position:absolute;inset:9px;border-radius:50%;background:radial-gradient(circle at 35% 30%,#fff7d9 0%,transparent 50%);}
.logo::before{content:'';position:absolute;inset:-5px;border-radius:50%;border:1.5px solid rgba(244,179,60,.35);animation:logoRing 4s ease-in-out infinite;}
@keyframes logoBreathe{0%,100%{box-shadow:0 0 24px rgba(244,179,60,.4);}50%{box-shadow:0 0 44px rgba(244,179,60,.7);}}
@keyframes logoRing{0%,100%{transform:scale(1);opacity:.5;}50%{transform:scale(1.12);opacity:1;}}
.brand h1{font-size:24px;font-weight:800;letter-spacing:-.02em;}
.brand .sub{font-size:13px;color:var(--amber);font-style:italic;transition:opacity 400ms;min-height:18px;}
.brand .sub.fading{opacity:0;}

/* Tailnet-down banner */
.banner{display:none;align-items:center;gap:14px;background:linear-gradient(90deg,rgba(225,79,79,.18),rgba(225,79,79,.08));border:1px solid rgba(225,79,79,.45);border-radius:14px;padding:14px 18px;margin-bottom:24px;}
.banner.show{display:flex;animation:bannerIn 300ms ease-out;}
.banner.warn{background:linear-gradient(90deg,rgba(244,179,60,.16),rgba(244,179,60,.06));border-color:rgba(244,179,60,.45);}
@keyframes bannerIn{from{opacity:0;transform:translateY(-8px);}to{opacity:1;transform:none;}}
.banner .dot{width:10px;height:10px;border-radius:50%;background:var(--red);flex-shrink:0;animation:blink 1.2s ease-in-out infinite;}
.banner.warn .dot{background:var(--amber);}
@keyframes blink{0%,100%{opacity:1;}50%{opacity:.35;}}
.banner .msg{flex:1;font-size:13.5px;line-height:1.45;}
.banner .msg b{color:#ffb3b3;}
.banner.warn .msg b{color:var(--amber);}

/* Woolywubber — stat cards wub when their number changes */
@keyframes wub{0%{transform:scale(1) rotate(0);}25%{transform:scale(1.08) rotate(-1.2deg);}50%{transform:scale(.98) rotate(1deg);}75%{transform:scale(1.03) rotate(-.5deg);}100%{transform:scale(1) rotate(0);}}
.stat.wub{animation:wub 500ms ease-out;}
.stat .num{transition:color 200ms;}

/* Bamfloozle — celebration confetti */
.bam{position:fixed;width:10px;height:10px;pointer-events:none;z-index:999;border-radius:2px;}
@keyframes bamfall{to{transform:translate(var(--dx),105vh) rotate(720deg);opacity:.9;}}

/* Live pulse on share cards receiving traffic */
@keyframes livePulse{0%{box-shadow:0 0 0 0 rgba(43,174,102,.5);}100%{box-shadow:0 0 0 14px rgba(43,174,102,0);}}
.share.live{border-color:rgba(43,174,102,.55);animation:livePulse 1.2s ease-out 2;}
.share-error{background:rgba(225,79,79,.12);border:1px solid rgba(225,79,79,.4);color:#ffb3b3;border-radius:10px;padding:9px 12px;font-size:12px;margin-bottom:12px;line-height:1.4;}
.tn{padding:10px 16px;background:rgba(255,255,255,.06);border:1px solid var(--line);border-radius:10px;font-size:13px;color:rgba(255,255,255,.85);font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;cursor:pointer;transition:background 120ms,border-color 120ms;user-select:none;}
.tn:hover{background:rgba(244,179,60,.1);border-color:rgba(244,179,60,.45);color:white;}
.tn:active{transform:translateY(1px);}
.tn .ok{color:var(--amber);font-weight:600;margin-right:8px;}
.tn .hint{margin-left:10px;color:rgba(255,255,255,.45);font-size:11px;letter-spacing:.04em;}
.btn{padding:10px 18px;border-radius:999px;font-weight:600;font-size:14px;border:none;cursor:pointer;font-family:inherit;display:inline-flex;align-items:center;gap:8px;transition:all 120ms;}
.btn-primary{background:var(--amber);color:var(--navy);box-shadow:0 6px 20px rgba(244,179,60,.35);}
.btn-primary:hover{transform:translateY(-1px);box-shadow:0 10px 26px rgba(244,179,60,.5);}
.btn-ghost{background:transparent;color:white;border:1px solid rgba(255,255,255,.25);}
.btn-ghost:hover{background:rgba(255,255,255,.08);}
.btn-danger{background:rgba(225,79,79,.12);color:#ff8a8a;border:1px solid rgba(225,79,79,.4);}
.btn-danger:hover{background:rgba(225,79,79,.25);}
.btn-tiny{padding:6px 12px;font-size:12px;}

.summary{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:28px;}
.stat{background:rgba(255,255,255,.05);border:1px solid var(--line);border-radius:14px;padding:18px 20px;}
.stat .label{font-size:11px;letter-spacing:.12em;text-transform:uppercase;color:rgba(255,255,255,.6);margin-bottom:4px;}
.stat .num{font-size:28px;font-weight:800;color:var(--amber);}
.stat .num small{font-size:14px;color:var(--gray-2);font-weight:500;margin-left:4px;}

h2.section{font-size:14px;letter-spacing:.12em;text-transform:uppercase;color:rgba(255,255,255,.55);margin:8px 0 16px;display:flex;justify-content:space-between;align-items:center;}
.shares{display:grid;grid-template-columns:repeat(auto-fill,minmax(440px,1fr));gap:18px;}
.share{background:rgba(255,255,255,.05);border:1px solid var(--line);border-radius:18px;overflow:hidden;transition:border-color 200ms;}
.share:hover{border-color:rgba(244,179,60,.4);}
.share-head{padding:18px 20px;border-bottom:1px solid var(--line);display:flex;justify-content:space-between;align-items:flex-start;gap:12px;}
.share-name{font-size:18px;font-weight:700;}
.share-path{font-size:12px;color:rgba(255,255,255,.55);font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;margin-top:4px;word-break:break-all;}
.badge{padding:4px 10px;border-radius:999px;font-size:11px;font-weight:700;letter-spacing:.05em;text-transform:uppercase;flex-shrink:0;}
.badge-pub{background:rgba(225,79,79,.15);color:#ff8a8a;}
.badge-priv{background:rgba(43,174,102,.15);color:#7be3a4;}
.badge-mix{background:rgba(244,179,60,.18);color:var(--amber);}
.badge-paused{background:rgba(168,168,168,.2);color:#d4d4d4;}
.paused-note{background:rgba(168,168,168,.12);border:1px solid rgba(168,168,168,.3);color:#d4d4d4;border-radius:10px;padding:9px 12px;font-size:12px;margin-bottom:12px;}
.share.paused{opacity:.82;}

.creds{background:rgba(244,179,60,.08);border:1px solid rgba(244,179,60,.3);border-radius:12px;padding:12px;margin-bottom:14px;}
.creds-head{display:flex;justify-content:space-between;align-items:center;font-size:12px;font-weight:700;color:var(--amber);margin-bottom:8px;letter-spacing:.04em;}
.cred-row{display:flex;align-items:center;gap:8px;font-size:12px;padding:4px 0;}
.cred-lbl{color:rgba(255,255,255,.5);width:70px;text-transform:uppercase;font-size:10px;letter-spacing:.08em;font-weight:600;}
.cred-row code{flex:1;font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;background:rgba(0,0,0,.3);padding:4px 8px;border-radius:6px;color:white;user-select:all;}
.cred-row .copy{background:rgba(255,255,255,.08);border:none;color:white;padding:4px 10px;border-radius:6px;font-size:11px;cursor:pointer;font-family:inherit;}
.cred-row .copy:hover{background:var(--amber);color:var(--navy);}

.share-body{padding:18px 20px;}
.urls{display:flex;flex-direction:column;gap:8px;margin-bottom:14px;}
.url{display:flex;align-items:center;gap:8px;background:rgba(0,0,0,.25);border:1px solid var(--line);border-radius:10px;padding:8px 10px 8px 12px;}
.url .lbl{font-size:11px;color:rgba(255,255,255,.5);text-transform:uppercase;letter-spacing:.08em;flex-shrink:0;width:96px;}
.url .val{flex:1;font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;font-size:12px;color:white;word-break:break-all;}
.url a.val{text-decoration:none;cursor:pointer;transition:color 120ms;}
.url a.val:hover{color:var(--amber);text-decoration:underline;}
.url .copy{background:rgba(255,255,255,.08);border:none;color:white;padding:5px 10px;border-radius:6px;font-size:11px;cursor:pointer;font-family:inherit;}
.url .copy:hover{background:var(--amber);color:var(--navy);}
.url .copy.copied{background:var(--green);color:white;}
.url.primary{background:rgba(244,179,60,.08);border-color:rgba(244,179,60,.3);}

.share-stats{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-bottom:14px;}
.share-stat{background:rgba(0,0,0,.25);border-radius:10px;padding:10px 12px;}
.share-stat .l{font-size:10px;color:rgba(255,255,255,.5);text-transform:uppercase;letter-spacing:.08em;}
.share-stat .v{font-size:18px;font-weight:700;color:var(--amber);font-variant-numeric:tabular-nums;}
.share-stat .v small{font-size:11px;color:var(--gray-2);font-weight:500;}

.spark{height:36px;width:100%;margin-bottom:12px;}
.spark .bar{fill:var(--amber);}

.share-actions{display:flex;gap:8px;flex-wrap:wrap;align-items:center;border-top:1px solid var(--line);padding-top:14px;}
.toggle-mode{display:flex;background:rgba(0,0,0,.25);border-radius:999px;padding:3px;border:1px solid var(--line);font-size:12px;}
.toggle-mode button{background:transparent;color:rgba(255,255,255,.6);border:none;padding:6px 12px;border-radius:999px;cursor:pointer;font-family:inherit;font-weight:600;}
.toggle-mode button.active{background:var(--amber);color:var(--navy);}
.toggle-mode button.active.proxy{background:#6c8cc8;color:#fff;}
.toggle-mode button.active.local{background:var(--green);color:#fff;}
.toggle-mode button:disabled{opacity:.45;cursor:default;}
.toggle-mode button.active.cf{background:#F6821F;color:#fff;}
.badge-proxy{background:rgba(108,140,200,.22);color:#bcd0f5;}
.badge-local{background:rgba(43,174,102,.15);color:#7be3a4;}
.badge-cf{background:rgba(246,130,31,.2);color:#ffb37a;}
.pub-panel.cf{background:rgba(246,130,31,.08);border-color:rgba(246,130,31,.4);}
.pub-panel.cf .pub-head{color:#ffb37a;}
.pub-status{display:inline-flex;align-items:center;gap:6px;font-size:11px;color:rgba(255,255,255,.7);}
.pub-status .dot{width:8px;height:8px;border-radius:50%;background:var(--gray-2);}
.pub-status .dot.on{background:var(--green);}
.pub-status .dot.warn{background:var(--amber);animation:blink 1.2s ease-in-out infinite;}
.pub-status .dot.off{background:var(--red);}
.pub-row select{background:rgba(0,0,0,.3);border:1px solid var(--line);color:white;padding:5px 8px;border-radius:6px;font-size:12px;font-family:inherit;min-width:160px;flex:1;}
.pub-row select option{background:var(--navy-2);}
.opn-push{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-top:8px;padding-top:8px;border-top:1px solid var(--line);font-size:11px;}
.opn-push .ok{color:#7be3a4;}
.modal .row2{display:grid;grid-template-columns:1fr 1fr;gap:10px;}
.modal .hintline{font-size:11px;color:rgba(255,255,255,.5);margin-top:6px;line-height:1.45;}
.modal .hintline a{color:var(--amber);}
.modal h4.sec{font-size:13px;letter-spacing:.1em;text-transform:uppercase;color:var(--amber);margin:22px 0 2px;display:flex;justify-content:space-between;align-items:center;}
.modal h4.sec:first-of-type{margin-top:8px;}
.modal .check{display:flex;align-items:center;gap:8px;font-size:13px;margin-top:12px;color:rgba(255,255,255,.8);}
.modal .check input{width:16px;height:16px;}
.testbox{margin-top:10px;font-size:12px;border-radius:10px;padding:9px 12px;display:none;line-height:1.45;}
.testbox.show{display:block;}
.testbox.ok{background:rgba(43,174,102,.1);border:1px solid rgba(43,174,102,.4);color:#c8f3d8;}
.testbox.bad{background:rgba(225,79,79,.12);border:1px solid rgba(225,79,79,.4);color:#ffb3b3;}

/* Publish-method config panel (proxy / local) */
.pub-panel{background:rgba(108,140,200,.08);border:1px solid rgba(108,140,200,.35);border-radius:12px;padding:12px;margin-bottom:14px;}
.pub-panel.local{background:rgba(43,174,102,.07);border-color:rgba(43,174,102,.3);}
.pub-head{display:flex;justify-content:space-between;align-items:center;font-size:12px;font-weight:700;color:#bcd0f5;margin-bottom:8px;letter-spacing:.04em;}
.pub-panel.local .pub-head{color:#7be3a4;}
.pub-row{display:flex;align-items:center;gap:8px;font-size:12px;padding:4px 0;flex-wrap:wrap;}
.pub-lbl{color:rgba(255,255,255,.5);width:70px;text-transform:uppercase;font-size:10px;letter-spacing:.08em;font-weight:600;flex-shrink:0;}
.pub-row code{flex:1;min-width:160px;font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;background:rgba(0,0,0,.3);padding:4px 8px;border-radius:6px;color:white;user-select:all;word-break:break-all;}
.pub-row input{flex:1;min-width:160px;background:rgba(0,0,0,.3);border:1px solid var(--line);color:white;padding:5px 8px;border-radius:6px;font-size:12px;font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;}
.pub-row input:focus{outline:none;border-color:var(--amber);}
.pill{display:inline-flex;background:rgba(0,0,0,.3);border-radius:999px;padding:2px;border:1px solid var(--line);font-size:10px;}
.pill button{background:transparent;color:rgba(255,255,255,.6);border:none;padding:3px 9px;border-radius:999px;cursor:pointer;font-family:inherit;font-weight:700;letter-spacing:.04em;}
.pill button.active{background:var(--amber);color:var(--navy);}
.pub-note{font-size:11px;color:rgba(255,255,255,.55);margin-top:6px;line-height:1.4;}
.pub-note b{color:var(--amber);}
.cfg-tabs{display:flex;gap:4px;margin:10px 0 6px;border-bottom:1px solid var(--line);}
.cfg-tabs button{background:transparent;border:none;color:rgba(255,255,255,.55);padding:6px 10px;font-size:11px;font-weight:700;cursor:pointer;font-family:inherit;border-bottom:2px solid transparent;margin-bottom:-1px;letter-spacing:.04em;}
.cfg-tabs button.active{color:var(--amber);border-bottom-color:var(--amber);}
.cfg-tabs .sp{flex:1;}
.cfg-tabs .copy{background:rgba(255,255,255,.08);border:none;color:white;padding:4px 10px;border-radius:6px;font-size:11px;cursor:pointer;font-family:inherit;align-self:center;margin-bottom:4px;}
.cfg-tabs .copy:hover{background:var(--amber);color:var(--navy);}
.cfg-tabs .copy.copied{background:var(--green);color:white;}
.cfg{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;font-size:10.5px;line-height:1.45;color:rgba(255,255,255,.85);background:rgba(0,0,0,.35);border-radius:8px;padding:10px;max-height:220px;overflow:auto;white-space:pre;margin:0;}

.share-extras{margin-top:12px;display:grid;grid-template-columns:1fr 1fr;gap:14px;}
.qr-wrap{background:white;border-radius:12px;padding:10px;display:flex;align-items:center;justify-content:center;}
.qr-wrap img{width:100%;height:auto;display:block;}
.recent-list{font-size:11px;color:rgba(255,255,255,.7);max-height:120px;overflow-y:auto;font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;}
.recent-list .row{padding:3px 0;border-bottom:1px solid rgba(255,255,255,.06);display:flex;justify-content:space-between;gap:8px;}
.recent-list .row:last-child{border-bottom:none;}
.recent-list .row .p{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
.recent-list .row .s{color:var(--gray-2);}
.empty{text-align:center;padding:60px;color:rgba(255,255,255,.5);font-size:14px;}

/* Modal */
.modal-overlay{position:fixed;inset:0;background:rgba(10,23,51,.85);display:none;align-items:center;justify-content:center;backdrop-filter:blur(8px);z-index:100;}
.modal-overlay.open{display:flex;}
.modal{background:var(--navy-2);border:1px solid rgba(255,255,255,.15);border-radius:18px;padding:28px;width:90%;max-width:480px;}
.modal h3{font-size:22px;font-weight:800;margin-bottom:6px;}
.modal p.sub{color:rgba(255,255,255,.6);font-size:13px;margin-bottom:20px;}
.modal label{display:block;font-size:12px;letter-spacing:.06em;text-transform:uppercase;color:rgba(255,255,255,.6);margin:14px 0 6px;font-weight:600;}
.modal input[type=text]{width:100%;background:rgba(0,0,0,.25);border:1px solid var(--line);color:white;padding:11px 14px;border-radius:10px;font-size:14px;font-family:inherit;}
.modal input[type=text]:focus{outline:none;border-color:var(--amber);}
.path-row{display:flex;gap:8px;}
.path-row input{flex:1;}
.mode-grid{display:grid;grid-template-columns:1fr 1fr;gap:8px;}
.mode-card{padding:14px;border:2px solid var(--line);border-radius:12px;cursor:pointer;background:rgba(0,0,0,.25);}
.mode-card.selected{border-color:var(--amber);background:rgba(244,179,60,.1);}
.mode-card h4{font-size:14px;font-weight:700;}
.mode-card p{font-size:11px;color:rgba(255,255,255,.6);margin-top:4px;line-height:1.4;}
.modal-actions{display:flex;gap:8px;justify-content:flex-end;margin-top:24px;}

.toast{position:fixed;bottom:24px;right:24px;background:var(--amber);color:var(--navy);padding:12px 18px;border-radius:10px;font-weight:600;font-size:14px;box-shadow:0 10px 30px rgba(0,0,0,.3);transform:translateY(100px);opacity:0;transition:all 200ms;z-index:200;}
.toast.show{transform:translateY(0);opacity:1;}

/* User chip */
.userchip{display:flex;align-items:center;gap:8px;padding:8px 8px 8px 14px;background:rgba(255,255,255,.06);border:1px solid var(--line);border-radius:999px;font-size:13px;}
.userchip .uc-role{font-size:10px;text-transform:uppercase;letter-spacing:.06em;padding:2px 7px;border-radius:999px;background:rgba(244,179,60,.18);color:var(--amber);font-weight:700;}
.userchip .uc-role.user{background:rgba(43,174,102,.16);color:#7be3a4;}
.userchip .uc-logout{background:rgba(255,255,255,.08);border:none;color:#fff;width:26px;height:26px;border-radius:50%;cursor:pointer;font-size:13px;line-height:1;}
.userchip .uc-logout:hover{background:var(--red);color:#fff;}
.badge-view{background:rgba(108,140,200,.22);color:#bcd0f5;}

/* Users management */
.user-row{display:flex;align-items:center;gap:12px;padding:12px;border:1px solid var(--line);border-radius:12px;margin-bottom:10px;background:rgba(0,0,0,.2);}
.user-row .u-name{font-weight:700;font-size:15px;}
.user-row .u-meta{font-size:11px;color:rgba(255,255,255,.55);margin-top:2px;}
.user-row .u-actions{margin-left:auto;display:flex;gap:6px;}
.role-pill{font-size:10px;text-transform:uppercase;letter-spacing:.05em;padding:3px 8px;border-radius:999px;font-weight:700;}
.role-pill.admin{background:rgba(244,179,60,.18);color:var(--amber);}
.role-pill.user{background:rgba(43,174,102,.16);color:#7be3a4;}
.grant-table{margin-top:10px;border-top:1px solid var(--line);padding-top:12px;}
.grant-row{display:flex;align-items:center;gap:10px;padding:7px 0;font-size:13px;}
.grant-row .g-name{flex:1;}
.seg{display:flex;background:rgba(0,0,0,.3);border-radius:999px;padding:3px;border:1px solid var(--line);font-size:11px;}
.seg button{background:transparent;color:rgba(255,255,255,.6);border:none;padding:5px 11px;border-radius:999px;cursor:pointer;font-family:inherit;font-weight:600;}
.seg button.active{background:var(--amber);color:var(--navy);}
.seg button.active.view{background:#6c8cc8;color:#fff;}
.modal.wide{max-width:620px;}
.genpw-box{background:rgba(43,174,102,.1);border:1px solid rgba(43,174,102,.4);border-radius:10px;padding:12px;margin-top:14px;font-size:13px;display:none;}
.genpw-box.show{display:block;}
.genpw-box code{background:rgba(0,0,0,.35);padding:3px 8px;border-radius:6px;user-select:all;}

/* Activity feed strip */
.feed{background:rgba(0,0,0,.3);border:1px solid var(--line);border-radius:14px;padding:16px;margin-top:24px;}
.feed h3{font-size:13px;letter-spacing:.1em;text-transform:uppercase;color:var(--amber);margin-bottom:10px;}
.feed-list{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;font-size:11px;color:rgba(255,255,255,.7);max-height:140px;overflow-y:auto;}
.feed-row{display:grid;grid-template-columns:140px 100px 60px 1fr 80px;gap:12px;padding:3px 0;border-bottom:1px solid rgba(255,255,255,.06);}
.feed-row .share-tag{color:var(--amber);font-weight:600;}
.feed-row .ip{color:var(--gray-2);}
.feed-row .status{color:var(--green);}
.feed-row.s-404 .status{color:#ff8a8a;}

@media(max-width:880px){.summary{grid-template-columns:repeat(2,1fr);}.shares{grid-template-columns:1fr;}}
</style></head>
<body>
<div class="wrap">
  <div class="head">
    <div class="brand">
      <div class="logo"></div>
      <div>
        <h1>Switchboard</h1>
        <div class="sub" id="tagline">Your shares, all in one place.</div>
      </div>
    </div>
    <div style="display:flex;align-items:center;gap:14px;flex-wrap:wrap;">
      <div class="tn" id="tn" title="Click to copy tailnet host · right-click for more" onclick="copyTailnet()" oncontextmenu="tnMenu(event); return false;">tailnet: <span id="tn-info">…</span><span class="hint">click to copy</span></div>
      <button class="btn btn-ghost" id="settings-btn" onclick="openSettings()" style="display:none;" title="Cloudflare &amp; OPNsense integrations">⚙ Settings</button>
      <button class="btn btn-ghost" id="users-btn" onclick="openUsersModal()" style="display:none;">👥 Users</button>
      <button class="btn btn-primary" id="newshare-btn" onclick="openModal()">+ New share</button>
      <div class="userchip" id="userchip" title="Signed in"><span id="uc-name">…</span><span id="uc-role" class="uc-role"></span><button class="uc-logout" onclick="logout()" title="Sign out">⎋</button></div>
    </div>
  </div>

  <div class="banner" id="banner">
    <div class="dot"></div>
    <div class="msg" id="banner-msg"></div>
    <button class="btn btn-primary btn-tiny" id="banner-btn" onclick="connectTailscale()">Connect Tailscale</button>
  </div>

  <div class="summary" id="summary"></div>

  <h2 class="section"><span>Active shares</span><span style="font-size:11px;color:var(--gray-2);"id="count"></span></h2>
  <div class="shares" id="shares"></div>

  <div class="feed">
    <h3>🛰 Live activity feed</h3>
    <div class="feed-list" id="feed"></div>
  </div>
</div>

<!-- Modal -->
<div class="modal-overlay" id="modal" onclick="if(event.target===this)closeModal()">
  <div class="modal">
    <h3>Add a new share</h3>
    <p class="sub">Pick a folder, give it a name, and choose how it should be reachable.</p>

    <label>Name</label>
    <input id="m-name" type="text" placeholder="e.g. Q4 board package">

    <label>Folder path</label>
    <div class="path-row">
      <input id="m-path" type="text" placeholder="C:\\Users\\you\\Documents\\…">
      <button class="btn btn-ghost" onclick="pickFolder()">Browse…</button>
    </div>

    <label>Visibility</label>
    <div class="mode-grid">
      <div class="mode-card" id="m-tailnet" onclick="setMode('tailnet')">
        <h4>🔒 Tailnet only</h4>
        <p>Only devices on your tailnet can reach it. Recommended for anything sensitive.</p>
      </div>
      <div class="mode-card selected" id="m-public" onclick="setMode('public')">
        <h4>🌐 Public (Funnel)</h4>
        <p>Anyone on the internet with the URL. Use for shipping public deliverables.</p>
      </div>
    </div>

    <div class="modal-actions">
      <button class="btn btn-ghost" onclick="closeModal()">Cancel</button>
      <button class="btn btn-primary" id="m-submit" onclick="createShare()">Create share</button>
    </div>
  </div>
</div>

<!-- Credentials modal -->
<div class="modal-overlay" id="auth-modal" onclick="if(event.target===this)closeAuthModal()">
  <div class="modal">
    <h3>🔐 Password protection</h3>
    <p class="sub">Visitors must enter these credentials (HTTP Basic auth) to open the share. Changing them takes effect immediately.</p>

    <label>Username</label>
    <input id="a-user" type="text" placeholder="guest">

    <label>Password</label>
    <div class="path-row">
      <input id="a-pass" type="text" placeholder="leave blank to auto-generate">
      <button class="btn btn-ghost" onclick="genPass()">🎲 Generate</button>
    </div>

    <div class="modal-actions">
      <button class="btn btn-ghost" onclick="closeAuthModal()">Cancel</button>
      <button class="btn btn-primary" id="a-submit" onclick="saveAuth()">Save</button>
    </div>
  </div>
</div>

<!-- Users management modal -->
<div class="modal-overlay" id="users-modal" onclick="if(event.target===this)closeUsersModal()">
  <div class="modal wide">
    <div style="display:flex;justify-content:space-between;align-items:center;">
      <h3>👥 Users &amp; access</h3>
      <button class="btn btn-primary btn-tiny" onclick="openUserEditor()">+ Add user</button>
    </div>
    <p class="sub">Give people their own login. Admins control everything; users see only the shares you grant them — view-only or manage.</p>
    <div id="users-list"></div>
    <div class="modal-actions"><button class="btn btn-ghost" onclick="closeUsersModal()">Close</button></div>
  </div>
</div>

<!-- Settings modal: Cloudflare + OPNsense -->
<div class="modal-overlay" id="settings-modal" onclick="if(event.target===this)closeSettings()">
  <div class="modal wide">
    <h3>⚙ Integrations</h3>
    <p class="sub">Credentials stay in <code>switchboard-settings.json</code> next to your other data and are never shown in full again.</p>

    <h4 class="sec"><span>☁ Cloudflare Tunnel</span><span id="cf-bin" style="font-size:11px;font-weight:500;letter-spacing:0;text-transform:none;color:rgba(255,255,255,.6);"></span></h4>
    <div class="hintline">Without credentials, Cloudflare shares get a random <b>trycloudflare.com</b> quick-tunnel URL. Add an API token to publish on <b>your own domain</b>: Switchboard creates one managed tunnel, writes an ingress rule per share and a proxied CNAME per hostname. Token permissions: <b>Account · Cloudflare Tunnel · Edit</b> and <b>Zone · DNS · Edit</b> on the zone.</div>
    <label>API token</label>
    <input id="st-cf-token" type="text" autocomplete="off" placeholder="paste a token (leave blank to keep the current one)">
    <div class="row2">
      <div><label>Zone (domain)</label><input id="st-cf-zone" type="text" placeholder="example.com"></div>
      <div><label>Account ID <span style="opacity:.5;text-transform:none;letter-spacing:0;">(auto-filled from the zone if blank)</span></label><input id="st-cf-account" type="text" placeholder="32-char account id"></div>
    </div>
    <div style="display:flex;gap:8px;margin-top:12px;align-items:center;flex-wrap:wrap;">
      <button class="btn btn-ghost btn-tiny" onclick="testCloudflare()" id="st-cf-test">Save &amp; test</button>
      <button class="btn btn-danger btn-tiny" onclick="clearCloudflare()" id="st-cf-clear" style="display:none;">Forget token</button>
      <span id="st-cf-state" style="font-size:12px;color:rgba(255,255,255,.6);"></span>
    </div>
    <div class="testbox" id="st-cf-result"></div>

    <h4 class="sec"><span>🛡 OPNsense (os-nginx)</span></h4>
    <div class="hintline">Lets a proxy share's OPNsense tab <b>push</b> the Upstream Server → Upstream → Location → HTTP Server objects straight into the firewall and reconfigure nginx. Create a key under <b>System → Access → Users → API keys</b> for a user with nginx privileges.</div>
    <label>OPNsense URL</label>
    <input id="st-op-url" type="text" placeholder="https://192.168.1.1  (or https://fw.lan:8443)">
    <div class="row2">
      <div><label>API key</label><input id="st-op-key" type="text" autocomplete="off" placeholder="key"></div>
      <div><label>API secret</label><input id="st-op-secret" type="text" autocomplete="off" placeholder="leave blank to keep current"></div>
    </div>
    <label class="check"><input type="checkbox" id="st-op-insecure" checked> Allow self-signed certificate on the OPNsense host</label>
    <div style="display:flex;gap:8px;margin-top:12px;align-items:center;flex-wrap:wrap;">
      <button class="btn btn-ghost btn-tiny" onclick="testOpnsense()" id="st-op-test">Save &amp; test</button>
      <span id="st-op-state" style="font-size:12px;color:rgba(255,255,255,.6);"></span>
    </div>
    <div class="testbox" id="st-op-result"></div>

    <div class="modal-actions">
      <button class="btn btn-ghost" onclick="closeSettings()">Close</button>
      <button class="btn btn-primary" onclick="saveSettings(true)">Save</button>
    </div>
  </div>
</div>

<!-- Add/edit user modal -->
<div class="modal-overlay" id="user-edit-modal" onclick="if(event.target===this)closeUserEditor()">
  <div class="modal wide">
    <h3 id="ue-title">Add user</h3>
    <p class="sub" id="ue-sub">Create a login and choose what they can reach.</p>

    <label>Username</label>
    <input id="ue-user" type="text" placeholder="e.g. dana">

    <label id="ue-pass-label">Password</label>
    <div class="path-row">
      <input id="ue-pass" type="text" placeholder="leave blank to auto-generate">
      <button class="btn btn-ghost" onclick="ueGenPass()">🎲 Generate</button>
    </div>

    <label>Role</label>
    <div class="mode-grid">
      <div class="mode-card" id="ue-role-user" onclick="ueSetRole('user')">
        <h4>🙋 User</h4><p>Sees only the shares you grant below. Can't create shares or manage other users.</p>
      </div>
      <div class="mode-card" id="ue-role-admin" onclick="ueSetRole('admin')">
        <h4>🛡 Admin</h4><p>Full control of every share plus user management. Grants below are ignored.</p>
      </div>
    </div>

    <div id="ue-grants-wrap">
      <label>Per-share access</label>
      <div class="grant-table" id="ue-grants"></div>
    </div>

    <div class="genpw-box" id="ue-genpw"></div>

    <div class="modal-actions">
      <button class="btn btn-ghost" onclick="closeUserEditor()">Cancel</button>
      <button class="btn btn-primary" id="ue-submit" onclick="saveUser()">Save user</button>
    </div>
  </div>
</div>

<div class="toast" id="toast"></div>

<script>
let MODE = 'public';
let allRecent = [];

// ——— Bamfloozles ———————————————————————————————————————————————
// Confetti burst for the good moments: share created, share resumed,
// tailnet reconnected. Pure DOM, no canvas, cleans itself up.
function bamfloozle(n) {
  n = n || 90;
  const colors = ['#F4B33C','#E09B1A','#2BAE66','#F7F4ED','#7be3a4','#ffd98a'];
  for (let i = 0; i < n; i++) {
    const d = document.createElement('div');
    d.className = 'bam';
    d.style.left = (Math.random()*100) + 'vw';
    d.style.top = '-14px';
    d.style.background = colors[Math.floor(Math.random()*colors.length)];
    d.style.setProperty('--dx', (Math.random()*180-90) + 'px');
    const sz = (6 + Math.random()*8) + 'px';
    d.style.width = sz; d.style.height = sz;
    if (Math.random() < 0.3) d.style.borderRadius = '50%';
    d.style.animation = 'bamfall ' + (1.4 + Math.random()*1.7).toFixed(2) + 's cubic-bezier(.2,.6,.4,1) forwards';
    d.style.animationDelay = (Math.random()*0.45).toFixed(2) + 's';
    document.body.appendChild(d);
    setTimeout(function(){ d.remove(); }, 4200);
  }
}

// ——— Woolywubbers ——————————————————————————————————————————————
// Rotating taglines under the wordmark.
const TAGLINES = [
  'Your shares, all in one place.',
  'Operator standing by.',
  'Plugging cords since 1926. Digitally since 2026.',
  'Now with 23% more bamfloozle.',
  'Hand-tuned woolywubbers on every jack.',
  'Connecting your call…',
  'Files in, links out.',
];
let tagIdx = 0;
setInterval(function() {
  const el = document.getElementById('tagline');
  el.classList.add('fading');
  setTimeout(function() {
    tagIdx = (tagIdx + 1) % TAGLINES.length;
    el.textContent = TAGLINES[tagIdx];
    el.classList.remove('fading');
  }, 400);
}, 8000);

async function connectTailscale() {
  const btn = document.getElementById('banner-btn');
  const label = btn.textContent;
  btn.textContent = 'Connecting…'; btn.disabled = true;
  const r = await api('POST', '/api/tailscale/up');
  btn.textContent = label; btn.disabled = false;
  if (r.error) { toast('Tailscale: ' + r.error); return; }
  toast('Tailscale connected');
  bamfloozle(60);
  refresh();
}

async function installTailscale() {
  const btn = document.getElementById('banner-btn');
  btn.textContent = 'Installing…'; btn.disabled = true;
  toast('Installing Tailscale — this can take a minute and may ask for admin permission.');
  const r = await api('POST', '/api/tailscale/install');
  btn.disabled = false; btn.textContent = '⬇ Install Tailscale';
  if (r.error) {
    toast('Install failed: ' + r.error);
    if (r.manualUrl) window.open(r.manualUrl, '_blank');
    return;
  }
  toast('Tailscale installed — now sign in to bring your shares online.');
  bamfloozle(80);
  refresh();
}
function setMode(m) { MODE = m;
  document.getElementById('m-tailnet').classList.toggle('selected', m==='tailnet');
  document.getElementById('m-public').classList.toggle('selected', m==='public');
}
function openModal() { document.getElementById('modal').classList.add('open'); }
function closeModal() { document.getElementById('modal').classList.remove('open'); }
function toast(msg) { const t = document.getElementById('toast'); t.textContent = msg; t.classList.add('show'); setTimeout(()=>t.classList.remove('show'), 2400); }
function fmtBytes(n){const u=['B','KB','MB','GB','TB'];let i=0;while(n>=1024&&i<u.length-1){n/=1024;i++;}return n.toFixed(n<10&&i>0?1:0)+' '+u[i];}
function fmtTime(t){if(!t)return'never';const d=new Date(t),s=Math.floor((Date.now()-d.getTime())/1000);if(s<60)return'just now';if(s<3600)return Math.floor(s/60)+'m ago';if(s<86400)return Math.floor(s/3600)+'h ago';return Math.floor(s/86400)+'d ago';}

async function api(method, url, body) {
  try {
    const r = await fetch(url, { method, headers:{'Content-Type':'application/json'}, body: body?JSON.stringify(body):undefined });
    if (!r.ok) {
      let t = ''; try { t = await r.text(); } catch {}
      return { error: 'HTTP ' + r.status + (t ? ' — ' + t.slice(0, 200) : '') };
    }
    return r.json();
  } catch (e) {
    return { error: 'Switchboard unreachable — is the service running? (' + (e && e.message || e) + ')' };
  }
}

async function pickFolder() {
  // Prefer the Electron native dialog (works on Windows + macOS) when the
  // dashboard is running inside the desktop app; otherwise hit the server-side
  // (Windows PowerShell) picker, and on other platforms just let the user type.
  if (window.switchboardNative && window.switchboardNative.pickFolder) {
    try {
      const folder = await window.switchboardNative.pickFolder();
      if (folder) document.getElementById('m-path').value = folder;
      return;
    } catch (e) { /* fall through to server picker */ }
  }
  const r = await api('GET', '/api/pickfolder');
  if (r.folder) document.getElementById('m-path').value = r.folder;
  else if (r.error) toast(r.error);
}

async function createShare() {
  const name = document.getElementById('m-name').value.trim();
  const root = document.getElementById('m-path').value.trim();
  if (!name || !root) { toast('Name and path required'); return; }
  document.getElementById('m-submit').textContent = 'Creating…';
  const r = await api('POST', '/api/shares', { name, root, mode: MODE });
  if (r.error) { toast('Error: '+r.error); document.getElementById('m-submit').textContent='Create share'; return; }
  closeModal();
  document.getElementById('m-name').value = '';
  document.getElementById('m-path').value = '';
  document.getElementById('m-submit').textContent='Create share';
  toast('Share created');
  bamfloozle();
  refresh();
}

async function delShare(id, name) {
  if (!confirm('Stop and delete share "' + name + '"?')) return;
  await api('DELETE', '/api/shares/'+id);
  toast('Share stopped');
  refresh();
}

async function toggleMode(id, mode) {
  const r = await api('POST', '/api/shares/'+id+'/mode', { mode });
  if (r && r.error) { toast('Error: ' + r.error); return; }
  toast('Switched to ' + mode);
  refresh();
}

// ——— Publish method (Tailscale / Proxy / Local) ————————————————————————
const PROXY_TAB = {};   // shareId -> 'nginx' | 'apache' | 'opnsense' (survives re-renders)
function esc(s) {
  return String(s == null ? '' : s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}
const METHOD_LABEL = { tailscale: 'Tailscale', proxy: 'Reverse proxy', cloudflare: 'Cloudflare Tunnel', local: 'Local only' };

// ——— OPNsense push (proxy shares, OPNsense tab) ———————————————————————
function opnsensePushHtml(s, canManage) {
  const op = (LAST_DATA && LAST_DATA.opnsense) || {};
  if (!ME_IS_ADMIN) return '';
  if (!op.configured) {
    return '<div class="opn-push"><span style="color:rgba(255,255,255,.6);">Tired of pasting? </span><a href="#" onclick="openSettings();return false;" style="color:var(--amber);">Connect OPNsense in ⚙ Settings</a><span style="color:rgba(255,255,255,.6);"> and push these four objects with one click.</span></div>';
  }
  const certs = op.certs || [];
  const chosen = s.opnsenseCert || '';
  const sel = '<select id="oc-' + s.id + '" onchange="setOpnCert(\\''+s.id+'\\', this.value)">' +
    '<option value=""' + (chosen===''?' selected':'') + '>' + (certs.length ? '— pick a TLS certificate —' : 'no certificates listed (run Save & test in Settings)') + '</option>' +
    certs.map(function(c){ return '<option value="' + esc(c.id) + '"' + (c.id===chosen?' selected':'') + '>' + esc(c.name) + '</option>'; }).join('') +
    '</select>';
  const pushed = s.opnsense;
  return '<div class="opn-push">' +
      '<span class="pub-lbl" style="width:auto;">Cert</span>' + sel +
      '<button class="btn btn-primary btn-tiny" onclick="pushOpnsense(\\''+s.id+'\\', this)">' + (pushed ? '⚡ Re-push' : '⚡ Push to OPNsense') + '</button>' +
      (pushed ? '<button class="btn btn-ghost btn-tiny" onclick="removeOpnsense(\\''+s.id+'\\', this)">Remove</button>' : '') +
    '</div>' +
    (pushed ? '<div class="pub-note"><span class="ok">✓ Pushed ' + fmtTime(pushed.pushedAt) + '</span> as <b>' + esc(pushed.tag) + '</b> → ' + esc(pushed.hostname||'') + ' ⇢ ' + esc(pushed.origin||'') +
      ((pushed.hostname !== s.proxyHost || pushed.origin !== (s.origin||'').replace(/^https?:\\/\\//,'')) ? ' <span style="color:var(--amber);">(share changed since — re-push)</span>' : '') + '</div>' : '') +
    (op.url ? '<div class="pub-note">Target: <b>' + esc(op.url) + '</b></div>' : '');
}
async function setOpnCert(id, v) {
  const s = (LAST_DATA && LAST_DATA.shares || []).find(function(x){ return x.id === id; });
  if (s) s.opnsenseCert = v;
  await api('POST', '/api/shares/' + id + '/publish', { opnsenseCert: v });   // persist so a re-render keeps it
}
async function pushOpnsense(id, btn) {
  const s = (LAST_DATA && LAST_DATA.shares || []).find(function(x){ return x.id === id; });
  if (!s) return;
  if (!s.proxyHost) { toast('Set the public hostname first'); return; }
  const sel = document.getElementById('oc-' + id);
  const cert = sel ? sel.value : (s.opnsenseCert || '');
  if (!cert && !confirm('No TLS certificate selected — OPNsense will use its default for this HTTP server. Push anyway?')) return;
  const old = btn.textContent; btn.disabled = true; btn.textContent = 'Pushing…';
  const r = await api('POST', '/api/shares/' + id + '/opnsense', { certificate: cert });
  btn.disabled = false; btn.textContent = old;
  if (r.error) { toast('OPNsense: ' + r.error); return; }
  toast('Pushed to OPNsense: ' + (r.steps || []).join(' → '));
  bamfloozle(60); refresh();
}
async function removeOpnsense(id, btn) {
  if (!confirm('Remove this share\\'s nginx objects from OPNsense and reconfigure?')) return;
  btn.disabled = true;
  const r = await api('DELETE', '/api/shares/' + id + '/opnsense');
  btn.disabled = false;
  if (r.error) { toast('OPNsense: ' + r.error); return; }
  toast('Removed from OPNsense'); refresh();
}

// ——— Cloudflare helpers ————————————————————————————————————————————————
async function installCloudflared(btn) {
  const old = btn ? btn.textContent : '';
  if (btn) { btn.disabled = true; btn.textContent = 'Installing…'; }
  toast('Installing cloudflared — this can take a minute and may ask for admin permission.');
  const r = await api('POST', '/api/cloudflare/install');
  if (btn) { btn.disabled = false; btn.textContent = old; }
  if (r.error) { toast('Install failed: ' + r.error); if (r.manualUrl) window.open(r.manualUrl, '_blank'); return; }
  toast(r.alreadyInstalled ? 'cloudflared is already installed' : 'cloudflared installed'); bamfloozle(50); refresh();
}

// ——— Settings modal ———————————————————————————————————————————————————
let SETTINGS = null;
function openSettings() { loadSettingsUi(); document.getElementById('settings-modal').classList.add('open'); }
function closeSettings() { document.getElementById('settings-modal').classList.remove('open'); }
function showTest(id, ok, html) { const b = document.getElementById(id); b.className = 'testbox show ' + (ok ? 'ok' : 'bad'); b.innerHTML = html; }
function hideTest(id) { document.getElementById(id).className = 'testbox'; }
async function loadSettingsUi() {
  const r = await api('GET', '/api/settings');
  if (r.error) { toast(r.error); return; }
  SETTINGS = r.settings;
  const c = r.settings.cloudflare, o = r.settings.opnsense, cfs = r.cloudflare || {};
  document.getElementById('st-cf-token').value = '';
  document.getElementById('st-cf-token').placeholder = c.apiTokenSet ? 'token saved (' + c.apiTokenHint + ') — paste to replace' : 'paste a Cloudflare API token';
  document.getElementById('st-cf-zone').value = c.zoneName || '';
  document.getElementById('st-cf-account').value = c.accountId || '';
  document.getElementById('st-cf-clear').style.display = c.apiTokenSet ? '' : 'none';
  document.getElementById('st-cf-state').textContent = c.tunnelName ? 'tunnel: ' + c.tunnelName + (cfs.tunnel && cfs.tunnel.connected ? ' · connected' : '') : (c.apiTokenSet ? 'token saved — no tunnel yet (created on first Cloudflare share)' : 'not configured → quick tunnels only');
  document.getElementById('cf-bin').textContent = cfs.installed ? 'cloudflared: ' + (cfs.bin || 'found') : 'cloudflared not installed';
  document.getElementById('st-op-url').value = o.url || '';
  document.getElementById('st-op-key').value = o.key || '';
  document.getElementById('st-op-secret').value = '';
  document.getElementById('st-op-secret').placeholder = o.secretSet ? 'secret saved (' + o.secretHint + ') — paste to replace' : 'secret';
  document.getElementById('st-op-insecure').checked = o.insecure !== false;
  document.getElementById('st-op-state').textContent = o.lastTestAt ? 'last test ' + fmtTime(o.lastTestAt) + (o.version ? ' · OPNsense ' + o.version : '') + ' · ' + (o.certs||[]).length + ' cert(s)' : (o.url ? 'not tested yet' : 'not configured');
  hideTest('st-cf-result'); hideTest('st-op-result');
}
function gatherSettings() {
  return {
    cloudflare: { apiToken: document.getElementById('st-cf-token').value, zoneName: document.getElementById('st-cf-zone').value, accountId: document.getElementById('st-cf-account').value },
    opnsense: { url: document.getElementById('st-op-url').value, key: document.getElementById('st-op-key').value, secret: document.getElementById('st-op-secret').value, insecure: document.getElementById('st-op-insecure').checked },
  };
}
async function saveSettings(close) {
  const r = await api('POST', '/api/settings', gatherSettings());
  if (r.error) { toast('Error: ' + r.error); return false; }
  toast('Settings saved');
  if (close) { closeSettings(); refresh(); } else { await loadSettingsUi(); }
  return true;
}
async function testCloudflare() {
  const btn = document.getElementById('st-cf-test'); btn.disabled = true; btn.textContent = 'Testing…';
  const saved = await api('POST', '/api/settings', gatherSettings());
  if (saved.error) { btn.disabled = false; btn.textContent = 'Save & test'; toast(saved.error); return; }
  const r = await api('POST', '/api/cloudflare/test');
  btn.disabled = false; btn.textContent = 'Save & test';
  if (r.error) { showTest('st-cf-result', false, '✗ ' + esc(r.error)); return; }
  const v = r.result || {};
  showTest('st-cf-result', true, '✓ Token valid' + (v.zoneName ? ' · zone <b>' + esc(v.zoneName) + '</b> found' : '') + (v.accountId ? ' · account ' + esc(v.accountId) : '') +
    (v.tunnel ? '<br>Tunnel <b>' + esc(v.tunnel.name) + '</b> exists (' + esc(v.tunnel.status||'') + ')' : '<br>No tunnel yet — it\\'s created the first time a share is published via Cloudflare.') +
    (v.cloudflared ? '' : '<br><span style="color:var(--amber);">cloudflared isn\\'t installed on this machine — install it from a Cloudflare share card.</span>'));
  await loadSettingsUi(); refresh();
}
async function clearCloudflare() {
  if (!confirm('Forget the Cloudflare API token? Existing Cloudflare shares fall back to quick tunnels on their next restart.')) return;
  const r = await api('POST', '/api/settings', { cloudflare: { clearApiToken: true } });
  if (r.error) { toast(r.error); return; }
  toast('Cloudflare token removed'); await loadSettingsUi(); refresh();
}
async function testOpnsense() {
  const btn = document.getElementById('st-op-test'); btn.disabled = true; btn.textContent = 'Testing…';
  const saved = await api('POST', '/api/settings', gatherSettings());
  if (saved.error) { btn.disabled = false; btn.textContent = 'Save & test'; toast(saved.error); return; }
  const r = await api('POST', '/api/opnsense/test');
  btn.disabled = false; btn.textContent = 'Save & test';
  if (r.error) { showTest('st-op-result', false, '✗ ' + esc(r.error)); return; }
  showTest('st-op-result', true, '✓ Connected' + (r.version ? ' · OPNsense ' + esc(r.version) : '') + ' · os-nginx present · ' + (r.certs||[]).length + ' certificate(s): ' + esc((r.certs||[]).map(function(c){return c.name;}).join(', ') || 'none'));
  await loadSettingsUi(); refresh();
}
async function setMethod(id, method) {
  const s = (LAST_DATA && LAST_DATA.shares || []).find(function(x){ return x.id === id; });
  if (s && (s.method || 'tailscale') === method) return;
  toast('Switching to ' + METHOD_LABEL[method] + '…');
  const r = await api('POST', '/api/shares/'+id+'/publish', { method: method });
  if (r && r.error) { toast('Error: ' + r.error); refresh(); return; }
  toast('Published via ' + METHOD_LABEL[method] + (method === 'proxy' && r.share && r.share.bind === '0.0.0.0' ? ' — origin now on LAN' : ''));
  if (method !== 'local') bamfloozle(40);
  refresh();
}
async function setBind(id, bind) {
  const s = (LAST_DATA && LAST_DATA.shares || []).find(function(x){ return x.id === id; });
  if (s && s.bind === bind) return;
  const r = await api('POST', '/api/shares/'+id+'/publish', { bind: bind });
  if (r && r.error) { toast('Error: ' + r.error); refresh(); return; }
  toast(bind === '0.0.0.0' ? 'Origin now listening on the LAN' : 'Origin now localhost-only');
  refresh();
}
async function saveProxyHost(id, el) {
  const s = (LAST_DATA && LAST_DATA.shares || []).find(function(x){ return x.id === id; });
  const v = (el.value || '').trim();
  if (s && (s.proxyHost || '') === v) return;
  const r = await api('POST', '/api/shares/'+id+'/publish', { proxyHost: v });
  if (r && r.error) { toast('Error: ' + r.error); return; }
  toast(v ? 'Hostname saved: ' + (r.share && r.share.proxyHost || v) : 'Hostname cleared');
  refresh();
}
function setProxyTab(id, tab) {
  PROXY_TAB[id] = tab;
  if (LAST_DATA) renderShares(LAST_DATA);
}
function copyCfg(id, btn) {
  const s = (LAST_DATA && LAST_DATA.shares || []).find(function(x){ return x.id === id; });
  const tab = PROXY_TAB[id] || 'nginx';
  const txt = s && s.proxyConfigs && s.proxyConfigs[tab];
  if (!txt) { toast('Nothing to copy yet'); return; }
  navigator.clipboard.writeText(txt).then(function(){
    if (btn) { const old = btn.textContent; btn.textContent = '✓ Copied'; btn.classList.add('copied'); setTimeout(function(){ btn.textContent = old; btn.classList.remove('copied'); }, 1500); }
  });
}

async function pauseShare(id) {
  const r = await api('POST', '/api/shares/'+id+'/pause');
  if (r && r.error) { toast('Error: ' + r.error); return; }
  toast('Share paused'); refresh();
}

let lastTailnet = { host: null, ipv4: null };
async function copyTailnet() {
  if (!lastTailnet.host) {
    const data = await api('GET', '/api/state');
    lastTailnet.host = data.tailnetHost; lastTailnet.ipv4 = data.tailnetIPv4;
  }
  if (!lastTailnet.host) { toast('Tailnet host unknown — is Tailscale connected?'); return; }
  navigator.clipboard.writeText(lastTailnet.host).then(()=>toast('Copied: ' + lastTailnet.host));
}
function tnMenu(e) {
  if (!lastTailnet.host) { copyTailnet(); return; }
  const choice = prompt(
    'Tailnet shortcuts — type a letter:\\n' +
    '  h  copy full host (' + lastTailnet.host + ')\\n' +
    '  s  copy short name (' + (lastTailnet.host||'').split('.')[0] + ')\\n' +
    '  i  copy IPv4 (' + (lastTailnet.ipv4||'?') + ')\\n' +
    '  a  open Tailscale admin in browser', 'h');
  if (!choice) return;
  const c = choice.trim().toLowerCase();
  if (c === 'h') { navigator.clipboard.writeText(lastTailnet.host); toast('Copied host'); }
  else if (c === 's') { navigator.clipboard.writeText(lastTailnet.host.split('.')[0]); toast('Copied short name'); }
  else if (c === 'i' && lastTailnet.ipv4) { navigator.clipboard.writeText(lastTailnet.ipv4); toast('Copied IPv4'); }
  else if (c === 'a') { window.open('https://login.tailscale.com/admin/machines','_blank'); }
}
async function resumeShare(id) {
  if (!confirm('Resume this share? It will go live on its URL again.')) return;
  const r = await api('POST', '/api/shares/'+id+'/resume');
  if (r.error) { toast('Error: '+r.error); return; }
  toast('Share resumed'); bamfloozle(45); refresh();
}

function copy(txt, btn) {
  navigator.clipboard.writeText(txt).then(()=>{
    if(btn){btn.textContent='✓';btn.classList.add('copied');setTimeout(()=>{btn.textContent='Copy';btn.classList.remove('copied');},1500);}
  });
}

function spark(series) {
  const max = Math.max(1, ...series);
  const w = 100, h = 36, bw = w / series.length;
  return '<svg class="spark" viewBox="0 0 ' + w + ' ' + h + '" preserveAspectRatio="none">' +
    series.map((v, i) => {
      const bh = (v/max) * (h-4);
      return '<rect class="bar" x="' + (i*bw + 0.5) + '" y="' + (h-bh) + '" width="' + (bw-0.5) + '" height="' + bh + '" rx="0.5" opacity="' + (0.4 + 0.6*(v/max||0)) + '"/>';
    }).join('') + '</svg>';
}

function qr(url) {
  const q = qrcode(0, 'M');
  q.addData(url);
  q.make();
  return q.createImgTag(4, 0);
}

function shareCard(s) {
  const primaryUrl = s.urls[0]?.url || '';
  const urlsHtml = s.urls.map(u =>
    '<div class="url' + (u.primary?' primary':'') + '">' +
      '<span class="lbl">' + u.label + '</span>' +
      '<a class="val" href="' + u.url + '" target="_blank" rel="noopener noreferrer" title="Open in browser">' + u.url + '</a>' +
      '<button class="copy" onclick="copy(\\''+u.url+'\\', this)">Copy</button>' +
    '</div>'
  ).join('');

  const canManage = (s.perm === 'manage');
  const credsHtml = s.auth
    ? '<div class="creds">' +
        '<div class="creds-head"><span>🔐 Password protected</span><span style="display:flex;gap:6px;">' +
          (canManage ? '<button class="btn btn-ghost btn-tiny" onclick="openAuthModalFor(\\''+s.id+'\\')">✏️ Edit</button>' +
          '<button class="btn btn-ghost btn-tiny" onclick="rmAuth(\\''+s.id+'\\')">Remove</button>' : '') +
        '</span></div>' +
        '<div class="cred-row"><span class="cred-lbl">User</span><code>'+s.auth.user+'</code><button class="copy" onclick="copy(\\''+s.auth.user+'\\', this)">Copy</button></div>' +
        '<div class="cred-row"><span class="cred-lbl">Password</span><code>'+s.auth.pass+'</code><button class="copy" onclick="copy(\\''+s.auth.pass+'\\', this)">Copy</button></div>' +
        '<button class="btn btn-ghost btn-tiny" style="width:100%;margin-top:8px;" onclick="copyShareBlob(\\''+s.id+'\\')">📋 Copy ready-to-send block (URL + creds)</button>' +
      '</div>'
    : (canManage ? '<button class="btn btn-ghost btn-tiny" onclick="openAuthModalFor(\\''+s.id+'\\')" style="width:100%;margin-bottom:10px;">🔐 Add password protection</button>' : '');

  const recentHtml = (s.stats.recent || []).slice(0,5).map(h =>
    '<div class="row"><span class="p">' + (h.path||'') + '</span><span class="s">' + fmtTime(h.t) + '</span></div>'
  ).join('') || '<div style="color:var(--gray-2);text-align:center;padding:14px;">No requests yet</div>';

  const method = s.method || 'tailscale';
  const lock = s.auth ? '🔐 ' : '';
  let badgeText, badgeClass;
  if (s.paused) { badgeText = '⏸ PAUSED'; badgeClass = 'badge-paused'; }
  else if (method === 'proxy') { badgeText = '🔀 ' + lock + 'PROXY'; badgeClass = 'badge-proxy'; }
  else if (method === 'cloudflare') { badgeText = '☁ ' + lock + (s.cfMode === 'named' ? 'CLOUDFLARE' : 'QUICK TUNNEL'); badgeClass = 'badge-cf'; }
  else if (method === 'local') { badgeText = '🏠 ' + lock + (s.bind === '0.0.0.0' ? 'LAN' : 'LOCAL'); badgeClass = 'badge-local'; }
  else if (s.mode === 'public') { badgeText = s.auth ? '🌐🔐 PUBLIC + AUTH' : '🌐 PUBLIC'; badgeClass = s.auth ? 'badge-mix' : 'badge-pub'; }
  else { badgeText = '🔒 TAILNET'; badgeClass = 'badge-priv'; }
  const viewBadge = !canManage ? '<span class="badge badge-view" title="You have view-only access">👁 VIEW ONLY</span>' : '';

  // Publish-method config panel: proxy gets origin + hostname + config tabs,
  // local just gets the localhost/LAN bind pill.
  const lan = s.bind === '0.0.0.0';
  const bindPill = canManage
    ? '<span class="pill">' +
        '<button class="' + (!lan?'active':'') + '" onclick="setBind(\\''+s.id+'\\', \\'127.0.0.1\\')" title="Only this machine (or a proxy running on it) can reach the origin">localhost</button>' +
        '<button class="' + (lan?'active':'') + '" onclick="setBind(\\''+s.id+'\\', \\'0.0.0.0\\')" title="Listen on all interfaces so other LAN devices / OPNsense can reach it">LAN 0.0.0.0</button>' +
      '</span>'
    : '<span class="pill"><button class="active" disabled>' + (lan ? 'LAN 0.0.0.0' : 'localhost') + '</button></span>';
  let pubHtml = '';
  if (method === 'proxy') {
    const tab = PROXY_TAB[s.id] || 'nginx';
    const cfgs = s.proxyConfigs || {};
    pubHtml = '<div class="pub-panel">' +
      '<div class="pub-head"><span>🔀 Reverse proxy</span><span style="font-weight:500;opacity:.7;">your nginx / Apache / OPNsense fronts this origin</span></div>' +
      '<div class="pub-row"><span class="pub-lbl">Origin</span><code>' + esc(s.origin || '') + '</code><button class="copy" onclick="copy(\\''+esc(s.origin||'')+'\\', this)" style="background:rgba(255,255,255,.08);border:none;color:white;padding:4px 10px;border-radius:6px;font-size:11px;cursor:pointer;font-family:inherit;">Copy</button>' + bindPill + '</div>' +
      '<div class="pub-row"><span class="pub-lbl">Hostname</span>' +
        (canManage
          ? '<input id="ph-' + s.id + '" value="' + esc(s.proxyHost||'') + '" placeholder="files.example.com" onkeydown="if(event.key===\\'Enter\\'){this.blur();}" onblur="saveProxyHost(\\''+s.id+'\\', this)">'
          : '<code>' + esc(s.proxyHost || '—') + '</code>') +
      '</div>' +
      (!lan ? '<div class="pub-note">Origin is on <b>localhost</b> — fine if nginx/Apache runs on this PC. For <b>OPNsense</b> or any other box, flip it to <b>LAN</b>.</div>' : '') +
      '<div class="cfg-tabs">' +
        ['nginx','apache','opnsense'].map(function(t){
          const lbl = t === 'nginx' ? 'nginx' : (t === 'apache' ? 'Apache' : 'OPNsense');
          return '<button class="' + (tab===t?'active':'') + '" onclick="setProxyTab(\\''+s.id+'\\', \\''+t+'\\')">' + lbl + '</button>';
        }).join('') +
        '<span class="sp"></span><button class="copy" onclick="copyCfg(\\''+s.id+'\\', this)">Copy ' + (tab==='opnsense'?'steps':'config') + '</button>' +
      '</div>' +
      '<pre class="cfg">' + esc(cfgs[tab] || '') + '</pre>' +
      (tab === 'opnsense' ? opnsensePushHtml(s, canManage) : '') +
    '</div>';
  } else if (method === 'cloudflare') {
    const cfg = (LAST_DATA && LAST_DATA.cloudflare) || {};
    const named = s.cfMode === 'named';
    let status;
    if (!cfg.installed) status = '<span class="pub-status"><span class="dot off"></span>cloudflared not installed</span>' +
      (ME_IS_ADMIN ? ' <button class="btn btn-primary btn-tiny" onclick="installCloudflared(this)">⬇ Install cloudflared</button>' : '');
    else if (s.paused) status = '<span class="pub-status"><span class="dot"></span>paused</span>';
    else if (named) {
      const t = cfg.tunnel || {};
      status = '<span class="pub-status"><span class="dot ' + (t.connected ? 'on' : (t.running ? 'warn' : 'off')) + '"></span>' +
        (t.connected ? 'tunnel connected' : (t.running ? 'tunnel connecting…' : 'tunnel not running')) +
        (t.name ? ' · ' + esc(t.name) : '') + '</span>' +
        (t.lastError && !t.connected ? '<div class="pub-note" style="color:#ffb3b3;">' + esc(t.lastError) + '</div>' : '');
    } else {
      status = '<span class="pub-status"><span class="dot ' + (s.cfQuickUrl ? 'on' : (s.running ? 'warn' : 'off')) + '"></span>' +
        (s.cfQuickUrl ? 'quick tunnel live' : (s.running ? 'waiting for URL…' : 'not running')) + '</span>';
    }
    pubHtml = '<div class="pub-panel cf">' +
      '<div class="pub-head"><span>☁ Cloudflare Tunnel</span>' + status + '</div>' +
      (cfg.configured
        ? '<div class="pub-row"><span class="pub-lbl">Hostname</span>' +
            (canManage
              ? '<input id="ph-' + s.id + '" value="' + esc(s.proxyHost||'') + '" placeholder="files.' + esc(cfg.zoneName||'example.com') + '" onkeydown="if(event.key===\\'Enter\\'){this.blur();}" onblur="saveProxyHost(\\''+s.id+'\\', this)">'
              : '<code>' + esc(s.proxyHost || '—') + '</code>') +
          '</div>' +
          (named
            ? '<div class="pub-note">Served through the managed tunnel <b>' + esc((cfg.tunnel||{}).name || '') + '</b> with a proxied CNAME on <b>' + esc(cfg.zoneName||'') + '</b>. Clear the hostname to fall back to a quick tunnel.</div>'
            : '<div class="pub-note">' + (s.proxyHost
                ? '<b>' + esc(s.proxyHost) + '</b> isn\\'t under your zone <b>' + esc(cfg.zoneName||'') + '</b>, so this share is on a random quick-tunnel URL. Use a name ending in .' + esc(cfg.zoneName||'') + '.'
                : 'No hostname → random <b>trycloudflare.com</b> URL that changes on restart. Enter a name under <b>' + esc(cfg.zoneName||'') + '</b> for a stable address.') + '</div>')
        : '<div class="pub-note">Random <b>trycloudflare.com</b> URL, no account needed — it changes every time the share restarts. ' +
            (ME_IS_ADMIN ? 'Add a Cloudflare API token in <a href="#" onclick="openSettings();return false;" style="color:var(--amber);">⚙ Settings</a> to publish on your own domain.' : 'Ask an admin to add a Cloudflare API token for a stable hostname.') + '</div>') +
    '</div>';
  } else if (method === 'local') {
    pubHtml = '<div class="pub-panel local">' +
      '<div class="pub-head"><span>🏠 Local only</span><span style="font-weight:500;opacity:.7;">nothing published</span></div>' +
      '<div class="pub-row"><span class="pub-lbl">Listen</span><code>' + esc(s.origin || '') + '</code>' + bindPill + '</div>' +
      (lan ? '<div class="pub-note">Reachable from any device on your <b>local network</b> at the LAN URL above.</div>'
           : '<div class="pub-note">Only <b>this machine</b> can open it. Flip to LAN to let other devices on your network in.</div>') +
    '</div>';
  }

  return '<div class="share' + (s.paused?' paused':'') + '" data-id="' + s.id + '">' +
    '<div class="share-head">' +
      '<div><div class="share-name">' + s.name + '</div><div class="share-path">' + s.root + '</div></div>' +
      '<div style="display:flex;gap:6px;flex-wrap:wrap;justify-content:flex-end;">' + viewBadge + '<span class="badge ' + badgeClass + '">' + badgeText + '</span></div>' +
    '</div>' +
    '<div class="share-body">' +
      (s.paused ? '<div class="paused-note">⏸ Paused — the URLs below are inactive until you resume this share.</div>' : '') +
      (!s.paused && !s.running && s.lastError ? '<div class="share-error">⚠ Not running: ' + s.lastError + ' <em style="opacity:.7">(auto-retries every 30s)</em></div>' : '') +
      '<div class="urls">' + urlsHtml + '</div>' +
      pubHtml +
      credsHtml +
      '<div class="share-stats">' +
        '<div class="share-stat"><div class="l">Hits</div><div class="v">' + s.stats.totalHits + '</div></div>' +
        '<div class="share-stat"><div class="l">Bytes</div><div class="v">' + fmtBytes(s.stats.totalBytes) + '</div></div>' +
        '<div class="share-stat"><div class="l">Visitors</div><div class="v">' + s.stats.uniqueIps + '</div></div>' +
      '</div>' +
      spark(s.stats.series) +
      '<div class="share-extras">' +
        '<div class="qr-wrap">' + qr(primaryUrl) + '</div>' +
        '<div><div style="font-size:11px;color:rgba(255,255,255,.5);text-transform:uppercase;letter-spacing:.08em;margin-bottom:4px;">Recent requests</div><div class="recent-list">' + recentHtml + '</div></div>' +
      '</div>' +
      '<div class="share-actions">' +
        (canManage
          ? '<div class="toggle-mode" title="Publish method">' +
              '<button class="' + (method==='tailscale'?'active':'') + '" onclick="setMethod(\\''+s.id+'\\', \\'tailscale\\')" title="tailscale serve / funnel">🔗 Tailscale</button>' +
              '<button class="' + (method==='proxy'?'active proxy':'') + '" onclick="setMethod(\\''+s.id+'\\', \\'proxy\\')" title="Your own reverse proxy (nginx / Apache / OPNsense)">🔀 Proxy</button>' +
              '<button class="' + (method==='cloudflare'?'active cf':'') + '" onclick="setMethod(\\''+s.id+'\\', \\'cloudflare\\')" title="Cloudflare Tunnel (quick trycloudflare.com link, or your own domain with an API token)">☁ Cloudflare</button>' +
              '<button class="' + (method==='local'?'active local':'') + '" onclick="setMethod(\\''+s.id+'\\', \\'local\\')" title="localhost / LAN only, nothing published">🏠 Local</button>' +
            '</div>' +
            (method === 'tailscale'
              ? '<div class="toggle-mode" title="Tailscale visibility">' +
                  '<button class="' + (s.mode==='public'?'active':'') + '" onclick="toggleMode(\\''+s.id+'\\', \\'public\\')">🌐 Public</button>' +
                  '<button class="' + (s.mode==='tailnet'?'active':'') + '" onclick="toggleMode(\\''+s.id+'\\', \\'tailnet\\')">🔒 Tailnet</button>' +
                '</div>'
              : '')
          : '') +
        '<div style="margin-left:auto;display:flex;gap:8px;">' +
          (canManage ? (s.paused
            ? '<button class="btn btn-primary btn-tiny" onclick="resumeShare(\\''+s.id+'\\')">▶ Resume</button>'
            : '<button class="btn btn-ghost btn-tiny" onclick="pauseShare(\\''+s.id+'\\')">⏸ Pause</button>') : '') +
          '<button class="btn btn-ghost btn-tiny" onclick="window.open(\\''+primaryUrl+'\\',\\'_blank\\')">Open ↗</button>' +
          (canManage ? '<button class="btn btn-danger btn-tiny" onclick="delShare(\\''+s.id+'\\', \\''+s.name.replace(/\\'/g,"")+'\\')">Stop</button>' : '') +
        '</div>' +
      '</div>' +
    '</div>' +
  '</div>';
}

let AUTH_SHARE = null;
function openAuthModalFor(id) {
  AUTH_SHARE = id;
  const s = (LAST_DATA && LAST_DATA.shares || []).find(function(x){ return x.id === id; });
  document.getElementById('a-user').value = (s && s.auth && s.auth.user) || 'guest';
  document.getElementById('a-pass').value = (s && s.auth && s.auth.pass) || '';
  document.getElementById('auth-modal').classList.add('open');
}
function closeAuthModal() { document.getElementById('auth-modal').classList.remove('open'); }
function genPass() {
  const alpha = 'abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const buf = new Uint8Array(16); crypto.getRandomValues(buf);
  let p = '';
  for (let i = 0; i < 16; i++) p += alpha[buf[i] % alpha.length];
  document.getElementById('a-pass').value = p;
}
async function saveAuth() {
  const user = document.getElementById('a-user').value.trim();
  const pass = document.getElementById('a-pass').value.trim();
  if (!user) { toast('Username required'); return; }
  const btn = document.getElementById('a-submit');
  btn.textContent = 'Saving…'; btn.disabled = true;
  const r = await api('POST', '/api/shares/'+AUTH_SHARE+'/auth', { user: user, pass: pass });
  btn.textContent = 'Save'; btn.disabled = false;
  if (r.error) { toast('Error: '+r.error); return; }
  closeAuthModal();
  toast('Credentials updated');
  bamfloozle(40);
  refresh();
}
async function rmAuth(id) {
  if (!confirm('Remove password protection? Anyone with the URL will be able to access.')) return;
  await api('DELETE', '/api/shares/'+id+'/auth');
  toast('Password removed'); refresh();
}
async function copyShareBlob(id) {
  const data = await api('GET', '/api/state');
  const s = data.shares.find(x=>x.id===id); if (!s) return;
  const url = s.urls[0]?.url || '';
  const blob = 'URL: ' + url + '\\nUser: ' + s.auth.user + '\\nPassword: ' + s.auth.pass;
  navigator.clipboard.writeText(blob).then(()=>toast('Copied URL + credentials'));
}

// ——— Identity / users ———————————————————————————————————————————
let ME_IS_ADMIN = false;
async function logout() {
  await api('POST', '/api/logout');
  location.href = '/login';
}

function openUsersModal() { renderUsers(); document.getElementById('users-modal').classList.add('open'); }
function closeUsersModal() { document.getElementById('users-modal').classList.remove('open'); }

let LAST_USERS = [];
async function renderUsers() {
  const r = await api('GET', '/api/users');
  const box = document.getElementById('users-list');
  if (r.error) { box.innerHTML = '<div class="share-error">'+r.error+'</div>'; return; }
  LAST_USERS = r.users;
  const shares = (LAST_DATA && LAST_DATA.shares) || [];
  box.innerHTML = r.users.map(function(u){
    let access;
    if (u.role === 'admin') access = 'Full access (all shares + user management)';
    else if (u.grants === 'all') access = 'All shares';
    else {
      const ids = Object.keys(u.grants || {});
      access = ids.length ? ids.map(function(id){
        const sh = shares.find(function(x){return x.id===id;});
        return (sh ? sh.name : id) + ' · ' + u.grants[id];
      }).join(', ') : 'No shares yet';
    }
    return '<div class="user-row">' +
      '<div><div class="u-name">' + u.username + ' <span class="role-pill ' + u.role + '">' + u.role + '</span></div>' +
        '<div class="u-meta">' + access + '</div></div>' +
      '<div class="u-actions">' +
        '<button class="btn btn-ghost btn-tiny" onclick="openUserEditor(\\''+u.id+'\\')">✏️ Edit</button>' +
        '<button class="btn btn-danger btn-tiny" onclick="deleteUser(\\''+u.id+'\\', \\''+u.username+'\\')">Delete</button>' +
      '</div></div>';
  }).join('') || '<div style="color:var(--gray-2);padding:14px;">No users.</div>';
}

let UE_ID = null;       // null = creating
let UE_ROLE = 'user';
let UE_GRANTS = {};     // { shareId: 'view'|'manage' }
function openUserEditor(id) {
  const editing = (typeof id === 'string');
  UE_ID = editing ? id : null;
  document.getElementById('ue-title').textContent = editing ? 'Edit user' : 'Add user';
  document.getElementById('ue-pass-label').textContent = editing ? 'New password (blank = keep current)' : 'Password';
  document.getElementById('ue-genpw').classList.remove('show');
  document.getElementById('ue-user').value = '';
  document.getElementById('ue-pass').value = '';
  UE_ROLE = 'user'; UE_GRANTS = {};
  if (editing) {
    const u = (LAST_USERS || []).find(function(x){ return x.id === id; });
    if (u) {
      document.getElementById('ue-user').value = u.username;
      UE_ROLE = u.role;
      UE_GRANTS = (u.grants === 'all' || !u.grants) ? {} : Object.assign({}, u.grants);
    }
  }
  ueSetRole(UE_ROLE);
  document.getElementById('user-edit-modal').classList.add('open');
}
function closeUserEditor() { document.getElementById('user-edit-modal').classList.remove('open'); }
function ueSetRole(role) {
  UE_ROLE = role;
  document.getElementById('ue-role-user').classList.toggle('selected', role === 'user');
  document.getElementById('ue-role-admin').classList.toggle('selected', role === 'admin');
  document.getElementById('ue-grants-wrap').style.display = role === 'admin' ? 'none' : '';
  renderGrants();
}
function renderGrants() {
  const shares = (LAST_DATA && LAST_DATA.shares) || [];
  const box = document.getElementById('ue-grants');
  if (!shares.length) { box.innerHTML = '<div style="color:var(--gray-2);font-size:12px;">No shares exist yet.</div>'; return; }
  box.innerHTML = shares.map(function(s){
    const g = UE_GRANTS[s.id] || 'none';
    return '<div class="grant-row"><span class="g-name">' + s.name + '</span>' +
      '<div class="seg">' +
        '<button class="' + (g==='none'?'active':'') + '" onclick="setGrant(\\''+s.id+'\\',\\'none\\')">None</button>' +
        '<button class="' + (g==='view'?'active view':'') + '" onclick="setGrant(\\''+s.id+'\\',\\'view\\')">View</button>' +
        '<button class="' + (g==='manage'?'active':'') + '" onclick="setGrant(\\''+s.id+'\\',\\'manage\\')">Manage</button>' +
      '</div></div>';
  }).join('');
}
function setGrant(id, level) {
  if (level === 'none') delete UE_GRANTS[id]; else UE_GRANTS[id] = level;
  renderGrants();
}
function ueGenPass() {
  const alpha = 'abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const buf = new Uint8Array(14); crypto.getRandomValues(buf);
  let p = ''; for (let i=0;i<14;i++) p += alpha[buf[i] % alpha.length];
  document.getElementById('ue-pass').value = p;
}
async function saveUser() {
  const username = document.getElementById('ue-user').value.trim();
  const password = document.getElementById('ue-pass').value;
  if (!username) { toast('Username required'); return; }
  if (!UE_ID && !password) { toast('Set a password (or hit Generate)'); return; }
  const btn = document.getElementById('ue-submit');
  btn.disabled = true; btn.textContent = 'Saving…';
  const body = { username: username, role: UE_ROLE, grants: UE_ROLE === 'admin' ? 'all' : UE_GRANTS };
  if (password) body.password = password;
  const r = UE_ID
    ? await api('POST', '/api/users/' + UE_ID, body)
    : await api('POST', '/api/users', body);
  btn.disabled = false; btn.textContent = 'Save user';
  if (r.error) { toast('Error: ' + r.error); return; }
  if (r.generatedPassword) {
    const gp = document.getElementById('ue-genpw');
    gp.innerHTML = '✅ User created. Auto-generated password (copy it now — it won\\'t be shown again):<br><code>' + r.generatedPassword + '</code>';
    gp.classList.add('show');
    toast('User created'); bamfloozle(40); renderUsers(); refresh();
    UE_ID = r.user.id; // switch to edit mode so re-saving doesn't duplicate
    document.getElementById('ue-title').textContent = 'Edit user';
  } else {
    toast('User saved'); closeUserEditor(); renderUsers(); refresh();
  }
}
async function deleteUser(id, name) {
  if (!confirm('Delete user "' + name + '"? They will lose access immediately.')) return;
  const r = await api('DELETE', '/api/users/' + id);
  if (r.error) { toast('Error: ' + r.error); return; }
  toast('User deleted'); renderUsers();
}

let prevSums = null;
let prevHitsByShare = {};
let LAST_DATA = null;

// Re-rendering innerHTML every poll destroys DOM nodes mid-click (buttons
// "do nothing" if the user clicks during a rebuild). Only touch the DOM
// when the rendered content actually changed.
function setHtmlIfChanged(id, html) {
  const el = document.getElementById(id);
  if (el.dataset.prev !== html) { el.innerHTML = html; el.dataset.prev = html; }
}
function renderShares(data) {
  // Don't yank a card out from under someone typing a proxy hostname — a hit
  // arriving mid-keystroke would otherwise re-render and eat their input.
  const box = document.getElementById('shares');
  const ae = document.activeElement;
  if (ae && (ae.tagName === 'INPUT' || ae.tagName === 'SELECT') && box.contains(ae)) return;
  setHtmlIfChanged('shares', data.shares.length
    ? data.shares.map(shareCard).join('')
    : '<div class="empty" style="grid-column:1/-1;">No shares yet. Click "+ New share" to add one.</div>');
}
async function refresh() {
  const data = await api('GET', '/api/state');
  if (data && data.error) {
    document.getElementById('tn-info').innerHTML = '<span style="color:#ff8a8a">● disconnected</span>';
    document.getElementById('count').textContent = data.error;
    return;
  }
  LAST_DATA = data;
  // Identity chip + admin-only controls
  if (data.me) {
    document.getElementById('uc-name').textContent = data.me.username;
    const rl = document.getElementById('uc-role');
    rl.textContent = data.me.role; rl.className = 'uc-role' + (data.me.role === 'user' ? ' user' : '');
    document.getElementById('users-btn').style.display = data.isAdmin ? '' : 'none';
    document.getElementById('settings-btn').style.display = data.isAdmin ? '' : 'none';
    document.getElementById('newshare-btn').style.display = data.isAdmin ? '' : 'none';
  }
  ME_IS_ADMIN = !!data.isAdmin;
  // Tailscale health banner
  const bs = data.backendState || 'Unknown';
  const banner = document.getElementById('banner');
  const bbtn = document.getElementById('banner-btn');
  const notInstalled = (bs === 'NotInstalled') || (data.tailscaleInstalled === false);
  if (bs !== 'Running') {
    const msgs = {
      NotInstalled: 'Tailscale isn\\'t installed — Switchboard needs it to publish your shares.',
      Stopped: 'Tailscale is <b>stopped</b> — share URLs are unreachable until it connects.',
      Starting: 'Tailscale is <b>starting</b> — shares will come back automatically once it connects.',
      NoState: 'Tailscale is <b>starting</b> — if this persists, restart the Tailscale service or reboot.',
      NeedsLogin: 'Tailscale is installed but <b>not signed in</b> — connect your account to bring shares online.',
      Unreachable: 'The Tailscale service is <b>not responding</b> — try restarting it from an admin terminal: <code>Restart-Service Tailscale</code>.',
    };
    document.getElementById('banner-msg').innerHTML = notInstalled ? msgs.NotInstalled : (msgs[bs] || ('Tailscale state: <b>' + bs + '</b>'));
    banner.classList.toggle('warn', bs === 'Starting' || bs === 'NoState' || bs === 'NeedsLogin');
    // Action button (admin only): INSTALL when missing, CONNECT/SIGN-IN when down.
    if (!data.isAdmin) {
      bbtn.style.display = 'none';
    } else if (notInstalled) {
      bbtn.style.display = ''; bbtn.textContent = '⬇ Install Tailscale'; bbtn.onclick = installTailscale;
    } else if (bs === 'Stopped' || bs === 'Unreachable' || bs === 'NoState' || bs === 'NeedsLogin') {
      bbtn.style.display = ''; bbtn.textContent = (bs === 'NeedsLogin' ? 'Sign in to Tailscale' : 'Connect Tailscale'); bbtn.onclick = connectTailscale;
    } else {
      bbtn.style.display = 'none';
    }
    banner.classList.add('show');
  } else {
    banner.classList.remove('show');
  }
  // Header tailnet info — cache for the click-to-copy handler
  lastTailnet = { host: data.tailnetHost, ipv4: data.tailnetIPv4 };
  document.getElementById('tn-info').innerHTML = bs === 'Running'
    ? '<span class="ok">●</span>' + (data.tailnetHost||'?') + ' · ' + (data.tailnetIPv4||'?')
    : '<span style="color:#ff8a8a">●</span> ' + bs;
  // Summary
  const totalHits = data.shares.reduce((a,s)=>a+s.stats.totalHits,0);
  const totalBytes = data.shares.reduce((a,s)=>a+s.stats.totalBytes,0);
  const totalVisitors = new Set(data.shares.flatMap(s=>(s.stats.recent||[]).map(h=>h.ip).filter(Boolean))).size;
  setHtmlIfChanged('summary',
    '<div class="stat"><div class="label">Active shares</div><div class="num">' + data.shares.length + '</div></div>' +
    '<div class="stat"><div class="label">Total hits today</div><div class="num">' + totalHits + '</div></div>' +
    '<div class="stat"><div class="label">Bytes served</div><div class="num">' + fmtBytes(totalBytes) + '</div></div>' +
    '<div class="stat"><div class="label">Unique visitors</div><div class="num">' + totalVisitors + '</div></div>');
  // Woolywubber: wub any summary stat whose value just changed
  const sums = [data.shares.length, totalHits, totalBytes, totalVisitors];
  if (prevSums) {
    const cards = document.querySelectorAll('#summary .stat');
    sums.forEach(function(v, i) { if (prevSums[i] !== v && cards[i]) cards[i].classList.add('wub'); });
  }
  prevSums = sums;
  // Shares
  document.getElementById('count').textContent = data.shares.length + ' share' + (data.shares.length===1?'':'s');
  renderShares(data);
  // Live pulse on cards that received fresh hits since last poll
  data.shares.forEach(function(s) {
    const prev = prevHitsByShare[s.id];
    if (prev != null && s.stats.totalHits > prev) {
      const card = document.querySelector('.share[data-id="' + s.id + '"]');
      if (card) card.classList.add('live');
    }
    prevHitsByShare[s.id] = s.stats.totalHits;
  });

  // Activity feed: merge all recents
  const all = [];
  data.shares.forEach(s => (s.stats.recent||[]).forEach(h => all.push({...h, share:s.name})));
  all.sort((a,b)=> new Date(b.t) - new Date(a.t));
  setHtmlIfChanged('feed', all.slice(0,30).map(h =>
    '<div class="feed-row s-' + (h.status||200) + '">' +
      '<span>' + new Date(h.t).toLocaleTimeString() + '</span>' +
      '<span class="share-tag">' + h.share + '</span>' +
      '<span class="status">' + (h.status||200) + '</span>' +
      '<span>' + (h.path||'') + '</span>' +
      '<span class="ip">' + (h.ip||'').replace('::ffff:','') + '</span>' +
    '</div>'
  ).join('') || '<div style="text-align:center;color:var(--gray-2);padding:20px;">No activity yet — share a URL to see live hits stream in.</div>');
}

refresh();
setInterval(refresh, 3000);
</script>
</body></html>`;

// ============================== HTTP SERVER ==============================
const server = http.createServer(async (req, res) => {
  const parsed = new URL(req.url, "http://127.0.0.1");
  const pathname = parsed.pathname;

  // ---- public (no-auth) endpoints: login page + login/logout API ----
  if (pathname === "/login") {
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" });
    res.end(LOGIN_HTML);
    return;
  }
  if (pathname === "/api/login" && req.method === "POST") {
    const body = await readBody(req);
    const user = users.find(u => u.username.toLowerCase() === String(body.username || "").trim().toLowerCase());
    if (!user || !verifyPassword(user, body.password || "")) {
      return send(res, 401, { error: "Invalid username or password" });
    }
    const token = createSession(user.id);
    return send(res, 200, { ok: true, user: publicUser(user) }, { "Set-Cookie": sessionCookie(token) });
  }
  if (pathname === "/api/logout" && req.method === "POST") {
    destroySession(parseCookies(req).sb_session);
    return send(res, 200, { ok: true }, { "Set-Cookie": clearCookie() });
  }

  // ---- everything else requires a valid session ----
  const me = userForRequest(req);
  if (!me) {
    if (pathname.startsWith("/api/")) return send(res, 401, { error: "auth required" });
    // HTML request → bounce to login
    res.writeHead(302, { Location: "/login" });
    res.end();
    return;
  }

  if (pathname === "/" || pathname === "/index.html") {
    // no-store: a cached copy of this page once outlived a JS fix and made the
    // dashboard look broken after the server was already patched.
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" });
    res.end(UI_HTML);
    return;
  }
  if (pathname.startsWith("/api/")) {
    return handleApi(req, res, parsed, me);
  }
  res.writeHead(404); res.end("Not found");
});

// A bind failure on 18800 used to throw uncaught and kill the whole app.
server.on("error", (e) => {
  if (e.code === "EADDRINUSE") {
    console.error(`Port ${PORT} already in use — another Switchboard is running. Exiting.`);
    process.exit(0);
  }
  console.error("Switchboard server error:", e.message);
});

// Keep Switchboard alive through unexpected errors instead of crashing.
process.on("uncaughtException", (e) => console.error("uncaughtException:", (e && e.stack) || e));
process.on("unhandledRejection", (e) => console.error("unhandledRejection:", (e && e.stack) || e));

// ============================== STARTUP ==============================
(async () => {
  console.log("Switchboard starting...");
  loadConfig();
  loadSettings();
  bootstrapUsersIfNeeded();

  // Bind the UI port FIRST so Switchboard is responsive instantly, and so the
  // single-instance guard (server 'error' handler) fires immediately on a clash.
  server.listen(PORT, "127.0.0.1", () => {
    console.log(`\n  ✓ Switchboard ready: http://127.0.0.1:${PORT}/\n`);
  });

  // Background bring-up — none of this blocks the UI from loading.
  await refreshTailscale();
  console.log(`Tailnet: ${state.tailnetHost} (${state.tailnetIPv4})`);
  // Clear orphaned share-servers from a previous crashed instance.
  await sweepOrphanShareServers();
  // (Re)start saved shares — paused shares stay dormant (no server, no Tailscale).
  for (const s of state.shares) {
    if (s.paused) { s.pid = null; console.log(`Paused (not started): ${s.name}`); continue; }
    // A share created via the API while the sweep above was running is already
    // live — starting it again would EADDRINUSE and tear down its tunnel.
    if (s.pid) continue;
    try { await startShare(s); s.lastError = null; console.log(`Started share: ${s.name}`); }
    catch (e) { s.lastError = e.message; console.error(`Failed to start ${s.name}:`, e.message); }
  }
  // Periodic tailnet refresh + share self-healing
  setInterval(async () => { await refreshTailscale(); reconcileShares(); }, 30000);
})();

// Cleanup on exit
function shutdown() {
  console.log("Shutting down...");
  state.shares.forEach(killShareServer);
  cf.stopAll();
  process.exit(0);
}
process.on("SIGINT", shutdown); process.on("SIGTERM", shutdown);

