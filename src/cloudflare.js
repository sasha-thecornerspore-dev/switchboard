// Cloudflare Tunnel publish method for Switchboard.
//
// Two flavours, chosen automatically:
//   quick  — no Cloudflare account needed. `cloudflared tunnel --url` hands back
//            a random https://*.trycloudflare.com URL for one share. Great for
//            "send someone a link right now"; the URL changes on every restart.
//   named  — API token + account + zone configured in Settings. Switchboard
//            owns ONE remotely-managed tunnel per install, writes an ingress rule
//            per share (hostname → http://127.0.0.1:port), upserts a proxied
//            CNAME for each hostname, and keeps a single `cloudflared tunnel run
//            --token` process alive. Stable hostnames on your own domain.
//
// Pure Node, no npm deps. The API base can be overridden (SWITCHBOARD_CF_API)
// so the whole flow is testable against a fake server.
const { spawn, exec, execSync } = require("child_process");
const fs = require("fs");
const path = require("path");
const os = require("os");
const { requestJson } = require("./http-json");

const API_BASE = process.env.SWITCHBOARD_CF_API || "https://api.cloudflare.com/client/v4";
const DOWNLOAD_URL = "https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/";
const QUICK_URL_RE = /https:\/\/[a-z0-9-]+\.trycloudflare\.com/i;

// ----- binary -----
// A `.js` path (via SWITCHBOARD_CLOUDFLARED) is run through node — this is how
// the test-suite substitutes a fake cloudflared without a real binary.
function spawnCloudflared(bin, args) {
  if (/\.js$/i.test(bin)) return spawn(process.execPath, [bin, ...args], { windowsHide: true, stdio: ["ignore", "pipe", "pipe"] });
  return spawn(bin, args, { windowsHide: true, stdio: ["ignore", "pipe", "pipe"] });
}
function candidatePaths() {
  const c = [];
  if (process.env.SWITCHBOARD_CLOUDFLARED) c.push(process.env.SWITCHBOARD_CLOUDFLARED);
  if (process.platform === "win32") {
    for (const base of [process.env.PROGRAMFILES, process.env["ProgramFiles(x86)"], process.env.LOCALAPPDATA && path.join(process.env.LOCALAPPDATA, "Microsoft", "WinGet", "Links")]) {
      if (!base) continue;
      c.push(path.join(base, "cloudflared", "cloudflared.exe"));
      c.push(path.join(base, "cloudflared.exe"));
    }
  } else {
    c.push("/opt/homebrew/bin/cloudflared", "/usr/local/bin/cloudflared", "/usr/bin/cloudflared");
  }
  return c;
}
function detectCloudflared() {
  for (const p of candidatePaths()) { try { if (fs.existsSync(p)) return p; } catch {} }
  try {
    const out = execSync(process.platform === "win32" ? "where cloudflared" : "command -v cloudflared", { stdio: ["ignore", "pipe", "ignore"] }).toString().trim().split(/\r?\n/)[0];
    if (out) return out;
  } catch {}
  return null;
}
function hasCmd(cmd) {
  try { execSync(process.platform === "win32" ? `where ${cmd}` : `command -v ${cmd}`, { stdio: "ignore" }); return true; } catch { return false; }
}
function installCloudflared() {
  return new Promise((resolve, reject) => {
    let cmd;
    if (process.platform === "win32") {
      if (!hasCmd("winget")) return reject(Object.assign(new Error("winget isn't available on this PC. Install cloudflared manually."), { manualUrl: DOWNLOAD_URL }));
      cmd = "winget install --id Cloudflare.cloudflared -e --silent --accept-package-agreements --accept-source-agreements";
    } else if (process.platform === "darwin") {
      if (!hasCmd("brew")) return reject(Object.assign(new Error("Homebrew isn't installed. Install cloudflared manually."), { manualUrl: DOWNLOAD_URL }));
      cmd = "brew install cloudflared";
    } else {
      return reject(Object.assign(new Error("Auto-install is only supported on Windows and macOS."), { manualUrl: DOWNLOAD_URL }));
    }
    exec(cmd, { windowsHide: true, timeout: 5 * 60 * 1000, maxBuffer: 8 * 1024 * 1024 }, (err, stdout, stderr) => {
      if (err) return reject(Object.assign(new Error("Install failed: " + (stderr || stdout || err.message || "").toString().slice(0, 400)), { manualUrl: DOWNLOAD_URL }));
      resolve((stdout || "").toString().slice(-400));
    });
  });
}

// ----- API -----
function cfError(r, what) {
  const msgs = (r.json && r.json.errors || []).map((e) => e.message || JSON.stringify(e)).join("; ");
  return new Error(`Cloudflare ${what} failed (HTTP ${r.status})${msgs ? ": " + msgs : ""}`);
}

class CloudflareTunnel {
  // getSettings() → the live settings.cloudflare object (mutated in place);
  // saveSettings() persists it. log(msg) for console output.
  constructor({ getSettings, saveSettings, log = console.log }) {
    this.getSettings = getSettings;
    this.saveSettings = saveSettings;
    this.log = log;
    this.bin = detectCloudflared();
    this.named = { proc: null, pid: null, connected: false, lastError: null, since: null, token: null };
    this.quick = new Map(); // shareId -> { proc, url }
  }

  refreshBinary() { this.bin = detectCloudflared(); return this.bin; }
  installed() { return !!this.bin; }
  configured() {
    const c = this.getSettings() || {};
    return !!(c.apiToken && c.accountId && c.zoneName);
  }
  zoneName() { return ((this.getSettings() || {}).zoneName || "").toLowerCase(); }
  hostnameInZone(h) {
    const z = this.zoneName(); h = String(h || "").toLowerCase();
    return !!z && !!h && (h === z || h.endsWith("." + z));
  }

  async api(method, apiPath, body) {
    const c = this.getSettings() || {};
    if (!c.apiToken) throw new Error("No Cloudflare API token configured");
    const r = await requestJson(API_BASE + apiPath, { method, body, headers: { Authorization: "Bearer " + c.apiToken } });
    return r;
  }

  // Settings → "Test": verifies the token, resolves the zone, and reports the
  // tunnel (if one exists yet). Never mutates settings except caching zoneId.
  async verify() {
    const c = this.getSettings() || {};
    const out = { ok: false, token: false, zoneId: null, zoneName: c.zoneName || null, accountId: c.accountId || null, tunnel: null, cloudflared: this.refreshBinary() };
    const v = await this.api("GET", "/user/tokens/verify");
    if (!v.ok || !v.json || !v.json.success) throw cfError(v, "token verify");
    out.token = true;
    if (c.zoneName) {
      const z = await this.api("GET", "/zones?name=" + encodeURIComponent(c.zoneName));
      if (!z.ok || !z.json || !z.json.success) throw cfError(z, "zone lookup");
      const zone = (z.json.result || [])[0];
      if (!zone) throw new Error(`Zone "${c.zoneName}" not found on this token — check the zone name and the token's Zone:DNS permission`);
      c.zoneId = zone.id; out.zoneId = zone.id;
      if (!c.accountId && zone.account && zone.account.id) { c.accountId = zone.account.id; out.accountId = c.accountId; }
      this.saveSettings();
    }
    if (c.accountId && c.tunnelId) {
      const t = await this.api("GET", `/accounts/${c.accountId}/cfd_tunnel/${c.tunnelId}`);
      if (t.ok && t.json && t.json.success && t.json.result && !t.json.result.deleted_at) {
        out.tunnel = { id: t.json.result.id, name: t.json.result.name, status: t.json.result.status };
      }
    }
    out.ok = true;
    return out;
  }

  async ensureZoneId() {
    const c = this.getSettings();
    if (c.zoneId) return c.zoneId;
    const z = await this.api("GET", "/zones?name=" + encodeURIComponent(c.zoneName));
    if (!z.ok || !z.json || !z.json.success) throw cfError(z, "zone lookup");
    const zone = (z.json.result || [])[0];
    if (!zone) throw new Error(`Zone "${c.zoneName}" not found on this token`);
    c.zoneId = zone.id; this.saveSettings();
    return c.zoneId;
  }

  // One tunnel per Switchboard install. Reuse the stored id if it still exists;
  // otherwise adopt an existing tunnel of our name or create a fresh one.
  async ensureTunnel() {
    const c = this.getSettings();
    const acct = c.accountId;
    if (c.tunnelId && c.tunnelToken) {
      const t = await this.api("GET", `/accounts/${acct}/cfd_tunnel/${c.tunnelId}`);
      if (t.ok && t.json && t.json.success && t.json.result && !t.json.result.deleted_at) return c.tunnelId;
      c.tunnelId = null; c.tunnelToken = null;
    }
    const name = c.tunnelName || ("switchboard-" + os.hostname().toLowerCase().replace(/[^a-z0-9-]+/g, "-"));
    let id = null;
    const existing = await this.api("GET", `/accounts/${acct}/cfd_tunnel?name=${encodeURIComponent(name)}&is_deleted=false`);
    if (existing.ok && existing.json && existing.json.success && (existing.json.result || []).length) id = existing.json.result[0].id;
    if (!id) {
      const made = await this.api("POST", `/accounts/${acct}/cfd_tunnel`, { name, config_src: "cloudflare" });
      if (!made.ok || !made.json || !made.json.success) throw cfError(made, "tunnel create");
      id = made.json.result.id;
    }
    const tok = await this.api("GET", `/accounts/${acct}/cfd_tunnel/${id}/token`);
    if (!tok.ok || !tok.json || !tok.json.success) throw cfError(tok, "tunnel token");
    c.tunnelId = id; c.tunnelName = name; c.tunnelToken = tok.json.result;
    this.saveSettings();
    return id;
  }

  // rules: [{ hostname, service }] — the catch-all 404 is appended here.
  async applyIngress(rules) {
    const c = this.getSettings();
    const id = await this.ensureTunnel();
    const ingress = rules.map((r) => ({ hostname: r.hostname, service: r.service, originRequest: { httpHostHeader: r.hostname } }));
    ingress.push({ service: "http_status:404" });
    const r = await this.api("PUT", `/accounts/${c.accountId}/cfd_tunnel/${id}/configurations`, { config: { ingress } });
    if (!r.ok || !r.json || !r.json.success) throw cfError(r, "ingress update");
    return id;
  }

  async upsertDns(hostname) {
    const c = this.getSettings();
    const zoneId = await this.ensureZoneId();
    const id = await this.ensureTunnel();
    const target = `${id}.cfargotunnel.com`;
    const q = await this.api("GET", `/zones/${zoneId}/dns_records?name=${encodeURIComponent(hostname)}`);
    if (!q.ok || !q.json || !q.json.success) throw cfError(q, "DNS lookup");
    const rec = (q.json.result || []).find((x) => x.name.toLowerCase() === hostname.toLowerCase());
    const body = { type: "CNAME", name: hostname, content: target, proxied: true, ttl: 1, comment: "Switchboard tunnel" };
    if (rec) {
      if (rec.type === "CNAME" && rec.content === target && rec.proxied) return rec.id;
      const u = await this.api("PUT", `/zones/${zoneId}/dns_records/${rec.id}`, body);
      if (!u.ok || !u.json || !u.json.success) throw cfError(u, "DNS update");
      return rec.id;
    }
    const m = await this.api("POST", `/zones/${zoneId}/dns_records`, body);
    if (!m.ok || !m.json || !m.json.success) throw cfError(m, "DNS create");
    return m.json.result.id;
  }

  async deleteDns(hostname) {
    const c = this.getSettings();
    if (!c.tunnelId) return false;
    const zoneId = await this.ensureZoneId();
    const target = `${c.tunnelId}.cfargotunnel.com`;
    const q = await this.api("GET", `/zones/${zoneId}/dns_records?name=${encodeURIComponent(hostname)}`);
    if (!q.ok || !q.json || !q.json.success) return false;
    // Only remove the record if WE made it (points at our tunnel) — never
    // clobber a user's unrelated record of the same name.
    const rec = (q.json.result || []).find((x) => x.name.toLowerCase() === hostname.toLowerCase() && x.type === "CNAME" && x.content === target);
    if (!rec) return false;
    const d = await this.api("DELETE", `/zones/${zoneId}/dns_records/${rec.id}`);
    return d.ok;
  }

  // ----- named tunnel process -----
  ensureRunning() {
    const c = this.getSettings();
    if (!c.tunnelToken) throw new Error("Tunnel has no token yet — run ensureTunnel first");
    if (!this.bin) this.refreshBinary();
    if (!this.bin) throw new Error("cloudflared is not installed");
    if (this.named.proc && this.named.token === c.tunnelToken) return this.named.pid;
    if (this.named.proc) this.stopNamed();
    const proc = spawnCloudflared(this.bin, ["tunnel", "--no-autoupdate", "run", "--token", c.tunnelToken]);
    const myPid = proc.pid;
    this.named = { proc, pid: myPid, connected: false, lastError: null, since: new Date().toISOString(), token: c.tunnelToken };
    const onLine = (d) => {
      const line = String(d);
      if (/Registered tunnel connection/i.test(line)) this.named.connected = true;
      if (/ERR/.test(line)) this.named.lastError = line.replace(/^.*?ERR\s*/, "").trim().slice(0, 240);
    };
    proc.stdout.on("data", onLine); proc.stderr.on("data", onLine);
    proc.on("exit", (code) => {
      this.log(`cloudflared (named tunnel, pid=${myPid}) exited code=${code}`);
      if (this.named.pid === myPid) { this.named.proc = null; this.named.pid = null; this.named.connected = false; }
    });
    proc.on("error", (e) => { this.named.lastError = e.message; if (this.named.pid === myPid) { this.named.proc = null; this.named.pid = null; } });
    return myPid;
  }
  stopNamed() {
    if (this.named.proc) { try { this.named.proc.kill(); } catch {} }
    this.named.proc = null; this.named.pid = null; this.named.connected = false;
  }

  // ----- quick tunnels -----
  startQuick(shareId, port, timeoutMs = 45000) {
    if (!this.bin) this.refreshBinary();
    if (!this.bin) return Promise.reject(Object.assign(new Error("cloudflared is not installed"), { needsInstall: true }));
    this.stopQuick(shareId);
    return new Promise((resolve, reject) => {
      const proc = spawnCloudflared(this.bin, ["tunnel", "--no-autoupdate", "--url", `http://127.0.0.1:${port}`]);
      const entry = { proc, url: null, pid: proc.pid, lastError: null };
      this.quick.set(shareId, entry);
      let done = false, tail = "";
      const timer = setTimeout(() => { if (!done) { done = true; this.stopQuick(shareId); reject(new Error("cloudflared didn't report a trycloudflare.com URL within " + (timeoutMs / 1000) + "s" + (tail ? ": " + tail.slice(-200) : ""))); } }, timeoutMs);
      const onLine = (d) => {
        const line = String(d); tail = (tail + line).slice(-800);
        const m = line.match(QUICK_URL_RE);
        if (m && !done) { done = true; clearTimeout(timer); entry.url = m[0]; resolve({ url: entry.url, pid: entry.pid }); }
        if (/ERR/.test(line)) entry.lastError = line.replace(/^.*?ERR\s*/, "").trim().slice(0, 240);
      };
      proc.stdout.on("data", onLine); proc.stderr.on("data", onLine);
      proc.on("exit", (code) => {
        this.log(`cloudflared (quick tunnel for ${shareId}, pid=${entry.pid}) exited code=${code}`);
        if (this.quick.get(shareId) === entry) this.quick.delete(shareId);
        if (!done) { done = true; clearTimeout(timer); reject(new Error("cloudflared exited (code " + code + ") before a URL appeared" + (entry.lastError ? ": " + entry.lastError : ""))); }
      });
      proc.on("error", (e) => { if (!done) { done = true; clearTimeout(timer); reject(new Error("cloudflared failed to start: " + e.message)); } });
    });
  }
  stopQuick(shareId) {
    const e = this.quick.get(shareId);
    if (!e) return;
    try { e.proc.kill(); } catch {}
    this.quick.delete(shareId);
  }
  quickUrl(shareId) { const e = this.quick.get(shareId); return e ? e.url : null; }
  quickRunning(shareId) { return this.quick.has(shareId); }
  stopAll() { this.stopNamed(); for (const id of [...this.quick.keys()]) this.stopQuick(id); }

  status() {
    const c = this.getSettings() || {};
    return {
      installed: !!this.bin, bin: this.bin, configured: this.configured(),
      zoneName: c.zoneName || null, accountId: c.accountId || null,
      tunnel: { id: c.tunnelId || null, name: c.tunnelName || null, running: !!this.named.proc, connected: this.named.connected, lastError: this.named.lastError, since: this.named.since },
      quickCount: this.quick.size, manualUrl: DOWNLOAD_URL,
    };
  }
}

module.exports = { CloudflareTunnel, detectCloudflared, installCloudflared, DOWNLOAD_URL };
