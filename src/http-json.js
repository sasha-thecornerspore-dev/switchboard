// Tiny JSON-over-HTTP(S) client shared by the Cloudflare and OPNsense
// integrations. No npm deps. Supports Basic/Bearer auth and — because OPNsense
// boxes almost always run a self-signed certificate — an `insecure` flag that
// skips TLS verification for that one request.
const http = require("http");
const https = require("https");

function requestJson(url, { method = "GET", headers = {}, body, insecure = false, timeoutMs = 20000 } = {}) {
  return new Promise((resolve, reject) => {
    let u;
    try { u = new URL(url); } catch { return reject(new Error("Bad URL: " + url)); }
    const mod = u.protocol === "https:" ? https : http;
    const data = body === undefined ? null : (typeof body === "string" ? body : JSON.stringify(body));
    const req = mod.request({
      protocol: u.protocol, hostname: u.hostname, port: u.port || (u.protocol === "https:" ? 443 : 80),
      path: u.pathname + u.search, method,
      headers: { "Accept": "application/json", ...(data ? { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(data) } : {}), ...headers },
      rejectUnauthorized: !insecure,
    }, (res) => {
      let buf = "";
      res.on("data", (c) => buf += c);
      res.on("end", () => {
        let json = null;
        try { json = buf ? JSON.parse(buf) : null; } catch { /* non-JSON body */ }
        resolve({ status: res.statusCode, ok: res.statusCode >= 200 && res.statusCode < 300, json, text: buf });
      });
    });
    req.setTimeout(timeoutMs, () => { req.destroy(new Error("Request timed out after " + timeoutMs + "ms")); });
    req.on("error", (e) => reject(new Error(e.code === "ECONNREFUSED" ? `Connection refused by ${u.host}` : e.message)));
    if (data) req.write(data);
    req.end();
  });
}

module.exports = { requestJson };
