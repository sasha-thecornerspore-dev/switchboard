// OPNsense os-nginx integration: push a share's reverse-proxy config straight
// into the firewall over its REST API instead of copy-pasting the four forms.
//
// Objects are created in dependency order and tagged by description so the push
// is idempotent (re-pushing updates in place):
//   Upstream Server  sb-<slug>        host:port of the share origin
//   Upstream         sb-<slug>        → that server entry
//   Location         sb-<slug>-root   URL pattern "/" → upstream, force https
//   HTTP Server      sb-<slug>        server_name <hostname>, 80/443, cert, location
// then Services → Nginx → reconfigure.
//
// Auth is the standard OPNsense API key/secret pair (System → Access → Users →
// API keys) sent as HTTP Basic. Self-signed certificates are the norm, so
// `insecure: true` skips TLS verification for the OPNsense host only.
const { requestJson } = require("./http-json");

const KINDS = {
  upstreamserver: { add: "addupstreamserver", set: "setupstreamserver", get: "getupstreamserver", search: "searchupstreamserver", del: "delupstreamserver", key: "upstreamserver" },
  upstream:       { add: "addupstream",       set: "setupstream",       get: "getupstream",       search: "searchupstream",       del: "delupstream",       key: "upstream" },
  location:       { add: "addlocation",       set: "setlocation",       get: "getlocation",       search: "searchlocation",       del: "dellocation",       key: "location" },
  httpserver:     { add: "addhttpserver",     set: "sethttpserver",     get: "gethttpserver",     search: "searchhttpserver",     del: "delhttpserver",     key: "httpserver" },
};

function slugify(name) {
  return (String(name || "share").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/(^-|-$)/g, "") || "share").slice(0, 40);
}

class OpnsenseClient {
  constructor({ url, key, secret, insecure = true }) {
    this.base = String(url || "").trim().replace(/\/+$/, "");
    if (this.base && !/^https?:\/\//i.test(this.base)) this.base = "https://" + this.base;
    this.key = key; this.secret = secret; this.insecure = !!insecure;
  }
  configured() { return !!(this.base && this.key && this.secret); }

  async call(method, apiPath, body) {
    if (!this.configured()) throw new Error("OPNsense isn't configured — add the URL, API key and secret in Settings");
    const auth = "Basic " + Buffer.from(`${this.key}:${this.secret}`).toString("base64");
    let r;
    try {
      r = await requestJson(this.base + apiPath, { method, body, insecure: this.insecure, headers: { Authorization: auth } });
    } catch (e) {
      const hint = /self[- ]signed|certificate|CERT_|unable to verify/i.test(e.message) ? " — enable “allow self-signed certificate” in Settings" : "";
      throw new Error(`OPNsense unreachable at ${this.base}: ${e.message}${hint}`);
    }
    if (r.status === 401 || r.status === 403) throw new Error("OPNsense rejected the API key/secret (HTTP " + r.status + ")");
    if (r.status === 404) throw new Error(`OPNsense returned 404 for ${apiPath} — is the os-nginx plugin installed?`);
    if (!r.ok) throw new Error(`OPNsense HTTP ${r.status} on ${apiPath}: ${(r.text || "").slice(0, 200)}`);
    return r.json;
  }

  // Settings → "Test": confirms auth + plugin presence and lists certificates
  // the HTTP Server form can use.
  async test() {
    const tpl = await this.call("GET", "/api/nginx/settings/gethttpserver");
    const certOpts = (tpl && tpl.httpserver && tpl.httpserver.certificate) || {};
    const certs = Object.entries(certOpts).map(([id, o]) => ({ id, name: (o && o.value) || id })).filter((c) => c.id !== "");
    let version = null;
    try { const fw = await this.call("GET", "/api/core/firmware/status"); version = fw && (fw.product_version || (fw.product && fw.product.product_version)) || null; } catch {}
    return { ok: true, certs, version };
  }

  async findUuid(kind, description) {
    const k = KINDS[kind];
    const r = await this.call("GET", `/api/nginx/settings/${k.search}?searchPhrase=${encodeURIComponent(description)}&current=1&rowCount=50`);
    const rows = (r && r.rows) || [];
    const hit = rows.find((x) => x.description === description);
    return hit ? hit.uuid : null;
  }

  // Create or update one object; returns its uuid.
  async upsert(kind, description, fields) {
    const k = KINDS[kind];
    const payload = { [k.key]: { description, ...fields } };
    const existing = await this.findUuid(kind, description);
    const r = existing
      ? await this.call("POST", `/api/nginx/settings/${k.set}/${existing}`, payload)
      : await this.call("POST", `/api/nginx/settings/${k.add}`, payload);
    if (!r || r.result !== "saved") {
      const v = r && r.validations ? Object.entries(r.validations).map(([f, m]) => `${f}: ${m}`).join("; ") : JSON.stringify(r).slice(0, 200);
      throw new Error(`OPNsense refused ${kind} "${description}": ${v}`);
    }
    return existing || r.uuid;
  }

  async remove(kind, uuid) {
    if (!uuid) return false;
    const k = KINDS[kind];
    try { const r = await this.call("POST", `/api/nginx/settings/${k.del}/${uuid}`, {}); return !!(r && r.result === "deleted"); }
    catch { return false; }
  }

  async reconfigure() {
    const r = await this.call("POST", "/api/nginx/service/reconfigure", {});
    if (!r || !/ok/i.test(String(r.status || r.result || ""))) throw new Error("OPNsense nginx reconfigure did not report OK: " + JSON.stringify(r).slice(0, 200));
    return true;
  }

  // The whole dance for one share. Returns the uuids so Switchboard can show
  // "pushed" state and remove the objects later.
  async pushShare({ name, originHost, originPort, hostname, certificate }) {
    if (!hostname) throw new Error("Set the share's public hostname first");
    if (!originHost || /^127\.|^localhost$/i.test(originHost)) throw new Error("Origin is on localhost — OPNsense can't reach it. Flip the origin to LAN first.");
    const slug = slugify(name);
    const tag = "sb-" + slug;
    const steps = [];
    const serverUuid = await this.upsert("upstreamserver", tag, { server: originHost, port: String(originPort), priority: "1" });
    steps.push("upstream server");
    const upstreamUuid = await this.upsert("upstream", tag, { serverentries: serverUuid, load_balancing_algorithm: "", tls_enable: "0" });
    steps.push("upstream");
    const locationUuid = await this.upsert("location", tag + "-root", { urlpattern: "/", matchtype: "", upstream: upstreamUuid, force_https: "1", enable_secrules: "0" });
    steps.push("location");
    const serverFields = { servername: hostname, locations: locationUuid, listen_http_port: "80", listen_https_port: "443", https_only: "1" };
    if (certificate) serverFields.certificate = certificate;
    const httpUuid = await this.upsert("httpserver", tag, serverFields);
    steps.push("http server");
    await this.reconfigure();
    steps.push("reconfigure");
    return { uuids: { upstreamserver: serverUuid, upstream: upstreamUuid, location: locationUuid, httpserver: httpUuid }, tag, steps, pushedAt: new Date().toISOString() };
  }

  async removeShare(uuids) {
    const u = uuids || {};
    const removed = {};
    // Reverse dependency order.
    removed.httpserver = await this.remove("httpserver", u.httpserver);
    removed.location = await this.remove("location", u.location);
    removed.upstream = await this.remove("upstream", u.upstream);
    removed.upstreamserver = await this.remove("upstreamserver", u.upstreamserver);
    try { await this.reconfigure(); } catch {}
    return removed;
  }
}

module.exports = { OpnsenseClient, slugify };
