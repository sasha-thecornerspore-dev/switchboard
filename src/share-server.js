// Generic static-file share server with directory listing + access logging.
// Usage: node share-server.js <port> <root_dir> <log_file> [share_name]
const http = require("http");
const fs = require("fs");
const path = require("path");

const PORT = parseInt(process.argv[2] || "18642", 10);
const ROOT = path.resolve(process.argv[3] || __dirname);
const LOG = process.argv[4] || path.join(__dirname, "share.log");
const NAME = process.argv[5] || path.basename(ROOT);
const AUTH_USER = process.env.SHARE_AUTH_USER || "";
const AUTH_PASS = process.env.SHARE_AUTH_PASS || "";
const AUTH_REALM = (process.env.SHARE_AUTH_REALM || NAME).replace(/"/g, "");

const MIME = {
  ".html": "text/html; charset=utf-8", ".htm": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8", ".js": "text/javascript; charset=utf-8",
  ".json": "application/json", ".xml": "application/xml",
  ".md": "text/markdown; charset=utf-8", ".txt": "text/plain; charset=utf-8",
  ".csv": "text/csv; charset=utf-8",
  ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
  ".gif": "image/gif", ".svg": "image/svg+xml", ".webp": "image/webp",
  ".pdf": "application/pdf",
  ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
  ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  ".zip": "application/zip", ".7z": "application/x-7z-compressed",
  ".mp3": "audio/mpeg", ".mp4": "video/mp4", ".mov": "video/quicktime",
};

function fmtBytes(n) {
  const u = ["B", "KB", "MB", "GB", "TB"]; let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(n < 10 && i > 0 ? 1 : 0)} ${u[i]}`;
}

function logHit(meta) {
  const line = JSON.stringify({ t: new Date().toISOString(), share: NAME, ...meta }) + "\n";
  fs.appendFile(LOG, line, () => {});
}

function listingHtml(reqPath, fsPath) {
  const items = fs.readdirSync(fsPath, { withFileTypes: true })
    .filter(d => !d.name.startsWith("."))
    .sort((a, b) => (a.isDirectory() === b.isDirectory()) ? a.name.localeCompare(b.name) : (a.isDirectory() ? -1 : 1));

  const rows = items.map(d => {
    const isDir = d.isDirectory();
    const stat = (() => { try { return fs.statSync(path.join(fsPath, d.name)); } catch { return null; }})();
    const size = isDir ? "—" : (stat ? fmtBytes(stat.size) : "?");
    const mtime = stat ? stat.mtime.toISOString().slice(0, 16).replace("T", " ") : "?";
    const href = encodeURIComponent(d.name) + (isDir ? "/" : "");
    const icon = isDir ? "📁" : (() => {
      const e = path.extname(d.name).toLowerCase();
      if (/\.(pdf)$/.test(e)) return "📕";
      if (/\.(docx?|odt|rtf)$/.test(e)) return "📄";
      if (/\.(xlsx?|csv)$/.test(e)) return "📊";
      if (/\.(pptx?)$/.test(e)) return "📊";
      if (/\.(jpe?g|png|gif|webp|bmp|svg)$/.test(e)) return "🖼";
      if (/\.(mp4|mov|mkv|avi|webm)$/.test(e)) return "🎬";
      if (/\.(mp3|wav|ogg|flac)$/.test(e)) return "🎵";
      if (/\.(zip|7z|tar|gz|rar)$/.test(e)) return "🗜";
      if (/\.(html?|js|css|json|xml|ya?ml)$/.test(e)) return "📜";
      return "📄";
    })();
    return `<tr><td class="ico">${icon}</td><td><a href="${href}">${d.name}${isDir?"/":""}</a></td><td class="sz">${size}</td><td class="mt">${mtime}</td></tr>`;
  }).join("");

  // Build breadcrumbs
  const parts = reqPath.split("/").filter(Boolean);
  let crumbs = `<a href="/">${NAME}</a>`;
  let acc = "";
  parts.forEach(p => {
    acc += "/" + p;
    crumbs += ` / <a href="${acc}/">${decodeURIComponent(p)}</a>`;
  });

  return `<!DOCTYPE html><html><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${NAME} — ${decodeURIComponent(reqPath)}</title>
<style>
  :root { --navy:#0A1733; --amber:#F4B33C; --cream:#F7F4ED; --ink:#0E0E0E; --gray:#6B7280; }
  *{box-sizing:border-box;margin:0;padding:0;-webkit-font-smoothing:antialiased;}
  body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Inter,Roboto,sans-serif;
    background:var(--cream);color:var(--ink);padding:32px 24px 80px;}
  .wrap{max-width:980px;margin:0 auto;}
  .header{display:flex;align-items:center;gap:14px;margin-bottom:6px;}
  .logo{width:40px;height:40px;border-radius:50%;
    background:radial-gradient(circle at 30% 30%,var(--amber) 0%,#E09B1A 60%,#5a3c0a 100%);
    box-shadow:0 0 24px rgba(244,179,60,.35);}
  h1{font-size:28px;font-weight:800;letter-spacing:-.02em;color:var(--navy);}
  .crumbs{color:var(--gray);font-size:14px;margin:8px 0 24px;}
  .crumbs a{color:var(--navy);text-decoration:none;}
  .crumbs a:hover{color:var(--amber);}
  .private-badge{display:inline-block;background:#1f5e3a;color:#d6f5e2;padding:4px 10px;
    border-radius:999px;font-size:11px;font-weight:700;letter-spacing:.05em;margin-left:8px;}
  table{width:100%;border-collapse:collapse;background:white;border-radius:14px;overflow:hidden;
    box-shadow:0 2px 14px rgba(10,23,51,.05);border:1px solid #ECE6D6;}
  th,td{padding:11px 14px;text-align:left;border-bottom:1px solid #F0EBDA;font-size:14px;}
  th{background:var(--navy);color:white;font-weight:600;font-size:12px;letter-spacing:.05em;text-transform:uppercase;}
  tr:last-child td{border-bottom:none;}
  tr:hover td{background:#FBF8EF;}
  td.ico{width:32px;text-align:center;font-size:18px;}
  td.sz,td.mt{color:var(--gray);font-variant-numeric:tabular-nums;white-space:nowrap;}
  td.sz{text-align:right;width:90px;}
  td.mt{width:140px;}
  a{color:var(--navy);text-decoration:none;font-weight:500;}
  a:hover{color:var(--amber);}
  .footer{margin-top:24px;color:var(--gray);font-size:12px;text-align:center;}
</style></head><body>
<div class="wrap">
  <div class="header"><div class="logo"></div><h1>${NAME}</h1><span class="private-badge">PRIVATE · TAILNET-ONLY</span></div>
  <div class="crumbs">${crumbs}</div>
  <table><thead><tr><th></th><th>Name</th><th style="text-align:right;">Size</th><th>Modified</th></tr></thead>
  <tbody>${rows || '<tr><td colspan="4" style="text-align:center;color:var(--gray);padding:40px;">Empty folder</td></tr>'}</tbody></table>
  <div class="footer">Hosted via Tailscale Serve · ${items.length} item${items.length===1?'':'s'} · Visible only to your tailnet</div>
</div>
</body></html>`;
}

http.createServer((req, res) => {
  const u = new URL(req.url, "http://127.0.0.1");
  let pathname = decodeURIComponent(u.pathname);

  // Optional Basic auth gate
  if (AUTH_USER && AUTH_PASS) {
    const h = req.headers.authorization || "";
    const m = h.match(/^Basic\s+(.+)$/i);
    let ok = false;
    if (m) {
      try {
        const decoded = Buffer.from(m[1], "base64").toString("utf8");
        const idx = decoded.indexOf(":");
        if (idx > -1) {
          ok = (decoded.slice(0, idx) === AUTH_USER && decoded.slice(idx + 1) === AUTH_PASS);
        }
      } catch {}
    }
    if (!ok) {
      res.writeHead(401, {
        "WWW-Authenticate": `Basic realm="${AUTH_REALM}", charset="UTF-8"`,
        "Content-Type": "text/plain; charset=utf-8"
      });
      res.end("Authentication required");
      logHit({ method: req.method, path: pathname, status: 401, ip: req.socket.remoteAddress, ua: req.headers["user-agent"] || "" });
      return;
    }
  }

  const safe = path.normalize(pathname).replace(/^(\.\.[\/\\])+/, "");
  const filePath = path.join(ROOT, safe);
  if (!filePath.startsWith(ROOT)) {
    res.writeHead(403); res.end("Forbidden"); return;
  }

  fs.stat(filePath, (err, st) => {
    if (err) { res.writeHead(404); res.end("Not found");
      logHit({method:req.method, path:pathname, status:404, ip:req.socket.remoteAddress, ua:req.headers["user-agent"]||""}); return;
    }
    if (st.isDirectory()) {
      // Ensure trailing slash for relative links
      if (!pathname.endsWith("/")) {
        res.writeHead(301, { Location: pathname + "/" }); res.end(); return;
      }
      const html = listingHtml(pathname, filePath);
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" });
      res.end(html);
      logHit({method:req.method, path:pathname, status:200, kind:"listing", ip:req.socket.remoteAddress, ua:req.headers["user-agent"]||""});
      return;
    }
    const ext = path.extname(filePath).toLowerCase();
    const mime = MIME[ext] || "application/octet-stream";
    res.writeHead(200, {
      "Content-Type": mime,
      "Content-Length": st.size,
      "Cache-Control": "no-store",
      ...(/\.(pptx|docx|xlsx|pdf|zip|7z|mp4|mov)$/i.test(filePath)
        ? { "Content-Disposition": `attachment; filename="${path.basename(filePath)}"` } : {})
    });
    fs.createReadStream(filePath).pipe(res);
    logHit({method:req.method, path:pathname, status:200, bytes:st.size, mime, ip:req.socket.remoteAddress, ua:req.headers["user-agent"]||""});
  });
}).listen(PORT, "127.0.0.1", () => {
  console.log(`[${NAME}] share server listening at http://127.0.0.1:${PORT} → ${ROOT}`);
}).on("error", (e) => {
  // Without this handler an EADDRINUSE (port already held by an orphaned
  // share-server) throws uncaught and kills the process silently — which is
  // exactly what left Funnel paths pointing at dead ports (502s).
  if (e.code === "EADDRINUSE") {
    console.error(`[${NAME}] port ${PORT} is already in use — exiting cleanly.`);
  } else {
    console.error(`[${NAME}] fatal server error:`, e.message);
  }
  process.exit(1);
});

process.on("uncaughtException", (e) => {
  console.error(`[${NAME}] uncaughtException:`, (e && e.stack) || e);
});
