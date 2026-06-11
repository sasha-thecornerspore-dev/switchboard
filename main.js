// Switchboard desktop — Electron main process.
//
// Unlike a thin viewer, this owns the whole lifecycle: it spawns the bundled
// switchboard.js service (as a Node child via ELECTRON_RUN_AS_NODE), points its
// writable data at the per-user app-data folder, then renders the dashboard in
// a native window with a tray icon. Quitting the app stops the service.

const { app, BrowserWindow, Tray, Menu, nativeImage, shell, dialog, ipcMain } = require("electron");
const { spawn } = require("child_process");
const path = require("path");
const net = require("net");

const SWITCHBOARD_PORT = Number(process.env.SWITCHBOARD_PORT) || 18800;
const SWITCHBOARD_URL = `http://127.0.0.1:${SWITCHBOARD_PORT}/`;

// In dev the service lives in ./src; once packaged it is shipped as an
// unpacked extraResource (so a child Node process can read it — code inside an
// asar archive isn't reachable by a plain spawn).
const SERVICE_DIR = app.isPackaged
  ? path.join(process.resourcesPath, "service")
  : path.join(__dirname, "src");
const SERVICE_ENTRY = path.join(SERVICE_DIR, "switchboard.js");
const ICON_PATH = app.isPackaged
  ? path.join(process.resourcesPath, "switchboard.ico")
  : path.join(__dirname, "assets", "switchboard.ico");

let mainWindow = null;
let tray = null;
let serviceProc = null;
let isQuitting = false;

// Single-instance: a second launch just refocuses the existing window.
if (!app.requestSingleInstanceLock()) {
  app.quit();
} else {
  app.on("second-instance", () => {
    if (mainWindow) { if (mainWindow.isMinimized()) mainWindow.restore(); mainWindow.show(); mainWindow.focus(); }
  });
}

function checkPort(port) {
  return new Promise((resolve) => {
    const s = net.createConnection({ host: "127.0.0.1", port, timeout: 700 });
    s.once("connect", () => { s.destroy(); resolve(true); });
    s.once("error", () => resolve(false));
    s.once("timeout", () => { s.destroy(); resolve(false); });
  });
}

function startService() {
  // Run the bundled service as a pure Node process using Electron's own binary.
  const env = {
    ...process.env,
    ELECTRON_RUN_AS_NODE: "1",
    SWITCHBOARD_DATA_DIR: app.getPath("userData"),
    SWITCHBOARD_PORT: String(SWITCHBOARD_PORT),
  };
  serviceProc = spawn(process.execPath, [SERVICE_ENTRY], { env, stdio: ["ignore", "pipe", "pipe"] });
  serviceProc.stdout.on("data", (d) => process.stdout.write(`[switchboard] ${d}`));
  serviceProc.stderr.on("data", (d) => process.stderr.write(`[switchboard] ${d}`));
  serviceProc.on("exit", (code) => { serviceProc = null; if (!isQuitting) console.error(`Service exited (${code})`); });
}

async function ensureServiceUp() {
  if (await checkPort(SWITCHBOARD_PORT)) return true; // already running (e.g. standalone install)
  startService();
  for (let i = 0; i < 40; i++) {
    await new Promise((r) => setTimeout(r, 400));
    if (await checkPort(SWITCHBOARD_PORT)) return true;
  }
  return false;
}

async function createWindow() {
  const up = await ensureServiceUp();

  mainWindow = new BrowserWindow({
    width: 1280, height: 900, minWidth: 760, minHeight: 580,
    icon: ICON_PATH, title: "Switchboard", backgroundColor: "#0A1733",
    autoHideMenuBar: true, show: false,
    webPreferences: { contextIsolation: true, nodeIntegration: false, sandbox: false, preload: path.join(__dirname, "preload.js") },
  });

  if (up) {
    mainWindow.loadURL(SWITCHBOARD_URL);
  } else {
    const html = `<!DOCTYPE html><meta charset="utf-8"><body style="font-family:-apple-system,Segoe UI,sans-serif;background:#0A1733;color:#F7F4ED;min-height:100vh;display:flex;align-items:center;justify-content:center;margin:0"><div style="max-width:520px;text-align:center;padding:32px"><h1 style="color:#F4B33C">Switchboard didn't start</h1><p style="line-height:1.6">The background service failed to come up on port ${SWITCHBOARD_PORT}. Check the logs in your app-data folder, then reopen.</p><button onclick="location.reload()" style="margin-top:24px;background:#F4B33C;color:#0A1733;border:none;border-radius:999px;padding:10px 22px;font-weight:700;cursor:pointer">Try again</button></div></body>`;
    mainWindow.loadURL("data:text/html;charset=utf-8," + encodeURIComponent(html));
  }

  mainWindow.once("ready-to-show", () => mainWindow.show());

  // Open external links (share URLs, tailnet admin) in the real browser.
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (/^https?:/i.test(url)) shell.openExternal(url);
    return { action: "deny" };
  });
  mainWindow.webContents.on("will-navigate", (e, url) => {
    if (!url.startsWith(SWITCHBOARD_URL)) { e.preventDefault(); if (/^https?:/i.test(url)) shell.openExternal(url); }
  });

  // Close → hide to tray; quit only via tray menu.
  mainWindow.on("close", (e) => { if (!isQuitting) { e.preventDefault(); mainWindow.hide(); } });
}

function createTray() {
  tray = new Tray(nativeImage.createFromPath(ICON_PATH));
  tray.setToolTip("Switchboard — Tailscale share manager");
  tray.setContextMenu(Menu.buildFromTemplate([
    { label: "Open dashboard", click: () => { if (mainWindow) { mainWindow.show(); mainWindow.focus(); } } },
    { label: "Open in default browser", click: () => shell.openExternal(SWITCHBOARD_URL) },
    { type: "separator" },
    { label: "Reload window", click: () => mainWindow && mainWindow.reload() },
    { type: "separator" },
    { label: "Quit Switchboard", click: () => { isQuitting = true; app.quit(); } },
  ]));
  tray.on("click", () => { if (mainWindow) { mainWindow.show(); mainWindow.focus(); } });
}

// Native folder picker exposed to the dashboard via preload — cross-platform,
// replaces the Windows-only PowerShell dialog when running inside the app.
ipcMain.handle("switchboard:pickFolder", async () => {
  const r = await dialog.showOpenDialog(mainWindow, { title: "Select a folder to share", properties: ["openDirectory"] });
  return (!r.canceled && r.filePaths[0]) ? r.filePaths[0] : "";
});

app.whenReady().then(() => { createWindow(); createTray(); });
app.on("window-all-closed", () => { /* stay in tray */ });
app.on("activate", () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });
app.on("before-quit", () => { isQuitting = true; if (serviceProc) { try { serviceProc.kill(); } catch {} } });
