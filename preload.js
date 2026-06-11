// Preload bridge: exposes a tiny, safe native API to the dashboard page.
// Only the folder picker is bridged; everything else goes through the local
// HTTP API. contextIsolation keeps this isolated from page scripts.
const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("switchboardNative", {
  // Returns the chosen absolute path, or "" if the user cancels.
  pickFolder: () => ipcRenderer.invoke("switchboard:pickFolder"),
});
