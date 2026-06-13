# 🎛 Switchboard

A self-hosted **Tailscale share manager** with **multi-user access control**.

Pick folders on your machine and publish them — privately to your tailnet or
publicly via Tailscale Funnel — then hand out clean URLs (with QR codes),
password-protect them, and watch a live dashboard of who's hitting what. Give
other people their own logins and grant them *view-only* or *manage* access to
exactly the shares you choose.

![Switchboard](assets/switchboard-1024.png)

---

## Features

- **One-click folder sharing** over Tailscale Serve (tailnet-private) or Funnel (public internet)
- **Multi-user accounts & profiles**
  - Admin and User roles
  - Per-share grants: each user gets **view-only** or **manage** on the specific shares you pick — the whole dashboard or just slices of it
  - Passwords stored as salted **scrypt** hashes (never plaintext)
  - Cookie sessions; first-run admin is auto-provisioned
- **Password-protected shares** (HTTP Basic auth) with auto-generated credentials and a one-click "ready-to-send" block
- **Live dashboard** — hits, bytes, unique visitors, per-minute sparkline, activity feed, QR codes
- **Tailscale-aware** — detects whether Tailscale is installed, running, and signed in; offers a one-click **install** (winget on Windows, Homebrew on macOS) or **connect** right from the dashboard when it's missing or down
- **Self-healing** — watches the Tailscale backend and auto-restarts shares when the tailnet recovers
- **Native desktop app** (Electron) with a tray icon, plus a plain browser dashboard

## How it works

Two small Node services, no external dependencies:

| File | Role |
|------|------|
| `src/switchboard.js` | The manager: dashboard UI, auth, REST API, Tailscale orchestration. Listens on `http://127.0.0.1:18800`. |
| `src/share-server.js` | A per-share static file server (directory listing, logging, optional Basic auth). One process per active share. |
| `main.js` / `preload.js` | The Electron desktop wrapper — spawns the service, renders the dashboard, adds a tray icon and a native folder picker. |

Each share gets its own local port; Switchboard wires `tailscale serve`/`funnel`
to it. The dashboard polls `/api/state` and renders everything client-side.

## Install

### Download an installer (recommended)

Grab the latest **Windows `.exe`** or **macOS `.dmg`** from the
[Releases page](https://github.com/sasha-thecornerspore-dev/switchboard/releases).

> **Tailscale** is required to publish shares. You don't have to install it first —
> if it's missing, Switchboard shows an **Install Tailscale** button (winget on
> Windows, Homebrew on macOS) and a **Sign in** prompt once it's installed. Public
> sharing additionally requires Funnel to be enabled for your tailnet.

### Run from source

```bash
git clone https://github.com/sasha-thecornerspore-dev/switchboard.git
cd switchboard
npm install
npm start          # launches the Electron desktop app
# — or, headless service only —
npm run service    # then open http://127.0.0.1:18800
```

## First login

On first run Switchboard creates an **admin** account and writes the password to
`FIRST-RUN-ADMIN-PASSWORD.txt` in its data folder (the login page tells you where).
Sign in, then open **👥 Users → Edit** to set your own password.

- **Standalone service:** data lives next to `switchboard.js` (or wherever
  `SWITCHBOARD_DATA_DIR` points).
- **Desktop app:** data lives in the per-user app-data folder
  (`%APPDATA%/Switchboard` on Windows, `~/Library/Application Support/Switchboard` on macOS).

## Access model

| Role | Can do |
|------|--------|
| **Admin** | Everything: create/delete shares, change modes & auth, manage users, connect Tailscale |
| **User · manage** (per share) | Pause/resume, switch public/tailnet, edit the share's password, stop the share |
| **User · view** (per share) | See the share, its URLs, QR, stats — open it — but no changes |

Users only ever see shares they've been granted. Enforcement is **server-side**,
not just hidden in the UI.

## Build installers yourself

```bash
npm run dist:win   # Windows nsis + portable  (build on Windows)
npm run dist:mac   # macOS dmg                 (build on macOS — cannot cross-build from Windows)
```

Output lands in `dist/`. The included GitHub Actions workflow
(`.github/workflows/release.yml`) builds **both** platforms on a version tag:

```bash
git tag v1.0.0 && git push origin v1.0.0
```

…and attaches the `.exe` and `.dmg` to a GitHub Release automatically.

## Configuration

| Env var | Default | Purpose |
|---------|---------|---------|
| `SWITCHBOARD_PORT` | `18800` | Dashboard port |
| `SWITCHBOARD_DATA_DIR` | code dir / app userData | Where config, users, and logs are written |

## Security notes

- Dashboard passwords are salted **scrypt** hashes; share Basic-auth passwords
  are stored so they can be re-displayed and handed out.
- The dashboard has no auth bypass — every page and API route except the login
  endpoints requires a valid session.
- **Don't expose the dashboard itself over public Funnel without a login** — it
  manages your file sharing. Tailnet-only access is recommended for the dashboard.
- `switchboard-config.json`, `switchboard-users.json`, and
  `FIRST-RUN-ADMIN-PASSWORD.txt` contain secrets and are **gitignored**.

## Platform support

| Platform | Status |
|----------|--------|
| **Windows** | Fully supported and tested |
| **macOS** | Supported (native folder picker, `tailscale` CLI); build via CI |
| **Linux** | Best-effort (AppImage target provided) |

## License

[MIT](LICENSE)
