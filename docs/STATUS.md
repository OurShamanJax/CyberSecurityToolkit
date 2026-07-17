# R.O.D.E v4 — Status: Done & To-Do

Living checklist of what's shipped and what's next. Pairs with `V4_STRATEGY.md`
(the plan) and `IDEAS.md` (the backlog).

---

## ✅ Have Done

### Core & shell
- Local-first FastAPI backend, single-file-free modular frontend, R.O.D.E-pillar **sidebar**
  (Workspace/Recon/Offense/Defense/Exploit/System).
- **Command palette** (Ctrl/⌘+K), keyboard nav, cross-tool **Send-to**, shared target context.
- **Security hardening:** loopback-only bind, WebSocket **origin checks**, security headers,
  SSRF-limited proxies. Documented in `SECURITY.md`.
- SQLite + SQLAlchemy with an auto **migration** on startup.

### Investigation (Workspace)
- Entity **graph** (Cytoscape): endpoints + category grouping, confidence, confirm/delete,
  rich **inspector** (metadata + plain-English + fix + run-next + send-to), zoom-adaptive
  scaling, filters, findings list (click to locate), typewriter console, splitters.
- **Entities now carry place + time** (`lat/lng`, `first_seen/last_seen`).
- **Map lens** — Graph/Map toggle; investigation entities plotted on a Cesium globe; click a
  pin → jump to its graph node. (Phase A, step 1 of the unify.)
- Tools feed the graph; growing plain-English **Report**.

### Tools / pages
- **Exposure** — Shodan InternetDB per-IP lookup (open ports / products / CVEs), "My IP",
  add-to-graph. Free, no account.
- **Wireless** — read-only AP scan (netsh/nmcli), clickable AP actions, router → Nmap.
- **Atlas** — CesiumJS globe: ESRI satellite imagery w/ zoom LOD, day-night sun, borders +
  labels, **real orbiting satellites** (Celestrak TLE + satellite.js) with live alt/speed,
  a **simulated satellite viewpoint** (follows the satellite, zoom, playback speed),
  **public camera feeds** (London TfL + New York DOT) with real **MP4 video** + **HLS**.
- **Credentials** — login auditor (JSON/form) + bundled wordlist; cracked creds → graph.
- **Live Traffic** — real **tshark** capture + heuristic alerts (port scan / DNS anomaly);
  simulated fallback; **buffer+drain display control** (play/pause/speed in both modes).
- **VPN** — real **WireGuard** config generator (X25519 keys) + guided deploy.
- **Analyzer** — running-app / directory / file analysis (binary inspector + Trivy),
  expand-to-detail view.
- **Settings** — animations, density, accent, tool/capability check.

### Ops
- `.gitignore` protecting personal data (`data/`, DB, GeoIP cache, VPN keys); README setup
  guide; requirements pinned; docs folder (STRATEGY / IDEAS / SECURITY / PROGRAM_REVIEW).

---

## 🔜 To Do — next up (ordered)

### Unify (finish the "one picture" — highest leverage)
- [ ] **Timeline lens** — scrub/replay when entities were found; linked selection with
      graph + map.
- [ ] **Universal inspector** — one detail panel shared by graph, map, and every tool.
- [ ] Home **dashboard** (command-center screen).

### Exploit focus (per the new direction)
- [ ] **searchsploit / Exploit-DB** integration — map a detected product+version to known
      public exploits, right on the vuln node. (The "exploitation database" ask, done the
      FOSS way.) `[WRAP]`
- [ ] **Metasploit (msfconsole)** as a Dockerized tool + in-app terminal, for authorized
      lab use. `[WRAP]` — see the note below on payloads.
- [ ] **Two-level explanations** everywhere (beginner + advanced), including the Report.
- [ ] **Report upgrade** — narrative + severity/loudness + fix steps at both levels.

### Backlog wins (from IDEAS.md)
- [ ] Threat-intel **node badges** (abuse.ch URLhaus/Feodo — free). `[API]`
- [ ] **Pwned Passwords** k-anonymity check. `[API]`
- [ ] **OWASP ZAP** baseline scan. `[WRAP]`
- [ ] **Lynis** host audit. `[WRAP]`
- [ ] **Suricata/Zeek** behind Live Traffic. `[WRAP]`
- [ ] **LAN auto-discovery** → map lens. `[WRAP]`
- [ ] gowitness **screenshots on nodes**; **live threat map**. `[WRAP]/[FUN]`

### Quality of life
- [ ] Notes + tags on entities; investigation **entity search**.
- [ ] **Run history** + re-run + diff between scans.
- [ ] Investigation **templates**; export (JSON/CSV/PDF).
- [ ] Consistency pass so every page uses one template.

### Platform / setup
- [ ] Document **WSL2 + usbipd** path for monitor-mode WiFi (deauth / handshake) on Windows.
- [ ] AV guidance for offensive tooling (exclusions, why Defender flags it).
- [ ] Dogfood: run Trivy on R.O.D.E itself; add `pip-audit` to the launcher.

---

## ⚠️ On Metasploit & payload generation (honest note)

Metasploit and Exploit-DB are legitimate, mainstream, FOSS pentest tools, and wrapping
them for **your own authorized lab** (e.g. your Pop!_OS box) fits this toolkit — the same
way sqlmap/hydra/nikto already do. So an **msfconsole terminal + searchsploit** are on the
roadmap.

The one thing I won't hand-author is **novel exploit or malware code**. A *payload
generator* is a grey area: msfvenom is a standard tool, but its output is functional
malware (that's why Windows Defender flags it), so if we add it, it'll be a thin interface
to the real msfvenom (in Docker) with strong "authorized-lab-only" framing and clear
education — I won't be writing custom payloads/exploits from scratch. We'll build the
*framework and the teaching*, and lean on the established tools for the actual offense.
