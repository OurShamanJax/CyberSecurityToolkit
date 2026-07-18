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
- **Exploit paths** — a vuln/service/tech node offers **Find exploits for this**; an exploit
  node offers **Open on Exploit-DB** + **Use in Metasploit** (hands `search cve:…` into
  msfconsole). Recon → exploit is one click.
- **Discover my LAN** button in the empty state maps every device on your network into the graph.

### Tools / pages
- **Exposure** — Shodan InternetDB per-IP lookup (open ports / products / CVEs), "My IP",
  add-to-graph. Free, no account.
- **Wireless** — read-only AP scan (netsh/nmcli), clickable AP actions, router → Nmap. Deauth /
  WPA-handshake are **clearly locked** (impossible on Windows WiFi) with the concrete Linux +
  monitor-mode-adapter path spelled out.
- **Atlas (v2 — geo lens)** — a CesiumJS globe aimed at YOUR data: **locate** any IP/domain,
  **traceroute-to-globe** (each hop GeoIP'd, drawn as an arc), and the **investigation
  overlay** (geolocated hosts + relationship arcs). Left tools/layers panel, Home + Clear,
  persistent layers. **Worldwide cameras** via Windy (optional free key, stored server-side in
  gitignored `data/`) + Caltrans/NYC/London no-key feeds, with **marker clustering**.
  Cameras/satellites are optional layers (off by default); real satellites + simulated
  viewpoint retained; no-key **hillshade** relief.
- **Credentials** — login auditor (JSON/form) + bundled wordlist; cracked creds → graph.
- **Live Traffic** — real **tshark** capture + heuristic alerts; simulated fallback;
  buffer+drain play/pause/speed. **Humanized display**: IPs annotated (this PC / your router /
  your <vendor> device / multicast / broadcast / internet), plain-English protocol names, and
  a per-packet explanation. IPv6/ARP src/dst now resolve.
- **VPN** — real **WireGuard** config generator (X25519 keys) + guided deploy.
- **Analyzer** — running-app / directory / file analysis (binary inspector + Trivy),
  expand-to-detail view.
- **LAN Discovery** — ping-sweep + ARP the local /24 into the graph (private-subnet-only),
  reverse-DNS, **MAC-vendor (OUI)** lookup, randomized-MAC detection, broadcast/multicast
  filtered. Results cached so Live Traffic can label devices.
- **Exploits** — two-level (beginner/advanced) education on exploitation, Metasploit,
  payloads, and severity/loudness reasoning.
- **Payloads (Metasploit workbench)** — thin wrapper over the real upstream tools:
  a **Payload Builder** that composes + runs an **msfvenom** command (Docker or local),
  showing the exact recipe, and an **msfconsole** command-runner (each command runs in a fresh
  `-x` console so output flushes reliably — no TTY-buffering hang). Every
  build is validated server-side (payload/format/encoder allowlists, port + iteration
  ranges, public-LHOST warning), argv-only (no shell), authorized-lab-gated. No
  hand-authored exploit/malware — msfvenom does the work.
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
- [x] **Exploit-DB + exploit paths** — Find-exploits from any vuln/service node, exploit nodes
      on the graph, one-click hand-off into msfconsole. `[WRAP]` — done.
- [x] **Metasploit (msfconsole)** Dockerized + in-app terminal, and **msfvenom Payload
      Builder**, for authorized lab use. `[WRAP]` — done (Payloads page).
- [ ] **Two-level explanations** everywhere (beginner + advanced), including the Report.
- [ ] **Report upgrade** — narrative + severity/loudness + fix steps at both levels.

### Backlog wins (from IDEAS.md)
- [ ] Threat-intel **node badges** (abuse.ch URLhaus/Feodo — free). `[API]`
- [ ] **Pwned Passwords** k-anonymity check. `[API]`
- [ ] **OWASP ZAP** baseline scan. `[WRAP]`
- [ ] **Lynis** host audit. `[WRAP]`
- [ ] **Suricata/Zeek** behind Live Traffic. `[WRAP]`
- [x] **LAN discovery** → graph (tool + one-click button, OUI vendors). `[WRAP]` — done.
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

**Built (Payloads page):** a thin interface to the real **msfvenom** (Docker or local)
with strong "authorized-lab-only" framing, live command preview, server-side validation
(allowlists + range checks + public-LHOST warning), and clear education. Plus a live
**msfconsole**. The one thing R.O.D.E still won't do is **hand-author novel exploit or
malware code** — msfvenom generates the payloads; R.O.D.E builds the framework, the
guardrails, and the teaching, and leans on the established tools for the actual offense.
Windows Defender will quarantine generated payloads on write (the UI says so, loudly) —
generate on the Linux attack box or use a lab-only exclusion folder.
