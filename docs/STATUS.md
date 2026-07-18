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
- **Map lens (the globe — formerly Atlas, now the Investigation → Map lens)** — a CesiumJS
  globe aimed at YOUR data: **locate** any IP/domain, **traceroute-to-globe** (each hop
  GeoIP'd), the **investigation overlay**, and **fly-to** any place name or lat,lng
  (free geocoder). Left tools/layers panel, Home + Clear, persistent layers, a **draggable +
  resizable compass** (double-click = north-up), and **horizon culling** so only the
  near-hemisphere icons draw (no far-side clutter through the globe).
  - **Cameras:** worldwide via Windy (optional free key) with a **multi-point viewport sweep**
    for density, plus no-key government feeds — Caltrans, NYC, London, the **"One Network"
    511 family** (10+ US states + Canadian provinces), and **New Zealand (NZTA)**.
    **Type-classified icons** (highway / intersection / roundabout / metro / bridge / street /
    webcam) + legend, marker clustering, and **multi-camera floating windows** (open many feeds
    at once; drag / resize / close each). **Mapillary street view** — 🛣 on a camera, or
    Street-view mode to click any road into the interactive viewer (coverage dots + address).
  - **Satellites:** real TLE-driven positions (labels on hover to declutter), simulated
    cinematic viewpoint (film-grain / scanline / HUD downlink look, clearly labelled SIM).
  - **Living Earth:** real-time sun/seasons; **Precipitation radar** (RainViewer) + **Wildfires**
    (NASA FIRMS, optional free key) — both with color keys; atmosphere/fog/HDR realism toggle;
    no-key hillshade. (Clouds + ocean-currents attempts were removed — see globe-polish notes.)
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

### Intelligence, durability & onboarding
- **MITRE ATT&CK mapping** — tools/entities → techniques; coverage view in the Report + on
  Home; per-node technique chips in the inspector.
- **Correlation engine** — combined-signal escalations (vuln + matched exploit, known-bad
  infra, exposed + vulnerable host, recovered creds) on Home + Report, with a map cross-link.
- **Threat-intel badges** — abuse.ch Feodo/URLhaus flag known-bad IPs/domains (red ring +
  inspector chip); auto-scan on graph load + a Threats toolbar button.
- **Run history + diff + export** — per-investigation run list, line-diff between runs of the
  same tool/target, JSON/CSV export.
- **Pwned Passwords** (k-anonymity, in Credentials) + **Lynis** host audit (wrapped tool).
- **First-run tour** — guided 6-step overlay on Home, with a replay button.

### Ops
- `.gitignore` protecting personal data (`data/`, DB, GeoIP cache, VPN keys, API tokens);
  README + `OFFENSIVE_SETUP.md`; requirements pinned; `start.bat audit` (pip-audit) self-check.
- Docs: PROGRAM_REVIEW (current architecture) · STATUS (this) · IDEAS (backlog) ·
  OFFENSIVE_SETUP · SECURITY. STRATEGY / DESIGN are historical planning docs.

---

## 🔜 To Do — what's actually left

*(The big arcs — the three lenses, the Map/globe, Metasploit + exploit paths, ATT&CK,
correlation, run history, threat-intel, onboarding, the platform/setup docs — are all done
and now live under "Have Done". These are the genuinely open items.)*

### Coverage & tools
- [ ] **OWASP ZAP** baseline web-app scan. `[WRAP]`
- [ ] **Suricata / Zeek** behind Live Traffic (turn it into a real IDS). `[WRAP]`
- [ ] gowitness **screenshots on graph nodes**. `[WRAP]`
- [ ] **Two-level explanations** on the remaining tool pages (Report + Exploits already have them).

### Workflow / quality of life
- [ ] Entity **notes + tags**, and investigation **entity search**.
- [ ] Investigation **templates** (starter scope + tool sets).
- [ ] **Consistency pass** so every page uses one shared shell/template.

### Bigger / parked
- [ ] **"Secure your own cameras" audit** *(pinned idea)* — the defensive counterpart to the
      camera globe: find + fix exposed cameras/IoT on your OWN network (LAN + Exposure), with a
      responsible-disclosure template. Legal, scoped, on-mission.
- [ ] **Live threat map** — plot traffic-alerts / honeypot hits on the globe by GeoIP. `[FUN]`
- [ ] **Ocean currents** (stretch) — a real particle-flow field from NASA OSCAR vectors + a
      WebGL layer (earlier tile/arrow/canvas attempts were removed as not good enough).
- [ ] **`atlas.js` refactor** — split the ~1k-line globe file (globe-core / data-layers /
      camera-windows). The main structural chore; contains the recent globe complexity.

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
