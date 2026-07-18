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
    for density, plus no-key government feeds — Caltrans, NYC, London, and the **"One Network"
    511 family** (10+ US states + Canadian provinces). **Type-classified icons** (highway /
    intersection / roundabout / metro / bridge / street / webcam) + legend, marker clustering,
    and **multi-camera floating windows** (open many feeds at once; drag / resize / close each).
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

### Ops
- `.gitignore` protecting personal data (`data/`, DB, GeoIP cache, VPN keys); README setup
  guide; requirements pinned; docs folder (STRATEGY / IDEAS / SECURITY / PROGRAM_REVIEW).

---

## 🔜 To Do — next up (ordered)

### Unify (finish the "one picture" — highest leverage)
- [x] **Timeline lens** — scrubbable time axis of when entities were discovered, lanes by
      type, Replay animation, click-to-focus in the graph. `[done]`
- [x] **Universal inspector** — shared `js/inspector.js` renderer (the graph popup's look,
      promoted); Live Traffic packet detail now renders through it; Map + Home reuse it. `[done]`
- [x] Home **dashboard** — command-center landing page (default route): current investigation
      summary, top findings, one-click jumps, investigation switcher. `[done]`
- [x] **Atlas merged into the Map lens** — one globe, not two. Atlas is now the Investigation
      Map lens (locate / traceroute / cameras / **fly-to place or lat,lng**); the standalone
      Recon page is retired. Analyzer moved to **Defense**. `[done]`

### Exploit focus (per the new direction)
- [x] **Exploit-DB + exploit paths** — Find-exploits from any vuln/service node, exploit nodes
      on the graph, one-click hand-off into msfconsole. `[WRAP]` — done.
- [x] **Metasploit (msfconsole)** Dockerized + in-app terminal, and **msfvenom Payload
      Builder**, for authorized lab use. `[WRAP]` — done (Payloads page).
- [x] **Report upgrade — two levels** — Beginner/Advanced toggle in the report; narrative
      overview, "severity vs loudness" explainer, and a per-finding **Technical detail** block
      (raw evidence: rule/template, CVE, matched-at, port, tool) with prioritisation. `[done]`
- [ ] **Two-level explanations** in the remaining tool pages (Report + Exploits done).

### Backlog wins (from IDEAS.md)
- [x] Threat-intel **node badges** (abuse.ch URLhaus/Feodo — free, cached) — known-bad IPs/
      domains get a red ring + an inspector chip naming the threat; auto-scan on graph load +
      a **Threats** toolbar button (force-refresh). `[API]` — done.
- [x] **Pwned Passwords** k-anonymity check — Credentials page; password never leaves the
      machine (only the SHA-1 prefix is sent). `[API]` — done.
- [ ] **OWASP ZAP** baseline scan. `[WRAP]`
- [x] **Lynis** host audit — wrapped tool + parser (warnings/suggestions → findings, hardening
      index → score). Linux/macOS. `[WRAP]` — done.
- [x] **MITRE ATT&CK mapping** — tool/entity→technique map, coverage endpoint, Report section +
      Home card + per-node inspector chips. — done.
- [x] **Correlation rules** — combined-signal escalations (vuln+exploit, known-bad, exposed+
      vulnerable, creds) on Home + Report; geo cross-link to the map. — done.
- [x] **Run history + diff + export** — history list, line-diff between runs, JSON/CSV export
      on Home. — done.
- [x] **First-run tour** — guided 6-step overlay on Home + replay button. — done.
- [ ] **Suricata/Zeek** behind Live Traffic. `[WRAP]`
- [x] **LAN discovery** → graph (tool + one-click button, OUI vendors). `[WRAP]` — done.
- [ ] gowitness **screenshots on nodes**; **live threat map**. `[WRAP]/[FUN]`

### Globe polish (Atlas / Map lens)
- [x] **More public camera feeds** — generic **"One Network" 511 importer** (public, no-key
      `/api/v2/get/cameras`) covering Ontario, Alberta, Nova Scotia, Saskatchewan, Nevada,
      Wisconsin, Pennsylvania, New England, Nebraska, Louisiana — on top of Caltrans / NYC /
      London / Windy. Cameras auto-load by viewport. Legit published DOT feeds only (no
      Insecam-style unsecured cams). `[WRAP]` *(endpoints implemented to documented schema;
      verify live coverage on a networked machine — dead ones fail gracefully.)*
- [x] **Satellite viewport → live-feed look** — CSS FX overlay: film grain, scanlines,
      vignette, corner brackets + crosshair, blinking REC, live LAT/LON/ALT + UTC telemetry,
      gentle drift. Still clearly labelled **SIM** (honest). `[done]`
- [x] **Globe realism** — always-on ground/sky atmosphere + depth fog + atmosphere
      saturation/brightness; **Cinematic quality** toggle for HDR + MSAA (default on, drop it
      if it lags). `[done]`
- [x] **Living Earth layers** — real-time sun/seasons (day-night terminator tracks the real
      clock); toggleable **Precipitation radar** (RainViewer, free) with a color key; and
      **Wildfires** (NASA FIRMS active fire detections, optional free key stored server-side
      like Windy) coloured by confidence, viewport-loaded, with a color key + click detail.
      Clouds layer was removed (GIBS tile jank). `[done]`
- [~] **Ocean currents** — removed. Tried directional arrows, glow lines, and a canvas
      particle flow; none read well without a real global velocity grid + land mask. Parked
      until it can be a proper dedicated build (NASA OSCAR data + WebGL particle layer).
- [x] **Compass** — draggable + resizable rose that tracks camera heading; double-click =
      north-up. `[done]`
- [x] **Camera-type icons** — highway / intersection / roundabout / metro / bridge / street /
      webcam glyphs + legend. `[done]`
- [x] **Multi-camera floating windows** — click a camera to open its feed in a floating panel;
      drag / resize / close each; open many at once from different places. `[done]`
- [x] **Horizon culling** — far-side icons (cameras / fires / sats / pins) hidden every frame
      so only the hemisphere you're looking at draws. `[done]`
- [x] **Satellite declutter** — 140 labels hidden by default, name shown on hover. `[done]`
- [x] **Windy density** — viewport multi-point sweep + quota-guard, fills any country. `[done]`

### Quality of life
- [ ] Notes + tags on entities; investigation **entity search**.
- [ ] **Run history** + re-run + diff between scans.
- [ ] Investigation **templates**; export (JSON/CSV/PDF).
- [ ] Consistency pass so every page uses one template.

### Platform / setup
- [x] Document **WSL2 + usbipd** path for monitor-mode WiFi (deauth / handshake) on Windows.
      → `docs/OFFENSIVE_SETUP.md` §1 (hardware, usbipd steps, honest WSL-kernel caveats).
- [x] AV guidance for offensive tooling (exclusions, why Defender flags it).
      → `docs/OFFENSIVE_SETUP.md` §2 (isolate in VM/Docker, one narrow exclusion folder).
- [x] Dogfood: `pip-audit` in the launcher (`start.bat audit`) + Trivy documented.
      pip-audit run on requirements = **no known vulnerabilities**. `[done]`

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
