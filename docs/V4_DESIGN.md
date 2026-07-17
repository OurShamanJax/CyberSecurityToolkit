# R.O.D.E v4 — Design & Change Plan

*From a local-first learning lab to an all-purpose, responsibly-built security multitool.*
Draft · supersedes the V3 "local lab" framing · authored 2026-07-10

---

## 0. How to read this doc
This is the plan for V4: what changes, what's new, what's hard, and the order to build
it. It keeps everything that made V3 good — the data-driven catalogue, the parser/graph
"brain," the noise metaphor, the safety layer — and expands the app from a single
graph screen into a **multi-page toolkit** with real defensive and offensive capability.

Where a feature is genuinely difficult or risky (packet capture privileges, WiFi
hardware, "is this traffic malicious?", building a VPN), the doc says so plainly and
proposes the smart path: **wrap proven open-source engines rather than reinvent them.**

---

## 1. The vision shift

**V3:** "a safe local lab for learning on your own machine."
**V4:** "an all-purpose security multitool you can point at anything you're authorized to
test — your own network, your own boxes, deliberately-vulnerable targets, or engagements
you have permission for."

That single change ripples through the whole product:

- The app is no longer organized around one investigation graph. It becomes a **workbench
  with several dedicated pages**, each a first-class tool, all feeding the same
  investigation/graph backbone.
- **Scope stops being a hard blocker.** In V3 an out-of-scope target is refused, which
  (as you found) blocks legitimate work. In V4 scope becomes **advisory**: loopback and
  in-scope targets run freely; anything else pops a one-time "you're going off your
  declared scope — confirm you're authorized" acknowledgement, then remembers your choice
  for that investigation. You're never blocked from a valid search; there's just a single
  legal speed-bump. (A global "I know what I'm doing" toggle can remove even that.)
- Because it can now touch real networks and real traffic, V4 needs a **clear
  responsible-use posture** baked into the UI, not buried (see §12).

### Responsible-use stance (non-negotiable, and it's a feature)
Every capable tool ships with (a) a plain statement of what's legal — test only what you
own or are authorized to test, (b) sensible defaults that don't fire the loud/destructive
stuff automatically, and (c) a defensive counterpart wherever possible (every attack tool
teaches the detection/defense that beats it). This is on-brand for R.O.D.E's "teach, don't
just execute" philosophy and it's what keeps an all-purpose tool on the right side.

---

## 2. Information architecture — the multi-page redesign

V4 introduces an **app shell** with a slim left **navigation rail** (icons + labels,
collapsible). The current single screen becomes the "Investigation" page; new pages sit
beside it and share the same header (investigation switcher, scope, footprint) and the
same graph/report backbone.

```
┌────┬───────────────────────────────────────────────────────────┐
│ N  │  header: investigation ▾   scope   footprint ▮▮▯▯▯         │
│ A  ├───────────────────────────────────────────────────────────┤
│ V  │                                                           │
│    │   ●  the active page renders here                         │
│ ▤  │                                                           │
│ ◈  │                                                           │
│ ⌁  │                                                           │
│ ⚿  │                                                           │
│ ⛨  │                                                           │
└────┴───────────────────────────────────────────────────────────┘
 nav rail pages:
  ▤  Investigation   the entity graph + console + findings (today's screen, refined)
  ⌁  Live Traffic    the Wireshark-like realtime monitor (NEW, §4)
  ◈  Analyzer        unified app/binary/directory analysis (NEW, §5)
  ⚿  Credentials     login & password auditing (NEW, §6)
  ⛨  Wireless        WiFi discovery & router analysis (NEW, §7)
  ↯  VPN             build/run your own WireGuard VPN (NEW, §8)
  ▦  Report          the growing report, full-page
  ⚙  Settings        scope policy, animation/motion, capture device, theme
```

Everything a page discovers still flows into the **shared graph** for the current
investigation, so the traffic monitor, the analyzer, and the recon tools all contribute
to one picture. Pages are *views/workflows*; the graph is the *memory*.

**Arsenal** moves per your note: it sits in the top toolbar **between "New" and the
delete (trash) button**, grouped with the investigation controls rather than floating
near Report.

---

## 3. Redesigning the program loop

V3's loop is: pick tool → run → stream → parse → graph. V4 keeps that spine but makes
every step richer and more alive:

1. **Frame** — choose/confirm the investigation *mode* (Infra, Identity, Traffic, Wireless
   — see §9). Mode sets the default tools, the graph layout, and the language.
2. **Choose** — pick a tool from the dropdown or Arsenal; the target box already adapts
   its placeholder per tool (shipped in V3). V4 adds **inline recipes**: one-click
   "next step" chains suggested from what's already on the graph.
3. **Consent** — scope is advisory; loud/destructive tools still confirm. A quick,
   non-blocking acknowledgement, not a wall.
4. **Run** — output streams with an **animated typing effect** (see §10), the origin node
   *pulses* while active, and new nodes **animate in** as they're discovered rather than
   snapping the whole layout.
5. **Understand** — click any node for the inspector (V3), click a finding to fly to its
   node (V3); V4 adds "explain this to me" that expands the knowledge-base entry inline.
6. **Act** — from any node, chain the next tool, send an endpoint to the Credentials page,
   or send a host to Live Traffic to watch it. Cross-page hand-off is the point.
7. **Report** — the growing report gains snapshots (see §11), so you can show *how* the
   picture evolved.

---

## 4. NEW PAGE — Live Traffic Monitor (the Wireshark-like tool)

A dedicated page for **realtime network traffic** with defensive alerting. This leans hard
into the Recon/Defensive quadrant of R·O·D·**E**.

### What the user sees
- A **live packet/flow feed** (streaming rows: time, src→dst, protocol, length, summary).
- **Transport controls** like a media player: **Play / Pause**, a **speed slider** (slow
  the feed to read it, or run realtime), **Step** (one packet/flow at a time), and
  **Reset/Clear**. A "follow tail" toggle for live vs. scrub-back.
- A **detail pane**: click any packet/flow to expand full layers (Ethernet/IP/TCP/HTTP…),
  like Wireshark's tree. From here, **"analyze further"**: send the IP to Nmap, the host to
  the graph, the URL to Nuclei, the domain to theHarvester — one click into the rest of the
  toolkit.
- An **alerts strip**: suspicious events surface as cards (severity, what/why, the packets
  involved) and drop into the investigation graph as `alert` nodes.
- **Filters** (BPF-style and simple chips: by host, port, protocol, "only alerts").

### How capture actually works (the honest tech)
Packet capture needs elevated privileges and a capture library. The pragmatic build:

- **Engine:** wrap **tshark** (the CLI behind Wireshark) or **scapy/pyshark** in Python. A
  new long-running **capture process** type in the executor streams packets as JSON lines
  over a dedicated WebSocket (`/ws/capture`). tshark's `-T ek`/JSON output is easy to parse.
- **Privileges:** raw capture requires admin/root (or `CAP_NET_RAW` on Linux, Npcap on
  Windows). V4 detects this and guides setup instead of failing silently.
- **Backpressure:** the feed can be enormous. The speed slider is implemented as a
  **server-side rate limiter + ring buffer** (keep the last N packets), not by trying to
  render everything. Pause = stop draining the buffer; Reset = clear it.
- **Cross-platform reality:** cleanest on Linux/WSL2; Windows needs Npcap. The page states
  requirements up front and degrades gracefully.

### The hard part — "normal vs suspicious"
This is genuinely difficult and worth being honest about: a naive rule flags everything.
V4 uses a **layered detection engine**, ideally by wrapping a proven FOSS IDS rather than
hand-rolling one:

1. **Signature layer** — run capture through **Suricata** or **Zeek** (both free, both
   battle-tested) with community rulesets. Known-bad patterns → high-confidence alerts.
2. **Heuristic layer** — cheap, explainable detectors R.O.D.E can script itself: port-scan
   fan-out, ARP spoofing (same IP, changing MAC), DNS anomalies (NXDOMAIN floods,
   long/entropy-high subdomains = tunnelling/DGA), SYN floods, plaintext-credential
   sightings, beaconing (regular-interval callbacks).
3. **Baseline layer** — learn "normal" for *this* network over a short window (usual hosts,
   ports, volumes) and flag deviations. Always show the user *why* something is anomalous,
   and let them mark false positives to tune it.

Every alert is **explainable** (what triggered it, which packets, how to confirm) — that's
the teaching value, and it keeps false positives honest.

---

## 5. NEW TOOL — Unified Analyzer (apps + binaries + directories)

Remaster V3's separate Binary Inspector and Trivy directory scanner into **one packaged
analysis tool with its own page/UI** and three ways to pick a target:

- **Running apps** — enumerate live processes (via `psutil`) with name, PID, path, and
  memory footprint; pick one and analyze its on-disk binary. (Your "Cheat Engine on
  Minecraft" example: we can't safely live-edit another process's memory in a
  container, but we *can* statically reveal what a running app's binary is capable of.)
- **Recently loaded** — a shortlist of recently launched/opened executables for quick
  re-analysis.
- **Directory** — point at a folder to scan dependencies, secrets, and misconfigs.

### What it does (merged capabilities)
- **Static binary capabilities** (from V3's inspector): can it read/write process memory,
  inject, hook, key-log, phone home? Extracted API groups, embedded URLs/IPs, strings.
- **Dependency & secret scanning** (Trivy): vulnerable libraries, leaked keys/passwords,
  misconfigurations.
- **New:** optional **YARA** rules for known-malware patterns, and a hash → reputation
  lookup for quick triage.
- Its own tidy result view (capability chips, severity-sorted findings, an evidence
  panel), and everything still lands in the shared graph as `file`/`capability`/`secret`
  nodes so the analyzer participates in the bigger investigation.

---

## 6. NEW CATEGORY — Credentials & Login Auditing (password testing)

For learning login security against **your own** OWASP Juice Shop and accounts you control.

### Tools (all established FOSS, wrapped by R.O.D.E)
- **Online form auditing — Hydra / a scripted requests-based attacker.** Point at the Juice
  Shop login form, supply a username (or list) and a wordlist, and watch attempts stream in
  the console with success/failure classification. Teaches lockout, rate-limiting, and why
  weak passwords fall instantly.
- **Offline hash cracking — hashcat / John the Ripper.** Feed a captured hash; identify the
  algorithm (V3 already has a hash identifier) and run a wordlist/rules attack. Teaches why
  fast hashes (MD5/SHA1) and unsalted storage are catastrophic.
- **Wordlist manager (I handle this).** R.O.D.E ships a curated set of well-known public
  lists and manages them for you: **rockyou.txt**, the **SecLists** collection
  (common-passwords, usernames, web-content, discovery), and small starter lists bundled
  for offline use. A picker lets you choose list + optional mangling **rules** (leetspeak,
  years, capitalization). Big lists download on first use with a clear size/time notice.
- **Attack templates / recipes.** Ready-made, editable recipes — e.g. "Juice Shop login:
  known-users × common-passwords," "credential stuffing with a breach list," "targeted
  rules from a person's OSINT profile." Templates encode the target form fields, success
  condition, and safe defaults (throttled, capped attempts).

### Guardrails
Defaults are throttled and capped; the page states in plain terms that this is for your own
systems / authorized targets; and each tool pairs with the defense ("this is why you need
rate-limiting, lockouts, MFA, and slow salted hashes"). Cracked results feed the graph as
`credential` nodes tied to the target/login endpoint.

---

## 7. NEW CATEGORY — Wireless / WiFi (recon + router analysis)

Go deeper than Nmap into the wireless layer, framed for **your own network**.

### Capabilities
- **Access-point discovery** — enumerate nearby APs: SSID, BSSID, channel, encryption
  (WEP/WPA2/WPA3), signal, connected clients. (Wraps the **aircrack-ng** suite:
  `airodump-ng`; or `nmcli`/`iw` for a lighter read-only scan.)
- **Router/AP analysis** — once on your own network, fingerprint the router (open ports,
  admin panel, default-credential check against *your* device, firmware/CVE lookup via the
  tools you already have). This is where "pentest my own stuff" lives.
- **Rogue-AP / Evil-Twin — detection first.** Because R.O.D.E teaches defense: detect
  suspicious duplicate SSIDs, deauth storms, and karma-style APs on your network. The
  *offensive* evil-twin/deauth side (for authorized testing of your own network) is
  gated behind explicit acknowledgement and clearly labelled, with the defensive lesson
  attached. This keeps a dual-use capability responsible.

### The honest constraints (hardware & OS)
Real wireless work needs a **WiFi adapter that supports monitor mode + packet injection**
(not all do), and typically **Linux** (or a passthrough to a Linux VM/WSL with USB access).
Windows built-in adapters generally can't. V4 detects adapter capability and says so up
front, offers the read-only `nmcli`/`iw` scan as a no-special-hardware fallback, and links a
short "recommended adapters" note. Under-promise, then guide.

---

## 8. NEW PAGE — Build-Your-Own VPN (do this the safe way)

You flagged this as over your head — good instinct, because **rolling your own VPN crypto
is exactly what experts tell you never to do.** So V4 doesn't. Instead it becomes a
**guided front-end to WireGuard**, the modern, audited, open-source VPN that's small enough
to reason about.

### What R.O.D.E actually builds for you
- A **config generator**: create a WireGuard server + peers, generate keypairs, assign the
  tunnel subnet, set DNS, and produce ready-to-import `.conf` files and QR codes for phones.
- A **guided setup** for running the server (on a box you control / a cheap VPS), with the
  exact commands and a plain-English explanation of each setting (why a preshared key, what
  `AllowedIPs` means, kill-switch basics).
- A **health view**: which peers are connected, handshake times, throughput — so you can
  *see* the tunnel working.
- **Teaching, not magic:** it explains what a VPN does and does not protect, so you learn
  the security model instead of trusting a black box.

### What it explicitly will NOT do
No custom crypto, no bespoke protocol, no "trust us" tunnel. Everything rests on WireGuard's
audited implementation. That's the responsible design, and the doc should say so loudly.

---

## 9. Graph model evolution — investigation *modes*

You're right that a **username** investigation shouldn't look like a **URL/infra** one —
different data, different story, different picture. V4 introduces **investigation modes**,
each with its own default layout and visual language, all on the same underlying graph:

- **Infra mode** (URL/domain/IP) — today's directed tree: `target → endpoints → issues`,
  breadthfirst/fcose. Node accents by type; category grouping for finding-heavy scans.
- **Identity mode** (username/email/person) — a **radial "identity map"**: the person/handle
  at the center, discovered **platform** nodes (with platform icons/colors) fanning out,
  each carrying pulled details (bio, location, linked emails). Reads like a profile, not an
  attack tree. Cross-links when the same email/handle appears on multiple platforms.
- **Traffic mode** (from the Live Monitor) — a **flow map**: hosts as nodes, live
  conversations as animated edges, alert nodes glowing where something's off.
- **Wireless mode** — APs and their clients as a star/hierarchy per SSID.

Mode is chosen when you create the investigation (or inferred from the first tool) and sets
the layout engine, the color language, and the default tool set. This is a clean way to make
each kind of work *feel* purpose-built while reusing one engine.

Implementation: modes are a property of the investigation; the graph renderer picks a layout
+ style preset per mode. Parsers already emit typed entities, so identity vs infra falls out
of the data naturally.

---

## 10. Animation & interactivity plan

Make it feel alive (all with `prefers-reduced-motion` respected and a Settings toggle):

- **Console typewriter effect** — stream text with a subtle typed cadence instead of
  instant printing (batched so it never lags behind a fast tool; a "skip animation" click
  jumps to the end). This is the example you called out and it sets the tone.
- **Nodes animate in** on discovery (scale/fade + a soft "ping"), **edges draw** along
  their path, and **findings pulse** when they arrive.
- **Live scan pulse** — the origin node radiates rings while a tool runs; particles flow
  along edges being explored; the footprint bars fill with a little bounce (and a red
  micro-shake when you cross into aggressive).
- **Animated layout transitions** (via fcose) so re-layouts glide instead of snapping.
- **Toasts** for key events instead of console-only messages; **button/press ripples**;
  spring-eased panel and modal transitions.
- **Later:** an investigation **timeline scrubber** to replay discovery, optional sound
  cues (toggle), and light gamification (first vuln, "stay silent" challenges).

---

## 11. Architecture changes to support all this

V4 outgrows several V3 assumptions. The big ones:

- **Frontend refactor.** A single 55 KB HTML file can't carry a multi-page app well. V4
  should move to a **small component structure with a light build step** (or at minimum
  split CSS/JS into modules and add a tiny bundler). This is the enabler for the nav shell,
  per-page views, and the animation layer — and it fixes V3's biggest structural risk.
- **New executor process types.** Beyond one-shot subprocesses, V4 needs **long-running,
  streaming processes** (packet capture, live crackers) with their own lifecycle, rate
  control, and clean cancellation. Generalize the runner into a "job" abstraction.
- **More WebSockets / channels.** `/ws/run` stays for tools; add `/ws/capture` for the
  traffic feed. Consider a small message envelope so pages can multiplex.
- **New persistence.** Tables/stores for **captures** (ring-buffered, not unbounded),
  **alerts**, **credentials** (treat as sensitive — encrypt at rest, never in plain logs),
  and **VPN configs** (private keys — same care).
- **Privilege handling.** Capture and WiFi need elevation; the app must detect, request,
  and explain rather than crash. A "capabilities check" on the Settings page.
- **Report snapshots.** Persist point-in-time report versions so the "growing" report can
  show evolution/diffs.
- **Scope becomes policy, not a gate.** Refactor `safety.ensure_in_scope` from a blocker
  into an **advisory** that returns an acknowledgement requirement the UI can satisfy once.

---

## 12. Security, legal & ethical guardrails (for an all-purpose tool)

Because V4 can touch real networks, the guardrails move from "sandbox everything" to
"inform, default-safe, and log intent":

- **Authorized-use acknowledgement** per investigation, plainly worded, remembered.
- **Default-safe everything** — throttled crackers, read-only wireless scans by default,
  detection-first framing for dual-use features, no destructive action without a confirm.
- **Every offense pairs with a defense** — the teaching hook that keeps it ethical and
  on-brand.
- **Sensitive data care** — credentials, keys, and captures encrypted at rest and kept out
  of logs/raw dumps.
- **Clear "what's legal" copy** where capable tools live, not buried in a EULA.

---

## 13. Hard problems & risks (be honest up front)

- **"Malicious vs normal" is unsolved in general** — expect false positives; explainability
  + user tuning + wrapping Suricata/Zeek is the sane path, not a magic classifier.
- **Packet capture & WiFi need privileges and specific hardware/OS** — cleanest on
  Linux/WSL2; Windows needs Npcap; WiFi needs a monitor-mode adapter. Detect and guide.
- **Dual-use tooling (deauth, evil-twin, cracking)** — real ethical/legal weight; gate,
  label, default-safe, teach the defense.
- **VPN security** — mitigated entirely by standing on WireGuard; do not deviate.
- **Frontend complexity** — the multi-page overhaul is the riskiest engineering lift;
  do the refactor deliberately, not by bolting pages onto the single file.
- **Cross-platform parity** — many new features are Linux-first; be explicit about what
  works where.

---

## 14. Phased roadmap

**V4.0 — Foundation & quick wins**
- Scope → advisory (no more accidental blocks); move Arsenal between New and trash;
  console typewriter effect; nodes-animate-in; fcose layout (kills horizontal sprawl).
- Frontend refactor to a nav-shell + page structure (the enabler for everything else).

**V4.1 — Defensive centerpiece**
- Live Traffic Monitor page: capture engine, transport controls, detail pane, click-to-
  analyze, wrapped Suricata/Zeek + heuristic alerts, traffic-mode graph.

**V4.2 — Analysis & identity**
- Unified Analyzer (running apps / recent / directory) as one page.
- Identity-mode graph for username/email investigations.

**V4.3 — Credentials & wireless**
- Credentials page (Hydra/hashcat/john + wordlist manager + Juice Shop recipes).
- Wireless page (aircrack-ng discovery, router analysis, rogue-AP detection).

**V4.4 — VPN & polish**
- WireGuard config generator + guided setup + health view.
- Timeline scrubber, sound cues, gamification, theme options.

---

## 15. Immediately actionable (can ship without the redesign)
These need no overhaul and directly unblock you today:
1. **Scope → advisory** so valid searches stop getting blocked.
2. **Move the Arsenal button** between New and the trash button.
3. **Console typewriter effect** as the first taste of the new animation direction.
4. **Merge Binary Inspector + Trivy** into one "Analyzer" tool entry (UI page can come later).

Say the word and I'll start with these three or four against the current V3 build, then we
tackle the nav-shell refactor that unlocks the rest.

---

## 16. Proposed file/structure changes (sketch)
```
rode-v4/
├── backend/
│   ├── executor/           + job.py (long-running/streaming jobs), capture.py
│   ├── capture/            NEW  tshark/scapy wrapper + Suricata/Zeek bridge
│   ├── detect/             NEW  heuristic + baseline detectors, alert model
│   ├── credentials/        NEW  hydra/hashcat/john wrappers + wordlist manager
│   ├── wireless/           NEW  aircrack-ng/iw wrappers + capability probe
│   ├── vpn/                NEW  WireGuard config generator + peer/health
│   ├── graph/              + modes (infra/identity/traffic/wireless presets)
│   └── … (config, db, safety→policy, parsers, report as today)
├── frontend/               refactor: app shell + nav rail + per-page views + build step
│   ├── pages/  investigation · traffic · analyzer · credentials · wireless · vpn
│   └── lib/    graph, animation, ws-client, components
└── docs/  PROGRAM_REVIEW.md · V4_DESIGN.md (this) · SECURITY.md (use policy)
```

*Bottom line: V4 keeps V3's excellent backbone and grows outward into a real, multi-page
security workbench — defensive traffic monitoring as the new centerpiece, a unified
analyzer, credential and wireless learning tools, and a safe WireGuard-based VPN — with
scope relaxed to advisory, a mode-aware graph, and an animation layer that finally makes it
feel as good as it works. The one big engineering bet is the frontend refactor; make it
first and everything else gets easier.*
