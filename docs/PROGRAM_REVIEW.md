# R.O.D.E v4 — Program Review

*Recon · Offense · Defense · Exploit — a local-first security learning lab*
Review date: 2026-07-18 · Build: "geo-lens / command-center build" · Status: audited & green

> Supersedes the v3 "inspector build" review. The v3 note is obsolete in several
> ways — most importantly the frontend is **no longer a single HTML file** (it's now
> modular ES modules), and route/test counts have roughly doubled.

---

## 1. What R.O.D.E is

R.O.D.E is a **single-user, local-first security toolkit** that wraps real recon / scan /
exploit / defense tools behind one calm, teaching-oriented interface. You create an
**investigation**, point tools at a target you own or are authorized to test, and every
result becomes a living **entity graph** you can also view as a **map** (a Cesium globe) or
a **timeline**. A console streams live tool output, a findings list surfaces what matters,
and a growing two-level (beginner/advanced) plain-English **report** is one click away.

It runs entirely on the user's machine (binds `127.0.0.1`, loopback-only CORS), most heavy
tools run in Docker, needs **no accounts and no API keys** (a couple of optional free keys —
Windy, NASA FIRMS — are stored server-side in gitignored `data/`), and launches from one
`start.bat`.

### The goal
Turn a pile of intimidating command-line security tools into something a **curious
non-expert can actually learn from** — safely, legally, on their own hardware — without
hiding what's really happening underneath. A lab and a teacher, not a push-button "hack"
product.

---

## 2. Design philosophy

1. **Local-first & safe by default** — loopback bind, loopback-only CORS, scope enforcement
   on every network tool, a workspace sandbox for file tools, and a confirmation gate before
   anything "loud." Nothing noisy happens by accident.
2. **Teach, don't just execute** — every tool carries `teach` metadata; findings get
   plain-English explanations at two levels; the "noise / loudness" metaphor builds intuition
   about *detectability*.
3. **One connected picture** — results are a directed graph rooted at your target, and the
   same investigation renders as **Graph / Map / Timeline**. Layout is meaning.
4. **Data-driven** — tools live in `tools.yaml`; parsers are pluggable and resolved by name.
5. **Honest about uncertainty** — nodes carry a *confidence* that rises with evidence; the
   user can "confirm" ground truth; findings are hints to validate, and the report says so.

---

## 3. System architecture

A layered FastAPI backend feeds a **modular ES-module frontend** over REST + WebSockets.

```
  Browser (localhost)
    index.html  →  js/core.js (state, WS runner, COLOR tokens, helpers)
                   js/app.js  (router, sidebar, palette, sendTo)
                   js/inspector.js  (shared detail-panel renderer)
                   js/pages/*.js    (investigation, exploit, traffic, atlas/map, …)
        │  REST /api/*                       │  WS /ws/run, /ws/capture, /ws/msf
  ┌─────▼────────────────────────────────────▼──────┐
  │                 backend/api/app.py (FastAPI, 51 routes)               │
  └──┬─────────┬──────────┬──────────┬──────────┬───────────┬────────────┘
     │ safety  │ executor │ parsers  │ graph/   │ report/   │ feature modules:
     │ scope,  │ runner + │ registry │ entity_  │ generator │ lan · nettrace · cams ·
     │ sandbox │ command  │ +parsers │ service  │ +knowledge│ metasploit · capture ·
     │ noise   │ +python  │          │ (brain)  │           │ threatintel · wildfire
     └─────────┴────┬─────┴──────────┴────┬─────┴───────────┴────────────┘
             Docker / local / python   models.py + SQLite (SQLAlchemy)
```

### The sidebar (the R.O.D.E pillars)
- **Workspace** — Home (command-center landing), Investigation (Graph / Map / Timeline).
- **Recon** — Exposure (Shodan InternetDB), Wireless (read-only AP scan).
- **Offense** — Credentials (login auditor).
- **Defense** — Live Traffic (tshark), VPN (WireGuard generator), Analyzer (files/binaries).
- **Exploit** — the unified Exploit workspace (Overview · Attack surface · Payload/Metasploit).
- **System** — Report, Settings.

### How a single run flows
UI sends `{tool_id, target, investigation_id}` over WS → **safety** checks scope → **noise
gate** confirms if loud → a `Run` row is created → **executor** builds an argv list
(`shell=False`, injection-proof) and streams output line-by-line → **parsers** normalize it
into `Entity` + `Relationship` objects → **entity_service** upserts them (confidence rises on
repeat), extracts **findings**, and the UI re-draws graph / findings / footprint / report.

---

## 4. The data & graph model (the heart)

- **`Entity`** — a typed node (`ip, host, domain, url, service, technology, vulnerability,
  exploit, email, username, capability, secret, file, alert, category, target`) with
  `value, label, confidence, times_seen, user_confirmed`, a JSON `metadata` blob, and now
  **place + time** (`lat/lng`, `first_seen/last_seen`) so the same graph plots on the map and
  animates on the timeline.
- **`Relationship`** — a typed edge (`HAS_ENDPOINT, HAS_VULNERABILITY, USES_TECH,
  HAS_EXPLOIT, ON_LAN, …`).

Confidence: first sighting = parser confidence; repeats +0.05 (cap 1.0); a user confirm pins
1.0 and glows green. Footprint is driven by the **loudest tool actually run**.

---

## 5. Safety model

Loopback always allowed; other targets must match a declared scope (CIDR / host / subdomain
suffix). File tools confined to `workspace/` via `safe_path`. Loud tools require an explicit
"I own this — run." Commands are argv lists (`shell=False`). Runs are named containers so
Stop issues a real `docker kill`. LAN discovery is private-/24-only. msfvenom builds are
validated server-side and authorized-lab-gated. Optional API keys live in gitignored
`data/secrets.json` and are never committed.

---

## 6. What shipped since v3 (the geo-lens / command-center era)

- **Three lenses** on one investigation: Graph, **Map** (Cesium globe), **Timeline** (scrubbable
  discovery replay).
- **The Map lens** (folded in from the old standalone Atlas): locate any IP/domain,
  traceroute-to-globe, fly-to place or lat/lng, the investigation overlay, a **draggable +
  resizable compass**, and **horizon culling** so only the near hemisphere draws.
  - Cameras: worldwide via Windy (optional key, multi-point viewport sweep) + no-key
    government feeds (Caltrans / NYC / London / "One Network" 511 family); **type-classified
    icons** + legend, clustering, and **multi-camera floating windows**.
  - Living Earth: real-time sun/seasons, **Precipitation radar** (RainViewer) + **Wildfires**
    (NASA FIRMS), each with a color key; atmosphere/fog/HDR realism.
  - Real satellites (labels on hover) + a cinematic "SIM" satellite viewport.
- **Universal inspector** (`js/inspector.js`) — one detail-panel look, adopted by the graph
  and Live Traffic (more surfaces pending).
- **Home dashboard** — command-center landing; **Exploit workspace** unified; **Analyzer**
  moved to Defense.
- **Exploit paths** — any vuln/service node offers "find exploits" → Exploit-DB → hand-off
  into a real **msfconsole** + **msfvenom Payload Builder** (Dockerized, validated).
- **Threat-intel node badges** — abuse.ch Feodo/URLhaus flag known-bad IPs/domains (red ring +
  inspector chip), auto-scan on graph load.
- **LAN discovery** (private /24, OUI vendors) and **humanized Live Traffic** (this-PC / your
  router / your <device> annotations, the user's own IP highlighted).
- **Two-level Report** (beginner/advanced toggle, narrative, severity-vs-loudness, technical
  evidence), **exploits included**.
- Dogfood: `start.bat audit` runs **pip-audit** (last run: no known vulns); Trivy documented.

---

## 7. Audit result (this review)

- **Backend:** all modules import; app boots with **51 routes**; **37/37 tests pass**.
- **Frontend:** 17/17 JS modules parse; no stray `console.log`/`debugger`; no `TODO`/`FIXME`;
  no dead element refs; node-type colors are a shared token source (consistent across
  graph/map/timeline).
- **Recent fixes:** Live Traffic capture is self-diagnosing; globe camera windows decoupled
  from the render loop; far-side icons horizon-culled.

---

## 8. Design flaws & structural risks (honest, ordered by impact)

1. **`atlas.js` is the new "big file"** (~480 LOC, ~54 hardcoded colors, several interacting
   per-frame loops). It works, but it's the current maintainability ceiling and the source of
   recent globe jank. Candidate for an internal split (globe-core / layers / cam-windows).
2. **Pillar imbalance** — Offense has one page (Credentials), Exploit one (the workspace),
   while Defense has three. The pillars are the identity; distribution should feel balanced.
3. **Findings vs entities are two stores that can drift** (findings are derived but stored
   separately). Long-term: compute findings from the graph on read.
4. **Investigations aren't durable** — no run-history view, no diff, no export/snapshot yet.
5. **Camera markers rebuild on every pan/zoom** instead of updating incrementally (globe perf).
6. **No frontend tests**; parsers are regex-over-text (golden fixtures for some, not all).
7. **Cross-tool handoff (`sendTo`) is thin** — only a few tools suggest a next step.
8. **No first-run onboarding** — a newcomer on Home has no guided path.

None are on fire; they're the shape of what to harden next.

---

## 9. Roadmap (current priorities)

1. **Refresh docs** *(this pass).*
2. **MITRE ATT&CK mapping** — the framework spine that ties Recon→Offense→Defense→Exploit into
   one coverage view. Highest cohesion win; free/open data.
3. **Correlation rules + GeoIP cross-linking** — turn separate signals into escalated findings;
   make the graph *smart*.
4. **Run history + diff + export** — durable, shareable investigations.
5. **Lynis + Pwned Passwords** — round out the Defense/Offense pillars (safe, free).
6. **First-run tour + command-center Home** — onboarding UX.

Backlog beyond that (from `IDEAS.md`): OWASP ZAP, Suricata/Zeek behind Live Traffic, gowitness
node screenshots, live threat map, honeypot, ambient globe layers (ADS-B / earthquakes),
themes + reduced-motion setting, and an `atlas.js` refactor.

---

*Bottom line: the architecture is sound and the "one connected picture" idea (graph = map =
timeline) is now real. The next investment is the **intelligence glue** — ATT&CK mapping and
correlation — plus durability (history/diff/export) and onboarding, with a contained
`atlas.js` refactor as the main structural chore.*
