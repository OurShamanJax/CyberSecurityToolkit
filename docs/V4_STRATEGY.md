# R.O.D.E v4 — Strategy, Improvements & Next Steps

*Where the project is, the one thing holding it back, and how to make it the
"Batcomputer / Palantir-Gotham" it wants to be — for authorized security work.*
Written 2026-07 · supersedes the earlier V4_DESIGN sketch

---

## 1. The idea, in one paragraph

R.O.D.E is a **local-first intelligence workbench for offensive & defensive security
learning**. You open an *investigation*, point free/open-source tools at targets you own
or are authorized to test, and every result becomes a **connected node in one living
picture** — hosts, endpoints, credentials, vulnerabilities, access points, traffic
alerts, geolocated assets. The north star is a **command center** (Batcomputer / Palantir
Gotham): link-analysis + geospatial + timeline, where everything you discover feeds a
single, explorable model of the thing you're investigating. Everything runs locally or in
Docker; no accounts, no keys, no cloud.

---

## 2. What it is today (honest inventory)

A genuinely capable, wide app organized by the **R.O.D.E pillars** in a left sidebar:

- **Workspace — Investigation:** the entity **graph** (Cytoscape) + streaming console +
  findings + a rich node inspector. The "brain" that other tools feed.
- **Recon — Exposure** (Shodan InternetDB lookup), **Wireless** (AP scan + router
  actions), **Atlas** (CesiumJS globe: real satellite imagery/LOD, day-night sun, orbiting
  satellites, public camera feeds, a simulated satellite viewpoint).
- **Offense — Credentials** (login auditor + wordlists).
- **Defense — Live Traffic** (tshark capture + heuristic alerts), **VPN** (WireGuard
  config generator).
- **Exploit — Analyzer** (binary/dir/running-app analysis).
- **System — Report** (growing plain-English report), **Settings**.

Cross-cutting wins already in place: tools push results **into the graph**, a **command
palette** (Ctrl+K), **Send-to** hand-offs between tools, a **shared target context**, and
real **security hardening** (loopback-only, WebSocket origin checks, security headers,
SSRF-limited proxies).

---

## 3. The one thing holding it back

**R.O.D.E is currently two products wearing one coat.** There's (a) the authorized-pentest
learning lab (Investigation, Credentials, Analyzer, Exposure, Wireless, Live Traffic, VPN),
and (b) a geospatial-intelligence toy (the Atlas globe with cameras & satellites). They're
both good, but they barely talk to each other, and that disconnect is exactly what makes
the whole thing feel "clunky / bolted-on" no matter how much we polish individual pages.

The deeper symptom: **the graph and the map are separate worlds, and there is no time
dimension at all.** In Palantir-Gotham terms, the product has the *graph lens* and a
detached *map*, but they aren't the same investigation seen two ways, and there's no
*timeline*. That's the gap between "a pile of security tools" and "a command center."

Three structural weaknesses fall out of this:
1. **Entities have no place or time.** A discovered host has relationships but no
   geolocation and no "when." So it can never appear on the map or a timeline.
2. **Tool → graph is one-way and shallow.** Results become nodes, but you can't pivot,
   annotate, tag, or query them as an analyst would.
3. **The Atlas globe shows *the world*, not *your investigation*.** It's a cool globe of
   London traffic cams — but it should be the **geospatial lens of the case you're
   working**, plotting *your* hosts, APs, alerts, and cameras.

---

## 4. The unifying thesis (the biggest single improvement)

**Make everything an *entity* with three coordinates: relationships, place, and time —
then view the same investigation through three linked lenses.**

```
              ┌─────────────── ONE INVESTIGATION (entities) ───────────────┐
              │  each node: type · value · confidence · LINKS · GEO · TIME  │
              └───────┬───────────────────┬───────────────────┬────────────┘
                      ▼                   ▼                   ▼
                 GRAPH lens          MAP lens            TIMELINE lens
              (relationships)   (Cesium globe of      (when things were
               link analysis     YOUR entities)        found / happened)
                      └───────── selection is shared across all three ──────┘
```

- Add **`lat/lng`** and **`first_seen/last_seen`** to the entity model.
- Geolocate automatically: IPs via a free offline GeoIP DB (DB-IP/GeoLite-style, no
  account); APs from wifi scan; cameras already have coordinates; exposure lookups carry
  the target IP's location.
- The **Map lens reuses the Cesium engine we already built** — but plots the *current
  investigation's* entities (green host pins, red alert pins, camera icons), click a pin →
  same inspector as the graph. The Atlas "world cameras" become one optional layer.
- The **Timeline lens** scrubs the investigation: watch nodes appear in the order you
  discovered them, replay a case, or filter "what changed since yesterday."
- **Selection is linked:** click a node in the graph → it highlights on the map and the
  timeline, and vice-versa. *That* is the Gotham/Batcomputer feel, and it turns two
  half-products into one coherent intelligence tool.

This is the highest-leverage change in the whole project. Everything else is polish on top.

---

## 5. Improving each aspect

**Data & model.** Entities gain geo + temporal fields and free-text **notes** and
**tags**. Findings become a *view* over vulnerability/secret entities rather than a
parallel store (removes the drift class of bugs we already hit). Add an **entity search**
across the whole investigation.

**The investigation loop.** Tighten to: *frame (mode) → gather (tool) → link (graph) →
locate (map) → understand (inspector + KB) → act (send-to / next tool) → report*. Every
step already exists; the missing links are locate (map lens) and a persistent inspector.

**Tools.** Each tool should (1) push richly-typed entities with geo+time, (2) offer a
consistent "add to graph / send to" surface, and (3) expose a re-run + run-history. Live
Traffic wants deeper detection (wrap Suricata/Zeek); Credentials wants offline hashcat/john;
Exposure wants enrichment (reverse-DNS, org, ASN) to make nodes richer.

**Reporting.** Auto-generate a **narrative** ("what we found, in order, and what to fix"),
include the **timeline** and a **map snapshot**, and support export to PDF/JSON/CSV.

**Performance & scale.** Cap/virtualize the graph for large cases; ring-buffer the traffic
feed (done); lazy-load map pins; guard the console. Add a lightweight **tool-status
dashboard** (Docker/tshark/adapters) so setup problems are visible in one place.

**Security posture.** Already solid (documented in SECURITY.md). Keep dogfooding: run the
Analyzer's Trivy scan on R.O.D.E itself, pin deps, add `pip-audit` to the launcher.

---

## 6. UI redesign for the actual goal

The sidebar restructure (R.O.D.E pillars) was the right move. The next redesign step is to
make the **investigation the shell, and the lenses the main stage**:

- **A "Board" as the default view** for the active investigation, with a **lens switcher**
  (Graph · Map · Timeline · Console) across one main canvas, and a **persistent right-hand
  Inspector** that shows whatever entity is selected — no matter which lens or tool
  surfaced it. Click a cracked credential in Credentials, a host in Exposure, or a pin on
  the map → the *same* inspector opens. One consistent detail surface everywhere.
- **Tools become actions, not destinations.** Keep the sidebar for launching, but the
  result always lands on the Board. Less "leaving the graph to go use a tool."
- **A command-center dashboard** (home): current investigation at a glance — entity counts
  by type, latest findings, footprint, a mini-map, quick-launch. The "sit down at the
  Batcomputer" screen.
- **Cinematic dark theme** consistent with the Palantir vibe: one accent, quiet surfaces,
  dense but legible, subtle motion (node arrivals, edge draws, map fly-tos) — carry the
  animation polish we started into a single coherent language.
- **Consistency pass:** every page uses one template (header + primary action + results +
  send-to). This kills the "each page looks different" complaint for good.

---

## 7. Quality-of-life features (concrete, high-value)

Ranked roughly by value-to-effort:

1. **Universal entity inspector** — one detail panel used by every tool and lens.
2. **Notes & tags on entities** — analyst annotations; tag-based filtering.
3. **Entity search / quick-filter** within an investigation (fuzzy, keyboard-first).
4. **Run history + one-click re-run** of any past tool run; **diff** between two runs
   ("what changed since last scan").
5. **Investigation templates** — "Web app pentest," "My home network," "OSINT on a
   handle" — pre-load the right mode, tools, and scope.
6. **Export** — JSON/CSV of entities, PDF of the report, a shareable investigation file.
7. **Saved filters / views** on the graph and map.
8. **Watchlists & scheduled scans** — re-scan an asset on a cadence, alert on change.
9. **Undo / autosave / session history** — never lose work; replay a session.
10. **Onboarding tour** + an in-app "what is this tool / when to use it" everywhere.
11. **Multi-select on the graph** (bulk confirm/delete/tag), lasso select.
12. **Global keyboard-first UX** — palette can already navigate; extend to actions.
13. **Theme + density + reduced-motion** as first-class settings (partly done).

---

## 8. Next steps — phased roadmap

**Phase A — Unify (the big one).** Add geo+time to entities; free offline GeoIP; a **Map
lens** that plots the current investigation on the Cesium engine; a **Timeline lens**;
**linked selection** across Graph/Map/Timeline; a persistent **universal inspector**. This
is what turns R.O.D.E from "tools + a globe" into the command center.

**Phase B — Analyst workflow.** Notes, tags, entity search, run history + re-run + diff,
saved filters, export. Consistency pass so every page shares one template.

**Phase C — Depth.** Live Traffic → wrap Suricata/Zeek + richer heuristics; Credentials →
offline hashcat/john; Exposure → ASN/org/reverse-DNS enrichment + correlation rules;
Report → narrative + timeline + map snapshot + PDF.

**Phase D — Scale & assist.** Graph virtualization, watchlists, scheduled scans,
investigation templates, tool-status dashboard, dogfood security (Trivy-on-self, pip-audit).

**Phase E — Delight.** Command-center dashboard, cinematic theme + motion language,
onboarding tour, optional sound cues, gamified learning (first vuln, "stay silent"
challenges).

Suggested first move: **Phase A, step 1** — add `lat/lng` + `first_seen/last_seen` to
entities and stand up the **Map lens** plotting the investigation's own hosts/APs/alerts.
It's the single change that makes the whole thing feel like one product.

---

## 9. Honest constraints to hold in view

- **Local & single-user** is the safety model and a limit on the "real-world" ambition —
  lean into it as a *personal command center for authorized work*, not a SaaS.
- **Free/no-account data is scarce** for some dreams (global cameras, exposure firehose) —
  design around per-target lookups + user-added feeds, not mass indexing.
- **Dual-use ethics** — every capable tool stays pointed at owned/authorized targets and
  pairs with the defensive lesson. That framing is a feature.
- **Cesium/WebGL can't be render-tested here** — the map lens will need in-browser
  iteration; build it defensively with graceful fallbacks.
- **Scope creep is the real enemy.** The unify work (Phase A) will do more for the product
  than five more tools. Resist breadth until the core picture is coherent.

*Bottom line: R.O.D.E has the pieces of something genuinely special. The move that makes it
feel like the Batcomputer isn't another tool — it's making every tool feed one investigation
you can see as a graph, a map, and a timeline at once, with a single inspector tying it all
together. Build that, then polish.*
