# R.O.D.E v3 — Program Review

*Recon · Offense · Defense · Exploit — a local-first security learning lab*
Review date: 2026-07-10 · Build: "inspector build" · Status: audited & green

---

## 1. What R.O.D.E is

R.O.D.E is a **single-user, local-first offensive-security toolkit** that wraps a
catalogue of real recon/scan/exploit tools (Nmap, Nuclei, Nikto, SQLMap, Sherlock,
theHarvester, Trivy, …) behind one calm, teaching-oriented interface. You create an
**investigation**, point tools at a target, and every result is turned into a living
**entity graph** — hosts, endpoints, technologies, vulnerabilities — that grows as you
work. Alongside the graph, a console streams live tool output, a findings list
surfaces what matters, and a growing plain-English **report** is always one click away.

It runs entirely on the user's machine (binds `127.0.0.1`, CORS restricted to loopback),
most tools execute in Docker, and the whole thing launches from one `start.bat`.

### The goal
Turn a pile of intimidating command-line security tools into something a **curious
non-expert can actually learn from** — safely, legally, and on their own hardware —
without hiding what's really happening underneath. It is a lab and a teacher, not a
push-button "hack" product.

---

## 2. Design philosophy

Five principles run through the codebase:

1. **Local-first & safe by default.** Loopback binding, loopback-only CORS, scope
   enforcement on every network tool, a workspace sandbox for file tools, and a
   confirmation gate before anything "loud." Nothing noisy happens by accident.

2. **Teach, don't just execute.** Every tool carries `teach` metadata (what it does,
   why, what to run next, warnings). Findings get plain-English explanations from a
   knowledge base. The whole "noise" metaphor exists to build intuition about
   *detectability* — the thing beginners never think about.

3. **The graph tells a story.** Results aren't a flat list; they're a directed graph
   rooted at your origin target, flowing outward along the chain of discovery:
   `target → endpoints/surfaces → issues`. Layout is meaning, not decoration.

4. **Data-driven, not hard-coded.** Tools live in `tools.yaml` — you can add one by
   copying a block, no Python required. Parsers are pluggable and resolved by name.

5. **Honest about uncertainty.** Nodes carry a *confidence* that rises as evidence
   repeats; the user can "confirm" a node as ground truth. Findings are hints to
   validate, and the report says so.

---

## 3. System architecture

A clean layered backend feeds a single-file frontend over REST + one WebSocket.

```
                        ┌──────────────────────────────────────────────┐
   Browser (localhost)  │              frontend/index.html              │
                        │  Cytoscape graph · console · findings ·       │
                        │  inspector card · footprint bars · report     │
                        └───────────────┬───────────────┬──────────────┘
                          REST /api/*    │               │  WS /ws/run
                        ┌───────────────▼───────────────▼──────────────┐
                        │                api/app.py (FastAPI)           │
                        │   investigations · graph · entity · findings  │
                        │   footprint · report · suggest · tools · WS   │
                        └───┬─────────┬──────────┬──────────┬──────────┘
                            │         │          │          │
                   ┌────────▼──┐ ┌────▼─────┐ ┌──▼───────┐ ┌▼──────────┐
                   │  safety   │ │ executor │ │ parsers  │ │  graph /  │
                   │ scope,    │ │ runner + │ │ registry │ │ entity_   │
                   │ sandbox,  │ │ command  │ │ + 12     │ │ service   │
                   │ noise gate│ │ + python │ │ parsers  │ │ (the brain)│
                   └───────────┘ └────┬─────┘ └────┬─────┘ └────┬──────┘
                                      │ Docker /   │            │
                                      │ local /    │            │
                                      │ python     ▼            ▼
                                      │        report/     models.py +
                                      ▼        generator +  SQLite (SQLAlchemy)
                                 real tools    knowledge.json
```

### How a single run flows through the system
1. **UI** sends `{tool_id, target, investigation_id}` over the WebSocket.
2. **`safety`** checks the target against the investigation scope (loopback is always
   allowed); network tools outside scope are blocked with a helpful message.
3. **Noise gate**: if the tool is `loud`/`aggressive`, the server asks for an explicit
   confirmation click before proceeding.
4. A **`Run`** row is created; **`executor/runner`** resolves an exec mode
   (`python` → `local` → `docker`), **`executor/command`** builds a safe argv **list**
   (never a shell string — structurally injection-proof), naming the container
   `rode-run-<id>` so it can be killed later.
5. Output streams **line-by-line** back over the WebSocket (Docker gets a pseudo-TTY so
   line-buffered tools like Nikto stream live). Raw text is saved to disk.
6. **`parsers`** turn that raw text into typed `Entity` + `Relationship` objects.
7. **`graph/entity_service`** upserts them into the graph (confidence rises on repeat),
   extracts **findings**, and the UI re-draws the graph, findings, footprint, and (on
   demand) the report.

### The layers, briefly
- **`config.py`** — one settings object; safe defaults, all overridable via env.
- **`db.py` / `models.py`** — SQLAlchemy + SQLite. Four tables: Investigation, Run,
  Entity, Relationship, Finding.
- **`safety.py`** — pure-stdlib guardrails: `ensure_in_scope`, `safe_path`,
  `requires_confirmation`. Trivial to test and reason about.
- **`tools/`** — the `tools.yaml` catalogue + a loader/validator registry.
- **`executor/`** — `runner` (streaming subprocess engine), `command` (argv builder +
  Docker networking policy), `python_tools` (built-in tools: CVE lookup, log analyzer,
  hash id, binary inspector).
- **`parsers/`** — a registry mapping a tool's `parser` field to one of 12 parsers;
  each normalizes messy tool text into the same Entity/Relationship shape.
- **`graph/entity_service.py`** — the "brain": upsert, confidence, confirm/delete/reset,
  `graph_data`, tool suggestions, and the footprint computation.
- **`report/`** — `generator` builds a self-contained HTML report; `knowledge.json`
  supplies plain-English explanations.
- **`api/app.py`** + **`run.py`** — the FastAPI surface and the uvicorn entrypoint
  (`ws=wsproto`, Windows Proactor loop).

---

## 4. The data & graph model (the heart of the app)

Everything the user sees is derived from two tables:

- **`Entity`** — a typed node: `type` (ip, domain, url, service, vulnerability, email,
  username, technology, capability, secret, file, **category**, target), `value`,
  `label`, `confidence`, `times_seen`, `user_confirmed`, plus a JSON `metadata` blob.
  Deduplicated per investigation on `(type, value)`.
- **`Relationship`** — a typed, weighted edge (`HAS_ENDPOINT`, `HAS_VULNERABILITY`,
  `HAS_ISSUE`, `HAS_ISSUE_GROUP`, `USES_TECH`, …).

The recent modeling work made this *story-shaped*: instead of dumping every finding as a
flat sibling off the root, parsers now attach findings to **where they live**. Nikto and
Nuclei create real **endpoint** nodes for discovered paths (`/ftp/`, `/.htpasswd`,
`/metrics`) and collapse location-less findings (missing headers, CORS, backup-file
guesses) under labelled **category** nodes (`Headers & policies · 7`). The graph then
reads target → surfaces → issues.

**Confidence & confirmation:** first sighting uses the parser's confidence; repeats add
+0.05 (capped at 1.0); a user "confirm" pins a node to 1.0 and glows it green.

**Footprint** is deliberately driven by the **loudest tool actually run**, not a running
sum — you can't un-ring a bell. It surfaces as five signal-strength bars.

---

## 5. Safety model

- **Scope:** loopback (your own machine) is always allowed; any other target must match a
  declared scope entry (supports CIDR, exact host, and subdomain suffix). Enforced for
  every tool whose input is an ip/domain/url/host.
- **Sandbox:** file-reading tools are confined to the `workspace/` directory via
  `safe_path` (path-escape attempts are refused).
- **Noise gate:** tools at or above the `loud` threshold require an explicit
  "I own this — run" confirmation.
- **Injection-proof execution:** commands are always argv lists with `shell=False`.
- **Cancellation:** runs are named containers, so Stop issues a real `docker kill`.

---

## 6. Current UI design & interaction model

A single-file, dark, calm interface with a clear division of labour:

- **Header** — investigation switcher, New/Delete, scope chip (click to edit), Arsenal
  (browse the full catalogue), Report, and the footprint signal bars.
- **Left canvas** — the Cytoscape entity graph with type filters, Fit/Focus/Reset,
  an empty-state, and **zoom-adaptive scaling** so nodes/labels/edges stay legible when
  you zoom out. Clicking a node opens a rich **inspector card** (badge, value, confidence,
  metadata, plain-English explanation, and Confirm/Focus/Copy/Delete + run-next tools).
- **Right side panel** — a teaching strip (what the tool does), a streaming **console**
  with Clear + maximize, and a **findings** list (click any finding to fly to its node).
  A draggable horizontal splitter resizes graph vs. panel; a vertical splitter resizes
  console vs. findings.
- **Report** — a draggable, resizable panel rendering the growing HTML report.

Design system: a proper type/spacing scale, one inline-SVG icon set, unified color
tokens where **hue = meaning** (noise tier and node type), focus rings, ARIA labels, and
icon+color severity encoding.

---

## 7. Audit result (this review)

Everything currently green:

- **Backend:** 34 modules compile; app imports with 22 routes; **25/25 tests pass**;
  tool catalogue integrity clean (20 tools, all required fields, every parser resolves).
- **Runtime:** **18/18** live checks — all REST endpoints, a full WebSocket tool run
  (started→output→parsed→done), entity inspector, confirm, footprint, reset, delete — no
  server errors.
- **Frontend:** valid JS, every element reference binds, no stale refs, no corruption,
  all recent features present.
- **Bug fixed during this pass:** findings were **appended on every run** while entities
  were upserted, so re-running a tool duplicated findings. Findings are now
  de-duplicated per investigation (3 identical runs → 1 finding).

---

## 8. Design flaws & structural risks

Honest list, roughly ordered by impact:

1. **The frontend is one 55 KB HTML file** (all CSS + JS inline). It works and keeps the
   "single artifact" simplicity, but it's near its maintainability ceiling: no module
   boundaries, no component reuse, no UI tests, and it's the file most prone to the
   edit-corruption problems we've hit. *Biggest long-term structural risk.*
2. **Graph layout sprawls horizontally.** The `breadthfirst` layout places all
   same-depth leaves in a single wide row, so a finding-heavy Nikto run becomes a long
   horizontal smear. Needs a compaction strategy (see roadmap).
3. **Knowledge base is thin.** Many finding types (most Nikto checks) fall back to a
   generic severity blurb, so "what this means" reads samey. High-value, low-effort to
   expand.
4. **Two parallel stores can drift.** Findings are *derived* from entities but stored
   separately; the dedup fix patched the symptom. Cleaner long-term: compute findings
   from the graph on read, or make them a view over vulnerability/secret entities.
5. **Parsers are regex-over-text.** Robust today, but brittle to tool version/output
   changes. There are golden-output tests for some tools, not all — format drift could
   silently break parsing.
6. **No frontend tests.** JS is only validated by `node --check` + manual runs.
7. **No limits on graph/console size.** A very large investigation could bloat the DOM
   and Cytoscape; there's no pagination, virtualization, or node cap.
8. **Single WebSocket, no reconnect/backpressure**, and each run holds a worker thread.
   Fine for one user; not built for concurrency.
9. **`docker_available()` is cached once.** If Docker starts *after* the server, tools
   stay marked "needs setup" until restart.
10. **Path-input tools read arbitrary host paths** (by design, for binary/dir analysis) —
    they're outside the workspace sandbox. Reasonable for a local lab, worth a conscious
    note.
11. **Report has no history.** It's regenerated live each time; there's no saved snapshot
    or diff over the life of an investigation.

None of these are on-fire; they're the shape of what to harden as the project matures.

---

## 9. Roadmap — animation, interactivity & "fun"

The thing you asked for. R.O.D.E already *feels* alive during a scan; here's how to make
it genuinely delightful, grouped by effort. (Respect `prefers-reduced-motion` throughout.)

### Quick wins (mostly CSS + small JS)
- **Nodes animate in** as they're discovered (pop/scale-fade) instead of a full re-layout.
- **Edges draw** along their path; **new findings pulse** briefly (already have a flash —
  extend it to arrival).
- **Footprint bars fill with a bounce**; a subtle red "detected" shake when you tip into
  aggressive.
- **Toast notifications** for key events (finding confirmed, run blocked, scan done)
  instead of console-only text.
- **Button/press ripples** and springier hover transitions on cards and chips.

### Medium (a nicer graph engine)
- Swap `breadthfirst` for **fcose** (force-directed + compound) with **animated layout
  transitions** — fixes the horizontal sprawl *and* gives organic motion.
- **Collapsible compound clusters**: category nodes become bubbles you expand/collapse
  with animation; huge scans stay tidy.
- **Live "scan pulse"**: while a tool runs, its origin node radiates rings and particles
  flow along the edges being explored — turning waiting into feedback.

### Bigger / later
- **Investigation timeline scrubber** — replay discovery as it happened, node by node.
- **Guided first-run tour** and light **gamification** (first vuln, "stay silent"
  challenges, detectability score) to teach through play.
- **Optional sound design** (toggle): subtle blips on discovery/confirm.
- **Themes** + a reduced-motion mode as a first-class setting.

### Structural enablers (do these to make the above sane)
- Consider a **light build step / component split** for the frontend before it grows
  further — or at minimum extract CSS and JS into separate files with a tiny bundler.
- Adopt **fcose** and treat layout as animated state, not a one-shot.
- **Expand the knowledge base** so the richer inspector/report has richer things to say.
- Add **golden-fixture parser tests** for every tool to catch output drift.

---

## 10. File map

```
rode-v3/
├── start.bat                     one-click launcher (venv + deps + run)
├── backend/
│   ├── run.py                    uvicorn entrypoint (ws=wsproto)
│   ├── config.py  db.py  models.py  logger.py  safety.py
│   ├── api/app.py                REST + WebSocket surface
│   ├── tools/  tools.yaml + registry   (data-driven catalogue, 20 tools)
│   ├── executor/  runner · command · python_tools
│   ├── parsers/   registry + 12 tool parsers + base
│   ├── graph/     entity_service.py    (the brain)
│   └── report/    generator.py + knowledge.py + knowledge.json
├── frontend/index.html           the entire UI (single file)
└── tests/         test_parsers · test_registry · test_safety   (25 tests)
```

---

*Bottom line: the architecture is sound, the safety model is real, and the graph-as-story
idea is the app's soul. The two things to invest in next are (a) a graph layout that
scales to finding-heavy scans and (b) the animation/feedback layer that turns a capable
tool into one that's a joy to use — with a modest frontend refactor being the enabler for
both.*
