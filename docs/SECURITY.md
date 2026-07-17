# R.O.D.E v4 — Security Posture (of the toolkit itself)

A security tool that's itself hackable is a liability. This documents R.O.D.E's own
threat model and the controls in place, and honestly maps the standard "secure a web
app" checklist to what actually applies here.

## Threat model
R.O.D.E is **local-first and single-user**: the server binds `127.0.0.1`, there are no
accounts, no multi-tenant data, and no cloud. That removes whole classes of risk (there
is no other user to steal data from, no login to phish, no public endpoint to DDoS). The
real attack surface is different from a public SaaS:

1. **The local server is reachable from your browser.** A malicious *web page* you visit
   could try to talk to `http://127.0.0.1:8000` and drive the tool runner or packet
   capture. This is the primary threat and the one most people miss.
2. **R.O.D.E runs tools** (Docker, subprocesses, packet capture) and fetches URLs — so
   command injection, SSRF, and path traversal matter.
3. **It handles sensitive output** (cracked credentials, VPN keys) stored locally.

## Controls in place
- **Loopback only** — binds `127.0.0.1`; CORS restricted to loopback origins.
- **WebSocket origin check** — `/ws/run` and `/ws/capture` reject handshakes whose
  `Origin` isn't localhost, so a malicious page can't open a socket and run tools.
  (Native clients with no Origin still work.) *Verified.*
- **Security headers** on every response — `X-Frame-Options: DENY`,
  `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`,
  `Content-Security-Policy: frame-ancestors 'none'; object-src 'none'`, plus `no-store`.
- **No shell, ever** — every external command is a fixed `argv` list with `shell=False`,
  which structurally removes command injection. Docker containers are named so they can
  be killed cleanly.
- **Parameterized DB access** — all queries go through SQLAlchemy's ORM (bound params),
  so no SQL injection.
- **Input validation** — every API body is a Pydantic model (typed, coerced).
- **SSRF-limited proxies** — the camera snapshot proxy only fetches URLs already in the
  saved feed list, blocks the cloud-metadata IP (`169.254.169.254`), caps response size,
  and never serves a feed back as renderable HTML (content-type clamped to images).
- **Output encoding** — user-supplied strings are HTML-escaped in the UI and report
  (`escapeHtml` / `html.escape`); graph labels render as text, console via `textContent`.
- **File sandbox** — log/file tools are confined to the `workspace/` directory
  (path-escape attempts refused).

## How the modern "secure a web app" checklist maps here
Most of the standard advice (OAuth/OIDC, MFA/passkeys, JWT rotation, BOLA/BFLA
multi-user authorization, API gateways, IaC/cloud scanning, secret managers) targets a
**public, multi-user, cloud-deployed** app — R.O.D.E is none of those, so those items
don't apply. The parts that *do* apply are already addressed above (server-side trust,
injection defense, input validation, security headers, supply-chain hygiene below).

## Supply-chain hygiene (recommended, easy adds)
- Pin dependencies and run `pip-audit` / `npm audit` before shipping.
- R.O.D.E can **audit itself**: point the Analyzer's Trivy scan at its own directory to
  catch vulnerable deps and accidental secrets.

## Residual risks (accepted for a local single-user tool)
- Cracked credentials and generated WireGuard private keys are stored in plaintext in the
  local SQLite DB / files. Acceptable single-user, but don't share the `data/` folder.
- Analyzer path-input tools read arbitrary host paths you point them at (by design).
- No cap on graph/console size for very large investigations.

*Bottom line: the toolkit's own front door is locked (loopback + origin-checked sockets +
headers + no-shell exec + validated input), which is the security that actually matters
for a local-first tool. The residual items are documented, not hidden.*
