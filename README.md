# R.O.D.E v4 — a local, free/open-source security learning workbench

*Recon · Offense · Defense · Exploit.* A single-user "command center" for learning
offensive & defensive security **on systems you own or are authorized to test**. Every
result feeds one connected picture — a graph, a map, and (soon) a timeline. Runs locally
or in Docker; **no accounts, no API keys, no cloud.**

> ⚠️ **Use responsibly.** Only scan, test, or attack targets you own or have explicit
> written permission to test (your own machines, your own network, deliberately-vulnerable
> labs like OWASP Juice Shop). Unauthorized use is illegal.

---

## 1. Prerequisites

| Requirement | Why | Notes |
|---|---|---|
| **Python 3.10+** | runs the app | tick "Add Python to PATH" on Windows |
| **Docker Desktop** | most tools run in containers | see §3 |
| *(optional)* **Wireshark** | real packet capture (Live Traffic) | includes tshark + Npcap; run app as admin |
| *(optional)* WiFi adapter w/ monitor mode + Linux/WSL | deep wireless features | read-only AP scan works without it |

No Node.js needed — the frontend is plain files served by the backend.

## 2. Install & run

```bash
# from the RODE-V4 folder
python -m venv .venv
.venv\Scripts\activate            # Windows   (macOS/Linux: source .venv/bin/activate)
pip install -r requirements.txt
python -m backend.run
```

…or on Windows just double-click **`start.bat`** (creates the venv, installs deps, opens
the browser). Then open **http://127.0.0.1:8000**.

## 3. Docker & the tool images

Most Recon/Offense/Analyze tools run in Docker so you don't have to install each one.

1. Install **Docker Desktop**: https://www.docker.com/products/docker-desktop/ — install,
   launch it, and wait until it says "running."
2. R.O.D.E pulls each tool's image automatically the first time you run that tool (first
   run of a tool is slower while it downloads). To pre-pull the common ones:
   ```bash
   docker pull projectdiscovery/nuclei:latest
   docker pull ghcr.io/sullo/nikto:latest
   docker pull instrumentisto/nmap:latest
   docker pull sherlock/sherlock
   docker pull aquasec/trivy:latest
   ```
3. In the app, **Settings → Tools & capabilities → Re-check** shows whether Docker is
   detected. A tool marked "needs setup" just means its image/binary isn't available yet.

## 4. What's inside (by R.O.D.E pillar)

- **Workspace — Investigation:** the entity graph + console + findings + inspector, with a
  **Graph / Map** lens toggle (geolocated entities on a globe).
- **Recon:** Exposure (Shodan InternetDB lookup), Wireless (AP scan), Atlas (globe of
  public cameras + satellites).
- **Offense:** Credentials (login auditor + wordlists).
- **Defense:** Live Traffic (tshark capture + heuristic alerts), VPN (WireGuard generator).
- **Exploit:** Analyzer (binary / directory / running-app analysis).
- **System:** Report, Settings.

Press **Ctrl/⌘ + K** for the command palette.

## 5. Security & privacy

- The server binds **127.0.0.1 only**, with WebSocket origin checks and security headers.
- Your scans, IPs, and results live in **`data/`**, which is **git-ignored** — it never
  gets committed. Generated VPN `.conf` files (private keys) are ignored too.
- See `docs/SECURITY.md` for the full threat model.

## 6. Docs

- `docs/STATUS.md` — what's done and what's next.
- `docs/V4_STRATEGY.md` — the vision and roadmap.
- `docs/IDEAS.md` — the tool/feature backlog.
- `docs/SECURITY.md` — the toolkit's own security posture.
