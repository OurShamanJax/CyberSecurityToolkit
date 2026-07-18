# R.O.D.E — Tool & Feature Idea Backlog ("The Bat Computer")

Candidate additions, all **free / open-source (wrap in Docker or shell)** or **codeable
from scratch**, no accounts / no API keys. Tags:
`[WRAP]` existing FOSS tool · `[CODE]` I build it in Python/JS · `[API]` free no-key public
data · `[FUN]` command-center flair. Everything stays pointed at **owned/authorized targets**
and pairs offense with the matching defense.

---

## RECON — discover & map
- **crt.sh certificate-transparency subdomains** `[API]` — passive subdomain enum, no key.
- **SpiderFoot** `[WRAP]` — huge open-source OSINT automation engine; wrap its API to pull
  emails, subdomains, breaches, leaks into the graph in one shot.
- **holehe** `[WRAP]` — check which sites an email is registered on (account presence).
- **WHOIS / RDAP + ASN/BGP lookup** `[CODE][API]` — who owns a domain/IP, which network.
- **katana / hakrawler** `[WRAP]` — crawl a site's endpoints and JS for hidden paths/params.
- **gowitness / EyeWitness** `[WRAP]` — screenshot every live web endpoint → **thumbnails on
  the graph nodes** (great visual, very Gotham).
- **testssl.sh / sslscan** `[WRAP]` — full TLS/cipher/cert audit of a host.
- **exiftool** `[WRAP]` — pull GPS + metadata out of images/docs → geolocate on the map.
- **GeoIP enrichment (offline DB-IP)** `[CODE]` — put every IP entity on the map lens.
- **LAN auto-discovery** `[WRAP]` (arp-scan / nmap ping sweep) — map every device on *your*
  home network and plot it. The "my network" Bat Computer view.

## OFFENSE — attack (authorized)
- **OWASP ZAP (baseline scan)** `[WRAP]` — the big free web-app scanner; Dockerized, no
  account. Huge coverage boost for web pentests.
- **ffuf / feroxbuster** `[WRAP]` — fast directory & parameter fuzzing.
- **dalfox** `[WRAP]` — XSS scanner.
- **searchsploit (Exploit-DB, offline)** `[WRAP]` — map a detected version → known public
  exploits, right on the vuln node.
- **hashcat / John** `[WRAP]` — offline hash cracking to pair with the login auditor.
- **hydra / medusa** `[WRAP]` — broaden the credential auditor beyond HTTP logins (SSH, FTP…
  on your own boxes).

## DEFENSE — protect & detect
- **Suricata / Zeek** `[WRAP]` — real IDS engine behind Live Traffic (signatures + logs).
- **Sigma rules engine** `[CODE]` — run open detection rules over captured traffic/logs.
- **Lynis** `[WRAP]` — audit *your own* host's security posture and get a hardening checklist.
- **ClamAV + YARA** `[WRAP]` — scan files/dirs for malware and custom rules.
- **Pwned Passwords (k-anonymity)** `[API]` — check if a password is in a breach corpus
  **without ever sending the password** (safe, free, no account).
- **abuse.ch threat feeds (URLhaus / Feodo / ThreatFox)** `[API]` — flag known-malicious
  IPs/domains/URLs; enrich graph nodes with a "known bad" badge.
- **Email header / .eml analyzer** `[CODE]` — SPF/DKIM/DMARC + phishing indicators.
- **Domain security check** `[CODE]` — SPF/DKIM/DMARC/DNSSEC/CAA for a domain you own.
- **File Integrity Monitor** `[CODE]` — snapshot a folder's hashes, alert on change.
- **Certificate-expiry watchlist** `[CODE]` — monitor your own certs, warn before expiry.
- **Simple honeypot** `[CODE]` — open a port, log every connection attempt, drop them on the
  graph/map as `alert` nodes (defensive + fun).

## EXPLOIT / ANALYZE — artifacts & forensics
- **binwalk** `[WRAP]` — firmware/file extraction (great for IoT firmware analysis).
- **oletools / pdfid / pdf-parser** `[WRAP]` — spot malicious Office docs & PDFs.
- **volatility3** `[WRAP]` — memory-image forensics.
- **steghide / stegseek / zsteg** `[WRAP]` — detect/extract hidden data in images.
- **radare2 / capstone / pefile** `[WRAP]` — deeper binary reversing than the current inspector.
- **foremost / scalpel** `[WRAP]` — file carving from disk images.

## CROSS-CUTTING — the intelligence glue (highest leverage)
- **Graph + Map + Timeline unify** `[CODE]` — the big one from the strategy doc.
- **MITRE ATT&CK mapping** `[CODE][API]` — tag findings with ATT&CK techniques; a
  "command-center" coverage view. ATT&CK data is free/open.
- **Correlation rules** `[CODE]` — "open RDP + known CVE + known-bad IP → escalate."
- **Threat-intel enrichment** `[API]` — auto-badge nodes from the free feeds above.
- **Encrypted local vault** `[CODE]` — safely store found credentials/keys at rest.
- **Run history + diff** `[CODE]` — re-run any scan, see "what changed since last time."
- **Investigation templates & export** `[CODE]` — JSON/CSV/PDF; shareable case files.
- **Watchlists & scheduled scans** `[CODE]` — re-scan on a cadence, alert on change.

## FUN — Bat Computer flair (mostly `[FUN]`)
- **Live threat map** — plot honeypot hits + traffic alerts on the globe by GeoIP (the
  classic "cyber attack map").
- **OpenSky ADS-B live aircraft** `[API]` — real planes flying across the globe (free,
  anonymous tier). Pure Batcomputer ambience.
- **USGS live earthquakes** `[API]` — real-time quake feed as a globe layer (free, no key).
- **NOAA / weather & space-weather layers** `[API]` — aurora, solar activity.
- **"World monitor" ambient mode** — idle screen cycling map layers + a status ticker.
- **Radar-sweep scan animation**, boot sequence, optional sound cues, gamified learning
  (first-vuln, "stay silent" challenges), achievements.

---

## My top picks (biggest value, low friction, safe)
1. ✅ **Graph/Map/Timeline unify + GeoIP** — DONE. Three lenses on one investigation; entities
   carry lat/lng and plot on the Cesium map.
2. **OWASP ZAP** — instantly serious web-app coverage, free/Docker.
3. 🟡 **Threat-intel enrichment (abuse.ch)** — DONE (Feodo/URLhaus node badges). **Pwned
   Passwords** still to do.
4. **Lynis** — audit your own machine; pure defensive value, easy win. *(in progress)*
5. **Suricata/Zeek behind Live Traffic** — turns the traffic tab into a real IDS.
6. **MITRE ATT&CK mapping** — the "command center" layer that ties findings to a framework.
   *(in progress)*
7. ✅ **LAN auto-discovery → map** — DONE (private-/24 sweep + OUI vendors → graph).
8. **gowitness screenshots on nodes** + **live threat map** — the visual wow.

*(Also shipped from the lists above: searchsploit/Exploit-DB exploit paths, the Metasploit
workbench, and the Windy/DOT camera + Living-Earth globe layers.)*

*Guardrail through all of it: owned/authorized targets, offense paired with defense, free &
local. Breadth is tempting — but the unify work makes every one of these land better, so
it comes first.*
