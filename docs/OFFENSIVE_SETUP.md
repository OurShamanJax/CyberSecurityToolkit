# R.O.D.E — offensive-tooling setup & safety (Windows)

Practical setup for the two things Windows makes awkward — **monitor-mode WiFi** and
**antivirus friction** — plus how to **audit R.O.D.E itself**. Everything here is for
systems and networks you **own or are explicitly authorized to test**.

---

## 1. Monitor-mode WiFi on Windows (deauth / handshake capture)

R.O.D.E's Wireless page is **read-only** on Windows on purpose: the Windows WiFi stack
can't do **monitor mode** or **packet injection**, so deauth and WPA-handshake capture are
impossible there — the buttons are locked and say so. The real path is Linux drivers with a
compatible adapter. On Windows you get there through **WSL2 + usbipd** (USB passthrough).

**You need compatible hardware.** Not every WiFi adapter supports monitor mode + injection.
Known-good external chipsets:

- **Atheros AR9271** (e.g. Alfa AWUS036NHA) — the most painless.
- **Realtek RTL8812AU** (e.g. Alfa AWUS036ACH) — dual-band, needs the `8812au` DKMS driver.
- **MediaTek MT7612U** (e.g. Alfa AWUS036ACM) — good mainline-kernel support.

### Steps

1. **Install WSL2 + Ubuntu** (admin PowerShell), then reboot:
   ```powershell
   wsl --install -d Ubuntu
   ```

2. **Install usbipd-win** on Windows:
   ```powershell
   winget install dorssel.usbipd-win
   ```

3. **Attach the adapter to WSL.** Plug it in, then in an **admin** PowerShell:
   ```powershell
   usbipd list                       # find the adapter's BUSID, e.g. 2-4
   usbipd bind --busid 2-4
   usbipd attach --wsl --busid 2-4
   ```

4. **Confirm + drivers inside Ubuntu:**
   ```bash
   lsusb                             # your adapter should be listed
   sudo apt update && sudo apt install -y aircrack-ng
   # RTL8812AU only: sudo apt install -y realtek-rtl88xxau-dkms
   ```

5. **Enable monitor mode and work (authorized networks only):**
   ```bash
   sudo airmon-ng start wlan0
   sudo airodump-ng wlan0mon                     # find your target AP + channel
   sudo airodump-ng -c <ch> --bssid <AP> -w cap wlan0mon
   sudo aireplay-ng --deauth 5 -a <AP> wlan0mon  # your own AP, to force a re-handshake
   # cap-01.cap now holds the WPA handshake → crack offline with hashcat/aircrack-ng
   ```

### Honest caveats

- **WSL2's kernel often lacks the WiFi driver / full `cfg80211`.** The stock WSL kernel is
  minimal; getting monitor mode working can require a **custom-compiled WSL2 kernel** with the
  adapter's module. If it fights you, a **native Linux boot (live USB)** or a **Linux VM with
  USB passthrough** is more reliable and is the recommended path for serious wireless work.
- R.O.D.E does not automate any of this — it can't (Windows limitation). This is the external
  toolchain the locked buttons point you toward.

---

## 2. Antivirus / Windows Defender

**Why Defender flags offensive tools.** Payload generators (msfvenom), some scanners, and
password-cracking tools share signatures and behaviours with real malware — because they're
dual-use, they *are* functionally the same code. Generated payloads especially get
**quarantined the moment they're written to disk**, and again on execution (AMSI).

**How to work without disabling protection:**

- **Best: isolate.** Run offensive tooling in a **VM, WSL2, or Docker**, separated from your
  daily machine and pointed at an isolated target VM. R.O.D.E already runs msfvenom in Docker
  for this reason.
- **If you must run locally: a narrow exclusion folder.** Windows Security → *Virus & threat
  protection* → *Manage settings* → *Exclusions* → *Add or remove exclusions* → **Add a
  folder** — one dedicated `C:\lab\payloads` directory. Keep generated payloads only there.
- **Never** disable AV entirely, and **never** exclude broad locations (your whole user
  profile, `Downloads`, `C:\`). A single scoped lab folder is the whole point.
- Treat it as a lesson: watching Defender quarantine a meterpreter payload is a live demo of
  **why EDR works**.

R.O.D.E's Payloads page says all of this in the UI, loudly — generate on the Linux attack box,
or in the excluded lab folder, never on a machine you actually use.

---

## 3. Dogfooding — audit R.O.D.E itself

R.O.D.E wraps security tools, so it should hold itself to the same standard. Two free scanners:

### pip-audit (Python dependency CVEs)

Checks R.O.D.E's Python deps against the PyPI advisory database.

```cmd
start.bat audit          REM Windows — installs pip-audit if needed, then scans
```
or directly:
```bash
pip install pip-audit
pip-audit -r requirements.txt
```

**Last run: `No known vulnerabilities found`** across FastAPI, uvicorn, SQLAlchemy, pydantic,
cryptography, requests, and the rest. Re-run before each push.

### Trivy (deps + secrets + misconfig)

[Trivy](https://github.com/aquasecurity/trivy) scans the whole repo — dependency CVEs, IaC
misconfig, and **accidentally-committed secrets** (valuable here, since Windy/FIRMS keys must
never be pushed). Run it from the repo root:

```bash
# via the binary
trivy fs .

# or via Docker, no install
docker run --rm -v "%cd%":/scan aquasec/trivy fs /scan
```

Pay attention to the **secret** and **vuln** findings. If Trivy ever flags `data/secrets.json`,
your `.gitignore` isn't protecting it — fix that before committing.

**Cadence:** `start.bat audit` (pip-audit) on every launch you care about, and a `trivy fs .`
before pushing to GitHub.
