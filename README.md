# RFID Security Toolkit

Hardware-security–focused **educational** tooling for **authorized labs** only. It helps instructors and defenders study legacy proximity-access weaknesses—especially **cleartext Wiegand** on the wire and **MIFARE Classic** deployments that reuse default keys—without pretending cryptography exists where it does not.

### What this repo contains

| Component | What it does |
|-----------|----------------|
| **`rfid_wiegand_sniffer`** | Decodes **26-bit Wiegand** frames (facility + card fields, parity checks). On a **Raspberry Pi**, optional GPIO capture listens for `D0`/`D1` pulses and logs decoded credential fields as JSON, alongside notes on **small brute-forceable card keyspace** and **replay risk**. **Mock** mode runs anywhere without hardware. |
| **`mifare_analyzer`** | Loads **MIFARE Classic 1K** dumps as raw **1024-byte** binaries (common `.mfcdump`/`.bin` exports) or **Proxmark-style `.eml`** (64 lines × 32 hex chars). Parses **sector trailers** (Key A/B), validates **access-byte transport coding**, derives **C1/C2/C3** ACL summaries, flags keys that appear in a **default-key dictionary**, and decodes **manufacturer block** data (e.g. UID byte `0x04` → **NXP**). |
| **`lab_sim/`** | Short, safety-bounded write-ups: modeled scenarios (eavesdrop, replay, cloning, relay, reader DoS) for **bench rigs**, plus a **mitigation playbook** (OSDP Secure Channel, DESFire EV3, MFA). |

### Who it is for

Security courses, red-team exercisers with a signed scope, access-control engineers migrating off legacy stacks, and researchers who need **repeatable offline parsers** for dumps captured from **their own** tokens or **explicitly permitted** assessments.

### What it does *not* do

It does not bypass third-party systems, crack Crypto1 from ciphertext-only dumps at scale, or replace Proxmark for live RF—it **documents limits** (e.g. dictionary checks on **plaintext** trailer keys after a successful dump).

---

## Legal and ethics

Use only on hardware and credentials **you own** or under **explicit written authorization**. Tampering with physical access systems without permission may violate criminal law in your jurisdiction. This software is for training, research, and defensive design—not unauthorized entry.

---

## Repository layout

| Path | Purpose |
|------|---------|
| `src/rfid_wiegand_sniffer/` | Wiegand decode + Pi GPIO sniffer CLI (`decode`, `mock-sniff`, `pi-sniff`) |
| `src/mifare_analyzer/` | Dump loaders, ACL decode, manufacturer/block 0 helpers, `mifare-analyze` CLI |
| `lab_sim/` | Attack narratives, mitigation playbook, sample `.eml` under `lab_sim/data/` |
| `docs/` | Extra policy reference (`AUTHORIZED_USE.md`) |
| `DEVLOG.md` | Change journal for the maintainers |

---

## Installation (detailed)

### Prerequisites

- **Python 3.10 or newer** (3.11+ recommended). Check with:

  ```bash
  python --version
  ```

  On Windows, use **Python from python.org** or the Microsoft Store; ensure “Add Python to PATH” is enabled if you use the installer.

- **Git** (only if you are cloning from GitHub rather than using a zip download).

### 1. Get the source

**Clone**

```bash
git clone https://github.com/PjDailey11/rfid-security-toolkit.git
cd rfid-security-toolkit
```

**Or** download the repository as a ZIP from GitHub and extract it, then open a terminal in the extracted `rfid-security-toolkit` folder.

### 2. Create an isolated environment (recommended)

Virtual environments avoid conflicting with system Python or other projects.

**Windows (PowerShell or Command Prompt)**

```powershell
python -m venv .venv
.\.venv\Scripts\activate
python -m pip install --upgrade pip
```

**macOS / Linux**

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
```

Your shell prompt should usually show `(.venv)` when the environment is active. **Deactivate** later with `deactivate`.

### 3. Install the package

**Standard editable install** (recommended while developing or updating from git—changes under `src/` are picked up without reinstall):

```bash
pip install -e .
```

**Plain install** (copies the package into the venv; use if you prefer not to track the repo live):

```bash
pip install .
```

There are **no mandatory runtime dependencies** for core decoding/analysis; `RPi.GPIO` is optional and only needed on Raspberry Pi for GPIO sniffing.

### 4. Raspberry Pi (optional GPIO sniffing)

On Raspberry Pi OS, after activating your venv:

```bash
pip install -e ".[pi]"
```

That pulls **`RPi.GPIO`** (see `pyproject.toml` optional extra `pi`). Wiring **5 V** Wiegand reader outputs to **3.3 V** Pi GPIO requires **level shifting**—do not connect 5 V swings directly to the Pi.

### 5. Verify the install

```bash
wiegand-sniffer --help
mifare-analyze --help
```

Smoke-test without hardware:

```bash
wiegand-sniffer mock-sniff
mifare-analyze lab_sim/data/sample_weak.eml
```

You should see JSON on stdout. If `wiegand-sniffer` / `mifare-analyze` are **not found**, ensure the venv is activated and that `pip install -e .` completed without errors; on Windows, scripts live under `.venv\Scripts\`.

---

## CLI overview

```bash
wiegand-sniffer decode --bits "0,1,0,..."
wiegand-sniffer mock-sniff [--facility N] [--card N]
wiegand-sniffer pi-sniff --pin-d0 BCM_NUM --pin-d1 BCM_NUM [--log path]

mifare-analyze path/to/dump.bin
mifare-analyze path/to/dump.eml
mifare-analyze dump.eml --extra-keys keys.txt
```

Use `--help` on each command for full options.

---

## Development log

See `DEVLOG.md` for what changed, why, and planned next steps.
