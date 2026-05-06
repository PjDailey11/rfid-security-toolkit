# Development log

## 2026-05-06 — Initial scaffold

**What changed**

- Created repository layout: `src/rfid_wiegand_sniffer`, `src/mifare_analyzer`, `lab_sim/`, `docs/`.
- Implemented 26-bit Wiegand decode with parity verification, facility/card extraction, security notes on keyspace and replay.
- Implemented MIFARE Classic 1K dump loaders (binary `.mfcdump`/`.bin`, Proxmark-style `.eml`), sector trailer parsing, access-bits decoding, Block 0 UID/manufacturer mapping, and default-key scanning against sector trailers.
- Added `lab_sim/` documentation for eavesdropping, replay, cloning, relay, and reader DoS **as simulations** with ESP32 + MFRC522 door-sim guidance; mitigation playbook (OSDP Secure Channel, DESFire EV3, MFA).

**Why**

- Deliver a single cohesive, type-hinted toolkit with small CLIs suitable for defensive security curricula and controlled labs.

**Next steps**

- Optional: extend parsers for MIFARE 4K / NTAG-adjacent formats if needed.
- Optional: add timed GPIO backend using `lgpio` / `pigpio` for sub-microsecond scheduling on newer Pi OS images.
- Optional: integrate lightweight Crypto1 verification for ciphertext-only dumps (higher complexity).

**Verification**

- `pip install -e .` on Windows; `wiegand-sniffer mock-sniff` and `mifare-analyze lab_sim/data/sample_weak.eml` return valid JSON (synthetic dump uses transport-valid ACL bytes `78 87 96`).

---

## 2026-05-06 — GitHub remote

**What changed**

- Initialized a standalone git repository in `rfid-security-toolkit/`, added `.gitignore`, committed initial tree, created public remote `origin`.

**Why**

- Publish the toolkit independently of the `portfolio-website` monorepo.

**Next steps**

- Optionally add GitHub Actions (lint / `pip install -e .` smoke test).
- Link from portfolio README if desired.

**Remote:** https://github.com/PjDailey11/rfid-security-toolkit
