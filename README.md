# RFID Security Toolkit

Hardware-security–focused **educational** utilities for **authorized lab environments** only: Wiegand observation, MIFARE Classic dump analysis, and documented attack/mitigation narratives.

## Legal and ethics

Use only on systems you own or have **explicit written authorization** to test. Unauthorized access to physical access control systems may violate criminal law. This software is provided for security research, training, and defensive hardening.

## Layout

| Path | Purpose |
|------|---------|
| `src/rfid_wiegand_sniffer/` | Raspberry Pi GPIO sniffer + 26-bit Wiegand decoder (with offline/mock modes) |
| `src/mifare_analyzer/` | Offline `.mfcdump` / `.eml` parsing, ACL decode, default-key checks |
| `lab_sim/` | Safe lab setups, attack simulations, mitigation playbook |
| `docs/` | Supplementary references |

## Install

```bash
cd rfid-security-toolkit
python -m venv .venv
.venv\Scripts\activate   # Windows
pip install -e .
# On Raspberry Pi only:
pip install -e ".[pi]"
```

## CLI

```bash
wiegand-sniffer --help
mifare-analyze --help
```

## Development log

See `DEVLOG.md`.
