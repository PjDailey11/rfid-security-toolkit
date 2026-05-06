# Lab simulations (safe bench setups)

This folder describes **non-destructive**, **authorized** labs for teaching RFID and access-control weaknesses.

## Reference hardware profile

| Role | Example stack | Notes |
|------|----------------|-------|
| Door / reader sim | ESP32 + MFRC522 (`SPI`) | Drive MFRC522 as *reader* only; never attach to production wiring. |
| Sniffer tap | Raspberry Pi + level shifters | Use for **Wiegand observation** exercises; isolate from mains-powered panels until reviewed by an electrician. |
| Ground truth | Proxmark3 / Flipper Zero | Capture `.mfcdump` / `.eml` only from cards **you own**. |

Always document chain-of-custody for credential artifacts and wipe flash media after class.

## Contents

- `ATTACK_SIMULATIONS.md` — Models eavesdropping, replay, cloning, relay, reader DoS with explicit safety boundaries.
- `MITIGATION_PLAYBOOK.md` — OSDP Secure Channel, DESFire EV3 migration, MFA layering.
- `data/sample_weak.eml` — Synthetic Classic 1K dump for pipeline testing (weak default keys + valid ACL transport bytes).
