# Mitigation playbook (physical access control)

## 1. Replace Wiegand with OSDP (Secure Channel)

**Problem.** Wiegand exposes static credential frames with no MAC or session keys.

**Action.**

- Specify readers and panels supporting **OSDP v2** with **Secure Channel** (AES-128 per SIA OSDP).
- Disable legacy Wiegand forwarding except during phased migration.
- Validate firmware signing and trusted boot on edge devices handling OSDP.

**Verification.** Packet captures on RS-485 should show encrypted payloads after SC handshake; no stable credential bit patterns.

## 2. Deprecate MIFARE Classic → move to DESFire EV3

**Problem.** MF Classic relies on Crypto1 + sector keys; offline dictionary attacks and cloning are routine in weak deployments.

**Action.**

- Inventory tokens; rotate high-risk sites first.
- Prefer **MIFARE DESFire EV3** with diversified keys and **proximity check** features where vendor supports it.
- Backhaul credential verification to panels that enforce **card-level crypto** rather than UID-only modes.

**Verification.** Panels reject UID-only emulation; personalization audit shows diversified keys.

## 3. Add MFA for physical access

**Problem.** Something-you-have alone fails under relay/cloning pressure.

**Action.**

- Layer **PIN**, mobile push, or biometric **at the reader** or supervised vestibule.
- Separate **visitor** credentials with short TTL and monitored paths.

**Verification.** Red-team exercises show relay/cloning cannot complete MFA-bound paths.

## 4. Operational controls

- Maintain asset registry for readers/firmware hashes.
- Log anti-passback and duress codes where available.
- Run tabletop exercises for credential revocation at scale.
