# Attack simulations (models + safe lab framing)

These scenarios are **thought experiments tied to bench rigs**. They are **not** instructions for bypassing third-party systems.

## 1. Eavesdropping (Wiegand)

**Model.** An attacker probes `D0/D1` between reader and controller (or uses an inline tap) and logs pulse intervals.

**Lab.** Raspberry Pi GPIO sniffer + bench reader outputting Wiegand test frames; **no** production controller.

**Observable.** Facility/card fields appear in plaintext; parity bits offer integrity against single-bit noise but **no cryptographic authenticity**.

## 2. Replay

**Model.** Recorded bit patterns are replayed into the controller input.

**Lab.** Microcontroller firmware replays a captured 26-bit frame into a **disconnected** controller dev kit or logic analyzer sink — not a live secured door.

**Lesson.** Without OSDP Secure Channel or upstream challenge-response, legacy buses frequently accept repeats.

## 3. Cloning (MF Classic)

**Model.** Sector keys + block payloads extracted from a dump are written to a blank UID-compatible token.

**Lab.** Proxmark / Flipper write onto **training tags** in a shielded enclosure; validate only against your MFRC522 dev reader.

**Lesson.** Static symmetric keys + writable trailers ⇒ trivial duplication if defaults persist.

## 4. Relay

**Model.** RF or wired bridge extends the effective coupling distance between card and reader.

**Lab.** Two MFRC522 modules communicating over UART/Ethernet with **explicit oscilloscope monitoring**; keep transmit power minimal and shielded.

**Lesson.** Cryptography must bind **reader authentication** and **freshness** to defeat naive relays.

## 5. Reader denial-of-service

**Model.** Noise, intentional invalid modulation, or power sag prevents stable ISO14443 framing.

**Lab.** Function generator + attenuator into a **non-production** antenna loop; measure only on disposable readers.

**Lesson.** Pair reader hardening (watchdogs, backoff) with site monitoring and failover unlock policies.
