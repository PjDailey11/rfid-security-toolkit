"""MF Classic manufacturer / UID helper decoding."""

from __future__ import annotations

# ISO/IEC 7816-6 RID first byte (UID0 on many NXP tags) — illustrative subset.
MANUFACTURER_BY_CODE: dict[int, str] = {
    0x01: "Motorola",
    0x02: "STMicroelectronics",
    0x03: "HID Global",
    0x04: "NXP Semiconductors",
    0x05: "Infineon Technologies",
    0x06: "Cylink",
    0x07: "Texas Instruments",
    0x08: "Mitsubishi Electric",
    0x09: "Atmel",
    0x0A: "EM Microelectronic-Marin",
    0x0B: "Keystone Technologies",
    0x0F: "Melexis",
    0x13: "Cologne Chip",
    0x14: "Micron",
    0x15: "Intel",
    0x16: "Siemens",
    0x17: "Inside Secure",
    0x21: "HID Global",
    0x22: "ASK",
    0x26: "Sony",
    0x31: "Philips Semiconductors (legacy)",
    0x56: "INSIDE Secure",
    0x62: "Gemalto",
    0x63: "LEGIC Identsystems",
    0x81: "Infineon",
    0x95: "Microsoft",
}


def manufacturer_name(code: int) -> str:
    return MANUFACTURER_BY_CODE.get(code & 0xFF, "unknown / assignee not listed")


def xor_bytes(data: bytes) -> int:
    x = 0
    for b in data:
        x ^= b
    return x


def decode_block0_manufacturer(block0: bytes) -> dict[str, object]:
    """
    Interpret manufacturer block (sector 0 block 0) for common 4-byte UID layouts.

    Layout assumed (Proxmark-style plaintext dump): UID (4B) || BCC (1B) || ...
    BCC should equal UID0 ⊕ UID1 ⊕ UID2 ⊕ UID3 on valid cards.
    """
    if len(block0) < 16:
        raise ValueError("block0 must be 16 bytes")

    uid4 = block0[0:4]
    bcc = block0[4]
    uid_xor = xor_bytes(uid4)
    manufacturer_code = uid4[0]

    return {
        "uid_hex": uid4.hex().upper(),
        "uid_bytes": list(uid4),
        "manufacturer_code": f"0x{manufacturer_code:02X}",
        "manufacturer_name": manufacturer_name(manufacturer_code),
        "bcc_byte": f"0x{bcc:02X}",
        "bcc_xor_valid": bool(bcc == uid_xor),
        "note": "UID endianness and 7-byte UID variants require firmware/context flags from reader.",
    }
