"""26-bit Wiegand decode with parity verification (HID-style layout)."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class DecodeResult:
    """Decoded 26-bit Wiegand frame."""

    bits: tuple[int, ...]  # length 26, MSB first
    facility_code: int
    card_number: int
    even_parity_ok: bool
    odd_parity_ok: bool
    parity_valid: bool


def _even_parity(bits: tuple[int, ...]) -> int:
    """Return 0/1 parity bit such that all bits including parity have even number of ones."""
    ones = sum(bits)
    return ones & 1


def _odd_parity(bits: tuple[int, ...]) -> int:
    """Return 0/1 parity bit such that all bits including parity have odd number of ones."""
    return 1 - _even_parity(bits)


def decode_wiegand_26(bits: tuple[int, ...] | list[int]) -> DecodeResult:
    """
    Decode standard 26-bit Wiegand:

    - Bit 0 (MSB): even parity over facility code (next 12 bits)
    - Bits 1-12: facility code (12 bits, MSB at bit 1)
    - Bits 13-24: card number (12 bits, MSB at bit 13)
    - Bit 25 (LSB): odd parity over card number (previous 12 bits)

    Pulse capture should order bits MSB-first as transmitted.
    """
    b = tuple(int(x) & 1 for x in bits)
    if len(b) != 26:
        raise ValueError(f"expected 26 bits, got {len(b)}")

    p_even = b[0]
    facility_bits = b[1:13]
    card_bits = b[13:25]
    p_odd = b[25]

    exp_even = _even_parity(facility_bits)
    exp_odd = _odd_parity(card_bits)

    facility_code = int("".join(str(x) for x in facility_bits), 2)
    card_number = int("".join(str(x) for x in card_bits), 2)

    even_ok = p_even == exp_even
    odd_ok = p_odd == exp_odd

    return DecodeResult(
        bits=b,
        facility_code=facility_code,
        card_number=card_number,
        even_parity_ok=even_ok,
        odd_parity_ok=odd_ok,
        parity_valid=even_ok and odd_ok,
    )


def bits_from_pulse_tokens(tokens: list[tuple[str, int]]) -> tuple[int, ...]:
    """
    Convert alternating pulse annotations to bits.

    Each token is ("D0"|"D1", timestamp_us). D0 => bit 0, D1 => bit 1.
    Tokens must be in transmission order.
    """
    out: list[int] = []
    for line, _ts in tokens:
        if line == "D0":
            out.append(0)
        elif line == "D1":
            out.append(1)
        else:
            raise ValueError(f"unknown line {line!r}")
    return tuple(out)
