"""
MIFARE Classic access bits (Proxmark-compatible triplets).

Bit extraction mirrors RfidResearchGroup Proxmark3 `cmdhfmf.c` rights[] packing for blocks 0–3.
Descriptions summarize data/trailer permissions; consult NXP AN10787 for authoritative tables.
"""

from __future__ import annotations

from dataclasses import dataclass


def validate_transport_coding(trailer_16: bytes) -> bool:
    """Inverted-nibble transport coding on access bytes (bytes 6–8 of sector trailer)."""
    if len(trailer_16) < 9:
        return False

    def ok(b: int) -> bool:
        return ((b >> 4) ^ (b & 0x0F)) == 0x0F

    return ok(trailer_16[6]) and ok(trailer_16[7]) and ok(trailer_16[8])


def extract_c1c2c3(block_idx: int, trailer_16: bytes) -> tuple[int, int, int]:
    """Return (C1, C2, C3) for block index 0–3 within sector."""
    d7 = trailer_16[7]
    d8 = trailer_16[8]
    if block_idx == 0:
        packed = ((d7 & 0x10) >> 2) | ((d8 & 0x1) << 1) | ((d8 & 0x10) >> 4)
    elif block_idx == 1:
        packed = ((d7 & 0x20) >> 3) | ((d8 & 0x2) >> 0) | ((d8 & 0x20) >> 5)
    elif block_idx == 2:
        packed = ((d7 & 0x40) >> 4) | ((d8 & 0x4) >> 1) | ((d8 & 0x40) >> 6)
    elif block_idx == 3:
        packed = ((d7 & 0x80) >> 5) | ((d8 & 0x8) >> 2) | ((d8 & 0x80) >> 7)
    else:
        raise ValueError("block_idx must be 0..3")

    c1 = (packed >> 2) & 1
    c2 = (packed >> 1) & 1
    c3 = packed & 1
    return c1, c2, c3


# Condensed summaries — see AN10787 §10 tables for exact operations (incl. value blocks).
_DATA_ACL: dict[tuple[int, int, int], str] = {
    (0, 0, 0): "never / transport factory — invalid once user-programmed",
    (0, 0, 1): "data: read Key A|B; write Key A|B",
    (0, 1, 0): "data: read Key A|B; write never",
    (0, 1, 1): "data: read Key A|B; write Key B only",
    (1, 0, 0): "data: read Key A|B; write Key B; Key B may decrement (value blk ops)",
    (1, 0, 1): "data: read Key B; write Key B",
    (1, 1, 0): "data: read Key A|B; write Key B",
    (1, 1, 1): "data: read Key B; write Key B (value-block transfer semantics apply)",
}


_TRAILER_ACL: dict[tuple[int, int, int], str] = {
    (0, 0, 0): "trailer: keys/ac bits locked — avoid programming",
    (0, 0, 1): "trailer: read AC bits Key A|B; write AC bits Key A; Key A read never",
    (0, 1, 0): "trailer: read AC bits Key A; write AC bits Key A; Key A/B per AN10787 trailer table",
    (0, 1, 1): "trailer: read AC bits Key A|B; write AC bits Key B if Key B readable",
    (1, 0, 0): "trailer: read AC bits Key A|B; write keys/ac bits Key B",
    (1, 0, 1): "trailer: read AC bits Key A|B; write Key B",
    (1, 1, 0): "trailer: read AC bits Key A|B; write Key B",
    (1, 1, 1): "trailer: read AC bits Key A|B; write Key B (depends on Key visibility bits)",
}


@dataclass(frozen=True)
class SectorAclSummary:
    sector: int
    transport_valid: bool
    blocks: list[dict[str, object]]


def describe_sector_acl(sector: int, trailer_16: bytes) -> SectorAclSummary:
    tv = validate_transport_coding(trailer_16)
    rows: list[dict[str, object]] = []
    for bi in range(4):
        c1, c2, c3 = extract_c1c2c3(bi, trailer_16)
        triplet = (c1, c2, c3)
        if bi < 3:
            desc = _DATA_ACL.get(triplet, "unknown / reserved triplet")
        else:
            desc = _TRAILER_ACL.get(triplet, "unknown / verify against AN10787 trailer table")
        rows.append(
            {
                "block_in_sector": bi,
                "c1c2c3": f"{c1}{c2}{c3}",
                "description": desc,
            }
        )
    return SectorAclSummary(sector=sector, transport_valid=tv, blocks=rows)
