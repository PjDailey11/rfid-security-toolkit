"""Load MIFARE Classic 1K dumps (.mfcdump/.bin, Proxmark .eml)."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


MFCLASSIC_1K_BYTES = 1024
MFCLASSIC_1K_BLOCKS = 64


@dataclass(frozen=True)
class ClassicDump:
    """Normalized MIFARE Classic 1K layout (64 × 16-byte blocks)."""

    blocks: tuple[bytes, ...]

    @staticmethod
    def from_bytes(data: bytes) -> ClassicDump:
        if len(data) != MFCLASSIC_1K_BYTES:
            raise ValueError(f"Classic 1K expects {MFCLASSIC_1K_BYTES} bytes, got {len(data)}")
        blocks = tuple(data[i : i + 16] for i in range(0, MFCLASSIC_1K_BYTES, 16))
        return ClassicDump(blocks=blocks)

    def sector_trailer(self, sector: int) -> bytes:
        if sector < 0 or sector > 15:
            raise ValueError("Classic 1K has sectors 0..15")
        idx = sector * 4 + 3
        return self.blocks[idx]


def load_binary(path: Path) -> ClassicDump:
    data = path.read_bytes()
    return ClassicDump.from_bytes(data)


def load_eml(path: Path) -> ClassicDump:
    """
    Proxmark-style `.eml`: one line per block, 32 hex chars (16 bytes), ASCII order.

    Blank lines and `#` comments are skipped.
    """
    lines: list[str] = []
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        lines.append(line)

    if len(lines) != MFCLASSIC_1K_BLOCKS:
        raise ValueError(f".eml expected {MFCLASSIC_1K_BLOCKS} block lines, got {len(lines)}")

    blob = bytearray()
    for ln in lines:
        if len(ln) != 32:
            raise ValueError(f"each .eml line must be 32 hex chars, got {len(ln)}")
        blob.extend(bytes.fromhex(ln))

    return ClassicDump.from_bytes(bytes(blob))


def sniff_load(path: Path) -> ClassicDump:
    suf = path.suffix.lower()
    if suf in {".eml"}:
        return load_eml(path)
    return load_binary(path)
