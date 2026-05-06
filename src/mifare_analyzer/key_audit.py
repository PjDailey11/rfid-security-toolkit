"""Offline checks for weak/default keys present in sector trailers."""

from __future__ import annotations

from dataclasses import dataclass

from mifare_analyzer.default_keys import DEFAULT_KEYS_HEX, default_key_set_bytes, hex_key_to_bytes


@dataclass(frozen=True)
class TrailerKeys:
    sector: int
    key_a: bytes
    key_b: bytes


def parse_trailer_keys(trailer_16: bytes) -> tuple[bytes, bytes]:
    if len(trailer_16) != 16:
        raise ValueError("trailer must be 16 bytes")
    key_a = trailer_16[0:6]
    key_b = trailer_16[10:16]
    return key_a, key_b


def audit_sector_keys(sector: int, trailer_16: bytes, defaults: frozenset[bytes]) -> dict[str, object]:
    key_a, key_b = parse_trailer_keys(trailer_16)

    def classify(k: bytes) -> dict[str, object]:
        weak = k in defaults
        return {
            "hex": k.hex().upper(),
            "in_default_dictionary": weak,
        }

    return {
        "sector": sector,
        "key_a": classify(key_a),
        "key_b": classify(key_b),
    }


def brute_force_note() -> str:
    return (
        "MF Classic keys are 48-bit secrets per sector. Offline exhaustive search against "
        "ciphertext-only dumps is not practically tractable without nonce traces (Proxmark "
        "`darkside`, nested auth, etc.). This tool matches plaintext trailer keys against a "
        "default-key dictionary — the dominant practical weakness in legacy deployments."
    )


def load_extra_dictionary(path: str | None) -> frozenset[bytes]:
    if not path:
        return frozenset()
    keys: set[bytes] = set()
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            keys.add(hex_key_to_bytes(line.split(";")[0].strip()))
    return frozenset(keys)


def merged_defaults(extra_path: str | None) -> tuple[frozenset[bytes], list[str]]:
    merged = set(default_key_set_bytes())
    notes: list[str] = []
    if extra_path:
        extra = load_extra_dictionary(extra_path)
        merged |= extra
        notes.append(f"Merged {len(extra)} keys from {extra_path}")
    notes.append(f"Total dictionary size: {len(merged)} keys")
    return frozenset(merged), notes
