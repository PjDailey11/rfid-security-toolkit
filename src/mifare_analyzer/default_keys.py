"""
Known/default MIFARE Classic keys commonly tested first on Proxmark3 / Flipper workflows.

Full keyspace is 48 bits per key — exhaustive brute force offline without nonce traces is
generally infeasible; dictionary attacks succeed because deployments reuse defaults.
"""

from __future__ import annotations

# Hex strings, 12 chars = 6 bytes. Order blends Proxmark `default_keys.dic` staples.
DEFAULT_KEYS_HEX: tuple[str, ...] = (
    "ffffffffffff",
    "a0a1a2a3a4a5",
    "d3f7d3f7d3f7",
    "000000000000",
    "b0b1b2b3b4b5",
    "c0c1c2c3c4c5",
    "aabbccddeeff",
    "4d3a99c351dd",
    "1a982c7e459a",
    "714c5c886e97",
    "587ee5f9350f",
    "a0478cc39091",
    "26940b21f5ee",
    "fc00018778f7",
    "00000ffe2488",
    "5c598c9c58b5",
    "e4d2770a89be",
    "434f4d444541",
    "444f43545246",
    "666666666666",
    "50617269746f",
    "776974687573",
    "8fe644038790",
    "505249564141",
    "484f52535447",
    "1322285230b8",
    "05d73cd2ac01",
    "2012053082ad",
    "bbac458cb714",
    "5f31f6fcd3a0",
    "951bc994933f",
    "992368042234",
    "6ec225fc23f8",
    "8ada03676205",
    "8fe758a8f039",
    "9de89e070277",
    "ef1232ab18a0",
    "f662248e7e89",
    "7ad30d8696f6",
    "fff087132cbd",
)


def hex_key_to_bytes(h: str) -> bytes:
    h = h.strip().replace(" ", "")
    if len(h) != 12:
        raise ValueError(f"key must be 6 bytes hex (12 chars), got {len(h)}")
    return bytes.fromhex(h)


def default_key_set_bytes() -> frozenset[bytes]:
    return frozenset(hex_key_to_bytes(k) for k in DEFAULT_KEYS_HEX)
