"""CLI for mfcdump analysis."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from mifare_analyzer import __version__
from mifare_analyzer.acl import describe_sector_acl
from mifare_analyzer.default_keys import DEFAULT_KEYS_HEX
from mifare_analyzer.dump_parser import sniff_load
from mifare_analyzer.key_audit import audit_sector_keys, brute_force_note, merged_defaults
from mifare_analyzer.manufacturer import decode_block0_manufacturer


def cmd_analyze(args: argparse.Namespace) -> int:
    path = Path(args.dump)
    dump = sniff_load(path)

    defaults, dict_notes = merged_defaults(args.extra_keys)

    sector_reports: list[dict[str, object]] = []
    for sector in range(16):
        trailer = dump.sector_trailer(sector)
        acl = describe_sector_acl(sector, trailer)
        keys = audit_sector_keys(sector, trailer, defaults)
        sector_reports.append(
            {
                "sector": sector,
                "acl_transport_valid": acl.transport_valid,
                "acl_blocks": acl.blocks,
                "keys": keys,
                "trailer_hex": trailer.hex().upper(),
            }
        )

    block0 = dump.blocks[0]
    manu = decode_block0_manufacturer(block0)

    out: dict[str, object] = {
        "dump_file": str(path),
        "format": "MIFARE Classic 1K (64 blocks)",
        "block0": manu,
        "sectors": sector_reports,
        "dictionary": {
            "builtin_default_key_count": len(DEFAULT_KEYS_HEX),
            "notes": dict_notes + [brute_force_note()],
        },
        "risk_summary": (
            "Default keys in trailers imply trivial cloning/rewriting. "
            "Even custom keys do not stop relay against naive readers — migrate credential tech."
        ),
    }

    print(json.dumps(out, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="mifare-analyze", description="Offline MF Classic 1K dump analyzer")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument("dump", help="Path to 1024-byte binary dump or Proxmark .eml")
    p.add_argument(
        "--extra-keys",
        help="Optional text file with additional 12-hex-char keys, one per line (# comments ok)",
    )
    p.set_defaults(func=cmd_analyze)
    return p


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except ValueError as e:
        print(str(e), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
