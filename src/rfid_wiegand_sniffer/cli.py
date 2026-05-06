"""CLI for Wiegand sniffer / decoder."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from rfid_wiegand_sniffer import __version__
from rfid_wiegand_sniffer.gpio_sniffer import (
    WiegandGpioSniffer,
    validate_pulse_intervals,
)
from rfid_wiegand_sniffer.security_notes import (
    REPLAY_RISK,
    brute_force_card_note,
)
from rfid_wiegand_sniffer.wiegand import bits_from_pulse_tokens, decode_wiegand_26


def _emit_json(obj: dict[str, object]) -> None:
    print(json.dumps(obj, indent=2))


def cmd_decode(args: argparse.Namespace) -> int:
    bits = [int(x) for x in args.bits.split(",") if x.strip() != ""]
    try:
        dec = decode_wiegand_26(bits)
    except ValueError as e:
        print(str(e), file=sys.stderr)
        return 2
    payload = {
        "facility_code": dec.facility_code,
        "card_number": dec.card_number,
        "parity_valid": dec.parity_valid,
        "bits": "".join(str(b) for b in dec.bits),
        "security": {
            "brute_force": brute_force_card_note(facility_known=True),
            "replay": REPLAY_RISK,
        },
    }
    _emit_json(payload)
    return 0


def cmd_mock_sniff(args: argparse.Namespace) -> int:
    """Simulated pulses for CI/demo without GPIO."""
    # Example facility 123 (0x07B) card 456 (0x1C8) — construct valid parity bits.
    from rfid_wiegand_sniffer.wiegand import _even_parity, _odd_parity

    facility = args.facility
    card = args.card
    fb = tuple((facility >> (11 - i)) & 1 for i in range(12))
    cb = tuple((card >> (11 - i)) & 1 for i in range(12))
    p_even = _even_parity(fb)
    p_odd = _odd_parity(cb)
    bits = (p_even,) + fb + cb + (p_odd,)
    assert len(bits) == 26
    dec = decode_wiegand_26(bits)
    payload = {
        "mode": "mock",
        "decoded": {
            "facility_code": dec.facility_code,
            "card_number": dec.card_number,
            "parity_valid": dec.parity_valid,
        },
        "security": {
            "brute_force": brute_force_card_note(facility_known=True),
            "replay": REPLAY_RISK,
        },
    }
    _emit_json(payload)
    return 0


def cmd_pi_sniff(args: argparse.Namespace) -> int:
    sniffer = WiegandGpioSniffer(args.pin_d0, args.pin_d1, frame_gap_us=args.frame_gap_us)
    sniffer.setup()
    sniffer.attach_callbacks()
    log_path = Path(args.log) if args.log else None
    print(
        json.dumps(
            {
                "status": "listening",
                "pins": {"d0": args.pin_d0, "d1": args.pin_d1},
                "hint": "Present badge; Ctrl+C to stop.",
            },
            indent=2,
        ),
        flush=True,
    )
    try:
        last_len = 0
        while True:
            time.sleep(args.poll / 1000.0)
            pulses = sniffer.state.pulses
            if len(pulses) == last_len:
                continue
            last_len = len(pulses)
            if len(pulses) != 26:
                continue
            ok, reason = validate_pulse_intervals(pulses)
            tokens = [(p.line, p.t_us) for p in pulses]
            bits = bits_from_pulse_tokens(tokens)
            dec = decode_wiegand_26(bits)
            record = {
                "ts_unix": time.time(),
                "facility_code": dec.facility_code,
                "card_number": dec.card_number,
                "parity_valid": dec.parity_valid,
                "pulse_timing_ok": ok,
                "pulse_timing_reason": reason,
                "security_notes": {
                    "brute_force": brute_force_card_note(facility_known=True),
                    "replay": REPLAY_RISK,
                },
            }
            line = json.dumps(record)
            print(line, flush=True)
            if log_path:
                log_path.parent.mkdir(parents=True, exist_ok=True)
                with log_path.open("a", encoding="utf-8") as f:
                    f.write(line + "\n")
            sniffer.state.pulses.clear()
            last_len = 0
    except KeyboardInterrupt:
        pass
    finally:
        sniffer.teardown()
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="wiegand-sniffer", description="Wiegand 26-bit lab sniffer/decoder")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("decode", help="Decode comma-separated 26 bits (MSB first)")
    d.add_argument("--bits", required=True, help="e.g. 1,0,0,...,0")
    d.set_defaults(func=cmd_decode)

    m = sub.add_parser("mock-sniff", help="Emit a mock credential decode for testing without GPIO")
    m.add_argument("--facility", type=int, default=123)
    m.add_argument("--card", type=int, default=456)
    m.set_defaults(func=cmd_mock_sniff)

    s = sub.add_parser("pi-sniff", help="Raspberry Pi GPIO sniff (requires RPi.GPIO)")
    s.add_argument("--pin-d0", type=int, required=True)
    s.add_argument("--pin-d1", type=int, required=True)
    s.add_argument("--poll", type=int, default=5, help="Poll interval in ms")
    s.add_argument("--frame-gap-us", type=int, dest="frame_gap_us", default=25_000)
    s.add_argument("--log", help="Append JSON lines log file")
    s.set_defaults(func=cmd_pi_sniff)

    return p


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
