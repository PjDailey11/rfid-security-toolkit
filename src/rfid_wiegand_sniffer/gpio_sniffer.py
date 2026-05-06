"""
GPIO-backed Wiegand pulse capture for Raspberry Pi.

Requires optional dependency: RPi.GPIO (install extras: pip install -e ".[pi]").
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Pulse:
    line: str  # "D0" or "D1"
    t_us: int


@dataclass
class SnifferState:
    pulses: list[Pulse] = field(default_factory=list)
    last_reset_us: int = 0

    # Heuristic inter-frame gap (default 25 ms): configurable
    frame_gap_us: int = 25_000


def _now_us() -> int:
    return int(time.perf_counter() * 1_000_000)


class WiegandGpioSniffer:
    """
    Falling-edge triggered capture on DATA0/DATA1.

    Wiegand readers normally idle high and pulse low ~40–100 µs; timing varies by vendor.
    This sniffer records which line fired and the timestamp (microseconds, monotonic clock).
    """

    def __init__(
        self,
        pin_d0: int,
        pin_d1: int,
        *,
        frame_gap_us: int = 25_000,
        gpio_module: Any | None = None,
    ) -> None:
        self.pin_d0 = pin_d0
        self.pin_d1 = pin_d1
        self._gpio = gpio_module
        self.state = SnifferState(frame_gap_us=frame_gap_us)

    def _ensure_gpio(self) -> Any:
        if self._gpio is None:
            try:
                import RPi.GPIO as GPIO  # type: ignore[import-untyped]

                self._gpio = GPIO
            except ImportError as e:
                raise RuntimeError(
                    "RPi.GPIO is not installed. On Raspberry Pi run: pip install 'rfid-security-toolkit[pi]'"
                ) from e
        return self._gpio

    def setup(self) -> None:
        GPIO = self._ensure_gpio()
        GPIO.setmode(GPIO.BCM)
        GPIO.setup(self.pin_d0, GPIO.IN, pull_up_down=GPIO.PUD_UP)
        GPIO.setup(self.pin_d1, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    def teardown(self) -> None:
        GPIO = self._ensure_gpio()
        GPIO.cleanup()

    def _record_edge(self, line: str) -> None:
        now = _now_us()
        if self.state.last_reset_us and (now - self.state.last_reset_us) > self.state.frame_gap_us:
            self.state.pulses.clear()
        self.state.pulses.append(Pulse(line=line, t_us=now))
        self.state.last_reset_us = now

    def attach_callbacks(self) -> None:
        GPIO = self._ensure_gpio()

        def cb_d0(_ch: int) -> None:
            if GPIO.input(self.pin_d0) == GPIO.LOW:
                self._record_edge("D0")

        def cb_d1(_ch: int) -> None:
            if GPIO.input(self.pin_d1) == GPIO.LOW:
                self._record_edge("D1")

        GPIO.add_event_detect(self.pin_d0, GPIO.FALLING, callback=cb_d0, bouncetime=1)
        GPIO.add_event_detect(self.pin_d1, GPIO.FALLING, callback=cb_d1, bouncetime=1)

    def drain_pulses(self) -> list[Pulse]:
        """Return a copy of accumulated pulses and clear buffer."""
        out = list(self.state.pulses)
        self.state.pulses.clear()
        return out


def validate_pulse_intervals(
    pulses: list[Pulse],
    *,
    min_sep_us: int = 200,
    max_sep_us: int = 50_000,
) -> tuple[bool, str]:
    """
    Basic sanity check on pulse spacing.

    Defaults are permissive to accommodate varied hardware; tighten for noisy buses.
    """
    if len(pulses) < 2:
        return True, "ok"
    for a, b in zip(pulses, pulses[1:], strict=False):
        dt = b.t_us - a.t_us
        if dt < min_sep_us:
            return False, f"pulses too close ({dt} us)"
        if dt > max_sep_us:
            return False, f"pulses too far apart ({dt} us)"
    return True, "ok"


def run_poll_loop(
    read_bit: Callable[[], tuple[str | None, int]],
    *,
    frame_gap_us: int = 25_000,
    stop_when: Callable[[list[Pulse]], bool] | None = None,
) -> list[Pulse]:
    """
    Generic polling loop for tests without GPIO.

    read_bit returns (None, _) when idle, or ("D0"|"D1", timestamp_us) when a pulse occurs.
    """
    pulses: list[Pulse] = []
    last_ts = 0
    while True:
        line, ts = read_bit()
        if line is None:
            if stop_when and stop_when(pulses):
                break
            time.sleep(0.0005)
            continue
        if last_ts and (ts - last_ts) > frame_gap_us:
            pulses.clear()
        pulses.append(Pulse(line=line, t_us=ts))
        last_ts = ts
        if stop_when and stop_when(pulses):
            break
    return pulses
