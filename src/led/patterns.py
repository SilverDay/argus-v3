"""LED patterns per state/verdict (spec §3.3 LED column; plan Phase 6 for non-verdict states).

``frame(pattern, t)`` is a pure function of time, so patterns are testable without
hardware or real time. Colours are (r, g, b) intensities 0.0–1.0.
"""
from __future__ import annotations

import math
from dataclasses import dataclass

Color = tuple[float, float, float]

OFF: Color = (0.0, 0.0, 0.0)
WHITE: Color = (1.0, 1.0, 1.0)
RED: Color = (1.0, 0.0, 0.0)
GREEN: Color = (0.0, 1.0, 0.0)
BLUE: Color = (0.0, 0.0, 1.0)
AMBER: Color = (1.0, 0.35, 0.0)


@dataclass(frozen=True)
class Pattern:
    name: str
    kind: str                  # solid | pulse | blink | alternate
    a: Color
    b: Color = OFF
    hz: float = 0.0


SOLID_WHITE = Pattern("white_solid", "solid", WHITE)

VERDICT_PATTERNS: dict[str, Pattern] = {
    "CLEAN": Pattern("green_solid", "solid", GREEN),
    "THREAT": Pattern("red_pulse", "pulse", RED, hz=4.0),
    "SUSPICIOUS": Pattern("amber_pulse", "pulse", AMBER, hz=2.0),
    "INCOMPLETE": Pattern("white_amber_alternate", "alternate", WHITE, AMBER, hz=1.0),
    "ERROR": Pattern("white_blink", "blink", WHITE, hz=2.0),
    "REJECTED": Pattern("white_amber_blink", "alternate", WHITE, AMBER, hz=2.0),
    "NOT_READY": SOLID_WHITE,
}

STATE_PATTERNS: dict[str, Pattern] = {
    "STARTING": SOLID_WHITE,
    "NOT_READY": SOLID_WHITE,
    "IDLE": Pattern("blue_pulse", "pulse", BLUE, hz=1.0),
    "VALIDATING": Pattern("amber_solid", "solid", AMBER),
    "MOUNTING": Pattern("amber_solid", "solid", AMBER),
    "SCANNING": Pattern("amber_solid", "solid", AMBER),
    "EVALUATING": Pattern("amber_solid", "solid", AMBER),
    "EJECTING": SOLID_WHITE,
    # Not in the spec table: "do not remove" must stand out from every verdict pattern.
    "EJECT_FAILED": Pattern("red_white_alternate", "alternate", RED, WHITE, hz=2.0),
    "REJECTED": VERDICT_PATTERNS["REJECTED"],
    "ERROR": VERDICT_PATTERNS["ERROR"],
}

UNAVAILABLE = SOLID_WHITE      # orchestrator unreachable == scanning unavailable


def pattern_for(state: str | None, verdict: str | None = None) -> Pattern:
    """RESULT and OPERATOR_HOLD show the verdict; other states have fixed patterns."""
    if state in ("RESULT", "OPERATOR_HOLD"):
        return VERDICT_PATTERNS.get(verdict or "", VERDICT_PATTERNS["ERROR"])
    if state is None:
        return UNAVAILABLE
    return STATE_PATTERNS.get(state, VERDICT_PATTERNS["ERROR"])


def _scale(c: Color, k: float) -> Color:
    return (c[0] * k, c[1] * k, c[2] * k)


def frame(p: Pattern, t: float) -> Color:
    if p.kind == "solid" or p.hz <= 0:
        return p.a
    phase = (t * p.hz) % 1.0
    if p.kind == "pulse":
        # Smooth breathing between 10 % and 100 %, peak at mid-period.
        return _scale(p.a, 0.1 + 0.9 * (0.5 - 0.5 * math.cos(2 * math.pi * phase)))
    if p.kind == "blink":
        return p.a if phase < 0.5 else OFF
    if p.kind == "alternate":
        return p.a if phase < 0.5 else p.b
    return p.a
