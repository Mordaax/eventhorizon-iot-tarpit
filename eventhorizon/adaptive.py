"""Bio-inspired adaptive drip latency.

Real, simple, documented mechanism. The metaphor is an **innate immune
response**: the more an attacker pokes at the tarpit, the "hotter" the response
gets, and the slower we drip bytes back to them. Persistent / aggressive
sessions are progressively throttled, which wastes more of the attacker's time
while still bounding our own resource use.

Inputs that raise the "threat level" (analogous to inflammation signals):
  * connection age (longer-lived sessions look more like a real attacker)
  * number of interactions (commands / chunks received)
  * volume of bytes received (scanners that blast payloads)

The output is a *latency multiplier* applied to the base drip delay, clamped to
``[1.0, max_multiplier]`` so the immune response can never run away and the
session is still eventually reaped by the hard caps in the server.

This is deliberately a transparent heuristic (a logistic-style saturation
curve). A full ML-driven behavioural model is documented as DEFERRED in
ARCHITECTURE.md.
"""

from __future__ import annotations

import math
from dataclasses import dataclass


@dataclass
class AdaptiveState:
    """Mutable per-session signal accumulator (the 'inflammation' state)."""

    interactions: int = 0
    bytes_seen: int = 0
    age_seconds: float = 0.0

    def observe(self, *, nbytes: int = 0, interaction: bool = False, age: float = 0.0) -> None:
        if nbytes:
            self.bytes_seen += nbytes
        if interaction:
            self.interactions += 1
        if age:
            self.age_seconds = age


class AdaptiveLatency:
    """Compute a drip-delay multiplier from session behaviour.

    The "threat score" combines three normalised signals, then a logistic
    function maps it onto ``[1, max_multiplier]``. Constants are chosen so a
    fresh session is ~1x and a busy, long-lived session saturates near the cap.
    """

    def __init__(
        self,
        enabled: bool = True,
        max_multiplier: float = 8.0,
        # normalisation scales (how much of each signal == "1 unit of threat")
        interactions_scale: float = 8.0,
        bytes_scale: float = 4096.0,
        age_scale: float = 30.0,
        # logistic steepness / midpoint in threat-units
        steepness: float = 1.5,
        midpoint: float = 1.2,
    ):
        self.enabled = enabled
        self.max_multiplier = max(1.0, max_multiplier)
        self.interactions_scale = interactions_scale
        self.bytes_scale = bytes_scale
        self.age_scale = age_scale
        self.steepness = steepness
        self.midpoint = midpoint

    def threat_score(self, state: AdaptiveState) -> float:
        """Normalised, unbounded-ish threat score (~0 for fresh sessions)."""
        return (
            state.interactions / self.interactions_scale
            + state.bytes_seen / self.bytes_scale
            + state.age_seconds / self.age_scale
        )

    def multiplier(self, state: AdaptiveState) -> float:
        """Map session state to a drip-delay multiplier in [1, max_multiplier]."""
        if not self.enabled:
            return 1.0
        score = self.threat_score(state)
        # Logistic in (0,1); 0 at score=0-ish, ->1 as score grows.
        logistic = 1.0 / (1.0 + math.exp(-self.steepness * (score - self.midpoint)))
        # Rescale so a brand-new session is ~1x, saturating toward max_multiplier.
        base = 1.0 / (1.0 + math.exp(-self.steepness * (0.0 - self.midpoint)))
        norm = (logistic - base) / (1.0 - base) if (1.0 - base) > 0 else logistic
        norm = max(0.0, min(1.0, norm))
        return 1.0 + norm * (self.max_multiplier - 1.0)

    def delay_for(self, base_delay: float, state: AdaptiveState) -> float:
        """Return the actual per-drip delay for the current session state."""
        return base_delay * self.multiplier(state)
