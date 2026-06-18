"""EventHorizon - Bio-Inspired IoT Tarpit with OpenTelemetry.

A safe deception/tarpit honeypot that emulates fake vulnerable IoT-style
services, wastes attacker time with slow "drip" responses, and produces rich
observability via OpenTelemetry.

SAFETY: This package only *emulates* fake services and records attacker input.
It NEVER executes attacker-supplied commands and is not a relay/proxy.
"""

__version__ = "0.1.0"
