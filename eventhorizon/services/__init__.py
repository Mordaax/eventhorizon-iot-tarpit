"""Tarpit service implementations.

Each service is an asyncio server that emulates a fake vulnerable IoT-style
service and drips responses slowly to waste attacker time. None of them ever
execute attacker-supplied input.
"""

from .base import BaseTarpitService, ConnectionContext
from .telnet import TelnetTarpit
from .http import HttpTarpit
from .ssh import SshTarpit
from .ssdp import SsdpTarpit

__all__ = [
    "BaseTarpitService",
    "ConnectionContext",
    "TelnetTarpit",
    "HttpTarpit",
    "SshTarpit",
    "SsdpTarpit",
]
