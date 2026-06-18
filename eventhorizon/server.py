"""Server orchestrator.

Wires the config, shared session logger, telemetry, and a global
connection-cap semaphore into all three tarpit services and runs them
concurrently under one asyncio event loop.

Run with::

    python -m eventhorizon

or programmatically via :func:`run`.
"""

from __future__ import annotations

import asyncio
import contextlib
import signal
import sys
from typing import Optional

from .config import TarpitConfig
from .services import HttpTarpit, SshTarpit, SsdpTarpit, TelnetTarpit
from .session import Metrics, SessionLogger
from .telemetry import Telemetry


class TarpitOrchestrator:
    def __init__(self, config: Optional[TarpitConfig] = None):
        self.config = config or TarpitConfig()
        self.metrics = Metrics()
        self.logger = SessionLogger(
            path=self.config.log_file,
            metrics=self.metrics,
            flush_every=self.config.log_flush_every,
        )
        self.telemetry = Telemetry.from_config(self.config)
        self._sem = asyncio.Semaphore(self.config.max_connections)
        self.services = [
            TelnetTarpit(self.config, self.logger, self.telemetry, self._sem),
            HttpTarpit(self.config, self.logger, self.telemetry, self._sem),
            SshTarpit(self.config, self.logger, self.telemetry, self._sem),
            SsdpTarpit(self.config, self.logger, self.telemetry, self._sem),
        ]
        self._servers: list[object] = []
        self._dashboard = None  # populated if dashboard_enabled

    async def start(self) -> None:
        for svc in self.services:
            try:
                server = await svc.start()
                self._servers.append(server)
            except OSError as exc:
                # A privileged/occupied port (e.g. SSDP 1900 may need a higher
                # port unprivileged) must not abort the whole tarpit.
                print(
                    f"WARNING: could not start {svc.name} on port {svc.port}: {exc}",
                    file=sys.stderr,
                    flush=True,
                )
        if self.config.dashboard_enabled:
            await self._start_dashboard()

    async def _start_dashboard(self) -> None:
        from .dashboard_server import start_dashboard

        try:
            self._dashboard = await start_dashboard(
                self.config, self.metrics, self.config.log_file
            )
        except Exception as exc:  # dashboard is optional; never abort the tarpit
            print(
                f"WARNING: dashboard failed to start: {exc}",
                file=sys.stderr,
                flush=True,
            )

    def describe(self) -> str:
        cfg = self.config
        lines = [
            "EventHorizon tarpit started",
            f"  host:            {cfg.host}",
            f"  telnet:          {cfg.host}:{cfg.telnet_port}",
            f"  http:            {cfg.host}:{cfg.http_port}",
            f"  ssh (banner):    {cfg.host}:{cfg.ssh_port}",
            f"  ssdp (udp):      {cfg.host}:{cfg.ssdp_port}",
            f"  drip_delay:      {cfg.drip_delay}s  chunk={cfg.drip_chunk}B",
            f"  adaptive:        {'on' if cfg.adaptive_enabled else 'off'} "
            f"(max x{cfg.adaptive_max_multiplier})",
            f"  telemetry:       {self.telemetry.backend} "
            f"(enabled={self.telemetry.enabled})",
            f"  dashboard:       "
            + (
                f"http://{cfg.host}:{cfg.dashboard_port}/  "
                "(live SSE + /metrics)"
                if cfg.dashboard_enabled
                else "off (set EH_DASHBOARD_ENABLED=true)"
            ),
            f"  log:             {cfg.log_file or 'stdout'}",
            f"  caps:            {cfg.max_session_seconds}s / "
            f"{cfg.max_session_bytes}B / {cfg.max_connections} conns",
        ]
        return "\n".join(lines)

    async def stop(self) -> None:
        for svc in self.services:
            with contextlib.suppress(Exception):
                await svc.stop()
        if self._dashboard is not None:
            with contextlib.suppress(Exception):
                await self._dashboard.stop()
        self.logger.close()

    async def serve_forever(self) -> None:
        await self.start()
        print(self.describe(), file=sys.stderr, flush=True)

        stop_event = asyncio.Event()
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            with contextlib.suppress(NotImplementedError):
                loop.add_signal_handler(sig, stop_event.set)
        try:
            await stop_event.wait()
        finally:
            await self.stop()


def run(config: Optional[TarpitConfig] = None) -> None:
    orch = TarpitOrchestrator(config)
    try:
        asyncio.run(orch.serve_forever())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    run()
