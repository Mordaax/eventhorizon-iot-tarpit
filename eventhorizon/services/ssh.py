"""Fake SSH banner tarpit.

This is the classic "SSH tarpit" (cf. endlessh): we present an SSH-looking
identification banner and then drip an *endless* stream of random SSH version
banner lines very slowly. A real SSH client follows RFC 4253 and waits for the
server's identification string, so it sits there blocked, holding the
connection open and tying up the attacker / scanner.

We do NOT implement the SSH transport, key exchange, or auth. Nothing the
attacker sends is ever interpreted as a command. We just log their bytes and
keep dripping junk banner lines until a cap is hit.
"""

from __future__ import annotations

import random
import string

from .base import BaseTarpitService, ConnectionContext


def _fake_banner_line() -> str:
    # Looks like an SSH identification continuation line but is meaningless.
    junk = "".join(random.choices(string.ascii_letters + string.digits, k=16))
    return f"SSH-2.0-OpenSSH_{random.randint(5,9)}.{random.randint(0,9)} {junk}"


class SshTarpit(BaseTarpitService):
    name = "ssh"

    @property
    def port(self) -> int:
        return self.config.ssh_port

    async def handle(self, ctx: ConnectionContext) -> None:
        # Endlessh-style: drip banner lines slowly, forever (until caps reap us).
        # Opportunistically read (and log) whatever the client sends, but we
        # never block the drip on it.
        await ctx.drip_line(_fake_banner_line())
        lines_sent = 1

        while True:
            if ctx.time_left() <= 0:
                break
            if ctx.writer.is_closing():
                break
            # Non-fatal: peek for attacker bytes with the standard read helper.
            # read() already honours idle_timeout, so this paces the loop too.
            data = await ctx.read(limit=512)
            if data:
                cmd_ev = ctx.session.record_command(
                    "ssh_client_data:" + data.decode("latin-1", "replace")[:64]
                )
                ctx.logger.log_event(ctx.session, cmd_ev)
            await ctx.drip_line(_fake_banner_line())
            lines_sent += 1
            try:
                ctx.span.add_event("banner_drip", {"lines_sent": lines_sent})
            except Exception:
                pass
