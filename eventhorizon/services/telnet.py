"""Fake BusyBox-style Telnet tarpit.

Emulates the login prompt of a cheap IoT device (the kind Mirai-style botnets
brute-force over Telnet). It ALWAYS asks for more credentials and never
authenticates, dripping each prompt out slowly to keep the bot stuck.

It records every login/password the attacker tries (great threat-intel) but of
course never validates them and never runs anything.
"""

from __future__ import annotations

from .base import BaseTarpitService, ConnectionContext

_BANNER = (
    "\r\n"
    "(none) login: "
)


class TelnetTarpit(BaseTarpitService):
    name = "telnet"

    @property
    def port(self) -> int:
        return self.config.telnet_port

    async def handle(self, ctx: ConnectionContext) -> None:
        # Initial vendor-ish banner, dripped slowly.
        await ctx.drip(
            b"\r\nBusyBox v1.21.1 (2014-04-15) built-in shell (ash)\r\n"
        )
        await ctx.drip(_BANNER.encode())

        attempts = 0
        while True:
            username = await ctx.read()
            if not username:
                break
            login_ev = ctx.session.record_command(
                "login:" + username.decode("latin-1", "replace").strip()
            )
            ctx.logger.log_event(ctx.session, login_ev)
            # Drip the password prompt s-l-o-w-l-y.
            await ctx.drip(b"Password: ")
            password = await ctx.read()
            if not password:
                break
            attempts += 1
            ev = ctx.session.record_command(
                "pass:" + password.decode("latin-1", "replace").strip()
            )
            ctx.logger.log_event(ctx.session, ev)
            try:
                ctx.span.add_event("login_attempt", {"attempt": attempts})
            except Exception:
                pass

            # Always reject, with an escalating "try again" — never authenticate.
            await ctx.drip(b"\r\nLogin incorrect\r\n")
            await ctx.drip_line("")
            await ctx.drip(_BANNER.encode())
