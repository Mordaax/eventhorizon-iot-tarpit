"""Fake IoT router/camera admin HTTP tarpit + fake UPnP/SOAP endpoint.

Serves a believable but entirely fake embedded-device web UI and a UPnP/SOAP
control endpoint (the kind targeted by CVE-laden router exploits). Responses are
dripped out byte-by-byte so an attacker's HTTP client blocks waiting for the
body, wasting their time.

It parses just enough of the request line / headers to log what the attacker
asked for. It NEVER acts on the request, executes SOAP actions, or follows any
attacker-controlled instruction.
"""

from __future__ import annotations

from .base import BaseTarpitService, ConnectionContext

_LOGIN_PAGE = (
    "<!DOCTYPE html><html><head><title>RT-AC68U Login</title></head>"
    "<body><h2>ASUS Wireless Router RT-AC68U</h2>"
    "<form method='post' action='/login.cgi'>"
    "User: <input name='username'><br>"
    "Pass: <input name='password' type='password'><br>"
    "<input type='submit' value='Sign in'></form>"
    "<!-- firmware 3.0.0.4.380 --></body></html>"
)

_SOAP_RESPONSE = (
    "<?xml version=\"1.0\"?>"
    "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\">"
    "<s:Body><u:GetExternalIPAddressResponse "
    "xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">"
    "<NewExternalIPAddress>0.0.0.0</NewExternalIPAddress>"
    "</u:GetExternalIPAddressResponse></s:Body></s:Envelope>"
)


def _http_response(status: str, body: str, content_type: str = "text/html") -> bytes:
    payload = body.encode("utf-8", "replace")
    headers = (
        f"HTTP/1.1 {status}\r\n"
        f"Server: lighttpd/1.4.39\r\n"
        f"Content-Type: {content_type}\r\n"
        f"Content-Length: {len(payload)}\r\n"
        "Connection: close\r\n"
        "\r\n"
    )
    return headers.encode("ascii", "replace") + payload


class HttpTarpit(BaseTarpitService):
    name = "http"

    @property
    def port(self) -> int:
        return self.config.http_port

    # Hard cap on how much request head we buffer. A client that never sends
    # the terminating blank line (slow-loris) is bounded here AND by the
    # per-session byte cap + wall-clock deadline in the base read() helper.
    _MAX_HEAD = 8192

    async def handle(self, ctx: ConnectionContext) -> None:
        # Read the request head (until blank line or cap). Each read() resets the
        # idle timer but the session deadline / byte cap still reap a dribbler.
        buf = bytearray()
        while b"\r\n\r\n" not in buf and len(buf) < self._MAX_HEAD:
            chunk = await ctx.read(limit=2048)
            if not chunk:
                break
            buf.extend(chunk)
            if len(buf) > self._MAX_HEAD:
                del buf[self._MAX_HEAD:]  # never let the buffer exceed the cap

        method, path = self._parse_request_line(bytes(buf))

        ev = ctx.session.record_command(f"{method} {path}")
        ctx.logger.log_event(ctx.session, ev)
        try:
            ctx.span.add_event("http_request", {"method": method, "path": path})
        except Exception:
            pass

        # Route to a believable-but-fake response. Everything is canned.
        lowered = path.lower()
        is_soap = (
            "soap" in lowered
            or "upnp" in lowered
            or (method == "POST" and "ctl" in lowered)
        )
        if is_soap:
            response = _http_response("200 OK", _SOAP_RESPONSE, "text/xml")
        elif lowered in ("/", "/index.html", "/login", "/login.cgi"):
            response = _http_response("200 OK", _LOGIN_PAGE)
        else:
            # Pretend the device is alive but the page needs auth — keeps them poking.
            response = _http_response(
                "401 Unauthorized",
                "<html><body>401 Authorization Required</body></html>",
            )

        # Drip the entire response (headers + body) out slowly.
        await ctx.drip(response)

    @staticmethod
    def _parse_request_line(buf: bytes) -> tuple[str, str]:
        """Best-effort, never-raising parse of method + path.

        Defends against empty input, missing CRLF, binary garbage, and absurdly
        long tokens. Returns safe defaults rather than throwing so a malformed
        probe is still logged and answered (and never executed).
        """
        method, path = "GET", "/"
        if not buf:
            return method, path
        try:
            head = buf.split(b"\r\n", 1)[0]
            # Also tolerate bare-LF request lines (some crude scanners).
            head = head.split(b"\n", 1)[0]
            decoded = head.decode("latin-1", "replace")
            parts = decoded.split()
            if len(parts) >= 1 and parts[0]:
                method = parts[0][:16]
            if len(parts) >= 2 and parts[1]:
                path = parts[1][:512]
        except Exception:
            pass
        return method, path
