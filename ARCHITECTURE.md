# EventHorizon — Architecture

This document covers the component / data-flow design, the session and trace
model, the slow-drip mechanism, the bio-inspired adaptation, the safety design,
and a "Deferred" section for the fuller research directions.

---

## 1. Component & data-flow overview

```
                         ┌──────────────────────────────────────────────┐
                         │              TarpitOrchestrator               │
                         │   server.py — one asyncio event loop          │
                         │                                               │
   attacker / scanner    │   shared: TarpitConfig                        │
   ─────────────────►    │           SessionLogger (JSON-lines)          │
        TCP              │           Telemetry (OTel facade or no-op)    │
                         │           Semaphore(max_connections)          │
                         │                                               │
  :2323 ──► TelnetTarpit ┐                                               │
  :8080 ──► HttpTarpit   ├──►  BaseTarpitService._on_connect(reader,writer)
  :2222 ──► SshTarpit    ┘            │                                  │
                         │            ▼                                  │
                         │   1. acquire connection slot (semaphore)      │
                         │   2. build Session(src_ip, src_port, service) │
                         │   3. open OTel session span                   │
                         │   4. await handle(ctx)  ◄─ subclass protocol  │
                         │        • ctx.drip(...)   slow byte writes     │
                         │        • ctx.read(...)   capped/timed reads   │
                         │   5. finally: close, log session summary,     │
                         │      release slot                             │
                         └───────────────┬───────────────┬──────────────┘
                                         │               │
                  ┌──────────────────────▼──┐   ┌────────▼─────────────────┐
                  │ ./data/sessions.jsonl    │   │ OpenTelemetry (OTLP gRPC)│
                  │  • record_type=event     │   │  span: session.<service> │
                  │  • record_type=session   │   │  span-events per action  │
                  └───────────┬──────────────┘   └────────┬─────────────────┘
                              │                            │
                  ┌───────────▼──────────────┐   ┌─────────▼──────────┐
                  │ tools/dashboard.py        │   │ otel-collector     │
                  │  CLI table + static HTML  │   │   └─► Jaeger UI     │
                  │  per-session timeline     │   │   └─► debug stdout  │
                  └───────────────────────────┘   └────────────────────┘

   tools/replay_attacker.py  ── client only ──►  drives all three services
```

### Module responsibilities

| Module | Responsibility |
|--------|----------------|
| `config.py` | `TarpitConfig` dataclass; every field is env-overridable (`EH_*`) with safe defaults (localhost bind, bounded caps). |
| `session.py` | `Event`, `Session` (timeline + byte counters), and `SessionLogger` (thread/async-safe JSON-lines writer). Pure stdlib. |
| `telemetry.py` | `Telemetry` facade over OpenTelemetry. Optional import; degrades to a `_NoopSpan` shim if OTel is absent/disabled or setup fails. |
| `adaptive.py` | `AdaptiveState` (per-session signal accumulator) + `AdaptiveLatency` (maps state → drip-delay multiplier). Pure stdlib + `math`. |
| `services/base.py` | `BaseTarpitService` (asyncio server scaffolding, caps, span/session lifecycle) and `ConnectionContext` (the `drip`/`read` primitives a handler uses). |
| `services/{telnet,http,ssh}.py` | The three fake protocol conversations. Each is a thin `handle()` method. |
| `server.py` | `TarpitOrchestrator` wires shared singletons into all services and runs them concurrently. |
| `tools/replay_attacker.py` | Client-only traffic generator for end-to-end testing/demo. |
| `tools/dashboard.py` | Reads JSONL, renders CLI + static HTML session timelines. |

---

## 2. Session & trace model

### Session (the primary record)

One TCP connection = one `Session`, keyed by `(src_ip, src_port)` and tagged
with `service` and a short random `session_id`. It accumulates a **timeline of
`Event`s** and byte counters.

`Event.kind` values:

| kind | emitted when | key detail fields |
|------|--------------|-------------------|
| `open` | connection accepted | — |
| `recv` | attacker bytes read | `bytes`, `preview` (inert, latin-1, ≤200 chars) |
| `command` | a parsed/logged "command" (login, HTTP request line, SSH ident) | `command` (≤200 chars) |
| `drip` | a slow chunk written to the attacker | `bytes`, `delay` |
| `limit` | a hard cap tripped | `reason` (`max_session_bytes` / `max_session_seconds`) |
| `error` | unexpected handler exception | `error` (exception type name only) |
| `close` | connection torn down | — |

### JSON-lines log (`./data/sessions.jsonl`)

Two record shapes, distinguished by `record_type`:

- `event` — streamed **live** as things happen (good for tailing / shipping).
- `session` — the **final summary** written once on close, containing the full
  embedded event list plus duration and byte totals.

The dashboard prefers `session` summaries but can **reconstruct** sessions from
`event` records alone if a process was killed before writing the summary.

Example (abridged):

```json
{"record_type":"event","session_id":"a1b2c3","service":"telnet","kind":"command","detail":{"command":"login:root"}}
{"record_type":"session","session_id":"a1b2c3","service":"telnet","src_ip":"127.0.0.1","src_port":57848,"duration":3.0,"bytes_received":12,"bytes_sent":96,"events":[ ... ]}
```

### OpenTelemetry mapping

```
Trace
└── Span: session.telnet            (one per attacker session)
    ├── attr eventhorizon.service   = "telnet"
    ├── attr eventhorizon.src.ip    = "127.0.0.1"
    ├── attr eventhorizon.src.port  = 57848
    ├── attr eventhorizon.session.id = "a1b2c3"
    ├── span-event recv          {bytes}
    ├── span-event login_attempt {attempt}
    ├── span-event drip          {bytes, delay}
    └── span-event ...
```

The same lifecycle that writes JSONL events also emits span-events, so the trace
view and the log view tell the same story. Export path:

- `EH_OTEL_ENDPOINT` set → **OTLP gRPC** via a `BatchSpanProcessor`.
- endpoint empty → **ConsoleSpanExporter** via a `SimpleSpanProcessor`
  (synchronous, so it never tries to flush to stdout from a background thread at
  shutdown).
- OTel not installed / setup raises → **no-op shim**.

---

## 3. The slow-drip mechanism (the heart of the tarpit)

`ConnectionContext.drip(data)` writes the response **one small chunk at a time**
with a sleep between chunks:

```
for each chunk of size `drip_chunk` (default 1 byte) in `data`:
    if writer closing or session deadline passed: stop
    delay = adaptive.delay_for(base_drip_delay, adaptive_state)
    record a `drip` event (JSONL + span-event)
    writer.write(chunk); await writer.drain()
    await asyncio.sleep(delay)
```

Because a well-behaved client blocks waiting for the rest of the response (an
HTTP client waits for `Content-Length` bytes; an SSH client waits for the
server's identification string per RFC 4253), dripping at, say, 1 byte / 50 ms
holds the connection open and **wastes the attacker's time** while costing us
almost nothing (one suspended coroutine).

Per-service drip strategy:

- **Telnet** — drip the BusyBox banner and `login:` prompt, read a username,
  drip `Password: `, read a password, drip `Login incorrect`, loop forever.
  Every credential pair is logged; a shell is **never** granted.
- **HTTP** — read the request head, log method/path (and any exploit string),
  then drip a canned response (login page / SOAP reply / `401`) byte-by-byte so
  the client blocks on the body.
- **SSH** — *endlessh* style: drip an endless stream of random SSH version
  banner lines slowly; opportunistically log whatever the client sends.

Reads are bounded by `ConnectionContext.read()`: it enforces `idle_timeout`, the
per-session byte cap, and the session deadline, returning `b""` (treated as
EOF/stop) on timeout/cap/EOF.

---

## 4. Bio-inspired adaptive latency (the "immune response")

The metaphor is an **innate immune response**: the more an attacker pokes at the
tarpit, the "hotter" (more inflamed) the response, and the slower we drip.
Persistent / aggressive sessions are progressively throttled — wasting more
attacker time — while our own resource use stays bounded.

`AdaptiveState` accumulates three inflammation signals per session:

- `interactions` — number of reads/commands,
- `bytes_seen` — total bytes received,
- `age_seconds` — session age.

`AdaptiveLatency` combines them into a normalised **threat score**:

```
score = interactions/8  +  bytes_seen/4096  +  age_seconds/30
```

then maps it onto a latency multiplier in `[1, max_multiplier]` with a
**logistic (saturation) curve**, renormalised so a brand-new session is ~1×:

```
logistic(s) = 1 / (1 + e^(-steepness · (s - midpoint)))
multiplier  = 1 + norm(logistic(score)) · (max_multiplier - 1)
```

Properties (asserted by `tests/test_adaptive.py`):

- a fresh session is ≈ 1× (baseline),
- the multiplier is **monotonic** in persistence/aggression,
- it is **bounded** by `max_multiplier` (default 8×) — the response can never
  run away, and the hard caps still reap the session,
- disabling it pins the multiplier at exactly 1×.

The actual drip delay is `base_drip_delay × multiplier(state)`. This is a
deliberately **transparent heuristic**; the ML-driven version is *Deferred*.

---

## 5. Safety design

Safety is enforced structurally, not just by convention:

1. **No code path executes attacker input.** Handlers only *log*, *count*, and
   *string-match* bytes. There is no `eval`/`exec`/`subprocess`/shell anywhere
   in the package. Attacker bytes are stored as a bounded, inert `latin-1`
   preview.
2. **No real protocol semantics.** Telnet never authenticates or opens a shell;
   HTTP never acts on a request or performs a SOAP action; SSH implements no
   transport/kex/auth. All responses are canned constants.
3. **No outbound connections** from the emulated services — they are listeners
   only.
4. **Safe-by-default binding.** `EH_HOST=127.0.0.1`; compose publishes ports to
   `127.0.0.1` on the host. Exposing the honeypot is an explicit, documented
   opt-in.
5. **Host-protection caps** (about protecting *us*, not the attacker):
   - global concurrent-connection **semaphore** (`max_connections`) — refuse new
     connections at capacity instead of exhausting the host,
   - per-session **wall-clock cap** (`max_session_seconds`) — every session is
     eventually reaped,
   - per-session **byte cap** (`max_session_bytes`) — bounds memory/log growth
     from a payload blaster.
6. **Fault isolation.** A handler exception is caught per-connection, logged as
   an `error` event (type name only), and never takes down the server. OTel
   setup failure degrades to no-op rather than crashing.
7. **Least privilege in Docker.** The image runs as a non-root `tarpit` user.

---

## 6. Extensibility

Adding a new fake protocol is small and safe:

```python
from .base import BaseTarpitService, ConnectionContext

class FtpTarpit(BaseTarpitService):
    name = "ftp"

    @property
    def port(self) -> int:
        return self.config.ftp_port

    async def handle(self, ctx: ConnectionContext) -> None:
        await ctx.drip(b"220 ProFTPD Server ready.\r\n")
        while True:
            line = await ctx.read()
            if not line:
                break
            ctx.logger.log_event(ctx.session, ctx.session.record_command(...))
            await ctx.drip(b"530 Login incorrect.\r\n")
```

The base class supplies the drip primitive, caps, session, span, and logging for
free — so a new service only describes its (canned) conversation.

---

## 7. Deferred (research directions)

Documented but intentionally out of scope for this PoC:

- **Full bio-inspired model.** Move beyond the per-session logistic heuristic to
  a richer artificial-immune-system: a *global* threat memory keyed by source IP
  / ASN / `(IP, payload-fingerprint)`, with "antibodies" that recognise
  recurring attack signatures and react faster on re-encounter. Add
  cross-session reputation so an IP that reconnects frequently starts already
  "inflamed" (slower drip from byte 0), with exponential decay so reputations
  cool over time. (The current per-session state and IP-keying are the seam this
  plugs into.)
- **ML on attacker behaviour.** Cluster sessions by event-timeline features
  (command cadence, payload n-grams, inter-arrival timing) to fingerprint
  botnet families and distinguish scanners from interactive operators; an online
  model could then *learn* the optimal drip schedule that maximises dwell time
  per family. Sequence models (HMM / small RNN/transformer) over the event
  stream to predict the next attacker action and pre-empt it with the
  most-engaging canned response.
- **Richer protocol fidelity & content.** Telnet IAC negotiation, a fuller fake
  busybox command surface (canned `cat /proc/cpuinfo`, `wget` "downloads" that
  never fetch), more router/camera CVE-shaped endpoints, and a real (but inert)
  SSH KEXINIT to fool more clients — all still execution-free.
- **Detection & alerting integration.** Map captured payloads to CVE/known-bot
  signatures; emit OTel metrics (sessions/sec, dwell-time histograms, top creds)
  and wire alerts; export to MISP / a SIEM.
- **Live web dashboard.** An optional FastAPI app (behind the same JSONL source)
  with live tailing, search, and per-IP drill-down — kept optional so the
  stdlib core stays dependency-free.
- **Scale & resilience.** Multi-process / sharded event loops behind a single
  listener, backpressure tuning, and a durable event sink (e.g. Kafka) for
  high-volume honeynets.
```
