# EventHorizon tarpit image.
# Slim, no build tools needed (pure Python). OTel deps are installed if present
# in requirements.txt; if the build is offline the app still runs via the
# no-op telemetry shim.
FROM python:3.13-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    EH_HOST=0.0.0.0 \
    EH_OTEL_ENABLED=true \
    EH_OTEL_ENDPOINT=http://otel-collector:4317 \
    EH_LOG_FILE=/data/sessions.jsonl

WORKDIR /app

# Install optional deps. `|| true` so an offline build still produces a working
# image (the tarpit degrades to the telemetry no-op shim).
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt || \
    echo "WARNING: pip install failed (offline?). Continuing with stdlib-only / OTel no-op shim."

COPY eventhorizon ./eventhorizon
COPY tools ./tools

RUN mkdir -p /data

# Telnet, HTTP, SSH-banner tarpits.
EXPOSE 2323 8080 2222

# Drop privileges: the honeypot should never run as root.
RUN useradd --create-home --uid 10001 tarpit && chown -R tarpit:tarpit /app /data
USER tarpit

CMD ["python", "-m", "eventhorizon"]
