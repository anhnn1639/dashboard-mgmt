FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY control-plane/requirements.txt .
RUN apt-get update && apt-get install -y --no-install-recommends gosu \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir -r requirements.txt
COPY control-plane/app ./app
COPY control-plane/entrypoint.sh /entrypoint.sh
COPY agent /opt/tram-agent-assets
RUN useradd --system --uid 10001 --home /app ops \
    && chown -R ops:ops /app \
    && chown -R root:root /opt/tram-agent-assets \
    && find /opt/tram-agent-assets -type d -exec chmod 0555 {} + \
    && find /opt/tram-agent-assets -type f -exec chmod 0444 {} + \
    && chmod 0555 /opt/tram-agent-assets/linux/x86_64/tram-agent \
    && chmod 0755 /entrypoint.sh
EXPOSE 8000
ENTRYPOINT ["/entrypoint.sh"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*"]
