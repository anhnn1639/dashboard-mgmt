FROM python:3.12-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PLAYWRIGHT_BROWSERS_PATH=/opt/browsers
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && playwright install --with-deps chromium \
    && apt-get update && apt-get install -y --no-install-recommends libnss3-tools fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 10002 --create-home worker
COPY browser_worker.py restricted_proxy.py auto_login.py entrypoint.py ./
USER 10002:10002
ENV HOME=/home/worker
EXPOSE 8081
ENTRYPOINT ["python", "/app/entrypoint.py"]
