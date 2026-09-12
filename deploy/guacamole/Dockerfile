FROM guacamole/guacamole:1.6.0

LABEL org.opencontainers.image.version="1.6.0-clipboard-sync.7"

USER root
COPY clipboard-sync /tmp/tram-clipboard-sync
RUN mkdir -p /etc/guacamole/extensions \
    && cd /tmp/tram-clipboard-sync \
    && jar --create --file /etc/guacamole/extensions/tram-clipboard-sync.jar \
        guac-manifest.json tram-display-resize-v1.js tram-session-auth-v1.js tram-clipboard-sync-v7.js tram-clipboard-sync.css \
    && chmod 0444 /etc/guacamole/extensions/tram-clipboard-sync.jar \
    && rm -rf /tmp/tram-clipboard-sync
USER guacamole
