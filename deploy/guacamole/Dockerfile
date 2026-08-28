FROM guacamole/guacamole:1.6.0

USER root
COPY clipboard-sync /tmp/tram-clipboard-sync
RUN mkdir -p /etc/guacamole/extensions \
    && cd /tmp/tram-clipboard-sync \
    && jar --create --file /etc/guacamole/extensions/tram-clipboard-sync.jar \
        guac-manifest.json tram-clipboard-sync.js \
    && chmod 0444 /etc/guacamole/extensions/tram-clipboard-sync.jar \
    && rm -rf /tmp/tram-clipboard-sync
USER guacamole