FROM ghcr.io/zaproxy/zaproxy@sha256:627781353231d056d5a6305ec1f2092f54735cc654915f533d2e8d5d9d41bcb2

USER root

# CRITICAL: keep the browser exact-pinned; Client Spider requires a real
# extension-capable browser and runtime package drift invalidates certification.
# CRITICAL: apk.log and generated fontconfig caches embed build-local state that
# breaks locked OCI identity; Chromium regenerates caches in its runtime home.
RUN apk add --no-cache chromium=149.0.7827.53-r0 \
    && rm -f /var/log/apk.log \
    && rm -rf /var/cache/fontconfig/*

LABEL org.opencontainers.image.title="RedAgent R104 certified ZAP runtime" \
      org.opencontainers.image.version="2.17.0-r104.2" \
      org.opencontainers.image.base.digest="sha256:627781353231d056d5a6305ec1f2092f54735cc654915f533d2e8d5d9d41bcb2" \
      io.redagent.owner="r104" \
      io.redagent.runtime="zap-controlled-runtime-v2"

USER zap
