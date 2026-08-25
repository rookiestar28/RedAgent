FROM projectdiscovery/nuclei@sha256:9fd705284ac4b5f721fa1e23bf366f26e985cd4ec65927fe9a53cb3fcb0417a6

USER root

# CRITICAL: the upstream v3.11.1 image ships vulnerable fixed packages and no
# runtime user. Keep exact versions and fail the build when repositories drift.
# CRITICAL: remove apk.log because its wall-clock entry breaks locked OCI identity.
RUN apk add --no-cache --upgrade \
        bind-libs=9.20.26-r0 \
        bind-tools=9.20.26-r0 \
        gnutls=3.8.13-r0 \
        libcrypto3=3.5.7-r0 \
        libssl3=3.5.7-r0 \
        libuv=1.52.1-r0 \
        libxml2=2.13.9-r2 \
        nghttp2-libs=1.69.0-r0 \
        p11-kit=0.26.2-r0 \
        xz-libs=5.8.3-r0 \
    && addgroup -S -g 65532 redagent \
    && adduser -S -D -H -u 65532 -G redagent redagent \
    && install -d -o 65532 -g 65532 -m 0700 /home/redagent \
    && rm -f /var/log/apk.log

ENV HOME=/home/redagent

LABEL org.opencontainers.image.title="RedAgent R105 certified Nuclei runtime" \
      org.opencontainers.image.version="3.11.1-r105.2" \
      org.opencontainers.image.base.digest="sha256:9fd705284ac4b5f721fa1e23bf366f26e985cd4ec65927fe9a53cb3fcb0417a6" \
      io.redagent.owner="r105" \
      io.redagent.runtime="nuclei-controlled-runtime-v2"

USER 65532:65532
