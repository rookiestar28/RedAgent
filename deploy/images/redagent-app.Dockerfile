# syntax=docker/dockerfile:1.7
FROM docker.io/library/node:22.14.0-bookworm-slim@sha256:1c18d9ab3af4585870b92e4dbc5cac5a0dc77dd13df1a5905cea89fc720eb05b AS console
WORKDIR /build
COPY package.json package-lock.json ./
COPY frontend ./frontend
RUN --mount=type=cache,target=/root/.npm,sharing=locked \
    npm ci --ignore-scripts --no-audit --no-fund && \
    npm run typecheck && \
    ./node_modules/.bin/vite build --config frontend/vite.config.ts

FROM docker.io/library/python:3.13.5-slim-bookworm@sha256:4c2cf9917bd1cbacc5e9b07320025bdb7cdf2df7b0ceaccb55e9dd7e30987419

ARG REDAGENT_SOURCE_REVISION=unknown
LABEL org.opencontainers.image.title="RedAgent control plane" \
      org.opencontainers.image.revision="${REDAGENT_SOURCE_REVISION}" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    REDAGENT_STATIC_DIRECTORY=/opt/redagent/frontend/dist

WORKDIR /opt/redagent
COPY requirements-control-plane.lock ./
RUN --mount=type=cache,target=/root/.cache/pip,sharing=locked \
    python -m pip install --require-hashes --no-deps -r requirements-control-plane.lock

COPY alembic.ini ./
COPY migrations ./migrations
COPY redagent_platform ./redagent_platform
COPY scripts ./scripts
COPY bundles ./bundles
COPY config ./config
COPY runtime-assets ./runtime-assets
COPY --from=console /build/frontend/dist ./frontend/dist

RUN groupadd --gid 10001 redagent && \
    useradd --uid 10001 --gid 10001 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin redagent && \
    chown -R 10001:10001 /opt/redagent

USER 10001:10001
EXPOSE 8443
ENTRYPOINT ["python", "scripts/redagent_control_plane_api.py"]
CMD ["--host", "0.0.0.0", "--port", "8443", "--private-cluster-bind", "--tls-cert-file", "/var/run/redagent/tls/tls.crt", "--tls-key-file", "/var/run/redagent/tls/tls.key"]
