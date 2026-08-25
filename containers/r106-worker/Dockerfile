FROM docker.io/library/python@sha256:399babc8b49529dabfd9c922f2b5eea81d611e4512e3ed250d75bd2e7683f4b0

COPY requirements-r106-worker.lock /tmp/requirements-r106-worker.lock
RUN python -m pip install --no-cache-dir --only-binary=:all: -r /tmp/requirements-r106-worker.lock \
    && rm -f /tmp/requirements-r106-worker.lock \
    && mkdir -p /run/redagent /work \
    && chown 65532:65532 /work
WORKDIR /app
COPY containers/r106-worker/worker.py /app/worker.py
USER 65532:65532
ENTRYPOINT ["python", "-I", "/app/worker.py"]
