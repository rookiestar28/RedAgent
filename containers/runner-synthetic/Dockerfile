FROM docker.io/library/python@sha256:53739acebd52a300f19f52d93f2a6165f63300689bdf6f8af2bff0d63780e5e6

WORKDIR /app
COPY --chown=0:0 --chmod=0555 containers/runner-synthetic/synthetic_entry.py /app/synthetic_entry.py
USER 65532:65532
ENTRYPOINT ["python", "-I", "/app/synthetic_entry.py"]
