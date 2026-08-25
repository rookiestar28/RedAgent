FROM docker.io/library/python@sha256:53739acebd52a300f19f52d93f2a6165f63300689bdf6f8af2bff0d63780e5e6

WORKDIR /app
COPY containers/r104-gateway/gateway_server.py /app/gateway_server.py
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["python", "-I", "/app/gateway_server.py"]
