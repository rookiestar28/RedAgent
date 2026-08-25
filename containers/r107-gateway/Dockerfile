FROM docker.io/library/python@sha256:399babc8b49529dabfd9c922f2b5eea81d611e4512e3ed250d75bd2e7683f4b0

WORKDIR /app
COPY containers/r107-gateway/gateway_server.py /app/gateway_server.py
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["python", "-I", "/app/gateway_server.py"]
