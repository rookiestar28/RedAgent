FROM docker.io/library/python@sha256:399babc8b49529dabfd9c922f2b5eea81d611e4512e3ed250d75bd2e7683f4b0

WORKDIR /app
COPY containers/r107-target/fixture_server.py /app/fixture_server.py
USER 65532:65532
EXPOSE 8080 8443
ENTRYPOINT ["python", "-I", "/app/fixture_server.py"]
