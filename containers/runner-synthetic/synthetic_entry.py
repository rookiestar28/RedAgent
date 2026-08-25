"""Benign deterministic R100 container conformance entrypoint."""

import json
import os
import pathlib


work = pathlib.Path("/work")
result = {"result": "synthetic-ok", "uid": os.getuid(), "workdir": "writable"}
pathlib.Path("/work/result.json").write_text(json.dumps(result, sort_keys=True), encoding="utf-8")
print(json.dumps(result, sort_keys=True, separators=(",", ":")))
