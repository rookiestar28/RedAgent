"""Benign long-running process-tree fixture for R101 containment proof."""

import json
import os
import signal
import subprocess
import sys
import time


ignore_term = os.environ.get("REDAGENT_SYNTHETIC_IGNORE_TERM") == "1"
child = subprocess.Popen([sys.executable, "-I", "-c", "import time; time.sleep(3600)"])


def _term(_signum, _frame):
    if ignore_term:
        return
    child.terminate()
    try:
        child.wait(timeout=1)
    except subprocess.TimeoutExpired:
        child.kill()
        child.wait(timeout=1)
    print(json.dumps({"state": "stopped", "cleanup": "completed"}, sort_keys=True), flush=True)
    raise SystemExit(0)


signal.signal(signal.SIGTERM, _term)
print(json.dumps({"state": "ready", "child": "started"}, sort_keys=True), flush=True)
while True:
    time.sleep(0.1)
