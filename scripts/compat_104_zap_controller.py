#!/usr/bin/env python3
"""Fixed in-container controller for the private compat_104 ZAP API."""

from __future__ import annotations

import json
from pathlib import Path
import sys
import time
from urllib.parse import urlencode
from urllib.request import Request, urlopen


API = "http://127.0.0.1:8090"
KEY_FILE = Path("/zap/wrk/zap-api-key")
PLAN_FILE = "/zap/wrk/plan.json"
STATE_FILE = Path("/zap/wrk/controller-state.json")
ALERTS_FILE = Path("/zap/wrk/alerts.json")
ALLOWED_ACTIONS = frozenset({"health", "addons", "run", "status", "cancel", "alerts"})


def api(component: str, kind: str, action: str, **parameters: object) -> dict[str, object]:
    allowed = {
        ("core", "view", "version"), ("automation", "action", "runPlan"),
        ("autoupdate", "view", "installedAddons"),
        ("automation", "view", "planProgress"), ("automation", "action", "stopPlan"),
        ("spider", "action", "stopAllScans"), ("clientSpider", "action", "stop"),
        ("ascan", "action", "stopAllScans"), ("pscan", "view", "recordsToScan"),
        ("core", "view", "alerts"),
    }
    if (component, kind, action) not in allowed:
        raise RuntimeError("zap_controller_api_operation_denied")
    key = KEY_FILE.read_text(encoding="utf-8").strip()
    query = urlencode({"apikey": key, **parameters})
    if kind == "action":
        request = Request(
            f"{API}/JSON/{component}/{kind}/{action}/", data=query.encode("ascii"), method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
    else:
        request = Request(f"{API}/JSON/{component}/{kind}/{action}/?{query}", method="GET")
    with urlopen(request, timeout=5) as response:
        body = response.read(2 * 1024 * 1024 + 1)
    if len(body) > 2 * 1024 * 1024:
        raise RuntimeError("zap_controller_response_too_large")
    value = json.loads(body)
    if not isinstance(value, dict):
        raise RuntimeError("zap_controller_response_invalid")
    return value


def health() -> dict[str, object]:
    return {"ok": True, "action": "health", "version": api("core", "view", "version").get("version")}


def addons() -> dict[str, object]:
    result = api("autoupdate", "view", "installedAddons")
    values = result.get("installedAddons", [])
    if not isinstance(values, list) or len(values) > 200 or any(not isinstance(item, dict) for item in values):
        raise RuntimeError("zap_controller_addon_inventory_invalid")
    inventory = sorted(
        ({"id": str(item.get("id", "")), "version": str(item.get("version", "")),
          "status": str(item.get("status", ""))} for item in values),
        key=lambda item: item["id"],
    )
    if any(not item["id"] or not item["version"] for item in inventory):
        raise RuntimeError("zap_controller_addon_inventory_invalid")
    Path("/zap/wrk/addons.json").write_text(
        json.dumps(inventory, sort_keys=True, separators=(",", ":")), encoding="utf-8",
    )
    return {"ok": True, "action": "addons", "count": len(inventory)}


def run() -> dict[str, object]:
    result = api("automation", "action", "runPlan", filePath=PLAN_FILE)
    plan_id = str(result.get("planId", ""))
    if not plan_id or len(plan_id) > 100:
        raise RuntimeError("zap_controller_plan_id_invalid")
    state = {"plan_id": plan_id, "started_at": time.time()}
    STATE_FILE.write_text(json.dumps(state, sort_keys=True), encoding="utf-8")
    return {"ok": True, "action": "run", "plan_id": plan_id}


def status() -> dict[str, object]:
    state = json.loads(STATE_FILE.read_text(encoding="utf-8"))
    plan_id = str(state["plan_id"])
    progress = api("automation", "view", "planProgress", planId=plan_id)
    passive = api("pscan", "view", "recordsToScan")
    return {
        "ok": True, "action": "status", "plan_id": plan_id,
        "progress": progress.get("planProgress", []), "passive_queue": passive.get("recordsToScan"),
    }


def cancel() -> dict[str, object]:
    state = json.loads(STATE_FILE.read_text(encoding="utf-8"))
    plan_id = str(state["plan_id"])
    operations = (
        ("automation", "stopPlan", {"planId": plan_id}),
        ("spider", "stopAllScans", {}),
        ("clientSpider", "stop", {}),
        ("ascan", "stopAllScans", {}),
    )
    acknowledged = 0
    for component, action, parameters in operations:
        try:
            api(component, "action", action, **parameters)
            acknowledged += 1
        except (OSError, ValueError, RuntimeError):
            continue
    if acknowledged == 0:
        raise RuntimeError("zap_controller_native_stop_unacknowledged")
    return {"ok": True, "action": "cancel", "plan_id": plan_id, "native_stop_attempted": True,
            "operation_count": len(operations), "acknowledged_count": acknowledged}


def alerts() -> dict[str, object]:
    result = api("core", "view", "alerts", baseurl="http://redagent-r104-gateway:8080", start=0, count=1000)
    values = result.get("alerts", [])
    if not isinstance(values, list) or len(values) > 1000:
        raise RuntimeError("zap_controller_alerts_invalid")
    ALERTS_FILE.write_text(json.dumps(values, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    return {"ok": True, "action": "alerts", "count": len(values)}


def main() -> int:
    if len(sys.argv) != 2 or sys.argv[1] not in ALLOWED_ACTIONS:
        print(json.dumps({"ok": False, "error": "zap_controller_action_denied"}), file=sys.stderr)
        return 2
    try:
        result = {
            "health": health, "addons": addons, "run": run, "status": status,
            "cancel": cancel, "alerts": alerts,
        }[sys.argv[1]]()
        print(json.dumps(result, sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, RuntimeError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
