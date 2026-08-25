"""Closed OPA Data API adapter for R099."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
import json
from typing import Any, Callable

from redagent_platform.policy_service.contracts import (
    PolicyDecision,
    PolicyDecisionInput,
    PolicyObligation,
    canonical_policy_input,
    policy_input_hash,
)


_MAX_RESPONSE_BYTES = 65_536
_DECISION_FIELDS = frozenset({
    "allowed", "reason_code", "bundle_revision", "input_hash", "obligations", "issued_at", "valid_until",
})


class PolicyProviderError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class PolicyProviderReadiness:
    ready: bool
    active_revision: str
    bundle_plugin_state: str


class OpaPolicyDecisionProvider:
    def __init__(self, client: Any, *, endpoint: str, token_source: Callable[[], str]) -> None:
        normalized = endpoint.rstrip("/")
        if not normalized.startswith(("https://", "http://127.0.0.1:", "http://localhost:")):
            raise ValueError("opa_endpoint_invalid")
        if not callable(token_source):
            raise ValueError("opa_token_source_invalid")
        self.client = client
        self.endpoint = normalized
        self.token_source = token_source

    async def assess_readiness(self, *, required_revision: str) -> PolicyProviderReadiness:
        await self._request("GET", "/health?bundles&plugins", expected=(200,))
        payload = await self._request("GET", "/v1/status", expected=(200,))
        status = payload.get("result")
        if not isinstance(status, dict):
            raise PolicyProviderError("opa_status_shape_invalid")
        bundles = status.get("bundles")
        plugins = status.get("plugins")
        bundle = bundles.get("redagent") if isinstance(bundles, dict) else None
        plugin = plugins.get("bundle") if isinstance(plugins, dict) else None
        active = bundle.get("active_revision") if isinstance(bundle, dict) else None
        state = plugin.get("state") if isinstance(plugin, dict) else None
        if active != required_revision:
            raise PolicyProviderError("opa_required_revision_not_active")
        if state != "OK":
            raise PolicyProviderError("opa_bundle_plugin_not_ready")
        return PolicyProviderReadiness(True, active, state)

    async def decide(
        self,
        request: PolicyDecisionInput,
        *,
        required_revision: str,
        now: datetime,
    ) -> PolicyDecision:
        policy_input = json.loads(canonical_policy_input(request))
        policy_input.update({
            "input_hash": policy_input_hash(request),
            "required_revision": required_revision,
            "decision_valid_until": (request.requested_at + timedelta(seconds=30)).isoformat(),
        })
        payload = await self._request(
            "POST", "/v1/data/redagent/decision", expected=(200,),
            json_body={"input": policy_input},
            correlation_id=request.correlation_id,
        )
        decision_id = payload.get("decision_id")
        result = payload.get("result")
        if not isinstance(decision_id, str) or not isinstance(result, dict) or set(result) != _DECISION_FIELDS:
            raise PolicyProviderError("opa_decision_undefined_or_invalid")
        obligations = result.get("obligations")
        if not isinstance(obligations, list) or not all(isinstance(value, str) for value in obligations):
            raise PolicyProviderError("opa_decision_undefined_or_invalid")
        try:
            decision = PolicyDecision(
                decision_id=decision_id,
                bundle_revision=result["bundle_revision"],
                input_hash=result["input_hash"],
                allowed=result["allowed"],
                reason_code=result["reason_code"],
                obligations=tuple(PolicyObligation(value) for value in obligations),
                issued_at=_datetime(result["issued_at"]),
                valid_until=_datetime(result["valid_until"]),
            )
            decision.assert_current(request, required_revision=required_revision, now=now)
        except (KeyError, TypeError, ValueError) as exc:
            raise PolicyProviderError("opa_decision_undefined_or_invalid") from exc
        return decision

    async def _request(
        self,
        method: str,
        path: str,
        *,
        expected: tuple[int, ...],
        json_body: dict[str, object] | None = None,
        correlation_id: str | None = None,
    ) -> dict[str, object]:
        token = self.token_source()
        if not isinstance(token, str) or not token or len(token) > 4096:
            raise PolicyProviderError("opa_token_source_invalid")
        headers = {"Accept": "application/json", "Authorization": f"Bearer {token}"}
        if correlation_id:
            headers["X-Request-ID"] = correlation_id
        try:
            response = await self.client.request(
                method, f"{self.endpoint}{path}", headers=headers, timeout=2.0,
                **({"json": json_body} if json_body is not None else {}),
            )
        except Exception as exc:
            raise PolicyProviderError("opa_transport_unavailable") from exc
        status = getattr(response, "status_code", 0)
        content = getattr(response, "content", b"")
        if not isinstance(content, bytes) or len(content) > _MAX_RESPONSE_BYTES:
            raise PolicyProviderError("opa_response_size_invalid")
        if status not in expected:
            raise PolicyProviderError(f"opa_http_status:{status}")
        content_type = str(getattr(response, "headers", {}).get("content-type", "")).split(";", 1)[0].lower()
        if content_type != "application/json":
            raise PolicyProviderError("opa_response_content_type_invalid")
        try:
            payload = response.json()
        except Exception as exc:
            raise PolicyProviderError("opa_response_json_invalid") from exc
        if not isinstance(payload, dict):
            raise PolicyProviderError("opa_response_shape_invalid")
        return payload


def _datetime(value: object) -> datetime:
    if not isinstance(value, str):
        raise ValueError("opa_decision_datetime_invalid")
    return datetime.fromisoformat(value.replace("Z", "+00:00"))
