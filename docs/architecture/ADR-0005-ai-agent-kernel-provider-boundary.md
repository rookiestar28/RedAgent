# ADR-0005: AI Agent Kernel and Provider Boundary

Status: Accepted as compat_113 implementation baseline
Date: 2026-07-12
Architecture contract: compat_113

## Context

RedAgent already owns deterministic authorization, exact approvals, tenant identity, durable workflow, short-lived credentials, certified compat_100-compat_112 capability manifests, isolated runners, immutable evidence, cancellation, cleanup, and audit. compat_113 must add model assistance without making a probabilistic model or third-party agent framework authoritative for any of those controls.

Current official sources establish that OpenAI's Agents SDK uses Responses by default but recommends using Responses directly when an application needs to own its orchestration loop. The SDK and PydanticAI offer useful provider, schema, approval, budget, memory, and trace patterns, but also expose broader tools, sessions, multi-agent flow, and telemetry defaults than compat_113 may safely promote.

Research record: `docs/resources/260712-compat_113-ai-agent-kernel-official-project-research.md`.

## Options Compared

| Option | Strengths | Primary risks for RedAgent | Decision |
| --- | --- | --- | --- |
| OpenAI Agents SDK as the kernel | Mature Responses integration, tools, guardrails, approvals, sessions, tracing | Framework runner/session/trace semantics compete with RedAgent workflow, approval, memory, and evidence; parallel/sensitive defaults require extensive containment; provider coupling at the domain boundary | Reject as kernel; retain as reference or future adapter |
| PydanticAI as the kernel | Strong typing, model independence, fake models, deferred tools, durable execution, OTel | Broad plugin/provider/MCP surface; `approve_all` and argument overrides conflict with exact approval; framework durable state duplicates compat_096 | Reject as kernel; retain concepts and possible future adapter |
| LangGraph or Microsoft framework as kernel | Durable state/interrupts, broad integrations, multi-agent patterns | Duplicates Temporal and existing control plane; large dynamic surface; unnecessary multi-agent/runtime authority | Reject for compat_113 |
| Minimal RedAgent-owned kernel with thin provider adapters | Small trust boundary, deterministic fake, exact compatibility with compat_100-compat_112, stable internal state/evidence | Requires maintaining a narrow provider normalization layer | Accept |

## Decision

RedAgent owns stable `ModelGateway`, `AgentRun`, `ProjectedTool`, `Proposal`, `Approval`, `Budget`, `Memory`, and `TraceEnvelope` contracts. The initial adapters are:

1. A deterministic scripted fake provider used for all qualification and CI.
2. A thin OpenAI Responses adapter whose request/response translation is isolated and optional. No production API call or credential is required for compat_113 acceptance.

The Agents SDK and PydanticAI do not enter the authorization, credential, runner, policy, memory, trace, evidence, or durable-workflow trust root.

## Provider Boundary Requirements

- Provider requests contain minimized trusted instructions/context and only selected projected tools; raw evidence and credentials never enter the adapter.
- OpenAI function definitions use `strict: true`, closed objects with `additionalProperties: false`, and required fields with nullable optionals. Incompatible schemas are rejected before any request.
- `parallel_tool_calls` is false, `store` is false, background mode and Conversations are disabled, and hosted tools/MCP/shell/computer/file/web/code tools are absent.
- Model output is untrusted. A function call becomes a validated proposal draft; it never invokes a local function or runner.
- Provider errors map to a closed RedAgent taxonomy without preserving raw exception chains or sensitive payloads.
- Provider cancellation is best effort and additive. RedAgent cancel/revoke blocks new progression regardless of provider availability.
- Provider tracing/export is disabled. RedAgent produces a versioned minimized envelope and an optional pure OTLP translation after redaction.

## Capability Projection Requirements

- Projection consumes only certified compat_100 manifests and pins capability ID/revision/digest, adapter/version, source schema ID, network/credential classes, resource limits, evidence schemas, unsupported features, and artifact receipt.
- A model-facing tool may be read-only metadata or a proposal wrapper. It may reduce arguments, modes, limits, egress, credentials, or evidence, but cannot broaden any source field.
- Fully qualified name, strict input/output schema digest, description digest, approval tier, model budget, and projection revision are stable and reviewed.
- Generic shell, subprocess, HTTP/URL/browser, arbitrary target or scanner controls, payloads, credentials, policy mutation, approval issuance, evidence export, and direct runner dispatch are structurally unrepresentable.

## Approval and State Requirements

- Side effects require deterministic policy and an independent one-time approval bound to the complete canonical context: tenant, operator, campaign, proposal, tool/version/schema, arguments, target/ROE/policy, credential and egress classes, side effects, budgets, registry revision, and expiry.
- `approve all`, approval-time argument overrides, replay, mutation, cross-tenant use, expired approvals, and drift are denied.
- Regenerated trusted context, encrypted TTL/size-limited working memory, reviewed provenance-bearing long-term facts, immutable evidence, and untrusted model/tool output are separate stores and types.
- Runs execute one proposal at a time with finite turns, calls, elapsed time, token, cost, and result-byte budgets.

## Consequences

- RedAgent retains one authoritative control/evidence model and can change providers without migrating authorization semantics.
- The first release has less framework convenience and no multi-agent/MCP/hosted-tool capability.
- Live provider qualification, background mode, provider-managed state, provider trace export, and additional frameworks each require a later explicit plan, data-retention review, signed promotion, adversarial tests, and full gate.

## Sources

- OpenAI Agents SDK agent choice: https://openai.github.io/openai-agents-python/agents/
- OpenAI function calling and strict mode: https://developers.openai.com/api/docs/guides/function-calling
- OpenAI conversation retention: https://developers.openai.com/api/docs/guides/conversation-state
- OpenAI background retention/cancel: https://developers.openai.com/api/docs/guides/background
- PydanticAI deferred approval: https://pydantic.dev/docs/ai/tools-toolsets/deferred-tools/
- OWASP Agentic Top 10: https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/
- NIST AI 600-1: https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence
