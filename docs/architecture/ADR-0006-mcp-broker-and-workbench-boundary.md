# ADR-0006: Attested MCP Broker and Supervised Workbench Boundary

Status: Accepted as compat_114 implementation baseline
Date: 2026-07-12
Architecture contract: compat_114

## Context

compat_113 provides a provider-neutral kernel, monotonic certified tools, deterministic policy, exact independent approvals, budgets, cancellation, minimized memory/traces, and tenant-isolated persistence. compat_114 must add a useful campaign workbench and MCP interoperability without allowing an MCP server, provider, transport, OAuth token, local executable, or untrusted result to bypass those controls.

MCP 2025-11-25 defines JSON-RPC/capability/schema behavior, Streamable HTTP, OAuth authorization, stdio, resources/prompts/tools, list-change notifications, and tasks. Its security guidance explicitly covers prompt/tool poisoning, inventory change, token passthrough, SSRF, session hijacking, confused deputy behavior, and local-server compromise. The official TypeScript SDK main branch currently labels v2 beta for the future 2026-07-28 protocol, so it is not an appropriate trust-root dependency.

Research record: `docs/resources/260712-compat_114-mcp-workbench-official-project-research.md`.

## Options Compared

| Option | Strengths | Primary risks | Decision |
| --- | --- | --- | --- |
| Give the model/provider direct remote MCP access | low integration effort, provider handles discovery/calls | provider receives URL/token/data; approvals and tool drift may not match RedAgent; bypasses broker observability and transport policy | Reject |
| Adopt an external enterprise MCP gateway wholesale | broad federation, plugins, protocols, admin and observability | huge dynamic surface, duplicate policy/identity, passthrough/plugin/virtualization features exceed scope | Reject; retain static concepts |
| Execute local stdio servers for initial qualification | exercises real protocol path | installed executable, ambient credential, filesystem/network, supply-chain and cleanup risk before sandbox qualification | Defer |
| RedAgent-owned attested broker with deterministic in-process fixture | smallest boundary, exact compat_113 integration, drift freeze, zero external execution | requires maintaining narrow protocol/attestation contracts | Accept |

## Decision

RedAgent owns the MCP broker registration, transport attestation, inventory, disclosure, freeze, and lifecycle contracts. The initial implementation pins MCP `2025-11-25` and JSON Schema 2020-12, uses a deterministic in-process fixture, and performs zero remote connections and zero process launches. Remote Streamable HTTP and local stdio exist only as strict attestation types and denial/adversarial test subjects until separately promoted.

Every imported MCP item is administrator-pinned and either a minimized read resource/prompt or an compat_113 proposal-only tool. MCP descriptions, resources, prompts, tool results, and task results are untrusted content. Provider-native MCP and provider-native approval do not replace the broker or compat_113 approval.

## Broker Trust Requirements

- Registration binds tenant, administrator/reviewer separation, server identity, protocol, transport, endpoint or artifact digest, inventory digest, risk/data classes, allowed items, authorization profile, expiry, and promotion signature.
- Discovery is a candidate inventory operation. It never automatically changes model-visible inventory.
- Any list notification, tool/resource/prompt addition/removal, name/alias, schema, description, server identity, transport, protocol, authorization, or content digest drift freezes the server and invalidates dependent proposals/approvals.
- Fully qualified names include the administrator-owned server identity and pinned item identity. Confusable names and aliases are rejected.
- Broker results are size/type bounded, provenance labeled, sanitized, and checked against disclosure policy before reaching the kernel or UI.
- Tasks are authorization-context bound, finite, tenant isolated, rate limited, cancellable, and minimized in audit/trace storage.

## Remote HTTP Requirements

- HTTPS only; exact registered origin, host, port, path/resource, certificate/server identity, and allowed redirects.
- Streamable HTTP `Origin` validation and authentication; local HTTP binds only to loopback if ever qualified.
- OAuth metadata discovery is SSRF-controlled through scheme/host/port allowlists, private/link-local/loopback/cloud-metadata denial, redirect revalidation, DNS answer pinning/revalidation, and egress policy.
- PKCE S256 support is required; redirect URIs and state are exact; RFC 8707 resource/audience binding is mandatory.
- Inbound MCP tokens are validated for the MCP server and never passed downstream. Downstream access uses a separate least-privilege credential reference brokered by RedAgent.
- Rate, concurrency, time, bytes, disclosure, revocation, session, and task limits fail closed.

## Local Stdio Requirements

- Signed/provenance-qualified artifact and exact executable/argument digest; direct non-shell launch only.
- No user-supplied command, argument, working directory, environment, package reference, or auto-install.
- Dedicated sandbox identity, explicit filesystem roots, network default deny, CPU/memory/process/time/output limits, no privilege elevation, and deterministic kill/cleanup.
- Environment starts empty except explicitly injected non-secret configuration; least-privilege secrets use references and never ambient inheritance.
- Stderr/stdout and MCP content are untrusted, bounded, minimized, and never treated as evidence without the evidence service.

## Workbench Information Boundary

- The primary screen supports one decision: approve/deny one exact proposal or stop/revoke its progression.
- Trusted operator context, immutable authority, untrusted external/MCP/evidence content, AI suggestion, approval, execution result, and reviewer conclusion are separate types and visual lanes.
- Proposal views show server/tool/schema identity, sanitized arguments, target/scope, disclosure manifest, credential/egress/side effects, budgets, policy rationale, approval requirement, expiry, and campaign lineage.
- Editing any material field creates a successor proposal and invalidates the old approval. No `approve all` exists.
- Raw credentials, tokens, raw evidence, provider reasoning, arbitrary prompts, transport configuration, and direct dispatch controls are absent.

## Consequences

- compat_114 proves a useful supervised workflow and the complete governance boundary before accepting network or process risk.
- Initial interoperability is contract/fixture-level, not a claim that arbitrary MCP servers are supported.
- Remote and stdio adapters each require a separate authorization record, threat review, signed artifact/config promotion, deterministic lab qualification, and full repository gate.
- A stable MCP SDK may later implement a transport adapter, but cannot own registration, policy, approval, disclosure, persistence, audit, or execution semantics.

## Sources

- MCP 2025-11-25 overview: https://modelcontextprotocol.io/specification/2025-11-25/basic
- MCP authorization: https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization
- MCP transports: https://modelcontextprotocol.io/specification/2025-11-25/basic/transports
- MCP tools: https://modelcontextprotocol.io/specification/2025-11-25/server/tools
- MCP security: https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices
- OpenAI MCP guide: https://developers.openai.com/api/docs/guides/tools-connectors-mcp
- RFC 7636: https://www.rfc-editor.org/info/rfc7636
- RFC 8707: https://www.rfc-editor.org/info/rfc8707
- RFC 9700: https://www.rfc-editor.org/info/rfc9700
- Official TypeScript SDK: https://github.com/modelcontextprotocol/typescript-sdk
