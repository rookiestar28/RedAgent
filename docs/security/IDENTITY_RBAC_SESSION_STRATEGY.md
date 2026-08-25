# Identity, RBAC, and Session Strategy

Date: 2026-07-08
Status: compat_005 baseline

## Purpose

This document defines the baseline identity, RBAC, tenant-boundary, session-security, CSRF, password/SSO, and audit requirements for the RedAgent platform.

compat_005 implements only the policy core and strategy. It does not implement a login UI, session middleware, SSO connector, user database, or production identity provider integration.

## Roles

The platform baseline roles are:

- administrator
- security lead
- operator
- reviewer
- read-only auditor
- service runner

## Least-Privilege Intent

- Administrator: manage platform administration, users, roles, and organization-wide settings.
- Security lead: manage engagements, targets, authorizations, test definitions, and approval workflows.
- Operator: create and operate approved jobs within scope, but not approve their own broad policy gates.
- Reviewer: review findings, evidence links, retest state, and report readiness.
- Read-only auditor: read approved records and audit context without modification.
- Service runner: perform constrained runner callbacks only; no human UI privileges.

## Tenant Boundary

Every protected resource must have an organization boundary. Authorization must deny access when the subject organization does not match the resource organization.

Tenant boundary checks apply to:

- engagement
- target
- job
- finding
- report
- evidence
- audit event
- policy decision
- authorization
- test definition
- runner
- user and role administration

## Session Security Requirements

Future web/session implementation must include:

- authenticated actor identity before sensitive actions
- secure cookies in production
- HttpOnly session cookies
- SameSite policy
- session expiration
- session rotation after login
- logout invalidation
- audit event for login
- audit event for logout
- audit event for failed login
- audit event for privilege or role changes

## CSRF Requirements

CSRF protection is required for state-changing browser requests. API routes that use bearer tokens or non-cookie authentication may use an equivalent anti-forgery strategy, but the strategy must be documented in the item plan.

State-changing actions include:

- creating or updating engagements
- changing targets
- changing authorizations
- queueing, cancelling, or approving jobs
- creating, changing, exporting, or publishing evidence, findings, or reports
- changing users, roles, credentials, or runner registration

## Password and SSO Strategy

The initial private deployment should prefer enterprise SSO with OIDC or SAML and MFA enforced by the identity provider.

If local passwords are ever added, the implementation must include:

- strong password hashing with a modern password hashing algorithm
- no plaintext password storage
- password reset token expiration
- brute-force and credential-stuffing protection
- audit events for reset and failed login flows
- explicit review before production use

## Audit Requirements

Identity and authorization audit events must record:

- actor identity or service runner identity
- organization
- action
- subject type and ID
- policy decision outcome
- denial reason when denied
- timestamp from the future audit layer
- redaction class for any included metadata

Audit events must not contain passwords, tokens, cookies, private keys, or raw credential material.

## Fail-Closed Rule

The platform must deny access when any of these are missing or invalid:

- authenticated subject
- organization ID
- subject role
- resource organization ID
- resource type
- requested action
- explicit role permission
