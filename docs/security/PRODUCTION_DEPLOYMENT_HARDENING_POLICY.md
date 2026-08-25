# Production Deployment Hardening Policy

Date: 2026-07-08
Status: compat_032 baseline

## Purpose

This policy defines the minimum private deployment topology for the RedAgent platform. The platform is dual-use, so production deployment must default to private access, least privilege, strong auditability, and fast emergency shutdown.

## Deployment Exposure

The default production exposure is private-only:

- No public internet ingress by default.
- Administrative access requires enterprise VPN or zero-trust access.
- Control plane, runners, and data stores are segmented into private network zones.
- Egress is default-deny.
- Runner-to-target egress requires an approved policy grant and target allowlist.

## TLS

- TLS is required for external and internal service traffic.
- Minimum TLS version is 1.3.
- Certificates require a defined rotation policy.
- Certificate ownership and rotation evidence must be retained with deployment records.

## Administrative Access

- Enterprise SSO is required.
- MFA is required at the identity provider.
- Administrative access requires VPN or zero-trust access.
- Break-glass users must be named, limited, monitored, and periodically reviewed.
- Administrative actions must emit audit events.

## Backup, Restore, and Retention

- Backups are required for database, evidence metadata, object storage metadata, and configuration state.
- Restore tests are required before production acceptance.
- Recovery point objective and recovery time objective must be documented.
- Data retention and log retention must be explicit.
- Log retention must be at least as long as data retention.
- Legal hold must be supported for investigations and regulated engagements.

## Runner Network Policy

- Runner egress is default-deny.
- Target allowlists are mandatory.
- DNS logging is required for runner network activity.
- Emergency shutdown must cut runner egress.
- Persistent endpoint agents remain out of scope until separately replanned and threat-modeled.

## Emergency Shutdown

The emergency shutdown procedure must:

- stop queue dispatch;
- revoke runner tokens;
- cut runner egress;
- preserve audit and evidence records;
- identify an emergency contact method; and
- be testable without contacting public targets.

## Least Privilege Boundaries

The following components require dedicated identities, scoped permissions, encryption, and rotation or lifecycle policies:

- secrets;
- evidence storage;
- database;
- queue; and
- object storage.

Shared administrative credentials are not acceptable for normal runtime operation.

## Rollback and Disaster Recovery

Rollback and disaster recovery must both be documented and tested before release acceptance. Evidence can be a local tabletop or dry-run record for the bootstrap phase, but production acceptance requires operational evidence from the deployment environment.

## Safety Boundary

compat_032 does not provision infrastructure or contact external services. It defines and validates local hardening requirements that compat_033 and compat_034 must consume.
