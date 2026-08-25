# Passive Reconnaissance Module Policy

compat_013 defines a platform-backed passive reconnaissance boundary. The module creates bounded metadata request specifications and ingests observations supplied by future authorized runners. It does not execute network requests.

## Allowed Metadata Categories

The passive module may plan or ingest:

- DNS metadata
- TLS certificate metadata
- HTTP status and headers
- known small metadata files such as `robots.txt`, `.well-known/security.txt`, and `sitemap.xml`
- technology fingerprints derived from returned metadata
- OpenAPI metadata where an approved API spec or known metadata URL is in scope

## Forbidden Activity

The passive module must not:

- scan ports
- crawl arbitrary links
- enumerate directories
- enumerate subdomains
- fuzz parameters
- brute force credentials
- send exploit payloads
- follow redirects as a crawler
- perform authenticated testing
- validate vulnerabilities
- run scanners or external reference repository code

## Scope and Rate Gate

Every plan must be authorized by the compat_006 scope engine using `TestMode.PASSIVE_SCAN`. The request count must fit the approved interaction cap, and the generated plan records the minimum delay derived from the approved rate limit.

## Evidence and Findings

Observations must be sanitized before evidence creation. Secret-like headers, cookies, authorization values, and email-like body values are redacted. Evidence records are stored in the compat_008 evidence chain and informational compat_011 findings link back to evidence for reviewer triage.
