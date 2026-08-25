# API Lab Module Policy

compat_014 imports OpenAPI metadata and creates API security lab case metadata for approved local lab targets. It does not execute API requests.

## Import Boundary

OpenAPI input must be supplied as an already parsed dictionary. The importer stores only:

- API title and version
- endpoint path and method
- operation ID
- auth requirements
- parameters
- request body content types
- response classes

Examples, callbacks, vendor extensions, scripts, and external references are inert metadata and must not be executed.

## Lab-Only Case Generation

API lab cases require an compat_012 lab target registration. Generated cases remain:

- `lab_only=True`
- `mode=LAB_ONLY_RUN`
- `execution_enabled=False`
- `active_enterprise_enabled=False`

Authorization-differential and object-property cases are not enterprise active tests. They remain lab-only until the active policy gate and item-specific adapters are implemented and accepted.

## Evidence Mapping

API lab results must map back to:

- case ID
- endpoint path
- HTTP method
- operation ID
- compat_008 evidence links

Results without evidence are invalid.
