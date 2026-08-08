# PolicyForge

[![CI](https://github.com/guneycangunay/PolicyForge/actions/workflows/ci.yml/badge.svg)](https://github.com/guneycangunay/PolicyForge/actions/workflows/ci.yml)
[![CodeQL](https://github.com/guneycangunay/PolicyForge/actions/workflows/codeql.yml/badge.svg)](https://github.com/guneycangunay/PolicyForge/actions/workflows/codeql.yml)
[![Python 3.12](https://img.shields.io/badge/Python-3.12%2B-3776AB.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

PolicyForge is a multi-tenant authorization engine that combines RBAC and ABAC without executing user-provided code. It defaults to deny, gives explicit denies precedence, isolates tenant decisions, versions policy bundles, caches safely, and records every decision in an HMAC-authenticated hash chain.

The example policy models payment operations such as refunds, captures, and high-value approvals—useful cases where “the user has a role” is rarely sufficient.

## Security properties

- cross-tenant access is rejected before policy evaluation
- unknown actions and missing policy produce an explicit default deny
- deny rules override matching allows
- condition depth and node count are bounded
- no `eval`, dynamic imports, regex, or callable policy values
- cache keys include policy version and complete decision context
- audit entries are sequenced, chained, and authenticated with HMAC-SHA256

## Quick start

```bash
make test
make check
export POLICYFORGE_AUDIT_KEY="$(openssl rand -hex 32)"
make run
```

```bash
curl -sS -X PUT http://localhost:8080/v1/tenants/acme/policy \
  -H 'content-type: application/json' \
  --data-binary @examples/payments-policy.json

curl -sS -X POST http://localhost:8080/v1/decisions \
  -H 'content-type: application/json' \
  --data-binary @examples/refund-request.json
```

See [the architecture](docs/architecture.md), [policy language](docs/policy-language.md), and [threat model](docs/threat-model.md).

## Honest boundaries

PolicyForge is a reference policy decision point, not an identity provider or enforcement proxy. Production deployment needs authenticated callers, tenant-scoped administration, TLS, secret rotation, a durable policy distribution channel, centralized audit export, availability engineering, and independent enforcement at every protected service.

## License

[MIT](LICENSE)
