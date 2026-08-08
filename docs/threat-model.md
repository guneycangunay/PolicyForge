# Threat model

| Threat | Reference control | Production requirement |
|---|---|---|
| Cross-tenant confused deputy | Tenant equality check precedes policy lookup | Authenticate tenant-bound caller identity |
| Policy code execution | Closed, bounded data DSL; no eval/import/regex | Review compiler changes and sign approved bundles |
| Allow masks a deny | Deny-overrides combining algorithm | Test business-specific deny invariants |
| Stale cached allow | Policy version in key; tenant invalidation; short TTL | Reliable bundle version distribution |
| Context omission | Missing paths evaluate false; default deny | Define per-action attribute contracts at the PEP |
| Audit modification | Sequenced HMAC hash chain verified before append | Protect key, export to immutable remote storage |
| Policy rollback | Version must monotonically increase in process | Durable compare-and-swap version registry |
| Resource exhaustion | Bounded body, rules, patterns, condition depth/nodes, cache | Rate limits, tenant quotas, load shedding |
| Unauthorized policy publish | Not implemented by demo server | Separate admin authentication and authorization |
| PDP outage bypass | No local bypass in engine | PEP deny-on-failure and reviewed emergency procedure |

## Critical assumption

Authorization is only as trustworthy as its attributes. PolicyForge evaluates the request it receives; it does not verify MFA ceremonies, payment ownership, merchant state, or risk scores. PEPs must obtain authoritative attributes and prevent clients from choosing them.
