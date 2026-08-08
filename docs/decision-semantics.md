# Decision semantics

| Reason | Allowed | Meaning |
|---|---:|---|
| `allowed` | yes | at least one allow matched, no deny matched, obligations agree |
| `cross_tenant` | no | principal and resource tenant differ |
| `no_policy` | no | tenant has no published bundle |
| `explicit_deny` | no | one or more deny rules matched |
| `default_deny` | no | no rule granted the request |
| `conflicting_obligations` | no | matching allows require incompatible enforcement behavior |

## Payment example

A `payments-ops` user requesting an €80 refund may match an allow that requires MFA and high-detail audit. If the risk score also matches `deny-high-risk-refund`, the result is denied. Rule order in JSON never changes that outcome.

The resource amount, currency, merchant state, principal MFA evidence, risk score, and policy version are all part of the decision context or audit record as appropriate. The PEP must source those attributes from trusted systems; a client-supplied `mfa: true` is not evidence.

## Cache behavior

The cache key includes the immutable policy version, action, principal identity/roles/attributes, resource identity/attributes, tenant IDs, and environment. Request ID is deliberately excluded so equivalent requests can share work; a cache hit is returned with the current request ID and every invocation still receives a new audit entry.

Publishing a higher tenant policy version invalidates that tenant's cached decisions. TTL is a secondary bound, not the primary policy invalidation mechanism.
