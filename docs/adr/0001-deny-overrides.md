# ADR 0001: Deny overrides with fail-closed obligations

- Status: Accepted
- Date: 2026-08-08

## Context

Payment authorization frequently combines broad operational grants with narrow risk, compliance, account-state, or transaction-limit restrictions. First-match evaluation makes security depend on document ordering and can let a broad allow hide a later deny.

## Decision

Evaluate every matching rule. Any matching deny rejects the request. Otherwise matching allows are combined; incompatible obligation values reject the request. No match is denied.

## Consequences

- Rule ordering has no security meaning.
- Emergency or compliance denies can constrain broad role grants.
- Authors must understand that any matching deny is global within the bundle.
- Conflicting enforcement instructions surface as a safe error rather than arbitrary precedence.
- Evaluation cost is bounded by the validated maximum rule count.
