# Policy language

A bundle belongs to exactly one tenant and has a monotonically increasing integer version.

```json
{
  "tenant_id": "acme",
  "version": 7,
  "rules": [
    {
      "id": "allow-small-refund",
      "effect": "allow",
      "actions": ["payment.refund"],
      "resources": ["payment:*"],
      "roles_any": ["payments-ops"],
      "condition": {
        "lte": [
          { "path": "resource.attributes.amount" },
          { "value": 500 }
        ]
      },
      "obligations": { "audit_level": "high" }
    }
  ]
}
```

## Match fields

- `actions` and `resources` are exact strings or a single terminal-prefix wildcard.
- `roles_any` is optional; at least one listed role must be present.
- `condition` is optional and must evaluate true.
- `obligations` are JSON values returned with a successful decision.

Wildcards are intentionally limited. There is no regular-expression engine and no mid-pattern glob.

## Conditions

Every condition object contains exactly one operator.

| Operator | Argument | Behavior |
|---|---|---|
| `all` | non-empty condition array | every child is true |
| `any` | non-empty condition array | at least one child is true |
| `not` | one condition | negates child |
| `present` | path operand | path resolves |
| `eq`, `ne` | two operands | equality comparison |
| `lt`, `lte`, `gt`, `gte` | two operands | ordered comparison; type mismatch is false |
| `in` | two operands | left value is in right array |
| `contains` | two operands | left string/array contains right value |

An operand is either `{ "path": "resource.attributes.amount" }` or `{ "value": 500 }`. Roots are limited to `principal`, `resource`, and `environment`; path depth, condition depth, and total nodes are bounded.

Missing paths and incomparable types evaluate false. Policies cannot invoke code, access the filesystem/network, interpolate templates, or call regular expressions.

## Combining algorithm

Matching denies win over matching allows. Without a matching deny, one or more matching allows produce an allow only if their obligations agree. Otherwise the result is `conflicting_obligations`. No matching rule is `default_deny`.
