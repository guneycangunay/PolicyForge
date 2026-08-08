# Contributing

Authorization changes must include allow, deny, default-deny, cross-tenant, and malformed-input cases affected by the change. Combining-algorithm, cache-key, condition-language, or audit-format changes require an architecture decision record.

Before opening a pull request:

```bash
make test
make check
pyright
ruff check src tests
```

Never weaken a fail-closed path to make an integration more convenient. Explain trusted attribute sources and enforcement obligations in policy examples.
