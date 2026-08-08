# Audit ledger

Each JSON Lines entry contains a sequence, previous entry hash, decision identifiers, and `entry_hash`. The hash is:

```text
HMAC-SHA256(secret, canonical-json(entry-without-entry_hash))
```

The ledger takes an exclusive OS file lock, verifies the existing chain, appends one canonical line with `O_APPEND`, and calls `fsync` before authorization returns. Concurrent request threads therefore produce one contiguous sequence.

## What it proves

With the HMAC key protected, verification detects modified, removed, reordered, inserted, or truncated historical entries within the retained file. The chain does not prevent deletion of the entire ledger or prove an external timestamp.

## Production controls

- keep the HMAC key in a managed secret service, separate from the ledger volume;
- rotate keys with an explicit key identifier and signed transition record;
- export entries continuously to immutable remote storage;
- alert on sequence gaps and verification failures;
- retain request attributes only when necessary and redact sensitive values;
- restrict verification and policy administration independently.
