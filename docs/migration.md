# Migrating from 0.1 to 0.2

This release intentionally tightens behavior. Do not copy the old policy
silently: validation rejects its unsupported fields.

| 0.1 | 0.2 |
| --- | --- |
| Unknown operations returned allow. | Only registered tool/operation pairs can proceed. |
| Operation/target/classification were unchecked. | Strict types, lowercase identifiers and explicit targets. |
| Flat destructive/sensitive/prefix lists. | Versioned tools, trusted_domains and external_data_classes. |
| Empty lists restored defaults. | Empty tools means deny all; empty lists are preserved. |
| Evaluation JSON included full action data. | Only decisions, reasons, rule IDs and fingerprints. |
| Approval was a decision label. | Guarded execution supports expiring, signed, single-use approvals. |

Default policy example:

```yaml
version: 1
tools:
  document_store: [read, list, search]
  mailer: [send]
trusted_domains: []
external_data_classes: []
```

`Gate()`, `Gate.evaluate()`, `ToolCall.from_dict()` and the old positional
CLI invocation remain available. Direct action evaluation is still a dry run.
Use trusted bindings and the executor to enforce real calls.

`Evaluation.action` has been removed to prevent accidental logging of inputs.
Use your trusted request context if the operator must review the full payload.
Never use the privacy-minimized evaluation record as a complete review screen.

The existing contract example now correctly documents `block`, exit 3.
Changing to the LegalTech example policy gives `require_approval`, exit 2.
