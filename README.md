# coolAI Gate

> A tiny, explainable policy gate for AI-agent tool calls.

Agents are useful until they can send an email, edit a CRM record, publish a document or leak personal data. **coolAI Gate** is the control point between an agent's intent and a real tool call.

It returns one of three explicit decisions:

| Decision | Meaning |
| --- | --- |
| `allow` | Low-risk, read-only action may continue. |
| `require_approval` | A person must approve a consequential action. |
| `block` | The action violates policy or resembles prompt injection. |

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e '.[test]'
coolai examples/send_contract.json --policy policies/default.yml
```

The example needs approval because sending is an external side effect and the contract contains personal data.

## Use it in an agent

```python
from coolai import Gate, ToolCall

gate = Gate()
action = ToolCall(
    tool="crm",
    operation="update",
    target="internal://customer/42",
    data_classes=("personal",),
)

result = gate.evaluate(action)
if result.decision.value == "allow":
    call_the_real_tool()
else:
    show_human_the_reasons(result.reasons)
```

## Current guardrails

- Blocks common prompt-injection attempts.
- Blocks sensitive data leaving for an external target.
- Requires approval for destructive or data-changing operations.
- Produces structured, auditable JSON suitable for logs and a future MCP proxy.

## Roadmap

- [ ] MCP proxy that intercepts real tool calls
- [ ] Signed approval records and audit trail
- [ ] GitHub Action for checking agent configurations in pull requests
- [ ] Policy packs for LegalTech, CRM and ECM workflows

## Development

```bash
pip install -e '.[test]'
pytest
```

## Community

Contributions, bug reports, and concrete feature proposals are welcome. Please read the [contribution guide](CONTRIBUTING.md), [Code of Conduct](CODE_OF_CONDUCT.md), and [Security Policy](SECURITY.md) first.

The project uses the [MIT License](LICENSE): you may use, modify, distribute, and use the code commercially, provided the copyright and license notice travel with it.
