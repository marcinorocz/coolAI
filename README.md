# coolAI Gate

**Explainable permission checks for AI-agent tool calls, with a working MCP bridge.**

[![Tests](https://github.com/marcinorocz/coolAI/actions/workflows/test.yml/badge.svg)](https://github.com/marcinorocz/coolAI/actions/workflows/test.yml)
![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)
![License: MIT](https://img.shields.io/badge/license-MIT-green)

Let an agent read a public document. Ask a person before changing a CRM record.
Stop a contract from reaching an unapproved recipient.

coolAI Gate separates a proposed action from permission to execute it. Its
deterministic policy engine returns a decision, a stable rule ID, and an explanation.
The guarded executor and optional stdio MCP bridge enforce that decision.

| Decision | Effect in the guarded executor |
| --- | --- |
| `allow` | A registered internal read can execute. |
| `require_approval` | Execution waits for a valid, single-use operator approval. |
| `block` | Execution is denied, even with an approval token. |

**Status: experimental 0.2.** Designed for controlled pilots and integration testing.
Read the [trust boundaries](docs/security-model.md) before connecting real tools.
There is no LLM, API key, cloud service or telemetry in the policy engine.

## Try it in two minutes

```bash
git clone https://github.com/marcinorocz/coolAI.git
cd coolAI
python -m venv .venv
source .venv/bin/activate
pip install -e '.[test]'
coolai demo
```

On Windows, activate with `.venv\Scripts\activate`.

The demo uses harmless local callbacks and prints:

| Scenario | Decision | Callback executed |
| --- | --- | --- |
| Read a public document | allow | yes |
| Send without approval | require_approval | no |
| Send a secret externally | block | no |
| Send the exact approved message | approved once | yes |

Try the original action-description CLI:

```bash
coolai evaluate examples/send_contract.json --policy policies/default.yml
```

**Expected: `block`, exit code 3.** Personal data cannot leave under the default
policy. The original `coolai examples/send_contract.json --policy ...` syntax
still works. This command evaluates descriptions; it never executes tools.

## What is implemented

- Fail-closed tool/operation registry. Unknown operations cannot become “read-only”.
- Strict action, policy, and tool-argument validation. Duplicate keys and ambiguous
  targets are rejected; explicit empty registries mean deny all.
- Trusted tool bindings assign operations and data classes. Agent-supplied labels
  do not override them.
- Exact recipient-domain matching and conservative handling of HTTP(S), email,
  mailto and internal targets.
- HMAC-signed approvals bound to the complete arguments, tool name, policy,
  bindings and upstream configuration. Expiry and SQLite-backed single-use consumption.
- Minimal SQLite audit records without prompts, recipients, arguments, tokens or results.
- A stdio MCP bridge using the official Python SDK, with a harmless example server.
- Offline policy simulation, before/after comparisons and a reusable CI workflow.
- Example LegalTech, CRM and ECM policies.

## Compare policies before applying them

```bash
coolai check --policy policies/default.yml --bindings examples/bindings.yml
coolai simulate examples/scenarios.json \
  --policy policies/default.yml --bindings examples/bindings.yml
coolai simulate examples/scenarios.json \
  --policy policies/default.yml --bindings examples/bindings.yml \
  --compare policies/legaltech.yml --fail-on-relaxation
```

The last command deliberately exits **5**: the LegalTech example changes two
contract scenarios from `block` to `require_approval`. It authorizes personal data
for the exact example.com domain, still subject to human approval. Reports show
changed cases, relaxed decisions and failed expectations. No tool is executed.

## Connect an MCP client

Install `pip install -e '.[mcp]'`, then follow the complete
[MCP and operator approval walkthrough](docs/mcp.md).

The bridge exposes only the names and schemas in your trusted bindings file.
Calls use an envelope so the approval token never reaches the upstream tool:

```json
{
  "name": "send_contract",
  "arguments": {
    "arguments": {
      "recipient": "email:client@example.com",
      "body": "A fictional demonstration contract."
    },
    "approval_token": "<operator-issued-token>"
  }
}
```

It is a deliberately narrow bridge: one local upstream process, tools only.
It does not forward roots, sampling, prompts or resources.

## Embed the engine

```python
from coolai import Gate, ToolCall

result = Gate().evaluate(ToolCall("crm", "update", "internal://customer/42", ("personal",)))
print(result.as_dict())  # require_approval; no raw action data
```

Use `GuardedExecutor` for actual dispatch. `Gate.evaluate` alone cannot prevent
an application from calling its tools directly. See [architecture and integration](docs/security-model.md).

## Policy packs

| File | Intent |
| --- | --- |
| `policies/default.yml` | No external transfer of sensitive data. |
| `policies/legaltech.yml` | Approved personal-data transfers to one exact example domain. |
| `policies/crm.yml` | CRM reads and writes, with approval for sensitive access and changes. |
| `policies/ecm.yml` | Document reads, search and publication; publication requires approval. |

These are starting points, not legal-compliance certifications. Tool bindings
must reflect the actual data and effects of your integration.

## Development

```bash
pip install -e '.[test,dev,mcp]'
ruff check .
ruff format --check .
pytest --cov=coolai --cov-report=term-missing
python -m build
```

Tests include a real MCP client → proxy → upstream process and assert exact
upstream invocation counts. CI runs Python 3.11, 3.12 and 3.13. Without the
optional MCP extra, its integration test is explicitly skipped.

Exit codes: **0** success/allow, **2** approval required, **3** block,
**4** invalid input/unavailable state, **5** simulation regression.

See [migration from 0.1](docs/migration.md), [contributing](CONTRIBUTING.md),
[security reporting](SECURITY.md), and [changes](CHANGELOG.md).

## Next milestones

- Authenticated multi-user approval UI and asymmetric signing.
- Version-aware document adapters and richer deployment examples.
- Streamable HTTP transport with explicit identity and authorization.
- Tamper-evident audit export and measured adversarial evaluation.

## Po polsku

coolAI Gate kontroluje, czy agent AI może wykonać konkretne działanie.
Nieznane operacje są blokowane, istotne zmiany wymagają jednorazowej zgody,
a symulator pokazuje skutki zmiany polityki przed jej wdrożeniem.
Zacznij od `coolai demo`; demonstracja nie wysyła wiadomości ani nie zmienia CRM.

Created by [Marcin Orocz](https://github.com/marcinorocz). MIT License.
