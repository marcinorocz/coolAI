# MCP bridge and operator approvals

The optional adapter uses the official [MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk)
supported v1 line (`mcp>=1.28,<2`). The upper bound is deliberate: SDK v2 has
breaking changes. The core engine does not require MCP.

## Start the harmless example

Run from the repository root in an activated virtual environment:

```bash
pip install -e '.[mcp]'
umask 077
mkdir -p .state
python -c "from pathlib import Path; import secrets; p=Path('.state/operator.key'); p.open('xb').write(secrets.token_bytes(32))"
coolai proxy \
  --policy policies/legaltech.yml \
  --bindings examples/bindings.yml \
  --upstream examples/upstream.json \
  --audit-db .state/audit.db \
  --approval-db .state/approvals.db \
  --key-file .state/operator.key
```

The last command waits for an MCP client on stdin; stdout is reserved for MCP.
Do not paste ordinary JSON directly into this process. Configure your MCP host
to launch it instead. A host configuration uses the absolute path to
`.venv/bin/coolai` as its command and the flags above as its argument array.
Use absolute paths and an explicit upstream `cwd` outside this repository demo.

The example upstream returns fictional results. It sends no email and changes
no real data. Only the three configured tools are exposed. Tool descriptions and
schemas come from the trusted bindings, not from upstream annotations.

Call `read_document` with `{"arguments": {}}`: it executes immediately.
Call `send_contract` with the envelope below: it returns `require_approval`.

```json
{
  "arguments": {
    "recipient": "email:client@example.com",
    "body": "A fictional demonstration contract."
  }
}
```

## Approve the exact call

In a separate **operator-controlled** terminal, review
`examples/contract_call.json`, then run:

```bash
coolai approve examples/contract_call.json \
  --policy policies/legaltech.yml \
  --bindings examples/bindings.yml \
  --upstream examples/upstream.json \
  --audit-db .state/audit.db \
  --approval-db .state/approvals.db \
  --key-file .state/operator.key \
  --actor operator --ttl 300 --yes
```

This prints a token. Resubmit the identical call with `approval_token` as a
sibling of `arguments`. The token is not forwarded upstream. Changing the body,
recipient, tool, bindings, policy or upstream configuration invalidates it.
Reusing it fails. Tokens and signing keys must not go into logs or Git.

`--yes` records explicit operator confirmation of the reviewed request; it is
not an authentication mechanism. Never delegate this CLI capability to the agent.
The approval CLI and proxy must load identical policy, binding and upstream
configurations. For deployment, use a fixed absolute executable path and `cwd`
so approvals cannot accidentally refer to a different program resolved via PATH.

Omit both approval flags to run a bridge that can execute only `allow` decisions.
All calls needing approval then remain unexecuted.

## Test the boundary

```bash
pytest tests/test_mcp_integration.py -q
```

This starts a real MCP client, proxy, and recording upstream, performs read,
unapproved send, blocked destination, metadata spoofing, changed-argument and
replay attempts, then checks the upstream log. Only the read and the exact
once-approved send are present.

Current limits: one stdio upstream, a 30-second upstream response timeout, no
automatic retry, no resources/prompts/roots/sampling forwarding, no HTTP server.
Upstream response content is passed through; output DLP is not implemented.
