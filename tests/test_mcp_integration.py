import asyncio
import json
import secrets
import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("mcp")
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.integration
def test_real_stdio_proxy_enforces_policy_and_one_time_operator_approval(tmp_path):
    log = tmp_path / "upstream.jsonl"
    upstream = tmp_path / "upstream.json"
    upstream.write_text(
        json.dumps(
            {
                "command": sys.executable,
                "args": [str(ROOT / "tests/fixtures/mcp_recording_server.py"), str(log)],
            }
        )
    )
    key = tmp_path / "operator.key"
    key.write_bytes(secrets.token_bytes(32))
    common = [
        "--policy",
        str(ROOT / "policies/legaltech.yml"),
        "--bindings",
        str(ROOT / "examples/bindings.yml"),
        "--upstream",
        str(upstream),
        "--key-file",
        str(key),
        "--approval-db",
        str(tmp_path / "approvals.db"),
        "--audit-db",
        str(tmp_path / "audit.db"),
    ]
    call = {
        "name": "send_contract",
        "arguments": {"recipient": "email:a@example.com", "body": "Reviewed body"},
    }
    call_file = tmp_path / "call.json"
    call_file.write_text(json.dumps(call))

    async def exercise():
        parameters = StdioServerParameters(
            command=sys.executable, args=["-m", "coolai.cli", "proxy", *common]
        )
        async with stdio_client(parameters) as (read, write), ClientSession(read, write) as client:
            await client.initialize()
            listed = await client.list_tools()
            assert "hidden_admin_tool" not in {t.name for t in listed.tools}
            assert not (await client.call_tool("read_document", {"arguments": {}})).isError
            assert (await client.call_tool("hidden_admin_tool", {"arguments": {}})).isError
            denied = await client.call_tool("send_contract", {"arguments": call["arguments"]})
            assert denied.isError
            assert json.loads(denied.content[0].text)["decision"] == "require_approval"
            blocked = await client.call_tool(
                "send_contract", {"arguments": call["arguments"] | {"recipient": "mailto:a@evil.example"}}
            )
            assert blocked.isError
            assert json.loads(blocked.content[0].text)["decision"] == "block"
            spoof = await client.call_tool(
                "send_contract", {"arguments": call["arguments"] | {"data_classes": ["public"]}}
            )
            assert spoof.isError
            issued = await asyncio.to_thread(
                subprocess.run,
                [
                    sys.executable,
                    "-m",
                    "coolai.cli",
                    "approve",
                    str(call_file),
                    *common,
                    "--actor",
                    "integration-operator",
                    "--yes",
                ],
                capture_output=True,
                text=True,
                timeout=15,
            )
            assert issued.returncode == 0, issued.stderr
            token = issued.stdout.strip()
            tampered = await client.call_tool(
                "send_contract",
                {"arguments": call["arguments"] | {"body": "Changed body"}, "approval_token": token},
            )
            assert tampered.isError
            accepted = await client.call_tool(
                "send_contract", {"arguments": call["arguments"], "approval_token": token}
            )
            assert not accepted.isError
            assert (
                await client.call_tool(
                    "send_contract", {"arguments": call["arguments"], "approval_token": token}
                )
            ).isError

    asyncio.run(asyncio.wait_for(exercise(), timeout=30))
    recorded = [json.loads(line) for line in log.read_text().splitlines()]
    assert recorded == [{"name": "read_document", "arguments": {}}, call]
