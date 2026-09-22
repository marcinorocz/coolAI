"""Test-only upstream: records actual invocations, including otherwise forbidden ones."""

import json
import sys
from pathlib import Path

from mcp.server.fastmcp import FastMCP

server = FastMCP("recording-test-upstream")
log = Path(sys.argv[1])


def record(name, arguments):
    with log.open("a") as handle:
        handle.write(json.dumps({"name": name, "arguments": arguments}) + "\n")
    return "executed"


@server.tool()
def read_document() -> str:
    return record("read_document", {})


@server.tool()
def send_contract(recipient: str, body: str) -> str:
    return record("send_contract", {"recipient": recipient, "body": body})


@server.tool()
def hidden_admin_tool() -> str:
    return record("hidden_admin_tool", {})


if __name__ == "__main__":
    server.run(transport="stdio")
