"""Harmless demo upstream. Never sends mail or modifies a real CRM."""

from mcp.server.fastmcp import FastMCP

server = FastMCP("coolai-demo-upstream")


@server.tool()
def read_document() -> str:
    return "A public demonstration document."


@server.tool()
def send_contract(recipient: str, body: str) -> str:
    return "Demo contract accepted; no email was sent."


@server.tool()
def update_customer(customer_id: int, display_name: str) -> str:
    return "Demo customer accepted; no CRM was changed."


if __name__ == "__main__":
    server.run(transport="stdio")
