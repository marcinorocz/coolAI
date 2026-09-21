"""Optional stdio MCP bridge; only operator-configured tools are exposed."""

import json
from datetime import timedelta

from .engine import ValidationError, canonical, obj
from .runtime import GateDenied, GuardedExecutor


def upstream_config(raw: dict) -> dict:
    obj(raw, {"command", "args", "cwd"}, {"command", "args"})
    if not isinstance(raw["command"], str) or not raw["command"]:
        raise ValidationError("Upstream command is required.")
    if not isinstance(raw["args"], list) or any(not isinstance(a, str) for a in raw["args"]):
        raise ValidationError("Upstream args must be strings.")
    if "cwd" in raw and not isinstance(raw["cwd"], str):
        raise ValidationError("Upstream cwd must be a string.")
    return dict(raw)


async def serve(executor: GuardedExecutor, config: dict, timeout: float = 30):
    from mcp import ClientSession, StdioServerParameters, types
    from mcp.client.stdio import stdio_client
    from mcp.server.lowlevel import Server
    from mcp.server.stdio import stdio_server

    config = upstream_config(config)
    server = Server("coolai-gate")

    @server.list_tools()
    async def list_tools():
        return [
            types.Tool(
                name=name,
                description="Policy-controlled tool. Approval may be required.",
                inputSchema={
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "arguments": json.loads(binding.schema_json),
                        "approval_token": {"type": "string", "maxLength": 8192},
                    },
                    "required": ["arguments"],
                },
            )
            for name, binding in executor.bindings.items()
        ]

    def failure(data):
        return types.CallToolResult(
            isError=True, content=[types.TextContent(type="text", text=canonical(data))]
        )

    # No shell; SDK supplies a minimal environment. Roots/sampling are not forwarded.
    async with stdio_client(StdioServerParameters(**config)) as (up_read, up_write):
        async with ClientSession(
            up_read, up_write, read_timeout_seconds=timedelta(seconds=timeout)
        ) as upstream:
            await upstream.initialize()

            async def dispatch(name, arguments):
                return await upstream.call_tool(name, arguments)

            @server.call_tool(validate_input=False)
            async def call_tool(name, arguments):
                try:
                    obj(arguments, {"arguments", "approval_token"}, {"arguments"})
                    if "approval_token" in arguments and not isinstance(arguments["approval_token"], str):
                        raise ValidationError("Invalid approval token.")
                    return await executor.execute(
                        name, arguments["arguments"], dispatch, arguments.get("approval_token")
                    )
                except GateDenied as exc:
                    return failure(exc.evaluation.as_dict())
                except ValidationError:
                    return failure({"decision": "block", "error": "invalid_tool_call"})
                except Exception:
                    return failure(
                        {
                            "decision": "block",
                            "error": "execution_failed",
                            "detail": "Execution may have started; do not retry a write automatically.",
                        }
                    )

            async with stdio_server() as (read, write):
                await server.run(read, write, server.create_initialization_options())
