"""MCP server — expose JanusGate as tools for any MCP-capable agent platform.

Model Context Protocol (stdio transport, mcp 2.x). Configure in any MCP client, e.g.:

    { "mcpServers": { "janusgate": {
        "command": "<repo>/.venv/Scripts/python.exe",
        "args": ["-m", "backend.mcp_server"] } } }

Tools: inspect_text (ingress ensemble), inspect_output (egress defense), audit_verify.
"""
from mcp.server.mcpserver import MCPServer

mcp = MCPServer("janusgate")


@mcp.tool()
async def inspect_text(text: str, source: str = "user_message",
                       session_id: str | None = None) -> dict:
    """Inspect text an AI agent is about to read (user message, email, document, tool
    output). Returns an evidence-backed verdict: is_attack, attack_class, risk 0-10,
    heuristic hits, semantic similarity, LLM judge verdict when configured."""
    from backend.sentinel_core import inspect_text as _inspect

    v = await _inspect(text, source=source, session_id=session_id)
    return v.model_dump()


@mcp.tool()
async def inspect_output(text: str) -> dict:
    """Inspect an AI agent's outgoing reply for leaks: canary tripwire, credential
    shapes (API keys, JWTs, private keys), verbatim system-prompt echoes."""
    from backend.engine.egress import inspect_output as _egress
    from backend import audit

    v = _egress(text)
    audit.record_egress(v)
    return v.model_dump()


@mcp.tool()
def audit_verify() -> dict:
    """Verify the tamper-evident hash chain of the audit log."""
    from backend.audit import verify_chain

    return verify_chain()


if __name__ == "__main__":
    mcp.run()
