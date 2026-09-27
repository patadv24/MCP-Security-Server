from mcp.server import MCPServer

from src.security_mcp.tools.ip import analyze_ip
from src.security_mcp.tools.hash import analyze_hash
from src.security_mcp.tools.dns import resolve_dns

mcp = MCPServer("Security MCP Server")


@mcp.tool()
def hello_security(name: str) -> str:
    """Return a security-themed greeting."""
    return f"Hello, {name}! Your MCP Security Server is working."


mcp.tool()(analyze_ip)
mcp.tool()(analyze_hash)
mcp.tool()(resolve_dns)


if __name__ == "__main__":
    mcp.run()