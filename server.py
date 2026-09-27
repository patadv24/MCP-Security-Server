from mcp.server import MCPServer

from src.security_mcp.tools.ip import analyze_ip


mcp = MCPServer("Security MCP Server")


@mcp.tool()
def hello_security(name: str) -> str:
    """Return a security-themed greeting."""
    return f"Hello, {name}! Your MCP Security Server is working."


mcp.tool()(analyze_ip)


if __name__ == "__main__":
    mcp.run()