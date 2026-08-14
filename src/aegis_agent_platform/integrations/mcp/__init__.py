"""Official-version MCP adapter boundary."""

from aegis_agent_platform.integrations.mcp.adapter import (
    MCP_CURRENT_VERSION,
    MCP_LEGACY_VERSION,
    McpApplicationPort,
    McpClientAdapter,
    McpServerAdapter,
    McpStreamableHttpRequest,
    RegisteredStdioCommand,
    StdioCommandRegistry,
)

__all__ = [
    "MCP_CURRENT_VERSION",
    "MCP_LEGACY_VERSION",
    "McpApplicationPort",
    "McpClientAdapter",
    "McpServerAdapter",
    "McpStreamableHttpRequest",
    "RegisteredStdioCommand",
    "StdioCommandRegistry",
]
