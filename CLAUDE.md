# TOOLS

You have access the MCP Launchpad: "ONE TOOL TO RULE THEM ALL".

The MCP Launchpad is a unified interface for discovering and executing tools from multiple MCP servers. It is installed as a uv tool and is available globally as `mcpl`. Instead of having all tools loaded, use the following commands to interact with the MCP Launchpad:

Access the main help menu:
```bash
mcpl --help
```

Search for tools (uses BM25 ranking by default):
```bash
mcpl search "<query>"
```

List all installed MCP Servers:
```bash
mcpl list
```

List all tools for a specific server:
```bash
mcpl list <server>
```
