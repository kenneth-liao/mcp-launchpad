# MCP Launchpad

A lightweight CLI for efficiently discovering and executing tools from multiple MCP (Model Context Protocol) servers.

## Features

- **Unified Tool Discovery** - Search across all configured MCP servers with BM25, regex, or exact matching
- **Persistent Connections** - Session daemon maintains server connections for faster repeated calls
- **Auto-Configuration** - Reads Claude Desktop's `.mcp.json` format for seamless integration
- **Cross-Platform** - Works on macOS, Linux, and Windows
- **JSON Mode** - Machine-readable output for scripting and automation

## Installation

Requires Python 3.13+

```bash
# Install from source
git clone https://github.com/kenneth-liao/mcp-launchpad.git
cd mcp-launchpad
uv sync
```

## Quick Start

### 1. Create a configuration file

Create `.mcp.json` in your project directory (or `~/.claude/mcp.json` for global config):

```json
{
  "mcpServers": {
    "github": {
      "command": "uvx",
      "args": ["mcp-server-github"],
      "env": {
        "GITHUB_TOKEN": "${GITHUB_TOKEN}"
      }
    },
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@anthropic/mcp-server-filesystem", "/path/to/allowed/dir"]
    }
  }
}
```

### 2. Search for tools

```bash
# Find tools matching a query
mcpl search "github issues"

# Get the top result with full details
mcpl search "github issues" --first
```

### 3. Execute a tool

```bash
mcpl call github list_issues '{"owner": "anthropics", "repo": "claude-code"}'
```

## Commands

### `mcpl search <query>`

Search for tools across all configured servers.

```bash
mcpl search "sentry errors"           # BM25 search (default)
mcpl search "list.*" --method regex   # Regex search
mcpl search "create" --method exact   # Exact substring match
mcpl search "issues" --first          # Top result with example call
```

### `mcpl list [server]`

List configured servers or tools for a specific server.

```bash
mcpl list                # List all servers
mcpl list github         # List tools for github server
mcpl list --refresh      # Refresh the tool cache
```

### `mcpl call <server> <tool> [arguments]`

Execute a tool on a server.

```bash
mcpl call github list_issues '{"owner": "acme", "repo": "api"}'
mcpl call filesystem read_file '{"path": "/tmp/test.txt"}'

# Read arguments from stdin for large payloads
cat args.json | mcpl call github create_issue --stdin
```

### `mcpl inspect <server> <tool>`

Get the full schema for a specific tool.

```bash
mcpl inspect github list_issues
mcpl inspect github list_issues --example  # Include example call
```

### `mcpl session status|stop`

Manage the session daemon.

```bash
mcpl session status   # Show daemon status and connected servers
mcpl session stop     # Stop the session daemon
```

## Configuration

MCP Launchpad searches for configuration files in this order:

1. `.mcp.json` (current directory)
2. `mcp.json` (current directory)
3. `.claude/mcp.json` (current directory)
4. `~/.claude/mcp.json` (home directory)

Environment variables can be loaded from:

1. `.env` (current directory)
2. `~/.claude/.env` (home directory)

### Server Configuration Format

```json
{
  "mcpServers": {
    "server-name": {
      "command": "executable",
      "args": ["arg1", "arg2"],
      "env": {
        "API_KEY": "${API_KEY}"
      }
    }
  }
}
```

- `command`: The executable to run (e.g., `uvx`, `npx`, `python`)
- `args`: Command line arguments for the server
- `env`: Environment variables (supports `${VAR}` syntax for referencing existing env vars)

## JSON Mode

Add `--json` for machine-readable output:

```bash
mcpl --json search "github"
mcpl --json call github list_repos '{}'
```

## Session Daemon

MCP Launchpad uses a session daemon to maintain persistent connections to MCP servers. This significantly improves performance when making multiple tool calls.

The daemon:
- Starts automatically on first `mcpl call`
- Maintains connections per terminal session
- Shuts down automatically when the parent terminal closes
- Can be manually stopped with `mcpl session stop`

## Development

```bash
# Install dev dependencies
uv sync --all-extras

# Run tests
uv run pytest

# Run tests with coverage
uv run pytest --cov=mcp_launchpad

# Type checking (if mypy is added)
uv run mypy mcp_launchpad
```

## License

MIT
