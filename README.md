# MCP Launchpad

A lightweight CLI for efficiently discovering and executing tools from multiple MCP (Model Context Protocol) servers.

## Features

- **Unified Tool Discovery** - Search across all configured MCP servers with BM25, regex, or exact matching
- **Persistent Connections** - Session daemon maintains server connections for faster repeated calls
- **Auto-Configuration** - Reads from `./mcp.json` (project-level) or `~/.claude/mcp.json` (user-level) for seamless integration
- **Cross-Platform** - Works on macOS, Linux, and Windows (experimental)
- **JSON Mode** - Machine-readable output for scripting and automation

## Requirements

You must have uv installed to use this tool.

- Python 3.13+
- [uv](https://docs.astral.sh/uv/getting-started/installation/) - a python package and environment manager

## Installation

The MCP Launchpad CLI is available as a uv tool. Install it with one command and it will be available globally so that any agent (Claude Code, Gemini, Codex, etc.) can use it from any project/terminal!

```bash
uv tool install https://github.com/kenneth-liao/mcp-launchpad.git
```

## Quick Start

### 1. Create a configuration file

Create `mcp.json` in your project directory (or `~/.claude/mcp.json` for global config):

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

You can validate installation by running `mcpl list`. If you don't see any servers, restart your terminal and run `mcpl list --refresh`.

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

# Bypass daemon for troubleshooting (slower but more reliable)
mcpl call github list_issues '{}' --no-daemon
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

### `mcpl enable|disable <server>`

Enable or disable servers without modifying the config file.

```bash
mcpl disable slow-server   # Temporarily disable a server
mcpl enable slow-server    # Re-enable it
mcpl list                  # Shows disabled status
```

### `mcpl config`

Show the current configuration and loaded servers.

```bash
mcpl config                # Show config summary
mcpl config --show-secrets # Include environment variable values
```

### `mcpl verify`

Test that all configured servers can connect and respond.

```bash
mcpl verify             # Test all servers
mcpl verify --timeout 60  # With custom timeout
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

### How It Works

The daemon:
- Starts automatically on first `mcpl call`
- Maintains connections per terminal/IDE session
- Pre-connects to all configured servers for faster first calls
- Reconnects automatically if a server connection drops

### Automatic Cleanup

The daemon shuts down automatically in these scenarios:

| Environment | Cleanup Trigger |
|-------------|-----------------|
| Regular terminal | Parent terminal process exits |
| VS Code / Claude Code | IDE session ends (detected via VS Code socket) |
| Any environment | Idle timeout (default: 1 hour of no activity) |
| Manual | `mcpl session stop` command |

### Troubleshooting

```bash
# Check daemon status and connected servers
mcpl session status

# Stop the daemon manually
mcpl session stop

# Bypass daemon entirely (slower but useful for debugging)
mcpl call github list_repos '{}' --no-daemon
```

If you encounter persistent issues, stopping and restarting the daemon usually resolves them.

## Advanced Configuration

### Environment Variables

All timeouts, daemon behavior, and session settings can be configured via environment variables.

#### Connection Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `MCPL_CONNECTION_TIMEOUT` | `45` | MCP server connection/initialization timeout (seconds) |
| `MCPL_RECONNECT_DELAY` | `5` | Delay before retrying a failed server connection (seconds) |
| `MCPL_MAX_RECONNECT_ATTEMPTS` | `3` | Max reconnection attempts before giving up |

#### Daemon Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `MCPL_DAEMON_START_TIMEOUT` | `30` | Max time to wait for daemon startup (seconds) |
| `MCPL_DAEMON_CONNECT_RETRY_DELAY` | `0.2` | Delay between connection attempts to daemon (seconds) |
| `MCPL_PARENT_CHECK_INTERVAL` | `5` | How often daemon checks if parent process is alive (seconds) |

#### IDE/Session Settings

These settings control daemon behavior in IDE environments (VS Code, Claude Code):

| Variable | Default | Description |
|----------|---------|-------------|
| `MCPL_IDLE_TIMEOUT` | `3600` | Shut down daemon after this many seconds of inactivity (0 to disable) |
| `MCPL_IDE_ANCHOR_CHECK_INTERVAL` | `10` | How often to check if IDE session is still active (seconds) |
| `MCPL_SESSION_ID` | (auto) | Override the session ID (for testing or advanced multi-session setups) |

#### Examples

```bash
# Increase timeout for slow servers
export MCPL_CONNECTION_TIMEOUT=120
mcpl call slow-server long_running_tool '{}'

# Disable idle timeout (daemon runs until explicitly stopped)
export MCPL_IDLE_TIMEOUT=0

# Use a custom session ID for isolated testing
export MCPL_SESSION_ID=test-session-1
mcpl call github list_repos '{}'
```

## Platform Notes

### Windows (Experimental)

Windows support uses named pipes for IPC communication. While functional, it may have limitations compared to Unix sockets on macOS/Linux. If you encounter issues on Windows:

1. Use `--no-daemon` flag to bypass the session daemon
2. Report issues at https://github.com/kenneth-liao/mcp-launchpad/issues

## Development

Requires Python 3.13+

```bash
# Install from source
git clone https://github.com/kenneth-liao/mcp-launchpad.git
cd mcp-launchpad

# Install dev dependencies
uv sync --all-extras

# Run tests
uv run pytest

# Run tests with coverage
uv run pytest --cov=mcp_launchpad

# Type checking
uv run mypy mcp_launchpad
```

## License

MIT
