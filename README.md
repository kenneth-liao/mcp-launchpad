# MCP Launchpad

A lightweight CLI for efficiently discovering and executing tools from multiple MCP (Model Context Protocol) servers.

## Features

- **Unified Tool Discovery** - Search across all configured MCP servers with BM25, regex, or exact matching
- **Persistent Connections** - Session daemon maintains server connections for faster repeated calls
- **HTTP & Stdio Support** - Connect to both local process-based servers and remote HTTP/Streamable MCP servers
- **OAuth 2.1 Authentication** - Secure authentication for OAuth-protected MCP servers (Notion, Figma, etc.)
- **Auto-Configuration** - Reads from `./mcp.json` (project-level) or `~/.claude/mcp.json` (user-level) for seamless integration
- **Cross-Platform** - Works on macOS, Linux, and Windows (experimental)
- **JSON Mode** - Machine-readable output for scripting and automation

## Requirements

- Python 3.13+
- [uv](https://docs.astral.sh/uv/getting-started/installation/) - Python package and environment manager

## Installation

The MCP Launchpad CLI is available as a uv tool. Install it with one command and it will be available globally so that any agent (Claude Code, Gemini, Codex, etc.) can use it from any project/terminal!

```bash
uv tool install https://github.com/kenneth-liao/mcp-launchpad.git
```

## Quick Start

### 1. Set up your MCP servers

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
    },
    "supabase": {
      "type": "http",
      "url": "https://your-project.supabase.co/functions/v1/mcp",
      "headers": {
        "Authorization": "Bearer ${SUPABASE_ANON_KEY}"
      }
    }
  }
}
```

MCP Launchpad supports two transport types:
- **stdio** (default): Local process-based servers using `command` and `args`
- **http**: Remote HTTP/Streamable MCP servers using `url` and optional `headers`

We use `mcp.json` (not `.mcp.json`) to avoid collision with Claude Code's convention.

Configuration files are searched in this order:

1. `mcp.json` (current directory)
2. `.claude/mcp.json` (current directory)
3. `~/.claude/mcp.json` (home directory)

You can validate installation by running `mcpl list`. If you don't see any servers, restart your terminal and run `mcpl list --refresh`.

#### Environment Variables

Environment variables can be specified in the `mcp.json` file using `${VAR}` syntax. The variables will be resolved at runtime.

**Note**: Environment variables must be available at runtime for servers to connect. MCP Launchpad automatically loads `.env` files from these locations (both are loaded, in order):

1. `~/.claude/.env` (global defaults)
2. `./.env` (project-specific overrides)

This allows you to store API keys globally in `~/.claude/.env` while still supporting project-specific overrides via a local `.env` file.

### 2. Search for tools

```bash
# Find tools matching a query
mcpl search "github issues"

# Get more results
mcpl search "github issues" --limit 10
```

### 3. Execute a tool

```bash
mcpl call github list_issues '{"owner": "anthropics", "repo": "claude-code"}'
```

## MCPL with Claude Code

MCP Launchpad integrates with [Claude Code](https://claude.com/claude-code), giving Claude access to all your configured MCP tools via bash. Copy the included `CLAUDE.md` to teach Claude how to use `mcpl`.

### Option 1: Project-Level Setup

Copy `CLAUDE.md` to your project root:

```bash
curl -o CLAUDE.md https://raw.githubusercontent.com/kenneth-liao/mcp-launchpad/main/CLAUDE.md
```

### Option 2: Global Setup

For access across all projects, copy to your user-level Claude directory:

```bash
curl -o ~/.claude/CLAUDE.md https://raw.githubusercontent.com/kenneth-liao/mcp-launchpad/main/CLAUDE.md
```

**Tip**: Add a section to your `CLAUDE.md` listing your connected MCP servers for better tool discovery.

### What This Enables

With the `CLAUDE.md` instructions in place, Claude Code can:

- **Search for tools** across all your MCP servers
- **Execute tools** by calling `mcpl` via bash
- **Discover capabilities** dynamically as you add new MCP servers
- **Handle errors** gracefully with built-in troubleshooting guidance

Example interaction with Claude Code:
```
You: List my open GitHub issues
Claude: [searches for github tools, then calls mcpl to list issues]
```

## Commands

### `mcpl search <query>`

Search for tools across all configured servers. Returns 5 results by default.

```bash
mcpl search "sentry errors"           # BM25 search (default)
mcpl search "list.*" --method regex   # Regex search
mcpl search "create" --method exact   # Exact substring match
mcpl search "issues" --limit 10       # Get more results
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

### `mcpl auth login|logout|status`

Manage OAuth 2.1 authentication for HTTP servers.

```bash
mcpl auth login notion    # Authenticate with an OAuth-protected server
mcpl auth logout notion   # Remove stored authentication
mcpl auth logout --all    # Clear all stored tokens
mcpl auth status          # Show authentication status for all servers
mcpl auth status notion   # Show status for a specific server
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

### HTTP Server Configuration

HTTP/Streamable MCP servers allow you to connect to remote MCP endpoints over HTTP instead of spawning local processes.

#### Basic HTTP Server

```json
{
  "mcpServers": {
    "remote-api": {
      "type": "http",
      "url": "https://api.example.com/mcp"
    }
  }
}
```

#### With Authentication Headers

```json
{
  "mcpServers": {
    "authenticated-api": {
      "type": "http",
      "url": "https://api.example.com/mcp",
      "headers": {
        "Authorization": "Bearer ${API_TOKEN}",
        "X-Custom-Header": "value"
      }
    }
  }
}
```

#### HTTP Configuration Options

| Field | Required | Description |
|-------|----------|-------------|
| `type` | Yes | Must be `"http"` for HTTP servers |
| `url` | Yes | Full URL to the MCP endpoint |
| `headers` | No | HTTP headers to include with requests (supports `${VAR}` syntax) |

**Notes:**
- Environment variables in `url` and `headers` are resolved using `${VAR}` syntax
- HTTP servers use the [Streamable HTTP transport](https://modelcontextprotocol.io/docs/concepts/transports#streamable-http) from the MCP specification
- Connection timeout is controlled by `MCPL_CONNECTION_TIMEOUT` (default: 45 seconds)

### OAuth 2.1 Authentication

MCP Launchpad supports OAuth 2.1 authentication for connecting to OAuth-protected MCP servers (Notion, Figma, etc.).

#### Quick Start

```bash
# Authenticate with an OAuth-protected server
mcpl auth login notion

# Check authentication status
mcpl auth status

# Remove authentication
mcpl auth logout notion
```

#### Auth Commands

| Command | Description |
|---------|-------------|
| `mcpl auth login <server>` | Authenticate with an OAuth-protected server |
| `mcpl auth logout <server>` | Remove stored authentication |
| `mcpl auth logout --all` | Clear all stored tokens |
| `mcpl auth status [server]` | Show authentication status |

#### Login Options

```bash
mcpl auth login server --force              # Force re-authentication
mcpl auth login server --scope "read write" # Custom scopes
mcpl auth login server --client-id "id"     # Specific client ID

# Secure secret input (recommended)
echo "secret" | mcpl auth login server --client-secret-stdin

# Or via environment variable
export MCPL_CLIENT_SECRET="secret"
```

#### OAuth Configuration

Pre-configure OAuth credentials in `mcp.json`:

```json
{
  "mcpServers": {
    "notion": {
      "type": "http",
      "url": "https://api.notion.com/mcp",
      "oauth_client_id": "${NOTION_CLIENT_ID}",
      "oauth_client_secret": "${NOTION_CLIENT_SECRET}",
      "oauth_scopes": ["read", "write"]
    }
  }
}
```

#### Client Registration Strategy

MCP Launchpad uses a flexible registration approach:

1. **Config file** - Pre-configured credentials in `mcp.json`
2. **DCR** - Dynamic Client Registration if supported by the server
3. **Interactive** - Manual input as fallback

This approach is more flexible than Claude Code, which requires DCR support.

#### Security Features

- **Fernet encryption** (AES-128-CBC + HMAC) for tokens at rest
- **OS keyring integration** (Keychain on macOS, libsecret on Linux, DPAPI on Windows)
- **PKCE with S256** (RFC 7636) for secure authorization
- **Token revocation** on logout (RFC 7009)
- **HTTPS enforcement** for all OAuth endpoints

> **Note:** If OS keyring is unavailable, a warning will be displayed and tokens will use fallback encryption.

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
