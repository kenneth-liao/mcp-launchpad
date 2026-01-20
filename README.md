# MCP Launchpad

A lightweight CLI for discovering and executing tools from multiple MCP (Model Context Protocol) servers.

![Python 3.13+](https://img.shields.io/badge/python-3.13+-blue.svg)
![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)

## Installation

> **Prerequisite**: [uv](https://docs.astral.sh/uv/getting-started/installation/) - Python package and environment manager

```bash
uv tool install https://github.com/kenneth-liao/mcp-launchpad.git
```

Verify it works:

```bash
mcpl --help
```

## Quick Reference

```bash
# Find tools
mcpl search "<query>"                    # Search all tools (returns 5 by default)
mcpl search "<query>" --limit 10         # Get more results
mcpl list                                # List all MCP servers
mcpl list <server>                       # List tools for a server

# Get tool details
mcpl inspect <server> <tool>             # Full schema
mcpl inspect <server> <tool> --example   # Schema + example call

# Execute tools
mcpl call <server> <tool> '{}'                        # No arguments
mcpl call <server> <tool> '{"param": "value"}'        # With arguments

# Troubleshooting
mcpl verify                              # Test all server connections
mcpl session status                      # Check daemon status
mcpl session stop                        # Restart daemon (auto-restarts on next call)
```

## Configuration

Create `mcp.json` in your project directory (or `~/.claude/mcp.json` for global config):

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@anthropic/mcp-server-filesystem", "/path/to/allowed/dir"]
    }
  }
}
```

Validate with `mcpl list`. If you don't see your servers, restart your terminal and run `mcpl list --refresh`.

### Adding More Servers

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@anthropic/mcp-server-filesystem", "/path/to/dir"]
    },
    "github": {
      "command": "uvx",
      "args": ["mcp-server-github"],
      "env": {
        "GITHUB_TOKEN": "${GITHUB_TOKEN}"
      }
    }
  }
}
```

Environment variables use `${VAR}` syntax and are loaded from `~/.claude/.env` and `./.env`.

### Config Discovery

MCP Launchpad searches for config files in this order:
1. `./mcp.json` - Project-level config
2. `./.claude/mcp.json` - Project-level Claude config
3. `~/.claude/mcp.json` - User-level config

When multiple config files are found, mcpl prompts you to select which ones to use. Your preferences are saved and can be changed later with `mcpl config files --select`.

## Agent Integration

MCP Launchpad works with any AI agent that can run bash commands (Claude Code, Cursor, Windsurf, etc.).

Copy the root `CLAUDE.md` contents into your own `CLAUDE.md` or `AGENTS.md` to teach your agent how to use `mcpl`. This can be done at the project level (`./CLAUDE.md`) or user level (`~/.claude/CLAUDE.md`).

> **Important: OAuth Authentication**
>
> Agents cannot complete OAuth flows because they require browser interaction. You must authenticate all OAuth-protected MCP servers **before** agents can use them:
> ```bash
> mcpl auth login <server>    # Authenticate a specific server
> mcpl list --refresh         # Prompts to authenticate each server that requires OAuth
> mcpl auth status            # Verify all servers are authenticated
> ```

**Tip**: Add a section to your `CLAUDE.md` listing your connected MCP servers for better tool discovery.

### What This Enables

With the instructions in place, your agent can:

- **Search for tools** across all your MCP servers
- **Execute tools** by calling `mcpl` via bash
- **Discover capabilities** dynamically as you add new MCP servers
- **Handle errors** gracefully with built-in troubleshooting guidance

## Table of Contents

- [Commands](#commands)
- [Session Daemon](#session-daemon)
- [Advanced Topics](#advanced-topics)
  - [HTTP Server Configuration](#http-server-configuration)
  - [SSE Transport Configuration](#sse-transport-configuration)
  - [OAuth Authentication](#oauth-authentication)
  - [Environment Variables](#environment-variables)
- [Platform Notes](#platform-notes)
- [Development](#development)

## Commands

### `mcpl search <query>`

Search for tools across all configured servers. Returns 5 results by default.

```bash
mcpl search "sentry errors"
mcpl search "issues" --limit 10   # Get more results
```

### `mcpl list [server]`

List configured servers or tools for a specific server.

```bash
mcpl list           # List all servers
mcpl list github    # List tools for github server
```

### `mcpl call <server> <tool> [arguments]`

Execute a tool on a server.

```bash
mcpl call github list_issues '{"owner": "acme", "repo": "api"}'
```

### `mcpl inspect <server> <tool>`

Get the full schema for a specific tool.

```bash
mcpl inspect github list_issues --example   # Include example call
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
```

### `mcpl enable|disable <server>`

Enable or disable servers without modifying the config file.

```bash
mcpl disable slow-server    # Temporarily disable a server
mcpl enable slow-server     # Re-enable it
```

### `mcpl config`

Show the current configuration and loaded servers.

```bash
mcpl config
```

### `mcpl config files`

Manage which config files are active when multiple are available.

```bash
mcpl config files                    # View config files and their status
mcpl config files --select           # Interactive selection prompt
mcpl config files --activate 1       # Activate config by number
mcpl config files --deactivate 2     # Deactivate config by number
mcpl config files --all              # Activate all discovered configs
mcpl config files --reset            # Clear preferences (re-prompts on next run)
```

### `mcpl verify`

Test that all configured servers can connect and respond.

```bash
mcpl verify
```

### JSON Mode

Add `--json` for machine-readable output:

```bash
mcpl --json search "github"
mcpl --json call github list_repos '{}'
```

## Session Daemon

MCP Launchpad uses a session daemon to maintain persistent connections to MCP servers, improving performance for repeated calls. The daemon starts automatically on first `mcpl call`.

### Automatic Cleanup

| Environment | Cleanup Trigger |
|-------------|-----------------|
| Regular terminal | Parent terminal process exits |
| VS Code / Claude Code | IDE session ends (detected via VS Code socket) |
| Any environment | Idle timeout (default: 1 hour of no activity) |
| Manual | `mcpl session stop` command |

### Troubleshooting

```bash
mcpl session status                         # Check daemon status
mcpl session stop                           # Stop the daemon manually
mcpl call github list_repos '{}' --no-daemon  # Bypass daemon for debugging
```

If you encounter persistent issues, stopping and restarting the daemon usually resolves them.

## Advanced Topics

### HTTP Server Configuration

HTTP servers connect to remote MCP endpoints over HTTP.

```json
{
  "mcpServers": {
    "remote-api": {
      "type": "http",
      "url": "https://api.example.com/mcp",
      "headers": {
        "Authorization": "Bearer ${API_TOKEN}"
      }
    }
  }
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `type` | Yes | Must be `"http"` |
| `url` | Yes | Full URL to the MCP endpoint |
| `headers` | No | HTTP headers (supports `${VAR}` syntax) |

For OAuth-protected servers, see [OAuth Authentication](#oauth-authentication).

### SSE Transport Configuration

Some legacy MCP servers use Server-Sent Events (SSE) instead of the newer Streamable HTTP transport:

```json
{
  "mcpServers": {
    "legacy-server": {
      "type": "sse",
      "url": "https://legacy.example.com/sse",
      "headers": {
        "Authorization": "Bearer ${API_TOKEN}"
      }
    }
  }
}
```

> **Note:** SSE transport is provided for compatibility with older MCP servers. New servers should use standard HTTP transport.

### OAuth Authentication

Some remote MCP servers (like Notion, Figma, and other cloud services) require OAuth authentication. MCP Launchpad handles this securely using OAuth 2.1 with PKCE.

#### Quick Start

When you connect to a server that requires authentication, mcpl will prompt you:

```bash
$ mcpl list notion --refresh
Server 'notion' requires OAuth authentication.
Would you like to authenticate now? [Y/n]
```

Or authenticate proactively:

```bash
mcpl auth login notion
```

This opens your browser for authorization. After you approve, tokens are stored securely.

#### Commands

| Command | Description |
|---------|-------------|
| `mcpl auth login <server>` | Authenticate with an OAuth-protected server |
| `mcpl auth logout <server>` | Remove stored authentication |
| `mcpl auth logout --all` | Clear all stored tokens |
| `mcpl auth status [server]` | Show authentication status |

#### Configuration

For servers that require pre-registered OAuth credentials:

```json
{
  "mcpServers": {
    "notion": {
      "type": "http",
      "url": "https://mcp.notion.com/mcp",
      "oauth_client_id": "${NOTION_CLIENT_ID}",
      "oauth_client_secret": "${NOTION_CLIENT_SECRET}",
      "oauth_scopes": ["read", "write"]
    }
  }
}
```

Tokens are encrypted and stored locally in `~/.cache/mcp-launchpad/oauth/` using your system's keyring.

#### Troubleshooting

| Issue | Solution |
|-------|----------|
| "Server requires OAuth authentication" | Run `mcpl auth login <server>` |
| Token expired | Run `mcpl auth login <server> --force` |
| Browser doesn't open | Copy the URL from terminal and open manually |
| "Invalid client" errors | Check `oauth_client_id` and `oauth_client_secret` |
| Keyring warnings | Using fallback encryption (still secure) |
| "Metadata fetch failed" | Configure credentials manually in `mcp.json` |

<details>
<summary><strong>Advanced: Login Options & Security Details</strong></summary>

#### Login Options

```bash
mcpl auth login notion                     # Basic authentication
mcpl auth login figma --scope "read write" # Request specific scopes
mcpl auth login custom --force             # Re-authenticate (replace existing tokens)
mcpl auth login server --client-id "id"    # Specific client ID

# Secure secret input (recommended)
echo "secret" | mcpl auth login server --client-secret-stdin

# Or via environment variable
export MCPL_CLIENT_SECRET="secret"
```

Options:
- `--scope TEXT` - Additional OAuth scopes to request
- `--force` - Force re-authentication even if already logged in
- `--client-id TEXT` - Use a specific OAuth client ID
- `--client-secret-stdin` - Read client secret from stdin
- `--timeout INTEGER` - Browser callback timeout (default: 120 seconds)

#### Client Registration Strategy

MCP Launchpad uses a flexible registration approach:

1. **Config file** - Pre-configured credentials in `mcp.json`
2. **DCR** - Dynamic Client Registration if supported by the server
3. **Interactive** - Manual input as fallback

This approach is more flexible than Claude Code, which requires DCR support.

#### Server Compatibility

MCP Launchpad supports OAuth servers with varying levels of standards compliance:

- **RFC 9728** - MCP-native OAuth servers with `/.well-known/oauth-authorization-server` at the MCP resource path
- **RFC 8414** - Standard OAuth servers with `/.well-known/oauth-authorization-server` at the server root
- **Non-compliant** - Servers without metadata discovery (falls back to manual configuration)

#### Security Features

- **Fernet encryption** (AES-128-CBC + HMAC) for tokens at rest
- **OS keyring integration** (Keychain on macOS, libsecret on Linux, DPAPI on Windows)
- **PKCE with S256** (RFC 7636) for secure authorization
- **Token revocation** on logout (RFC 7009)
- **HTTPS enforcement** for all OAuth endpoints

> **Note:** If OS keyring is unavailable, a warning will be displayed and tokens will use fallback encryption.

</details>

### Environment Variables

Common settings you may need to configure:

| Variable | Default | Description |
|----------|---------|-------------|
| `MCPL_CONFIG_FILES` | (auto) | Comma-separated list of config files (overrides discovery) |
| `MCPL_CONNECTION_TIMEOUT` | `45` | Server connection timeout in seconds |
| `MCPL_IDLE_TIMEOUT` | `3600` | Daemon idle timeout (0 to disable) |

<details>
<summary><strong>All Environment Variables</strong></summary>

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

| Variable | Default | Description |
|----------|---------|-------------|
| `MCPL_IDLE_TIMEOUT` | `3600` | Shut down daemon after this many seconds of inactivity (0 to disable) |
| `MCPL_IDE_ANCHOR_CHECK_INTERVAL` | `10` | How often to check if IDE session is still active (seconds) |
| `MCPL_SESSION_ID` | (auto) | Override the session ID (for testing or advanced multi-session setups) |

</details>

## Platform Notes

### Windows (Experimental)

Windows support uses named pipes for IPC communication. While functional, it may have limitations compared to Unix sockets on macOS/Linux.

If you encounter issues:

1. Use `--no-daemon` flag to bypass the session daemon
2. Set `MCPL_SESSION_ID` explicitly if session detection is unreliable
3. Report issues at https://github.com/kenneth-liao/mcp-launchpad/issues

## Development

Requires Python 3.13+

```bash
git clone https://github.com/kenneth-liao/mcp-launchpad.git
cd mcp-launchpad
uv sync --all-extras

# Run tests
uv run pytest

# Run tests with coverage
uv run pytest --cov=mcp_launchpad

# Type checking
uv run mypy mcp_launchpad
```

## Features

- **Unified Tool Discovery** - Search across all configured MCP servers with BM25, regex, or exact matching
- **Persistent Connections** - Session daemon maintains server connections for faster repeated calls
- **HTTP & Stdio Support** - Connect to both local process-based servers and remote HTTP/Streamable MCP servers
- **SSE Transport Support** - Connect to legacy MCP servers using Server-Sent Events
- **Multi-Config Management** - Use multiple config files simultaneously with interactive selection
- **OAuth 2.1 Authentication** - Secure authentication for OAuth-protected MCP servers (Notion, Figma, etc.)
- **Auto-Configuration** - Reads from `./mcp.json` (project-level) or `~/.claude/mcp.json` (user-level)
- **Cross-Platform** - Works on macOS, Linux, and Windows (experimental)
- **JSON Mode** - Machine-readable output for scripting and automation

## License

MIT
