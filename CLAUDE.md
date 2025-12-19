# MCP Launchpad  (Your gateway to ALL MCPs!)

You have access to the MCP Launchpad (`mcpl`), a unified CLI for discovering and executing tools from multiple MCP servers. The user may configure and change their MCP configuration at any time. So if your task requires a tool or functionality outside of your current capabilities, it's critical that you always check the MCP Launchpad for available tools that may be useful.

## Quick Reference

```bash
# Show help
mcpl --help

# Find tools
mcpl search "<query>"                    # Search all tools (shows required params)
mcpl search "<query>" --first            # Top result with full details + example call
mcpl list                                # List all MCP servers
mcpl list <server>                       # List tools for a server (shows required params)

# Get tool details
mcpl inspect <server> <tool>             # Full schema
mcpl inspect <server> <tool> --example   # Schema + example call

# Execute tools
mcpl call <server> <tool> '{}'                        # No arguments
mcpl call <server> <tool> '{"param": "value"}'        # With arguments

# Verify servers
mcpl verify                              # Test all servers are working
```

## Important: Always Discover Before Calling

Tool names vary between MCP servers. **Never guess tool names** - always discover them first.

### Recommended Workflow

1. **Search first** to find the right tool (shows required params):
   ```bash
   mcpl search "list projects"
   ```

2. **Call with required params**:
   ```bash
   mcpl call vercel list_projects '{"teamId": "team_xxx"}'
   ```

### Alternative: List Server Tools

If you know which server to use but not the tool name:
```bash
mcpl list vercel    # Shows all tools with required params
```

### Get Example Calls

For complex tools, use `--first` to get a ready-to-use example:
```bash
mcpl search "sentry issues" --first
# Shows: mcpl call sentry search_issues '{"organizationSlug": "<organizationSlug>", ...}'
```

## Error Recovery

If a tool call fails, mcpl provides helpful suggestions:

- **Tool not found**: Shows similar tool names from that server
- **Missing parameters**: Shows required params and an example call
- **Validation errors**: Shows expected parameter types

### Troubleshooting Commands

```bash
mcpl verify                 # Test all server connections
mcpl session status         # Check daemon and server connection status
mcpl session stop           # Restart daemon (stops current, auto-restarts on next call)
mcpl config                 # Show current configuration
mcpl call <server> <tool> '{}' --no-daemon  # Bypass daemon for debugging
```

### Common Issues

- **Server not connecting**: Run `mcpl verify` to test connections
- **Stale connections**: Run `mcpl session stop` then retry
- **Timeout errors**: Server may be slow; increase with `MCPL_CONNECTION_TIMEOUT=120`

## Server-Specific Tips

### Sentry

When searching for Sentry errors/issues:
- `search_events` is more reliable for finding actual errors - use this first
- `search_issues` returns grouped issues but may miss recent errors
- Always pass `regionUrl` when provided by `find_organizations`

Example workflow:
```bash
mcpl call sentry find_organizations '{}'
mcpl call sentry search_events '{"organizationSlug": "my-org", "naturalLanguageQuery": "show all errors from last 7 days", "regionUrl": "https://us.sentry.io"}'
```
