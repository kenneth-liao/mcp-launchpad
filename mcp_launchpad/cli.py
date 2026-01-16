"""CLI entry point for MCP Launchpad."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any, NoReturn

import click

from . import __version__
from .cache import ToolCache
from .config import Config, load_config
from .connection import ConnectionManager, ToolInfo
from .oauth import OAuthFlowError, TokenDecryptionError, get_oauth_manager
from .output import OutputHandler
from .search import SearchMethod, ToolSearcher
from .session import SessionClient
from .state import ServerState
from .suggestions import (
    find_similar_tools,
    format_tool_suggestions,
    format_validation_error,
)

# Logger for CLI
logger = logging.getLogger("mcpl")


def _check_tool_exists(
    server: str, tool: str, manager: ConnectionManager
) -> tuple[bool, list[ToolInfo]]:
    """Check if a tool exists on a server and get available tools.

    Returns:
        Tuple of (tool_exists, available_tools)
    """
    try:
        available_tools = asyncio.run(manager.list_tools(server))
        tool_exists = any(t.name == tool for t in available_tools)
        return tool_exists, available_tools
    except Exception as e:
        # Log the error but continue - we'll let the actual tool call fail
        # with a proper error message if the tool doesn't exist
        logger.debug(f"Failed to verify tool '{tool}' on server '{server}': {e}")
        logger.warning(
            f"Could not verify tool existence on '{server}'. "
            "Proceeding with tool call - error suggestions may be limited if it fails."
        )
        return True, []


def _handle_mcp_exception(
    e: Exception, server: str, tool: str, available_tools: list[ToolInfo]
) -> dict[str, Any] | None:
    """Handle MCP protocol exceptions and return enriched error if applicable.

    Returns:
        Dict with error info if handled, None otherwise
    """
    error_str = str(e)

    # Check for JSON-RPC error codes
    if "-32601" in error_str:  # Method not found
        similar = find_similar_tools(tool, available_tools)
        enriched = format_tool_suggestions(tool, server, similar, error_str)
        return {"result": enriched, "error": True, "error_type": "tool_not_found"}
    elif "-32602" in error_str:  # Invalid params
        tool_info = next((t for t in available_tools if t.name == tool), None)
        enriched = format_validation_error(tool, server, error_str, tool_info)
        return {"result": enriched, "error": True, "error_type": "validation_error"}

    return None


@click.group()
@click.option("--json", "json_mode", is_flag=True, help="Output in JSON format")
@click.option(
    "--config",
    "config_path",
    type=click.Path(exists=True),
    help="Path to MCP config file",
)
@click.option(
    "--env-file", "env_path", type=click.Path(exists=True), help="Path to .env file"
)
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose logging")
@click.version_option(version=__version__)
@click.pass_context
def main(
    ctx: click.Context,
    json_mode: bool,
    config_path: str | None,
    env_path: str | None,
    verbose: bool,
) -> None:
    """MCP Launchpad - Efficiently discover and execute MCP server tools."""
    ctx.ensure_object(dict)
    ctx.obj["json_mode"] = json_mode
    ctx.obj["config_path"] = Path(config_path) if config_path else None
    ctx.obj["env_path"] = Path(env_path) if env_path else None
    ctx.obj["output"] = OutputHandler(json_mode)

    # Configure logging based on verbosity
    if verbose:
        logging.basicConfig(
            level=logging.DEBUG,
            format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        )
    else:
        logging.basicConfig(level=logging.WARNING)


def get_config(ctx: click.Context) -> Config | NoReturn:
    """Get config from context, handling errors."""
    output: OutputHandler = ctx.obj["output"]
    try:
        return load_config(ctx.obj["config_path"], ctx.obj["env_path"])
    except FileNotFoundError as e:
        output.error(e, help_text=str(e))
        raise SystemExit(1) from e  # Never reached due to sys.exit in output.error
    except json.JSONDecodeError as e:
        output.error(
            e,
            error_type="ConfigParseError",
            help_text="The config file contains invalid JSON. Check for syntax errors.",
        )
        raise SystemExit(1) from e  # Never reached due to sys.exit in output.error


@main.command()
@click.argument("query")
@click.option(
    "--method",
    "-m",
    type=click.Choice(["bm25", "regex", "exact"]),
    default="bm25",
    help="Search method",
)
@click.option("--limit", "-l", default=5, help="Maximum results to return")
@click.option("--refresh", is_flag=True, help="Refresh the tool cache before searching")
@click.option(
    "--schema", "-s", is_flag=True, help="Include full input schema in results"
)
@click.pass_context
def search(
    ctx: click.Context, query: str, method: str, limit: int, refresh: bool, schema: bool
) -> None:
    """Search for tools matching a query."""
    output: OutputHandler = ctx.obj["output"]
    config = get_config(ctx)

    cache = ToolCache(config)

    # Get or refresh tools
    if refresh or not cache.is_cache_valid():
        try:
            tools = asyncio.run(cache.refresh())
        except Exception as e:
            output.error(
                e, help_text="Failed to refresh tool cache. Check server connections."
            )
            return
    else:
        tools = cache.get_tools()

    if not tools:
        output.error(
            ValueError("No tools found"),
            help_text="Run 'mcpl list --refresh' to populate the tool cache.",
        )
        return

    # Search
    searcher = ToolSearcher(tools)
    try:
        results = searcher.search(query, SearchMethod(method), limit)
    except ValueError as e:
        output.error(e, help_text="Check your search query syntax.")
        return

    # Output
    if ctx.obj["json_mode"]:
        result_data = []
        for r in results:
            item = r.to_dict()
            item["requiredParams"] = r.tool.get_required_params()
            if schema:
                item["inputSchema"] = r.tool.input_schema
            result_data.append(item)

        output.success(
            {
                "query": query,
                "method": method,
                "results": result_data,
            }
        )
    else:
        if not results:
            click.echo(f"No tools found matching '{query}'")
        else:
            click.echo(f"Found {len(results)} tools matching '{query}':\n")
            for r in results:
                click.secho(f"[{r.tool.server}] ", fg="cyan", nl=False)
                click.secho(r.tool.name, fg="green", bold=True)
                if r.tool.description:
                    click.echo(
                        f"  {r.tool.description[:80]}{'...' if len(r.tool.description) > 80 else ''}"
                    )
                # Show required params
                required = r.tool.get_required_params()
                if required:
                    click.secho("  ⚡ Requires: ", fg="yellow", nl=False)
                    click.echo(", ".join(required))
                if schema:
                    click.secho("  Schema: ", fg="blue", nl=False)
                    click.echo(
                        json.dumps(r.tool.input_schema, indent=4).replace(
                            "\n", "\n    "
                        )
                    )
                click.echo()

            # Usage hint footer
            click.secho("─" * 50, dim=True)
            click.echo("To execute: ", nl=False)
            click.secho('mcpl call <server> <tool> \'{"param": "value"}\'', fg="cyan")
            click.echo("Full schema: ", nl=False)
            click.secho("mcpl inspect <server> <tool>", fg="cyan")


@main.command()
@click.argument("server")
@click.argument("tool")
@click.option("--example", "-e", is_flag=True, help="Include an example call command")
@click.pass_context
def inspect(ctx: click.Context, server: str, tool: str, example: bool) -> None:
    """Get the full definition of a specific tool."""
    output: OutputHandler = ctx.obj["output"]
    config = get_config(ctx)
    cache = ToolCache(config)

    # Try cache first
    tools = cache.get_tools()
    tool_info = next((t for t in tools if t.server == server and t.name == tool), None)

    # If not in cache, try fetching from server
    if not tool_info:
        manager = ConnectionManager(config)
        try:
            server_tools = asyncio.run(manager.list_tools(server))
            tool_info = next((t for t in server_tools if t.name == tool), None)
        except Exception as e:
            output.error(
                e,
                help_text=(
                    f"Failed to connect to server '{server}'.\n"
                    "Try 'mcpl verify' to check server connections."
                ),
            )
            return

    if not tool_info:
        output.error(
            ValueError(f"Tool '{tool}' not found on server '{server}'"),
            help_text=f"Use 'mcpl search {tool}' to find available tools.",
        )
        return

    result = tool_info.to_dict()
    if example:
        result["exampleCall"] = tool_info.get_example_call()

    output.success(result)


@main.command()
@click.argument("server")
@click.argument("tool")
@click.argument("arguments", required=False)
@click.option("--stdin", is_flag=True, help="Read arguments from stdin")
@click.option(
    "--no-daemon",
    is_flag=True,
    help="Bypass daemon and connect directly (slower but more reliable)",
)
@click.pass_context
def call(
    ctx: click.Context,
    server: str,
    tool: str,
    arguments: str | None,
    stdin: bool,
    no_daemon: bool,
) -> None:
    """Execute a tool on a server.

    ARGUMENTS should be a JSON object with the tool parameters.
    Use --stdin to read arguments from stdin for large payloads.

    By default, uses a persistent session daemon to maintain stateful connections
    to MCP servers across multiple calls. Use --no-daemon to bypass the daemon
    and connect directly (slower but more reliable for troubleshooting).
    """
    output: OutputHandler = ctx.obj["output"]
    config = get_config(ctx)

    # Parse arguments
    if stdin:
        arguments = sys.stdin.read()

    if not arguments:
        args_dict: dict[str, Any] = {}
    else:
        try:
            args_dict = json.loads(arguments)
        except json.JSONDecodeError as e:
            output.error(
                e,
                error_type="ArgumentParseError",
                help_text=(
                    "Arguments must be valid JSON.\n\n"
                    'Example: mcpl call github list_issues \'{"owner": "acme", "repo": "api"}\''
                ),
            )
            return

    try:
        if no_daemon:
            # Direct connection without daemon
            logger.debug(f"Calling {server}/{tool} directly (no daemon)")
            manager = ConnectionManager(config)

            # Pre-check: verify tool exists before calling
            tool_exists, available_tools = _check_tool_exists(server, tool, manager)
            if not tool_exists:
                similar = find_similar_tools(tool, available_tools)
                enriched_error = format_tool_suggestions(tool, server, similar)
                output.success({"result": enriched_error})
                return

            # Call the tool
            try:
                result = asyncio.run(manager.call_tool(server, tool, args_dict))
            except Exception as call_error:
                # Handle MCP protocol errors
                handled = _handle_mcp_exception(
                    call_error, server, tool, available_tools
                )
                if handled:
                    output.success(handled)
                    return
                raise  # Re-raise if not a known MCP error

            # Extract content from MCP result
            result_data: Any
            if hasattr(result, "content"):
                content = []
                for item in result.content:
                    if hasattr(item, "text"):
                        content.append(item.text)
                    elif hasattr(item, "data"):
                        content.append(item.data)
                    else:
                        content.append(str(item))
                result_data = content[0] if len(content) == 1 else content
            else:
                result_data = result

            # Check if tool returned an error (using MCP's isError field)
            is_error = getattr(result, "isError", False)
            if is_error:
                output.success({"result": result_data, "error": True})
                return

            output.success({"result": result_data})
        else:
            # Call the tool via session daemon (maintains persistent connections)
            logger.debug(f"Calling {server}/{tool} via daemon")
            session = SessionClient(config)
            result = asyncio.run(session.call_tool(server, tool, args_dict))
            # Result is already extracted by the daemon (and errors enriched)
            result_data = result.get("result", result)

            output.success({"result": result_data})
    except Exception as e:
        # The error message from daemon/connection already includes context
        # Only add help text if not already present in the error message
        error_str = str(e)
        error_lower = error_str.lower()
        help_text = None

        # Only add suggestions if the error message doesn't already contain them
        if (
            "no response from daemon" in error_lower
            or "failed to connect to daemon" in error_lower
        ):
            if "--no-daemon" not in error_str:
                help_text = "Try using --no-daemon flag to bypass the daemon."

        output.error(e, help_text=help_text)


def _handle_oauth_required_servers(
    ctx: click.Context,
    config: Config,
    cache: ToolCache,
    servers: list[str],
) -> None:
    """Prompt user to authenticate with servers that require OAuth.

    For each server in the list, asks the user if they want to authenticate.
    If they agree, runs the OAuth flow and retries the connection.
    """
    oauth_manager = get_oauth_manager()

    for server_name in servers:
        server_config = config.servers.get(server_name)
        if not server_config or not server_config.is_http():
            continue

        url = server_config.get_resolved_url()

        # Check if already authenticated (token might have been obtained earlier in loop)
        if oauth_manager.has_valid_token(url):
            continue

        click.echo()
        click.secho(
            f"Server '{server_name}' requires OAuth authentication.", fg="yellow"
        )

        # Prompt user
        if not click.confirm("Would you like to authenticate now?", default=True):
            click.echo(f"Skipped. Run 'mcpl auth login {server_name}' to authenticate later.")
            continue

        # Run OAuth flow
        click.echo()
        try:
            def on_status(message: str) -> None:
                click.echo(f"  {message}")

            token = asyncio.run(
                oauth_manager.authenticate(
                    server_url=url,
                    client_id=server_config.get_resolved_oauth_client_id(),
                    client_secret=server_config.get_resolved_oauth_client_secret(),
                    scopes=server_config.oauth_scopes or None,
                    on_status=on_status,
                )
            )

            click.secho(f"✓ Authenticated with '{server_name}'", fg="green")

            # Retry connection for this server
            click.echo(f"  Retrying connection...")

            def retry_progress(
                name: str, status: str, tool_count: int | None, error: str | None
            ) -> None:
                if status == "done":
                    click.secho(f"  [{name}] ", fg="cyan", nl=False)
                    click.secho("OK", fg="green", nl=False)
                    click.echo(f" ({tool_count} tools)")
                elif status == "error":
                    click.secho(f"  [{name}] ", fg="cyan", nl=False)
                    click.secho("FAILED", fg="red", nl=False)
                    click.echo(f" - {error}")

            asyncio.run(
                cache.refresh(force=True, on_progress=retry_progress, servers=[server_name])
            )

        except OAuthFlowError as e:
            click.secho(f"✗ Authentication failed: {e}", fg="red")
            click.echo(f"  Run 'mcpl auth login {server_name}' to try again.")
        except Exception as e:
            click.secho(f"✗ Error: {e}", fg="red")


@main.command("list")
@click.argument("server", required=False)
@click.option("--refresh", is_flag=True, help="Refresh the tool cache")
@click.pass_context
def list_cmd(ctx: click.Context, server: str | None, refresh: bool) -> None:
    """List servers and their tools.

    Without arguments, lists all configured servers.
    With SERVER argument, lists all tools for that server.
    """
    output: OutputHandler = ctx.obj["output"]
    config = get_config(ctx)
    cache = ToolCache(config)
    state = ServerState(config)

    # Refresh cache if requested (only enabled servers)
    if refresh:
        enabled_servers = list(state.get_enabled_servers().keys())
        disabled_servers = state.get_disabled_servers()

        if not ctx.obj["json_mode"]:
            click.secho("\nRefreshing tool cache...\n", bold=True)

        # Track servers that need OAuth authentication
        oauth_required_servers: list[str] = []

        def on_progress(
            server_name: str, status: str, tool_count: int | None, error: str | None
        ) -> None:
            """Display progress updates during cache refresh."""
            if ctx.obj["json_mode"]:
                return
            if status == "connecting":
                click.secho(f"  [{server_name}] ", fg="cyan", nl=False)
                click.secho("connecting...", fg="yellow")
            elif status == "done":
                # Move cursor up one line and overwrite
                click.echo("\033[A\033[K", nl=False)
                click.secho(f"  [{server_name}] ", fg="cyan", nl=False)
                click.secho("OK", fg="green", nl=False)
                click.echo(f" ({tool_count} tools)")
            elif status == "error":
                # Move cursor up one line and overwrite
                click.echo("\033[A\033[K", nl=False)
                click.secho(f"  [{server_name}] ", fg="cyan", nl=False)
                # Check if this is an OAuth error
                if error and "requires OAuth" in error:
                    click.secho("AUTH REQUIRED", fg="yellow")
                    oauth_required_servers.append(server_name)
                else:
                    click.secho("FAILED", fg="red", nl=False)
                    click.echo(f" - {error}")

        try:
            asyncio.run(
                cache.refresh(
                    force=True, on_progress=on_progress, servers=enabled_servers
                )
            )
            # Show skipped disabled servers
            if disabled_servers and not ctx.obj["json_mode"]:
                click.echo()
                for name in disabled_servers:
                    click.secho(f"  [{name}] ", fg="cyan", nl=False)
                    click.secho("SKIPPED", dim=True, nl=False)
                    click.echo(" (disabled)")

            # Handle servers that need OAuth authentication
            if oauth_required_servers and not ctx.obj["json_mode"]:
                click.echo()
                _handle_oauth_required_servers(
                    ctx, config, cache, oauth_required_servers
                )

            if not ctx.obj["json_mode"]:
                click.secho("\nTool cache refreshed.", fg="green")
        except Exception as e:
            output.error(e, help_text="Failed to refresh tool cache.")
            return

    if server:
        # List tools for specific server
        tools = cache.get_tools()
        server_tools = [t for t in tools if t.server == server]

        if not server_tools:
            # Try fetching directly
            manager = ConnectionManager(config)
            try:
                server_tools = asyncio.run(manager.list_tools(server))
            except Exception as e:
                output.error(
                    e,
                    help_text=(
                        f"Failed to list tools from server '{server}'.\n"
                        "Try:\n"
                        "  1. Run 'mcpl verify' to check server connections\n"
                        "  2. Run 'mcpl list' to see all configured servers"
                    ),
                )
                return

        if ctx.obj["json_mode"]:
            output.success(
                {
                    "server": server,
                    "tools": [
                        {
                            "name": t.name,
                            "description": t.description,
                            "requiredParams": t.get_required_params(),
                        }
                        for t in server_tools
                    ],
                }
            )
        else:
            click.secho(f"\nTools for [{server}]:\n", bold=True)
            for t in server_tools:
                click.secho(f"  {t.name}", fg="green", bold=True)
                if t.description:
                    click.echo(
                        f"    {t.description[:70]}{'...' if len(t.description) > 70 else ''}"
                    )
                # Show required params to help AI agents know what's needed upfront
                required = t.get_required_params()
                if required:
                    click.secho("    ⚡ Requires: ", fg="yellow", nl=False)
                    click.echo(", ".join(required))
    else:
        # List all servers
        tools = cache.get_tools()
        server_tool_counts: dict[str, int] = {}
        for t in tools:
            server_tool_counts[t.server] = server_tool_counts.get(t.server, 0) + 1

        servers_data: list[dict[str, Any]] = []
        for name in config.servers:
            tool_count = server_tool_counts.get(name, 0)
            is_disabled = state.is_disabled(name)
            if is_disabled:
                status = "disabled"
            elif tool_count > 0:
                status = "cached"
            else:
                status = "not cached"
            servers_data.append(
                {
                    "name": name,
                    "status": status,
                    "tools": tool_count,
                    "disabled": is_disabled,
                }
            )

        if ctx.obj["json_mode"]:
            output.success({"servers": servers_data})
        else:
            click.secho("\nConfigured MCP Servers:\n", bold=True)
            for s in servers_data:
                if s["status"] == "disabled":
                    status_color = "red"
                elif s["status"] == "cached":
                    status_color = "green"
                else:
                    status_color = "yellow"
                click.secho(f"  [{s['name']}] ", fg="cyan", nl=False)
                click.secho(f"{s['status']}", fg=status_color, nl=False)
                if s["tools"] > 0:
                    click.echo(f" ({s['tools']} tools)")
                else:
                    click.echo()
            click.echo(f"\nConfig: {config.config_path}")
            if config.env_paths:
                if len(config.env_paths) == 1:
                    click.echo(f"Env: {config.env_paths[0]}")
                else:
                    click.echo(f"Env: {', '.join(str(p) for p in config.env_paths)}")


@main.group()
@click.pass_context
def session(ctx: click.Context) -> None:
    """Manage the session daemon for persistent MCP connections."""
    pass


@session.command("status")
@click.pass_context
def session_status(ctx: click.Context) -> None:
    """Show the status of the session daemon and connected servers."""
    output: OutputHandler = ctx.obj["output"]
    config = get_config(ctx)

    session_client = SessionClient(config)
    try:
        status = asyncio.run(session_client.get_status())

        if ctx.obj["json_mode"]:
            output.success(status)
        else:
            click.secho("\nSession Daemon Status:\n", bold=True)
            click.echo(f"  Parent PID: {status.get('parent_pid', 'unknown')}")
            click.echo(f"  Running: {status.get('running', False)}")
            click.echo()

            servers = status.get("servers", {})
            if servers:
                click.secho("Connected Servers:", bold=True)
                for name, info in servers.items():
                    connected = info.get("connected", False)
                    error = info.get("error")
                    status_color = "green" if connected else "red"
                    status_text = "connected" if connected else "disconnected"
                    click.secho(f"  [{name}] ", fg="cyan", nl=False)
                    click.secho(status_text, fg=status_color)
                    if error:
                        click.secho(f"    Error: {error}", fg="red")
            else:
                click.echo("  No servers connected yet.")
    except Exception as e:
        if "Failed to connect" in str(e) or "No response" in str(e):
            if ctx.obj["json_mode"]:
                output.success({"running": False, "servers": {}})
            else:
                click.echo("Session daemon is not running.")
        else:
            output.error(
                e,
                help_text="Run 'mcpl session stop' and retry if the daemon is in a bad state.",
            )


@session.command("stop")
@click.pass_context
def session_stop(ctx: click.Context) -> None:
    """Stop the session daemon."""
    output: OutputHandler = ctx.obj["output"]
    config = get_config(ctx)

    session_client = SessionClient(config)
    try:
        asyncio.run(session_client.shutdown())
        if ctx.obj["json_mode"]:
            output.success({"message": "Session daemon stopped"})
        else:
            click.secho("Session daemon stopped.", fg="green")
    except Exception as e:
        if "Failed to connect" in str(e):
            if ctx.obj["json_mode"]:
                output.success({"message": "Session daemon was not running"})
            else:
                click.echo("Session daemon was not running.")
        else:
            output.error(
                e,
                help_text=(
                    "Failed to stop the daemon cleanly.\n"
                    "The daemon may have crashed. Socket and PID files will be cleaned up on next run."
                ),
            )


# =============================================================================
# OAuth Authentication Commands
# =============================================================================


@main.group()
@click.pass_context
def auth(ctx: click.Context) -> None:
    """Manage OAuth authentication for MCP servers.

    OAuth authentication allows mcpl to connect to MCP servers that require
    authorization, such as Notion, Figma, and other remote services.
    """
    pass


@auth.command("login")
@click.argument("server")
@click.option("--scope", multiple=True, help="Additional scopes to request")
@click.option("--force", is_flag=True, help="Force re-authentication even if already logged in")
@click.option("--client-id", help="Use a specific OAuth client ID")
@click.option(
    "--client-secret-stdin",
    is_flag=True,
    help="Read client secret from stdin (one line)",
)
@click.option("--timeout", default=120, help="Timeout for browser callback (seconds)")
@click.pass_context
def auth_login(
    ctx: click.Context,
    server: str,
    scope: tuple[str, ...],
    force: bool,
    client_id: str | None,
    client_secret_stdin: bool,
    timeout: int,
) -> None:
    """Authenticate with an OAuth-protected MCP server.

    Opens a browser for authorization and stores tokens securely.
    Tokens are encrypted and stored in ~/.cache/mcp-launchpad/oauth/

    Client secret can be provided via:
      - MCPL_CLIENT_SECRET environment variable
      - Config file with oauth_client_secret (supports $ENV interpolation)
      - Interactive prompt (when DCR is unavailable)
      - --client-secret-stdin flag (reads one line from stdin)

    Example:
        mcpl auth login notion
        mcpl auth login figma --scope "read write"
        mcpl auth login custom --client-id my-client-id
        echo "secret" | mcpl auth login custom --client-id my-id --client-secret-stdin
    """
    output: OutputHandler = ctx.obj["output"]
    config = get_config(ctx)

    # Validate server exists
    if server not in config.servers:
        available = ", ".join(sorted(config.servers.keys()))
        output.error(
            ValueError(f"Server '{server}' not found"),
            help_text=f"Available servers: {available}",
        )
        return

    server_config = config.servers[server]

    # Check if it's an HTTP server
    if not server_config.is_http():
        output.error(
            ValueError(f"Server '{server}' is a stdio server, not HTTP"),
            help_text="OAuth authentication is only supported for HTTP servers.",
        )
        return

    url = server_config.get_resolved_url()
    oauth_manager = get_oauth_manager()

    # Check if already authenticated (unless --force)
    try:
        has_token = oauth_manager.has_valid_token(url)
    except TokenDecryptionError:
        # Token storage corrupted/key changed - proceed with login to overwrite
        if not ctx.obj["json_mode"]:
            click.secho(
                "Warning: Could not read existing tokens (encryption key changed?).",
                fg="yellow",
            )
            click.echo("Proceeding with fresh authentication...")
            click.echo()
        has_token = False

    if not force and has_token:
        if ctx.obj["json_mode"]:
            output.success({"server": server, "status": "already_authenticated"})
        else:
            click.secho(f"Already authenticated with '{server}'.", fg="green")
            click.echo("Use --force to re-authenticate.")
        return

    # Get client credentials
    # Priority: stdin > env var > config
    config_client_id = client_id or server_config.get_resolved_oauth_client_id()

    # Resolve client secret from multiple sources
    resolved_client_secret: str | None = None
    if client_secret_stdin:
        # Read from stdin (non-interactive)
        if sys.stdin.isatty():
            output.error(
                ValueError("--client-secret-stdin requires piped input"),
                help_text="Usage: echo 'secret' | mcpl auth login server --client-secret-stdin",
            )
            return
        resolved_client_secret = sys.stdin.readline().rstrip("\n") or None
    elif os.environ.get("MCPL_CLIENT_SECRET"):
        resolved_client_secret = os.environ["MCPL_CLIENT_SECRET"]
    else:
        resolved_client_secret = server_config.get_resolved_oauth_client_secret()

    config_client_secret = resolved_client_secret

    # Status callback for CLI feedback
    def on_status(message: str) -> None:
        if not ctx.obj["json_mode"]:
            click.echo(message)

    # Prompt callback for manual client registration
    def prompt_for_credentials() -> tuple[str, str | None]:
        click.echo()
        click.secho(
            "Dynamic Client Registration is not available for this server.",
            fg="yellow",
        )
        click.echo("You'll need to register mcpl manually with the authorization server.")
        click.echo()
        entered_client_id = click.prompt("Enter client_id")
        entered_client_secret = click.prompt(
            "Enter client_secret (leave blank for public client)",
            default="",
            show_default=False,
            hide_input=True,
        )
        return entered_client_id, entered_client_secret or None

    # Run OAuth flow
    try:
        scopes = list(scope) if scope else server_config.oauth_scopes or None

        token = asyncio.run(
            oauth_manager.authenticate(
                server_url=url,
                client_id=config_client_id,
                client_secret=config_client_secret,
                scopes=scopes,
                callback_timeout=timeout,
                on_status=on_status,
                prompt_for_credentials=prompt_for_credentials,
            )
        )

        if ctx.obj["json_mode"]:
            output.success(
                {
                    "server": server,
                    "status": "authenticated",
                    "expires_at": token.expires_at.isoformat() if token.expires_at else None,
                    "scope": token.scope,
                }
            )
        else:
            click.echo()
            click.secho(f"Successfully authenticated with '{server}'!", fg="green")
            click.echo("Tokens stored securely in ~/.cache/mcp-launchpad/oauth/")

            # Warn if using fallback encryption (no keyring)
            if not oauth_manager.token_store.is_using_keyring():
                click.echo()
                click.secho(
                    "Warning: OS keyring not available. Using fallback encryption.",
                    fg="yellow",
                )
                click.echo(
                    "Tokens are encrypted but with reduced security. "
                    "Consider installing a keyring backend."
                )

            # Restart daemon to use new token
            click.echo()
            click.echo("Restarting session daemon to use new credentials...")
            session_client = SessionClient(config)
            try:
                asyncio.run(session_client.shutdown())
            except Exception:
                pass  # Daemon may not be running

    except OAuthFlowError as e:
        output.error(
            e,
            help_text=(
                "OAuth authentication failed.\n\n"
                "Common issues:\n"
                "- The authorization server may not support Dynamic Client Registration\n"
                "- You may need to configure oauth_client_id in your config\n"
                "- The server may have denied the authorization request"
            ),
        )


@auth.command("logout")
@click.argument("server", required=False)
@click.option("--all", "logout_all", is_flag=True, help="Clear all stored tokens and credentials")
@click.pass_context
def auth_logout(ctx: click.Context, server: str | None, logout_all: bool) -> None:
    """Remove stored authentication for a server.

    This deletes the stored OAuth tokens for the specified server.
    Use --all to clear all stored tokens (useful when encryption key changes).

    Example:
        mcpl auth logout notion
        mcpl auth logout --all
    """
    output: OutputHandler = ctx.obj["output"]
    config = get_config(ctx)
    oauth_manager = get_oauth_manager()

    # Handle --all flag
    if logout_all:
        oauth_manager.token_store.clear_all()
        if ctx.obj["json_mode"]:
            output.success({"action": "clear_all", "success": True})
        else:
            click.secho("Cleared all stored authentication data.", fg="green")
        return

    # Server is required if not using --all
    if not server:
        output.error(
            ValueError("SERVER argument is required unless using --all"),
            help_text="Usage: mcpl auth logout <server> or mcpl auth logout --all",
        )
        return

    # Validate server exists
    if server not in config.servers:
        available = ", ".join(sorted(config.servers.keys()))
        output.error(
            ValueError(f"Server '{server}' not found"),
            help_text=f"Available servers: {available}",
        )
        return

    server_config = config.servers[server]
    if not server_config.is_http():
        output.error(
            ValueError(f"Server '{server}' is a stdio server"),
            help_text="OAuth authentication is only relevant for HTTP servers.",
        )
        return

    url = server_config.get_resolved_url()

    try:
        # Use async logout for server-side token revocation (RFC 7009)
        if not ctx.obj["json_mode"]:
            click.echo(f"Logging out from '{server}'...")

        deleted = asyncio.run(oauth_manager.logout_async(url))
    except TokenDecryptionError:
        # Can't read tokens, but we can still try to clear them
        click.secho(
            "Warning: Could not read existing tokens (encryption key changed?).",
            fg="yellow",
        )
        click.echo("Use 'mcpl auth logout --all' to clear all stored data.")
        return

    if ctx.obj["json_mode"]:
        output.success({"server": server, "logged_out": deleted})
    else:
        if deleted:
            click.secho(f"Logged out from '{server}'.", fg="green")
            click.echo("Tokens revoked and deleted locally.")
        else:
            click.echo(f"No stored authentication found for '{server}'.")


@auth.command("status")
@click.argument("server", required=False)
@click.pass_context
def auth_status(ctx: click.Context, server: str | None) -> None:
    """Show authentication status for servers.

    Without SERVER argument, shows status for all HTTP servers.
    With SERVER argument, shows detailed status for that server.

    Example:
        mcpl auth status
        mcpl auth status notion
    """
    output: OutputHandler = ctx.obj["output"]
    config = get_config(ctx)
    oauth_manager = get_oauth_manager()

    if server:
        # Show status for specific server
        if server not in config.servers:
            available = ", ".join(sorted(config.servers.keys()))
            output.error(
                ValueError(f"Server '{server}' not found"),
                help_text=f"Available servers: {available}",
            )
            return

        server_config = config.servers[server]
        if not server_config.is_http():
            output.error(
                ValueError(f"Server '{server}' is a stdio server"),
                help_text="OAuth authentication is only relevant for HTTP servers.",
            )
            return

        url = server_config.get_resolved_url()

        try:
            status = oauth_manager.get_auth_status(url, server)
        except TokenDecryptionError:
            output.error(
                ValueError("Cannot read stored tokens"),
                help_text=(
                    "The token storage file cannot be decrypted.\n"
                    "This usually means the encryption key has changed.\n\n"
                    "To fix: Run 'mcpl auth logout --all' to clear tokens,\n"
                    "then re-authenticate with 'mcpl auth login <server>'."
                ),
            )
            return

        if ctx.obj["json_mode"]:
            output.success(status.to_dict())
        else:
            click.secho(f"\nOAuth Status for [{server}]:\n", bold=True)
            if status.authenticated:
                if status.expired:
                    click.secho("  Status: ", nl=False)
                    click.secho("expired", fg="yellow")
                else:
                    click.secho("  Status: ", nl=False)
                    click.secho("authenticated", fg="green")

                if status.expires_at:
                    click.echo(f"  Expires: {status.expires_at}")
                if status.scope:
                    click.echo(f"  Scopes: {status.scope}")
                click.echo(f"  Has refresh token: {status.has_refresh_token}")

                if status.expired:
                    click.echo()
                    click.secho(f"  Run: mcpl auth login {server}", fg="cyan")
            else:
                click.secho("  Status: ", nl=False)
                click.secho("not authenticated", fg="red")
                click.echo()
                click.secho(f"  Run: mcpl auth login {server}", fg="cyan")

            # Warn if using fallback encryption (no keyring)
            if not oauth_manager.token_store.is_using_keyring():
                click.echo()
                click.secho(
                    "Warning: OS keyring not available. Using fallback encryption.",
                    fg="yellow",
                )
    else:
        # Show status for all HTTP servers
        try:
            statuses = []
            for name, server_config in config.servers.items():
                if server_config.is_http():
                    url = server_config.get_resolved_url()
                    status = oauth_manager.get_auth_status(url, name)
                    statuses.append(status)
        except TokenDecryptionError:
            output.error(
                ValueError("Cannot read stored tokens"),
                help_text=(
                    "The token storage file cannot be decrypted.\n"
                    "This usually means the encryption key has changed.\n\n"
                    "To fix: Run 'mcpl auth logout --all' to clear tokens,\n"
                    "then re-authenticate with 'mcpl auth login <server>'."
                ),
            )
            return

        if ctx.obj["json_mode"]:
            output.success({"servers": [s.to_dict() for s in statuses]})
        else:
            if not statuses:
                click.echo("No HTTP servers configured.")
                return

            click.secho("\nOAuth Authentication Status:\n", bold=True)
            for status in statuses:
                click.secho(f"  [{status.server_name}] ", fg="cyan", nl=False)

                if status.authenticated:
                    if status.expired:
                        click.secho("expired", fg="yellow")
                        if status.expires_at:
                            click.echo(f"    Expired: {status.expires_at}")
                    else:
                        click.secho("authenticated", fg="green")
                        if status.expires_at:
                            click.echo(f"    Expires: {status.expires_at}")
                        if status.scope:
                            click.echo(f"    Scopes: {status.scope}")
                else:
                    click.secho("not authenticated", fg="red")

            click.echo()

            # Warn if using fallback encryption (no keyring)
            if not oauth_manager.token_store.is_using_keyring():
                click.secho(
                    "Warning: OS keyring not available. Using fallback encryption.",
                    fg="yellow",
                )
                click.echo()

            # Show hint for unauthenticated servers
            unauthenticated = [s for s in statuses if not s.authenticated]
            if unauthenticated:
                click.echo("To authenticate: ", nl=False)
                click.secho("mcpl auth login <server>", fg="cyan")


@main.command()
@click.option(
    "--timeout", "-t", default=30, help="Connection timeout per server in seconds"
)
@click.pass_context
def verify(ctx: click.Context, timeout: int) -> None:
    """Verify all MCP servers are working.

    Tests each configured server by connecting and listing its tools.
    This is useful for quickly checking that all servers are properly
    configured and responsive.
    """
    import os

    output: OutputHandler = ctx.obj["output"]
    config = get_config(ctx)
    state = ServerState(config)

    # Set timeout via environment for the connection manager
    old_timeout = os.environ.get("MCPL_CONNECTION_TIMEOUT")
    os.environ["MCPL_CONNECTION_TIMEOUT"] = str(timeout)

    results: list[dict[str, Any]] = []
    all_passed = True

    if not ctx.obj["json_mode"]:
        click.secho("\nVerifying MCP Servers...\n", bold=True)

    async def verify_server(server_name: str) -> dict[str, Any]:
        """Verify a single server by listing its tools."""
        manager = ConnectionManager(config)
        try:
            tools = await manager.list_tools(server_name)
            return {
                "server": server_name,
                "status": "ok",
                "tools": len(tools),
                "error": None,
            }
        except Exception as e:
            return {
                "server": server_name,
                "status": "error",
                "tools": 0,
                "error": str(e).split("\n")[0],  # First line of error
            }

    # Test each enabled server
    for server_name in state.get_enabled_servers():
        result = asyncio.run(verify_server(server_name))
        results.append(result)

        if result["status"] != "ok":
            all_passed = False

        if not ctx.obj["json_mode"]:
            if result["status"] == "ok":
                click.secho(f"  [{server_name}] ", fg="cyan", nl=False)
                click.secho("OK", fg="green", nl=False)
                click.echo(f" ({result['tools']} tools)")
            else:
                click.secho(f"  [{server_name}] ", fg="cyan", nl=False)
                click.secho("FAILED", fg="red", nl=False)
                click.echo(f" - {result['error']}")

    # Show disabled servers
    disabled_servers = state.get_disabled_servers()
    if disabled_servers and not ctx.obj["json_mode"]:
        click.echo()
        for server_name in disabled_servers:
            click.secho(f"  [{server_name}] ", fg="cyan", nl=False)
            click.secho("SKIPPED", dim=True, nl=False)
            click.echo(" (disabled)")

    # Restore original timeout
    if old_timeout is not None:
        os.environ["MCPL_CONNECTION_TIMEOUT"] = old_timeout
    else:
        os.environ.pop("MCPL_CONNECTION_TIMEOUT", None)

    if ctx.obj["json_mode"]:
        output.success(
            {
                "results": results,
                "all_passed": all_passed,
                "total": len(results),
                "passed": sum(1 for r in results if r["status"] == "ok"),
                "failed": sum(1 for r in results if r["status"] != "ok"),
            }
        )
    else:
        click.echo()
        passed = sum(1 for r in results if r["status"] == "ok")
        failed = len(results) - passed
        if all_passed:
            click.secho(
                f"All {len(results)} servers verified successfully.", fg="green"
            )
        else:
            click.secho(
                f"Verification complete: {passed} passed, {failed} failed.", fg="yellow"
            )
            click.echo("\nTo debug a failed server, try:")
            for r in results:
                if r["status"] != "ok":
                    click.echo(f"  mcpl list {r['server']} --refresh")


@main.command("config")
@click.option(
    "--show-secrets",
    is_flag=True,
    help="Show actual values of environment variables (use with caution)",
)
@click.pass_context
def show_config(ctx: click.Context, show_secrets: bool) -> None:
    """Show the current MCP configuration.

    Displays the config file path, env file path, and all configured
    servers with their commands, arguments, and environment variables.
    """
    output: OutputHandler = ctx.obj["output"]
    config = get_config(ctx)
    state = ServerState(config)

    if ctx.obj["json_mode"]:
        servers_data = {}
        for name, server in config.servers.items():
            server_info: dict[str, Any] = {
                "type": server.server_type,
                "disabled": state.is_disabled(name),
            }
            if server.is_http():
                server_info["url"] = server.url
                if show_secrets:
                    server_info["headers"] = server.get_resolved_headers()
                else:
                    server_info["headers"] = {
                        k: "***" if v else "" for k, v in server.headers.items()
                    }
            else:
                server_info["command"] = server.command
                server_info["args"] = server.args
                if show_secrets:
                    server_info["env"] = server.get_resolved_env()
                else:
                    server_info["env"] = {
                        k: "***" if v else "" for k, v in server.env.items()
                    }
            servers_data[name] = server_info

        output.success(
            {
                "configPath": str(config.config_path) if config.config_path else None,
                "envPaths": [str(p) for p in config.env_paths] if config.env_paths else [],
                "servers": servers_data,
            }
        )
    else:
        click.secho("\nMCP Configuration\n", bold=True)
        click.echo(f"  Config file: {config.config_path or 'Not found'}")
        if config.env_paths:
            click.echo(f"  Env files: {', '.join(str(p) for p in config.env_paths)}")
        else:
            click.echo("  Env file: Not found")

        click.secho("\nConfigured Servers:\n", bold=True)
        for name, server in config.servers.items():
            click.secho(f"  [{name}]", fg="cyan", bold=True, nl=False)
            if state.is_disabled(name):
                click.secho(" (disabled)", fg="red")
            else:
                click.echo()

            if server.is_http():
                # HTTP server display
                click.echo("    type: http")
                click.echo(f"    url: {server.url}")
                if server.headers:
                    click.echo("    headers:")
                    if show_secrets:
                        resolved = server.get_resolved_headers()
                        for key, value in server.headers.items():
                            resolved_value = resolved.get(key, "")
                            if "${" in value:
                                click.secho(f"      {key}: ", nl=False)
                                click.secho(f"{resolved_value}", fg="yellow")
                            else:
                                click.echo(f"      {key}: {value}")
                    else:
                        for key, value in server.headers.items():
                            if "${" in value:
                                click.echo(f"      {key}: {value}")
                            else:
                                click.echo(f"      {key}: ***")
            else:
                # Stdio server display
                click.echo(f"    command: {server.command}")
                if server.args:
                    click.echo(f"    args: {' '.join(server.args)}")
                if server.env:
                    click.echo("    env:")
                    if show_secrets:
                        resolved = server.get_resolved_env()
                        for key, value in server.env.items():
                            resolved_value = resolved.get(key, "")
                            if "${" in value:
                                click.secho(f"      {key}: ", nl=False)
                                click.secho(f"{resolved_value}", fg="yellow")
                            else:
                                click.echo(f"      {key}: {value}")
                    else:
                        for key, value in server.env.items():
                            if "${" in value:
                                click.echo(f"      {key}: {value}")
                            else:
                                click.echo(f"      {key}: ***")
            click.echo()


@main.command()
@click.argument("server")
@click.pass_context
def enable(ctx: click.Context, server: str) -> None:
    """Enable a server for use with mcpl commands.

    Enabled servers will be included in refresh, verify, and other operations.
    """
    output: OutputHandler = ctx.obj["output"]
    config = get_config(ctx)
    state = ServerState(config)

    try:
        changed = state.enable(server)
        if ctx.obj["json_mode"]:
            output.success({"server": server, "enabled": True, "changed": changed})
        else:
            if changed:
                click.secho(f"Server '{server}' enabled.", fg="green")
            else:
                click.echo(f"Server '{server}' was already enabled.")
    except ValueError as e:
        output.error(
            e, help_text=f"Available servers: {', '.join(config.servers.keys())}"
        )


@main.command()
@click.argument("server")
@click.pass_context
def disable(ctx: click.Context, server: str) -> None:
    """Disable a server from mcpl commands.

    Disabled servers will be skipped during refresh, verify, and other operations.
    Use 'mcpl enable <server>' to re-enable.
    """
    output: OutputHandler = ctx.obj["output"]
    config = get_config(ctx)
    state = ServerState(config)

    try:
        changed = state.disable(server)
        if ctx.obj["json_mode"]:
            output.success({"server": server, "enabled": False, "changed": changed})
        else:
            if changed:
                click.secho(f"Server '{server}' disabled.", fg="yellow")
            else:
                click.echo(f"Server '{server}' was already disabled.")
    except ValueError as e:
        output.error(
            e, help_text=f"Available servers: {', '.join(config.servers.keys())}"
        )
