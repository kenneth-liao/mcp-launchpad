"""CLI entry point for MCP Launchpad."""

from __future__ import annotations

import asyncio
import json
import logging
import sys
from pathlib import Path
from typing import Any, NoReturn

import click

from . import __version__
from .cache import ToolCache
from .config import Config, load_config
from .connection import ConnectionManager, ToolInfo
from .output import OutputHandler
from .search import SearchMethod, ToolSearcher
from .session import SessionClient
from .suggestions import (
    find_similar_tools,
    format_tool_suggestions,
    format_validation_error,
    is_tool_not_found_error,
    is_validation_error,
)

# Logger for CLI
logger = logging.getLogger("mcpl")


def _enrich_mcp_errors(
    result_data: Any, server: str, tool: str, manager: ConnectionManager, config: Config
) -> Any:
    """Enrich MCP error messages with helpful suggestions.

    Checks if the result contains a tool-not-found or validation error,
    and enriches it with similar tool suggestions or schema information.
    """
    if not isinstance(result_data, str):
        return result_data

    if is_tool_not_found_error(result_data):
        # Get available tools and suggest similar ones
        try:
            available_tools = asyncio.run(manager.list_tools(server))
            similar = find_similar_tools(tool, available_tools)
            return format_tool_suggestions(tool, server, similar)
        except Exception:
            # If we can't get suggestions, return original error
            pass

    elif is_validation_error(result_data):
        # Try to get tool info for better error message
        try:
            available_tools = asyncio.run(manager.list_tools(server))
            tool_info = next((t for t in available_tools if t.name == tool), None)
            return format_validation_error(tool, server, result_data, tool_info)
        except Exception:
            # If we can't enrich, return original error
            pass

    return result_data


@click.group()
@click.option("--json", "json_mode", is_flag=True, help="Output in JSON format")
@click.option("--config", "config_path", type=click.Path(exists=True), help="Path to MCP config file")
@click.option("--env-file", "env_path", type=click.Path(exists=True), help="Path to .env file")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose logging")
@click.version_option(version=__version__)
@click.pass_context
def main(ctx: click.Context, json_mode: bool, config_path: str | None, env_path: str | None, verbose: bool) -> None:
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
        raise SystemExit(1)  # Never reached due to sys.exit in output.error
    except json.JSONDecodeError as e:
        output.error(
            e,
            error_type="ConfigParseError",
            help_text="The config file contains invalid JSON. Check for syntax errors.",
        )
        raise SystemExit(1)  # Never reached due to sys.exit in output.error


@main.command()
@click.argument("query")
@click.option("--method", "-m", type=click.Choice(["bm25", "regex", "exact"]), default="bm25", help="Search method")
@click.option("--limit", "-l", default=10, help="Maximum results to return")
@click.option("--refresh", is_flag=True, help="Refresh the tool cache before searching")
@click.option("--schema", "-s", is_flag=True, help="Include full input schema in results")
@click.option("--first", "-1", is_flag=True, help="Return only the top result with full details")
@click.pass_context
def search(ctx: click.Context, query: str, method: str, limit: int, refresh: bool, schema: bool, first: bool) -> None:
    """Search for tools matching a query."""
    output: OutputHandler = ctx.obj["output"]
    config = get_config(ctx)

    cache = ToolCache(config)

    # Get or refresh tools
    if refresh or not cache.is_cache_valid():
        try:
            tools = asyncio.run(cache.refresh())
        except Exception as e:
            output.error(e, help_text="Failed to refresh tool cache. Check server connections.")
            return
    else:
        tools = cache.get_tools()

    if not tools:
        output.error(
            ValueError("No tools found"),
            help_text="Run 'mcpl list --refresh' to populate the tool cache.",
        )
        return

    # If --first flag is set, only return 1 result
    effective_limit = 1 if first else limit

    # Search
    searcher = ToolSearcher(tools)
    try:
        results = searcher.search(query, SearchMethod(method), effective_limit)
    except ValueError as e:
        output.error(e, help_text="Check your search query syntax.")
        return

    # Output
    if ctx.obj["json_mode"]:
        result_data = []
        for r in results:
            item = r.to_dict()
            item["requiredParams"] = r.tool.get_required_params()
            if schema or first:
                item["inputSchema"] = r.tool.input_schema
            if first:
                item["exampleCall"] = r.tool.get_example_call()
            result_data.append(item)

        output.success({
            "query": query,
            "method": method,
            "results": result_data,
        })
    else:
        if not results:
            click.echo(f"No tools found matching '{query}'")
        else:
            # For --first flag, show full details like inspect
            if first and results:
                r = results[0]
                click.secho(f"[{r.tool.server}] ", fg="cyan", nl=False)
                click.secho(r.tool.name, fg="green", bold=True)
                click.echo()
                if r.tool.description:
                    click.echo(f"{r.tool.description}")
                    click.echo()
                click.secho("Parameters:", bold=True)
                params_summary = r.tool.get_params_summary()
                click.echo(f"  {params_summary}")
                click.echo()
                if schema:
                    click.secho("Input Schema:", bold=True)
                    click.echo(json.dumps(r.tool.input_schema, indent=2))
                    click.echo()
                click.secho("Example:", bold=True)
                click.echo(f"  {r.tool.get_example_call()}")
            else:
                click.echo(f"Found {len(results)} tools matching '{query}':\n")
                for r in results:
                    click.secho(f"[{r.tool.server}] ", fg="cyan", nl=False)
                    click.secho(r.tool.name, fg="green", bold=True)
                    if r.tool.description:
                        click.echo(f"  {r.tool.description[:80]}{'...' if len(r.tool.description) > 80 else ''}")
                    # Show required params
                    required = r.tool.get_required_params()
                    if required:
                        click.secho(f"  ⚡ Requires: ", fg="yellow", nl=False)
                        click.echo(", ".join(required))
                    if schema:
                        click.secho("  Schema: ", fg="blue", nl=False)
                        click.echo(json.dumps(r.tool.input_schema, indent=4).replace("\n", "\n    "))
                    click.echo()

                # Usage hint footer
                click.secho("─" * 50, dim=True)
                click.echo("To execute: ", nl=False)
                click.secho("mcpl call <server> <tool> '{\"param\": \"value\"}'", fg="cyan")
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
            output.error(e)
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
@click.option("--no-daemon", is_flag=True, help="Bypass daemon and connect directly (slower but more reliable)")
@click.pass_context
def call(ctx: click.Context, server: str, tool: str, arguments: str | None, stdin: bool, no_daemon: bool) -> None:
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
                    "Example: mcpl call github list_issues '{\"owner\": \"acme\", \"repo\": \"api\"}'"
                ),
            )
            return

    try:
        if no_daemon:
            # Direct connection without daemon
            logger.debug(f"Calling {server}/{tool} directly (no daemon)")
            manager = ConnectionManager(config)
            result = asyncio.run(manager.call_tool(server, tool, args_dict))

            # Extract content from MCP result
            if hasattr(result, "content"):
                content = []
                for item in result.content:
                    if hasattr(item, "text"):
                        content.append(item.text)
                    elif hasattr(item, "data"):
                        content.append(item.data)
                    else:
                        content.append(str(item))
                result_data: Any = content[0] if len(content) == 1 else content
            else:
                result_data = result

            # Check for MCP errors and enrich them (same as daemon does)
            result_data = _enrich_mcp_errors(result_data, server, tool, manager, config)
        else:
            # Call the tool via session daemon (maintains persistent connections)
            logger.debug(f"Calling {server}/{tool} via daemon")
            session = SessionClient(config)
            result = asyncio.run(session.call_tool(server, tool, args_dict))
            # Result is already extracted by the daemon (and errors enriched)
            result_data = result.get("result", result)

        output.success({"result": result_data})
    except Exception as e:
        output.error(e)


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

    # Refresh cache if requested
    if refresh:
        try:
            asyncio.run(cache.refresh(force=True))
            if not ctx.obj["json_mode"]:
                click.secho("Tool cache refreshed.", fg="green")
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
                output.error(e)
                return

        if ctx.obj["json_mode"]:
            output.success({
                "server": server,
                "tools": [
                    {
                        "name": t.name,
                        "description": t.description,
                        "requiredParams": t.get_required_params(),
                    }
                    for t in server_tools
                ],
            })
        else:
            click.secho(f"\nTools for [{server}]:\n", bold=True)
            for t in server_tools:
                click.secho(f"  {t.name}", fg="green", bold=True)
                if t.description:
                    click.echo(f"    {t.description[:70]}{'...' if len(t.description) > 70 else ''}")
                # Show required params to help AI agents know what's needed upfront
                required = t.get_required_params()
                if required:
                    click.secho(f"    ⚡ Requires: ", fg="yellow", nl=False)
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
            status = "cached" if tool_count > 0 else "not cached"
            servers_data.append({
                "name": name,
                "status": status,
                "tools": tool_count,
            })

        if ctx.obj["json_mode"]:
            output.success({"servers": servers_data})
        else:
            click.secho("\nConfigured MCP Servers:\n", bold=True)
            for s in servers_data:
                status_color = "green" if s["status"] == "cached" else "yellow"
                click.secho(f"  [{s['name']}] ", fg="cyan", nl=False)
                click.secho(f"{s['status']}", fg=status_color, nl=False)
                if s["tools"] > 0:
                    click.echo(f" ({s['tools']} tools)")
                else:
                    click.echo()
            click.echo(f"\nConfig: {config.config_path}")
            if config.env_path:
                click.echo(f"Env: {config.env_path}")


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
                    status_text = "connected" if connected else f"disconnected"
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
            output.error(e)


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
            output.error(e)


@main.command()
@click.option("--timeout", "-t", default=30, help="Connection timeout per server in seconds")
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

    # Test each server
    for server_name in config.servers:
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

    # Restore original timeout
    if old_timeout is not None:
        os.environ["MCPL_CONNECTION_TIMEOUT"] = old_timeout
    else:
        os.environ.pop("MCPL_CONNECTION_TIMEOUT", None)

    if ctx.obj["json_mode"]:
        output.success({
            "results": results,
            "all_passed": all_passed,
            "total": len(results),
            "passed": sum(1 for r in results if r["status"] == "ok"),
            "failed": sum(1 for r in results if r["status"] != "ok"),
        })
    else:
        click.echo()
        passed = sum(1 for r in results if r["status"] == "ok")
        failed = len(results) - passed
        if all_passed:
            click.secho(f"All {len(results)} servers verified successfully.", fg="green")
        else:
            click.secho(f"Verification complete: {passed} passed, {failed} failed.", fg="yellow")
            click.echo("\nTo debug a failed server, try:")
            for r in results:
                if r["status"] != "ok":
                    click.echo(f"  mcpl list {r['server']} --refresh")
