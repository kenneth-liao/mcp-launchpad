"""Session daemon for maintaining persistent MCP server connections."""

from __future__ import annotations

import asyncio
import logging
import os
import signal
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TextIO, cast

import httpx
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamable_http_client

from .config import Config, ServerConfig, load_config
from .ipc import IPCMessage, create_ipc_server
from .platform import (
    IS_WINDOWS,
    get_ide_session_anchor,
    get_parent_pid,
    get_pid_file_path,
    get_socket_path,
    is_ide_environment,
    is_process_alive,
)

# Logging configuration for daemon
logger = logging.getLogger("mcpl.daemon")

# How often to check if parent process is still alive (seconds)
PARENT_CHECK_INTERVAL = int(os.environ.get("MCPL_PARENT_CHECK_INTERVAL", "5"))

# Connection timeout for MCP servers (seconds) - configurable via env
CONNECTION_TIMEOUT = int(os.environ.get("MCPL_CONNECTION_TIMEOUT", "45"))

# Base delay before retrying a failed server connection (seconds)
# Actual delay uses exponential backoff: base * 2^(attempt-1)
RECONNECT_DELAY = int(os.environ.get("MCPL_RECONNECT_DELAY", "5"))

# Maximum reconnection attempts before giving up
MAX_RECONNECT_ATTEMPTS = int(os.environ.get("MCPL_MAX_RECONNECT_ATTEMPTS", "3"))


def _get_backoff_delay(attempt: int, base_delay: int = RECONNECT_DELAY) -> int:
    """Calculate exponential backoff delay for reconnection attempts.

    Returns base_delay * 2^(attempt-1), capped at 60 seconds.
    For default base_delay=5: attempt 1 -> 5s, attempt 2 -> 10s, attempt 3 -> 20s
    """
    delay = base_delay * (2 ** (attempt - 1))
    return int(min(delay, 60))  # Cap at 60 seconds

# Idle timeout for daemon shutdown (seconds) - 0 to disable
# In IDE environments, daemon shuts down after this period of inactivity
IDLE_TIMEOUT = int(os.environ.get("MCPL_IDLE_TIMEOUT", "3600"))  # 1 hour default

# How often to check IDE session anchor (seconds)
IDE_ANCHOR_CHECK_INTERVAL = int(os.environ.get("MCPL_IDE_ANCHOR_CHECK_INTERVAL", "10"))


@dataclass
class ServerState:
    """Tracks the state of a connected MCP server."""

    name: str
    session: ClientSession | None = None
    read_stream: Any = None
    write_stream: Any = None
    stderr_file: Any = None  # For stdio servers
    http_client: httpx.AsyncClient | None = None  # For HTTP servers
    connected: bool = False
    error: str | None = None


@dataclass
class DaemonState:
    """Overall daemon state."""

    config: Config
    servers: dict[str, ServerState] = field(default_factory=dict)
    parent_pid: int = 0
    running: bool = True
    last_activity: float = field(default_factory=time.time)
    ide_anchor: Path | None = None


class Daemon:
    """The session daemon that maintains persistent MCP connections."""

    def __init__(self, config: Config) -> None:
        self.state = DaemonState(
            config=config,
            parent_pid=get_parent_pid(),
            ide_anchor=get_ide_session_anchor(),
        )
        self._ipc_server = create_ipc_server(self._handle_request)
        self._connection_tasks: dict[str, asyncio.Task[None]] = {}

    async def start(self) -> None:
        """Start the daemon."""
        logger.info(f"Daemon starting, monitoring parent PID {self.state.parent_pid}")

        # Clean up any orphaned stderr files from previous daemon runs
        self._cleanup_orphaned_stderr_files()

        # Set up signal handlers for graceful shutdown
        self._setup_signal_handlers()

        # Write PID file
        self._write_pid_file()

        # Start IPC server
        await self._ipc_server.start()
        logger.info("IPC server started")

        # Pre-connect to all configured servers
        await self._connect_all_servers()

        # Start parent monitoring task
        parent_monitor = asyncio.create_task(self._monitor_parent())

        try:
            # Run until shutdown
            while self.state.running:
                await asyncio.sleep(1)
        finally:
            parent_monitor.cancel()
            await self._shutdown()

    def _setup_signal_handlers(self) -> None:
        """Set up signal handlers for graceful shutdown."""
        loop = asyncio.get_running_loop()

        def handle_signal(sig: signal.Signals) -> None:
            logger.info(f"Received signal {sig.name}, initiating shutdown")
            self.state.running = False

        # Register signal handlers
        if not IS_WINDOWS:
            # Unix signals
            for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
                loop.add_signal_handler(sig, handle_signal, sig)
        else:
            # Windows: only SIGTERM and SIGINT are supported
            for sig in (signal.SIGTERM, signal.SIGINT):
                signal.signal(sig, lambda s, f: handle_signal(signal.Signals(s)))

    async def _connect_all_servers(self) -> None:
        """Connect to all configured MCP servers."""
        for server_name in self.state.config.servers:
            task = asyncio.create_task(self._connect_server(server_name))
            self._connection_tasks[server_name] = task

    async def _connect_server(self, server_name: str) -> None:
        """Connect to a single MCP server and maintain the connection with auto-restart."""
        server_config = self.state.config.servers[server_name]

        if server_config.is_http():
            await self._connect_http_server(server_name, server_config)
        else:
            await self._connect_stdio_server(server_name, server_config)

    async def _connect_http_server(
        self, server_name: str, server_config: ServerConfig
    ) -> None:
        """Connect to an HTTP-based MCP server."""
        attempt = 0
        url = server_config.get_resolved_url()
        headers = server_config.get_resolved_headers()

        if not url:
            server_state = ServerState(
                name=server_name,
                error="HTTP server is missing 'url' in configuration",
            )
            self.state.servers[server_name] = server_state
            return

        while self.state.running and attempt < MAX_RECONNECT_ATTEMPTS:
            attempt += 1

            existing_state = self.state.servers.get(server_name)
            if not existing_state:
                server_state = ServerState(name=server_name)
                self.state.servers[server_name] = server_state
            else:
                server_state = existing_state
                server_state.error = None

            # Create httpx client with headers
            http_client = httpx.AsyncClient(
                headers=headers,
                timeout=httpx.Timeout(CONNECTION_TIMEOUT, connect=30.0),
            )
            server_state.http_client = http_client

            try:
                async with asyncio.timeout(CONNECTION_TIMEOUT):
                    async with streamable_http_client(
                        url, http_client=http_client, terminate_on_close=False
                    ) as (read, write, _get_session_id):
                        async with ClientSession(read, write) as session:
                            await session.initialize()

                            server_state.session = session
                            server_state.connected = True
                            attempt = 0  # Reset on success
                            logger.info(f"Connected to HTTP server: {server_name}")

                            # Keep connection alive until daemon shuts down
                            while self.state.running:
                                await asyncio.sleep(1)

                            # Clean exit
                            return

            except TimeoutError:
                server_state.error = (
                    f"Connection timed out after {CONNECTION_TIMEOUT}s.\n"
                    f"URL: {url}"
                )
                logger.error(f"Server {server_name}: {server_state.error}")
            except httpx.ConnectError as e:
                server_state.error = (
                    f"Could not connect to HTTP server.\n"
                    f"URL: {url}\n"
                    f"Error: {e}"
                )
                logger.error(f"Server {server_name}: {server_state.error}")
            except asyncio.CancelledError:
                logger.debug(f"Server {server_name}: connection task cancelled")
                return
            except Exception as e:
                server_state.error = str(e)
                logger.error(f"Server {server_name} error: {e}")
            finally:
                server_state.connected = False
                server_state.session = None
                await http_client.aclose()
                server_state.http_client = None

            # Wait before retrying with exponential backoff
            if self.state.running and attempt < MAX_RECONNECT_ATTEMPTS:
                delay = _get_backoff_delay(attempt)
                logger.info(
                    f"Server {server_name}: retrying in {delay}s "
                    f"(attempt {attempt}/{MAX_RECONNECT_ATTEMPTS})"
                )
                await asyncio.sleep(delay)

        if attempt >= MAX_RECONNECT_ATTEMPTS:
            logger.error(
                f"Server {server_name}: max reconnection attempts reached, giving up"
            )

    async def _connect_stdio_server(
        self, server_name: str, server_config: ServerConfig
    ) -> None:
        """Connect to a stdio-based MCP server."""
        attempt = 0

        while self.state.running and attempt < MAX_RECONNECT_ATTEMPTS:
            attempt += 1

            # Build environment with resolved variables
            env = {**os.environ, **server_config.get_resolved_env()}

            server_params = StdioServerParameters(
                command=server_config.command,
                args=server_config.get_resolved_args(),
                env=env,
            )

            # Create stderr capture file with mcpl- prefix for easy identification
            stderr_tmp = tempfile.NamedTemporaryFile(
                mode="w+", prefix="mcpl-", suffix=f".{server_name}.stderr", delete=False
            )
            # Cast to TextIO for type checker
            stderr_file = cast(TextIO, stderr_tmp)

            server_state = self.state.servers.get(server_name)
            if not server_state:
                server_state = ServerState(name=server_name, stderr_file=stderr_tmp)
                self.state.servers[server_name] = server_state
            else:
                server_state.stderr_file = stderr_tmp
                server_state.error = None

            try:
                # Start the server process
                async with stdio_client(server_params, errlog=stderr_file) as (
                    read,
                    write,
                ):
                    async with ClientSession(read, write) as session:
                        # Timeout only applies to initialization
                        async with asyncio.timeout(CONNECTION_TIMEOUT):
                            await session.initialize()

                        server_state.session = session
                        server_state.connected = True
                        attempt = 0  # Reset attempt counter on successful connection
                        logger.info(f"Connected to server: {server_name}")

                        # Keep connection alive until daemon shuts down
                        while self.state.running:
                            await asyncio.sleep(1)

                        # Clean exit - don't retry
                        return

            except TimeoutError:
                server_state.error = (
                    f"Connection timed out after {CONNECTION_TIMEOUT}s. "
                    f"The server may be slow to initialize or unresponsive."
                )
                logger.error(f"Server {server_name}: {server_state.error}")
            except FileNotFoundError:
                server_state.error = (
                    f"Command not found: '{server_config.command}'\n"
                    "Ensure the server package is installed. Common fixes:\n"
                    "  - For uvx servers: uvx install <package-name>\n"
                    "  - For npx servers: npm install -g <package-name>\n"
                    "  - Check your PATH environment variable"
                )
                logger.error(
                    f"Server {server_name}: Command not found: {server_config.command}"
                )
                # Don't retry if command not found
                return
            except asyncio.CancelledError:
                # Task was cancelled (daemon shutting down) - clean exit
                logger.debug(f"Server {server_name}: connection task cancelled")
                return
            except Exception as e:
                error_str = str(e)
                # Provide more context for common errors
                if "unhandled errors in a TaskGroup" in error_str:
                    server_state.error = (
                        f"Server crashed during initialization: {error_str}\n"
                        "This usually indicates a bug in the MCP server or missing dependencies."
                    )
                else:
                    server_state.error = error_str
                logger.error(f"Server {server_name} error: {e}")
            finally:
                server_state.connected = False
                server_state.session = None
                # Clean up stderr file if we're going to retry (new one will be created)
                # Keep it on final failure so _shutdown can read it for diagnostics
                if self.state.running and attempt < MAX_RECONNECT_ATTEMPTS:
                    try:
                        stderr_tmp.close()
                        Path(stderr_tmp.name).unlink(missing_ok=True)
                    except Exception as e:
                        logger.debug(f"Failed to cleanup stderr file: {e}")

            # Wait before retrying with exponential backoff
            if self.state.running and attempt < MAX_RECONNECT_ATTEMPTS:
                delay = _get_backoff_delay(attempt)
                logger.info(
                    f"Server {server_name}: retrying in {delay}s "
                    f"(attempt {attempt}/{MAX_RECONNECT_ATTEMPTS})"
                )
                await asyncio.sleep(delay)

        if attempt >= MAX_RECONNECT_ATTEMPTS:
            logger.error(
                f"Server {server_name}: max reconnection attempts reached, giving up"
            )

    async def _handle_request(self, message: IPCMessage) -> IPCMessage:
        """Handle an incoming IPC request."""
        # Update last activity time for idle timeout tracking
        self.state.last_activity = time.time()

        action = message.action
        payload = message.payload

        try:
            if action == "call_tool":
                result = await self._call_tool(
                    payload["server"], payload["tool"], payload.get("arguments", {})
                )
                return IPCMessage(action="result", payload={"success": True, **result})

            elif action == "list_tools":
                result = await self._list_tools(payload["server"])
                return IPCMessage(action="result", payload={"success": True, **result})

            elif action == "status":
                return IPCMessage(action="result", payload=self._get_status())

            elif action == "shutdown":
                self.state.running = False
                return IPCMessage(
                    action="result",
                    payload={"success": True, "message": "Shutting down"},
                )

            else:
                return IPCMessage(
                    action="error", payload={"error": f"Unknown action: {action}"}
                )

        except Exception as e:
            logger.exception(f"Error handling request {action}")
            return IPCMessage(action="error", payload={"error": str(e)})

    async def _ensure_server_connected(self, server_name: str) -> ServerState:
        """Ensure a server is connected, starting connection if needed."""
        if server_name not in self.state.config.servers:
            available = list(self.state.config.servers.keys())
            raise ValueError(
                f"Server '{server_name}' not found in configuration.\n"
                f"Available servers: {', '.join(available) if available else '(none)'}\n\n"
                "Use 'mcpl list' to see all configured servers."
            )

        server_state = self.state.servers.get(server_name)

        # If not connected and no connection task running, start one
        if not server_state or (not server_state.connected and not server_state.error):
            if (
                server_name not in self._connection_tasks
                or self._connection_tasks[server_name].done()
            ):
                self._connection_tasks[server_name] = asyncio.create_task(
                    self._connect_server(server_name)
                )

        # Wait for connection to be established (with timeout)
        start_time = asyncio.get_event_loop().time()
        while asyncio.get_event_loop().time() - start_time < CONNECTION_TIMEOUT:
            server_state = self.state.servers.get(server_name)
            if server_state and server_state.connected and server_state.session:
                return server_state
            if server_state and server_state.error:
                error_msg = (
                    f"Server '{server_name}' connection failed: {server_state.error}"
                )
                # Include stderr output if available
                if server_state.stderr_file:
                    try:
                        stderr_path = Path(server_state.stderr_file.name)
                        if stderr_path.exists():
                            with open(stderr_path) as f:
                                stderr_content = f.read().strip()
                                if stderr_content:
                                    error_msg += (
                                        f"\n\nServer stderr output:\n{stderr_content}"
                                    )
                    except Exception:
                        pass  # If we can't read stderr, just use the basic error
                raise RuntimeError(error_msg)
            await asyncio.sleep(0.1)

        # Connection timed out - provide helpful error message
        server_config = self.state.config.servers.get(server_name)
        cmd_info = f"Command: {server_config.command}" if server_config else ""
        raise RuntimeError(
            f"Server '{server_name}' connection timed out after {CONNECTION_TIMEOUT}s\n"
            f"{cmd_info}\n\n"
            "The MCP server process may be slow to start or unresponsive.\n\n"
            "Try:\n"
            "  1. Run 'mcpl verify' to test the server connection directly\n"
            "  2. Check that the server command and dependencies are installed\n"
            "  3. Check required environment variables with 'mcpl config --show-secrets'\n"
            f"  4. Increase timeout: MCPL_CONNECTION_TIMEOUT={CONNECTION_TIMEOUT * 2}"
        )

    async def _call_tool(
        self, server_name: str, tool_name: str, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        """Call a tool on the specified server."""
        from .connection import ToolInfo
        from .suggestions import (
            find_similar_tools,
            format_tool_suggestions,
            format_validation_error,
        )

        server_state = await self._ensure_server_connected(server_name)

        if server_state.session is None:
            raise RuntimeError(f"Server '{server_name}' session is not available")

        # Pre-check: verify tool exists before calling (provides better error messages)
        available_tools: list[ToolInfo] = []
        tool_exists = False
        try:
            tools_result = await server_state.session.list_tools()
            available_tools = [
                ToolInfo(
                    server=server_name,
                    name=t.name,
                    description=t.description or "",
                    input_schema=t.inputSchema if hasattr(t, "inputSchema") else {},
                )
                for t in tools_result.tools
            ]
            tool_exists = any(t.name == tool_name for t in available_tools)
        except Exception as e:
            # If we can't list tools, proceed anyway - the call will fail with its own error
            logger.debug(
                f"Failed to list tools for pre-check on '{server_name}': {e}"
            )
            logger.warning(
                f"Could not verify tool '{tool_name}' on '{server_name}'. "
                "Proceeding with call - error suggestions may be limited if it fails."
            )
            tool_exists = True  # Assume it exists, let the call fail naturally

        if not tool_exists:
            # Tool doesn't exist - provide helpful suggestions
            similar = find_similar_tools(tool_name, available_tools)
            enriched_error = format_tool_suggestions(tool_name, server_name, similar)
            return {
                "result": enriched_error,
                "error": True,
                "error_type": "tool_not_found",
            }

        # Call the tool
        try:
            result = await server_state.session.call_tool(tool_name, arguments)
        except Exception as e:
            # Handle MCP protocol errors (JSON-RPC errors)
            error_str = str(e)

            # Check for JSON-RPC error codes
            if "-32601" in error_str:  # Method not found
                similar = find_similar_tools(tool_name, available_tools)
                enriched_error = format_tool_suggestions(
                    tool_name, server_name, similar, error_str
                )
                return {
                    "result": enriched_error,
                    "error": True,
                    "error_type": "tool_not_found",
                }
            elif "-32602" in error_str:  # Invalid params
                tool_info = next(
                    (t for t in available_tools if t.name == tool_name), None
                )
                enriched_error = format_validation_error(
                    tool_name, server_name, error_str, tool_info
                )
                return {
                    "result": enriched_error,
                    "error": True,
                    "error_type": "validation_error",
                }
            else:
                # Other protocol error - return as-is
                return {"result": error_str, "error": True, "error_type": "mcp_error"}

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
            # Tool explicitly marked result as error - return with error flag
            # but don't try to guess the error type from text
            return {"result": result_data, "error": True, "error_type": "tool_error"}

        return {"result": result_data}

    async def _list_tools(self, server_name: str) -> dict[str, Any]:
        """List tools from the specified server."""
        server_state = await self._ensure_server_connected(server_name)

        if server_state.session is None:
            raise RuntimeError(f"Server '{server_name}' session is not available")

        result = await server_state.session.list_tools()
        tools = [
            {
                "name": tool.name,
                "description": tool.description or "",
                "inputSchema": tool.inputSchema if hasattr(tool, "inputSchema") else {},
            }
            for tool in result.tools
        ]
        return {"tools": tools}

    def _get_status(self) -> dict[str, Any]:
        """Get daemon status information."""
        servers = {}
        for name, state in self.state.servers.items():
            servers[name] = {
                "connected": state.connected,
                "error": state.error,
            }

        return {
            "success": True,
            "parent_pid": self.state.parent_pid,
            "servers": servers,
            "running": self.state.running,
        }

    async def _monitor_parent(self) -> None:
        """Monitor session health and trigger shutdown when appropriate.

        Monitors different conditions based on environment:
        - IDE environments: Monitor IDE session anchor (e.g., VS Code socket) and idle timeout
        - Regular terminals: Monitor parent process liveness

        This ensures proper cleanup in all scenarios:
        - Terminal closed: parent PID monitoring
        - VS Code closed: IDE anchor (socket) disappears
        - Claude Code closed: IDE anchor or idle timeout
        - Explicit shutdown: 'mcpl session stop' sets running=False
        """
        if is_ide_environment():
            await self._monitor_ide_session()
        else:
            await self._monitor_parent_process()

    async def _monitor_ide_session(self) -> None:
        """Monitor IDE session health for graceful shutdown.

        Checks:
        1. IDE session anchor (e.g., VS Code Git IPC socket) - if it disappears,
           the IDE has closed
        2. Idle timeout - if no requests for IDLE_TIMEOUT seconds, shut down
        3. Our own socket - if it's been removed, something is wrong
        """
        anchor = self.state.ide_anchor
        socket_path = get_socket_path()

        if anchor:
            logger.info(
                f"Persistent mode - monitoring session anchor: {anchor}"
            )
        else:
            logger.info("Persistent mode - monitoring idle timeout only")

        if IDLE_TIMEOUT > 0:
            logger.info(f"Idle timeout enabled: {IDLE_TIMEOUT}s")

        while self.state.running:
            await asyncio.sleep(IDE_ANCHOR_CHECK_INTERVAL)

            # Check if IDE session anchor is gone (VS Code closed)
            if anchor and not anchor.exists():
                logger.info(f"IDE session anchor gone ({anchor}), shutting down")
                self.state.running = False
                break

            # Check idle timeout
            if IDLE_TIMEOUT > 0:
                idle_time = time.time() - self.state.last_activity
                if idle_time > IDLE_TIMEOUT:
                    logger.info(
                        f"Idle timeout reached ({idle_time:.0f}s > {IDLE_TIMEOUT}s), shutting down"
                    )
                    self.state.running = False
                    break

            # Check if our socket was removed (shouldn't happen normally)
            if not IS_WINDOWS and not socket_path.exists():
                logger.warning(f"Socket file removed ({socket_path}), shutting down")
                self.state.running = False
                break

    async def _monitor_parent_process(self) -> None:
        """Monitor parent process for regular terminal sessions."""
        while self.state.running:
            await asyncio.sleep(PARENT_CHECK_INTERVAL)

            if not is_process_alive(self.state.parent_pid):
                logger.info(
                    f"Parent process {self.state.parent_pid} no longer alive, shutting down"
                )
                self.state.running = False
                break

    async def _shutdown(self) -> None:
        """Clean shutdown of daemon."""
        logger.info("Daemon shutting down")

        # Stop IPC server first (stop accepting new requests)
        await self._ipc_server.stop()

        # Cancel all connection tasks and wait for them to complete
        for server_name, task in self._connection_tasks.items():
            if not task.done():
                logger.debug(f"Cancelling connection task for {server_name}")
                task.cancel()

        # Wait for all tasks to complete cancellation
        if self._connection_tasks:
            await asyncio.gather(
                *self._connection_tasks.values(),
                return_exceptions=True,  # Don't raise on CancelledError
            )
            self._connection_tasks.clear()

        # Close all server connections and clean up resources
        for state in self.state.servers.values():
            state.session = None
            # Clean up stdio server stderr files
            if state.stderr_file:
                try:
                    state.stderr_file.close()
                    Path(state.stderr_file.name).unlink(missing_ok=True)
                except Exception as e:
                    logger.debug(f"Failed to cleanup stderr file for {state.name}: {e}")
            # Clean up HTTP server clients
            if state.http_client:
                try:
                    await state.http_client.aclose()
                except Exception as e:
                    logger.debug(f"Failed to cleanup HTTP client for {state.name}: {e}")
                state.http_client = None

        # Remove PID file
        self._remove_pid_file()

        logger.info("Daemon stopped")

    def _write_pid_file(self) -> None:
        """Write the daemon's PID to the PID file."""
        pid_file = get_pid_file_path()
        pid_file.write_text(str(os.getpid()))

    def _remove_pid_file(self) -> None:
        """Remove the PID file."""
        pid_file = get_pid_file_path()
        pid_file.unlink(missing_ok=True)

    def _cleanup_orphaned_stderr_files(self) -> None:
        """Clean up orphaned stderr files from previous daemon runs.

        These files are created in the system temp directory with mcpl- prefix
        and .stderr suffix. If the daemon crashed previously, these files may remain.
        """
        import glob

        temp_dir = tempfile.gettempdir()
        # Use specific pattern to avoid matching unrelated files
        pattern = os.path.join(temp_dir, "mcpl-*.stderr")
        orphaned_files = glob.glob(pattern)

        if orphaned_files:
            logger.debug(f"Cleaning up {len(orphaned_files)} orphaned stderr file(s)")
            for filepath in orphaned_files:
                try:
                    os.unlink(filepath)
                    logger.debug(f"Removed orphaned stderr file: {filepath}")
                except Exception as e:
                    logger.debug(f"Failed to remove orphaned file {filepath}: {e}")


async def run_daemon(config_path: Path | None = None) -> None:
    """Run the daemon with the given configuration."""
    # Set up logging for daemon
    # Use force=True to ensure logging is configured even if basicConfig was called before
    # (e.g., in tests or when running in same process)
    log_level = os.environ.get("MCPL_LOG_LEVEL", "INFO").upper()
    logging.basicConfig(
        level=getattr(logging, log_level, logging.INFO),
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[logging.StreamHandler()],
        force=True,
    )

    config = load_config(config_path)
    daemon = Daemon(config)
    await daemon.start()


def main() -> None:
    """Entry point for running daemon directly."""
    import argparse

    parser = argparse.ArgumentParser(description="MCP Launchpad Session Daemon")
    parser.add_argument("--config", "-c", type=Path, help="Path to config file")
    args = parser.parse_args()

    try:
        asyncio.run(run_daemon(args.config))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
