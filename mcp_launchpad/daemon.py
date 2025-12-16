"""Session daemon for maintaining persistent MCP server connections."""

import asyncio
import logging
import os
import signal
import sys
import tempfile
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from .config import Config, load_config
from .ipc import IPCMessage, create_ipc_server
from .platform import get_parent_pid, get_pid_file_path, is_process_alive

# Logging configuration for daemon
logger = logging.getLogger("mcpl.daemon")

# How often to check if parent process is still alive (seconds)
PARENT_CHECK_INTERVAL = 5

# Connection timeout for MCP servers (seconds)
CONNECTION_TIMEOUT = 30

# Delay before retrying a failed server connection (seconds)
RECONNECT_DELAY = 5

# Maximum reconnection attempts before giving up
MAX_RECONNECT_ATTEMPTS = 3


@dataclass
class ServerState:
    """Tracks the state of a connected MCP server."""

    name: str
    session: ClientSession | None = None
    read_stream: Any = None
    write_stream: Any = None
    stderr_file: Any = None
    connected: bool = False
    error: str | None = None


@dataclass
class DaemonState:
    """Overall daemon state."""

    config: Config
    servers: dict[str, ServerState] = field(default_factory=dict)
    parent_pid: int = 0
    running: bool = True


class Daemon:
    """The session daemon that maintains persistent MCP connections."""

    def __init__(self, config: Config):
        self.state = DaemonState(config=config, parent_pid=get_parent_pid())
        self._ipc_server = create_ipc_server(self._handle_request)
        self._connection_tasks: dict[str, asyncio.Task] = {}
        self._contexts: dict[str, Any] = {}  # Store context managers

    async def start(self) -> None:
        """Start the daemon."""
        logger.info(f"Daemon starting, monitoring parent PID {self.state.parent_pid}")

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

    async def _connect_all_servers(self) -> None:
        """Connect to all configured MCP servers."""
        for server_name in self.state.config.servers:
            asyncio.create_task(self._connect_server(server_name))

    async def _connect_server(self, server_name: str) -> None:
        """Connect to a single MCP server and maintain the connection with auto-restart."""
        server_config = self.state.config.servers[server_name]
        attempt = 0

        while self.state.running and attempt < MAX_RECONNECT_ATTEMPTS:
            attempt += 1

            # Build environment with resolved variables
            env = {**os.environ, **server_config.get_resolved_env()}

            server_params = StdioServerParameters(
                command=server_config.command,
                args=server_config.args,
                env=env,
            )

            # Create stderr capture file
            stderr_file = tempfile.NamedTemporaryFile(
                mode="w+", suffix=f".{server_name}.stderr", delete=False
            )

            server_state = self.state.servers.get(server_name)
            if not server_state:
                server_state = ServerState(name=server_name, stderr_file=stderr_file)
                self.state.servers[server_name] = server_state
            else:
                server_state.stderr_file = stderr_file
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

            except asyncio.TimeoutError:
                server_state.error = f"Connection timed out after {CONNECTION_TIMEOUT}s"
                logger.error(f"Server {server_name}: {server_state.error}")
            except FileNotFoundError:
                server_state.error = f"Command not found: {server_config.command}"
                logger.error(f"Server {server_name}: {server_state.error}")
                # Don't retry if command not found
                return
            except Exception as e:
                server_state.error = str(e)
                logger.error(f"Server {server_name} error: {e}")
            finally:
                server_state.connected = False
                server_state.session = None

            # Wait before retrying
            if self.state.running and attempt < MAX_RECONNECT_ATTEMPTS:
                logger.info(
                    f"Server {server_name}: retrying in {RECONNECT_DELAY}s "
                    f"(attempt {attempt}/{MAX_RECONNECT_ATTEMPTS})"
                )
                await asyncio.sleep(RECONNECT_DELAY)

        if attempt >= MAX_RECONNECT_ATTEMPTS:
            logger.error(
                f"Server {server_name}: max reconnection attempts reached, giving up"
            )

    async def _handle_request(self, message: IPCMessage) -> IPCMessage:
        """Handle an incoming IPC request."""
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
                    action="result", payload={"success": True, "message": "Shutting down"}
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
            raise ValueError(f"Server '{server_name}' not found in configuration")

        server_state = self.state.servers.get(server_name)

        # If not connected and no connection task running, start one
        if not server_state or (not server_state.connected and not server_state.error):
            if server_name not in self._connection_tasks or self._connection_tasks[server_name].done():
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
                raise RuntimeError(f"Server '{server_name}' connection failed: {server_state.error}")
            await asyncio.sleep(0.1)

        raise RuntimeError(f"Server '{server_name}' connection timed out")

    async def _call_tool(
        self, server_name: str, tool_name: str, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        """Call a tool on the specified server."""
        server_state = await self._ensure_server_connected(server_name)

        result = await server_state.session.call_tool(tool_name, arguments)

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
            result_data = content[0] if len(content) == 1 else content
        else:
            result_data = result

        return {"result": result_data}

    async def _list_tools(self, server_name: str) -> dict[str, Any]:
        """List tools from the specified server."""
        server_state = await self._ensure_server_connected(server_name)

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
        """Monitor if parent process is still alive."""
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

        # Stop IPC server
        await self._ipc_server.stop()

        # Close all server connections (they'll close when context exits)
        for state in self.state.servers.values():
            state.session = None
            if state.stderr_file:
                try:
                    state.stderr_file.close()
                    Path(state.stderr_file.name).unlink(missing_ok=True)
                except Exception:
                    pass

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


async def run_daemon(config_path: Path | None = None) -> None:
    """Run the daemon with the given configuration."""
    # Set up logging for daemon
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[logging.StreamHandler()],
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

