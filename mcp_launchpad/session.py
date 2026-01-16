"""Session client for communicating with the daemon."""

import asyncio
import logging
import os
import subprocess
import sys
import time
from typing import Any

from .config import Config

# Logger for session client
logger = logging.getLogger("mcpl.session")
from .ipc import IPCMessage, connect_to_daemon, read_message, write_message
from .platform import (
    IS_WINDOWS,
    get_legacy_pid_file_path,
    get_legacy_socket_path,
    get_log_file_path,
    get_pid_file_path,
    get_session_id,
    get_socket_path,
    is_process_alive,
)

# How long to wait for daemon to start (seconds) - configurable via env
DAEMON_START_TIMEOUT = int(os.environ.get("MCPL_DAEMON_START_TIMEOUT", "30"))

# How long to wait between connection attempts (seconds)
DAEMON_CONNECT_RETRY_DELAY = float(
    os.environ.get("MCPL_DAEMON_CONNECT_RETRY_DELAY", "0.2")
)


class SessionClient:
    """Client for communicating with the session daemon."""

    def __init__(self, config: Config):
        self.config = config

    async def call_tool(
        self, server_name: str, tool_name: str, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        """Call a tool via the daemon."""
        response = await self._send_request(
            IPCMessage(
                action="call_tool",
                payload={
                    "server": server_name,
                    "tool": tool_name,
                    "arguments": arguments,
                },
            )
        )
        return response.payload

    async def list_tools(self, server_name: str) -> list[dict[str, Any]]:
        """List tools from a server via the daemon."""
        response = await self._send_request(
            IPCMessage(action="list_tools", payload={"server": server_name})
        )
        tools: list[dict[str, Any]] = response.payload.get("tools", [])
        return tools

    async def get_status(self) -> dict[str, Any]:
        """Get daemon status."""
        response = await self._send_request(IPCMessage(action="status", payload={}))
        return response.payload

    async def shutdown(self) -> None:
        """Request daemon shutdown."""
        try:
            await self._send_request(IPCMessage(action="shutdown", payload={}))
            logger.debug("Daemon shutdown request sent successfully")
        except Exception as e:
            # Daemon may close connection before responding - this is expected
            logger.debug(f"Daemon shutdown request completed (connection closed: {e})")

    async def _send_request(self, message: IPCMessage) -> IPCMessage:
        """Send a request to the daemon and get the response."""
        # Ensure daemon is running
        await self._ensure_daemon_running()

        # Connect and send request
        socket_path = get_socket_path()
        connection = await connect_to_daemon()
        if not connection:
            raise RuntimeError(
                f"Failed to connect to daemon socket at {socket_path}\n\n"
                "The daemon process may have crashed. Try:\n"
                "  1. Run 'mcpl session stop' to clean up\n"
                "  2. Retry your command\n"
                "  3. Use --no-daemon flag to bypass the daemon entirely"
            )

        reader, writer = connection
        try:
            await write_message(writer, message)
            response = await read_message(reader)

            if not response:
                log_file = get_log_file_path()
                raise RuntimeError(
                    f"No response from daemon (connection closed unexpectedly)\n\n"
                    f"This may indicate the daemon crashed while processing the request.\n"
                    f"Check daemon log at: {log_file}\n\n"
                    "Try:\n"
                    "  1. Run 'mcpl session stop' to clean up\n"
                    "  2. Retry your command\n"
                    "  3. Use --no-daemon flag to bypass the daemon"
                )

            if response.action == "error":
                error_msg = response.payload.get("error", "Unknown error")
                # Add recovery suggestions for common errors (only if not already present)
                if (
                    "connection timed out" in error_msg.lower()
                    and "MCPL_CONNECTION_TIMEOUT" not in error_msg
                ):
                    error_msg += (
                        "\n\nThe MCP server took too long to connect. Try:\n"
                        "  1. Check if the server command is correct in your config\n"
                        "  2. Increase timeout with MCPL_CONNECTION_TIMEOUT env var\n"
                        "  3. Use --no-daemon to get more detailed error output"
                    )
                raise RuntimeError(error_msg)

            return response
        finally:
            writer.close()
            await writer.wait_closed()

    async def _ensure_daemon_running(self) -> None:
        """Ensure the daemon is running, starting it if necessary."""
        if await self._is_daemon_running():
            return

        # Clean up any legacy daemon before starting new one
        # This handles migration from old path format (pre-socket-path-fix)
        await self._cleanup_legacy_daemon()

        # Start the daemon
        await self._start_daemon()

        # Wait for daemon to be ready
        start_time = time.time()
        while time.time() - start_time < DAEMON_START_TIMEOUT:
            if await self._is_daemon_running():
                return
            await asyncio.sleep(DAEMON_CONNECT_RETRY_DELAY)

        # Daemon failed to start - provide helpful error message
        log_file = get_log_file_path()
        socket_path = get_socket_path()
        error_msg = f"Daemon failed to start within {DAEMON_START_TIMEOUT} seconds"

        # Try to read the last few lines of the log file for context
        log_context = ""
        if log_file.exists():
            try:
                with open(log_file) as f:
                    lines = f.readlines()
                    if lines:
                        # Get last 10 lines (or fewer if file is smaller)
                        tail_lines = lines[-10:]
                        log_context = "".join(tail_lines).strip()
            except Exception:
                pass

        if log_context:
            error_msg += f"\n\nDaemon log (last lines from {log_file}):\n{log_context}"
        else:
            error_msg += f"\n\nNo daemon log available at: {log_file}"

        error_msg += (
            f"\n\nSocket path: {socket_path}\n\n"
            "Possible causes:\n"
            "  - MCP server commands may be invalid or missing dependencies\n"
            "  - Environment variables may not be set correctly\n"
            "  - Another process may be using the socket\n\n"
            "Try:\n"
            "  1. Run 'mcpl verify' to test server connections\n"
            "  2. Run 'mcpl config' to check your configuration\n"
            "  3. Use --no-daemon flag to bypass the daemon\n"
            f"  4. Increase timeout: MCPL_DAEMON_START_TIMEOUT={DAEMON_START_TIMEOUT * 2}"
        )

        raise RuntimeError(error_msg)

    async def _is_daemon_running(self) -> bool:
        """Check if the daemon is currently running and responsive.

        This performs two checks:
        1. PID file exists and process is alive
        2. Daemon actually responds to a status ping

        The second check is important because the process could be alive but
        the IPC server might not be accepting connections (e.g., during startup
        or if something went wrong).
        """
        # Check PID file
        pid_file = get_pid_file_path()
        socket_path = get_socket_path()

        if not pid_file.exists():
            # No PID file - clean up any stale socket file
            if socket_path.exists():
                socket_path.unlink(missing_ok=True)
            return False

        try:
            pid = int(pid_file.read_text().strip())
            if not is_process_alive(pid):
                # Stale PID file - clean up both PID and socket files
                pid_file.unlink(missing_ok=True)
                if socket_path.exists():
                    socket_path.unlink(missing_ok=True)
                return False
        except (ValueError, OSError):
            return False

        # Process is alive - now verify it responds to IPC requests.
        # This sends an actual status message rather than just testing connectivity,
        # which is required on Windows where the named pipe server blocks on ReadFile.
        try:
            connection = await asyncio.wait_for(connect_to_daemon(), timeout=2.0)
            if not connection:
                return False

            reader, writer = connection
            try:
                # Send a status ping and wait for response
                ping_msg = IPCMessage(action="status", payload={})
                await asyncio.wait_for(write_message(writer, ping_msg), timeout=2.0)
                response = await asyncio.wait_for(read_message(reader), timeout=2.0)
                return response is not None and response.action == "result"
            finally:
                writer.close()
                await writer.wait_closed()
        except (asyncio.TimeoutError, OSError, Exception) as e:
            logger.debug(f"Daemon ping failed: {e}")
            return False

    async def _cleanup_legacy_daemon(self) -> None:
        """Clean up any legacy daemon from before path format change.

        Prior to the AF_UNIX socket path fix, socket paths used
        tempfile.gettempdir() (which returns long paths on macOS) and
        unhashed session IDs. This method detects and cleans up old daemons
        to prevent duplicate instances.
        """
        import signal

        legacy_pid_path = get_legacy_pid_file_path()
        legacy_socket_path = get_legacy_socket_path()

        # Skip on Windows or if no legacy paths (returns None)
        if legacy_pid_path is None or legacy_socket_path is None:
            return

        # Skip if legacy path is same as new path (no migration needed)
        if legacy_socket_path == get_socket_path():
            return

        # Skip if no legacy files exist
        if not legacy_pid_path.exists() and not legacy_socket_path.exists():
            return

        # If PID file exists, check if process is alive and terminate it
        if legacy_pid_path.exists():
            try:
                pid = int(legacy_pid_path.read_text().strip())
                if is_process_alive(pid):
                    # Gracefully terminate old daemon
                    os.kill(pid, signal.SIGTERM)
                    # Give it time to shut down
                    await asyncio.sleep(0.5)
            except (ValueError, OSError):
                pass
            finally:
                try:
                    legacy_pid_path.unlink(missing_ok=True)
                except OSError:
                    pass  # May fail if path no longer exists

        # Clean up legacy socket
        if legacy_socket_path.exists():
            try:
                legacy_socket_path.unlink(missing_ok=True)
            except OSError:
                pass  # May fail if path no longer exists

    async def _start_daemon(self) -> None:
        """Start the daemon process."""
        # Build command to run daemon
        # Use the same Python interpreter and run the daemon module
        python_exe = sys.executable
        daemon_cmd = [python_exe, "-m", "mcp_launchpad.daemon"]

        # Add config path if we have one
        if self.config.config_path:
            daemon_cmd.extend(["--config", str(self.config.config_path)])

        # Ensure daemon uses the same session ID as client
        # This is critical so they use the same socket/pid/log file paths
        daemon_env = os.environ.copy()
        daemon_env["MCPL_SESSION_ID"] = get_session_id()

        # Open log file for daemon output
        log_file = get_log_file_path()
        log_file.parent.mkdir(parents=True, exist_ok=True)
        log_handle = open(log_file, "w")

        try:
            # Start as detached process
            if IS_WINDOWS:
                # Windows: Use CREATE_NEW_PROCESS_GROUP and DETACHED_PROCESS
                DETACHED_PROCESS = 0x00000008
                CREATE_NEW_PROCESS_GROUP = 0x00000200
                subprocess.Popen(
                    daemon_cmd,
                    env=daemon_env,
                    creationflags=DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP,
                    stdout=log_handle,
                    stderr=log_handle,
                    stdin=subprocess.DEVNULL,
                )
            else:
                # Unix: Use double-fork or nohup pattern
                subprocess.Popen(
                    daemon_cmd,
                    env=daemon_env,
                    stdout=log_handle,
                    stderr=log_handle,
                    stdin=subprocess.DEVNULL,
                    start_new_session=True,
                )
        finally:
            # Close the log handle in the parent process - the child has its own copy
            log_handle.close()
