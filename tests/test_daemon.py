"""Tests for session daemon."""

import os
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from mcp_launchpad.config import Config, ServerConfig
from mcp_launchpad.connection import OAuthRequiredError
from mcp_launchpad.daemon import Daemon, DaemonState, ServerState
from mcp_launchpad.ipc import IPCMessage


@pytest.fixture
def mock_config():
    """Create a mock config for testing."""
    return Config(
        servers={
            "test-server": ServerConfig(
                name="test-server",
                command="echo",
                args=["hello"],
            )
        },
        config_path=Path("/tmp/test-config.json"),
    )


class TestServerState:
    """Tests for ServerState dataclass."""

    def test_default_values(self):
        """Test default values for ServerState."""
        state = ServerState(name="test")
        assert state.name == "test"
        assert state.session is None
        assert state.connected is False
        assert state.error is None


class TestDaemonState:
    """Tests for DaemonState dataclass."""

    def test_default_values(self, mock_config):
        """Test default values for DaemonState."""
        state = DaemonState(config=mock_config)
        assert state.config == mock_config
        assert state.servers == {}
        assert state.parent_pid == 0
        assert state.running is True


class TestDaemon:
    """Tests for Daemon class."""

    def test_initialization(self, mock_config):
        """Test daemon initialization."""
        with patch("mcp_launchpad.daemon.get_parent_pid", return_value=12345):
            daemon = Daemon(mock_config)

            assert daemon.state.parent_pid == 12345
            assert daemon.state.config == mock_config
            assert daemon.state.running is True

    @pytest.mark.asyncio
    async def test_handle_request_call_tool(self, mock_config):
        """Test handling call_tool request."""
        with patch("mcp_launchpad.daemon.get_parent_pid", return_value=12345):
            daemon = Daemon(mock_config)

            # Mock server state
            mock_session = MagicMock()
            mock_result = MagicMock()
            mock_result.content = [MagicMock(text="result text")]
            mock_session.call_tool = AsyncMock(return_value=mock_result)

            daemon.state.servers["test-server"] = ServerState(
                name="test-server",
                session=mock_session,
                connected=True,
            )

            message = IPCMessage(
                action="call_tool",
                payload={"server": "test-server", "tool": "my_tool", "arguments": {}},
            )

            response = await daemon._handle_request(message)

            assert response.action == "result"
            assert response.payload["success"] is True
            assert response.payload["result"] == "result text"

    @pytest.mark.asyncio
    async def test_handle_request_list_tools(self, mock_config):
        """Test handling list_tools request."""
        with patch("mcp_launchpad.daemon.get_parent_pid", return_value=12345):
            daemon = Daemon(mock_config)

            # Mock server state
            mock_session = MagicMock()
            mock_tool = MagicMock()
            mock_tool.name = "tool1"
            mock_tool.description = "A test tool"
            mock_tool.inputSchema = {}
            mock_session.list_tools = AsyncMock(
                return_value=MagicMock(tools=[mock_tool])
            )

            daemon.state.servers["test-server"] = ServerState(
                name="test-server",
                session=mock_session,
                connected=True,
            )

            message = IPCMessage(action="list_tools", payload={"server": "test-server"})

            response = await daemon._handle_request(message)

            assert response.action == "result"
            assert response.payload["success"] is True
            assert len(response.payload["tools"]) == 1
            assert response.payload["tools"][0]["name"] == "tool1"

    @pytest.mark.asyncio
    async def test_handle_request_status(self, mock_config):
        """Test handling status request."""
        with patch("mcp_launchpad.daemon.get_parent_pid", return_value=12345):
            daemon = Daemon(mock_config)

            daemon.state.servers["test-server"] = ServerState(
                name="test-server",
                connected=True,
            )

            message = IPCMessage(action="status", payload={})

            response = await daemon._handle_request(message)

            assert response.action == "result"
            assert response.payload["success"] is True
            assert response.payload["parent_pid"] == 12345
            assert "test-server" in response.payload["servers"]
            assert response.payload["servers"]["test-server"]["connected"] is True

    @pytest.mark.asyncio
    async def test_handle_request_shutdown(self, mock_config):
        """Test handling shutdown request."""
        with patch("mcp_launchpad.daemon.get_parent_pid", return_value=12345):
            daemon = Daemon(mock_config)

            assert daemon.state.running is True

            message = IPCMessage(action="shutdown", payload={})

            response = await daemon._handle_request(message)

            assert response.action == "result"
            assert response.payload["success"] is True
            assert daemon.state.running is False

    @pytest.mark.asyncio
    async def test_handle_request_unknown_action(self, mock_config):
        """Test handling unknown action."""
        with patch("mcp_launchpad.daemon.get_parent_pid", return_value=12345):
            daemon = Daemon(mock_config)

            message = IPCMessage(action="unknown_action", payload={})

            response = await daemon._handle_request(message)

            assert response.action == "error"
            assert "unknown" in response.payload["error"].lower()

    @pytest.mark.asyncio
    async def test_handle_request_exception(self, mock_config):
        """Test handling exception during request processing."""
        with patch("mcp_launchpad.daemon.get_parent_pid", return_value=12345):
            daemon = Daemon(mock_config)

            # Call tool on non-existent server should raise
            message = IPCMessage(
                action="call_tool",
                payload={"server": "nonexistent", "tool": "test", "arguments": {}},
            )

            response = await daemon._handle_request(message)

            assert response.action == "error"
            assert "error" in response.payload

    @pytest.mark.asyncio
    async def test_ensure_server_connected_not_found(self, mock_config):
        """Test _ensure_server_connected with non-existent server."""
        with patch("mcp_launchpad.daemon.get_parent_pid", return_value=12345):
            daemon = Daemon(mock_config)

            with pytest.raises(ValueError, match="not found"):
                await daemon._ensure_server_connected("nonexistent-server")

    @pytest.mark.asyncio
    async def test_ensure_server_connected_with_error(self, mock_config):
        """Test _ensure_server_connected when server has an error."""
        with patch("mcp_launchpad.daemon.get_parent_pid", return_value=12345):
            daemon = Daemon(mock_config)

            # Add server state with error
            daemon.state.servers["test-server"] = ServerState(
                name="test-server", connected=False, error="Connection refused"
            )

            with pytest.raises(RuntimeError, match="Connection refused"):
                await daemon._ensure_server_connected("test-server")

    def test_get_status(self, mock_config):
        """Test _get_status method."""
        with patch("mcp_launchpad.daemon.get_parent_pid", return_value=12345):
            daemon = Daemon(mock_config)

            daemon.state.servers["server1"] = ServerState(
                name="server1", connected=True
            )
            daemon.state.servers["server2"] = ServerState(
                name="server2", connected=False, error="Failed"
            )

            status = daemon._get_status()

            assert status["success"] is True
            assert status["parent_pid"] == 12345
            assert status["running"] is True
            assert status["servers"]["server1"]["connected"] is True
            assert status["servers"]["server2"]["connected"] is False
            assert status["servers"]["server2"]["error"] == "Failed"

    def test_write_and_remove_pid_file(self, mock_config, tmp_path):
        """Test PID file operations."""
        pid_file = tmp_path / "test.pid"

        with patch("mcp_launchpad.daemon.get_parent_pid", return_value=12345):
            with patch("mcp_launchpad.daemon.get_pid_file_path", return_value=pid_file):
                daemon = Daemon(mock_config)

                # Write PID file
                daemon._write_pid_file()
                assert pid_file.exists()
                assert pid_file.read_text() == str(os.getpid())

                # Remove PID file
                daemon._remove_pid_file()
                assert not pid_file.exists()

    @pytest.mark.asyncio
    async def test_call_tool_extracts_text_content(self, mock_config):
        """Test that _call_tool extracts text content from result."""
        with patch("mcp_launchpad.daemon.get_parent_pid", return_value=12345):
            daemon = Daemon(mock_config)

            mock_session = MagicMock()
            mock_item = MagicMock()
            mock_item.text = "extracted text"
            delattr(mock_item, "data") if hasattr(mock_item, "data") else None
            mock_result = MagicMock()
            mock_result.content = [mock_item]
            mock_session.call_tool = AsyncMock(return_value=mock_result)

            daemon.state.servers["test-server"] = ServerState(
                name="test-server",
                session=mock_session,
                connected=True,
            )

            result = await daemon._call_tool("test-server", "tool", {})

            assert result["result"] == "extracted text"

    @pytest.mark.asyncio
    async def test_call_tool_extracts_data_content(self, mock_config):
        """Test that _call_tool extracts data content from result."""
        with patch("mcp_launchpad.daemon.get_parent_pid", return_value=12345):
            daemon = Daemon(mock_config)

            mock_session = MagicMock()
            mock_item = MagicMock(spec=["data"])
            mock_item.data = {"key": "value"}
            mock_result = MagicMock()
            mock_result.content = [mock_item]
            mock_session.call_tool = AsyncMock(return_value=mock_result)

            daemon.state.servers["test-server"] = ServerState(
                name="test-server",
                session=mock_session,
                connected=True,
            )

            result = await daemon._call_tool("test-server", "tool", {})

            assert result["result"] == {"key": "value"}

    @pytest.mark.asyncio
    async def test_call_tool_multiple_content_items(self, mock_config):
        """Test _call_tool with multiple content items returns list."""
        with patch("mcp_launchpad.daemon.get_parent_pid", return_value=12345):
            daemon = Daemon(mock_config)

            mock_session = MagicMock()
            mock_item1 = MagicMock()
            mock_item1.text = "item1"
            mock_item2 = MagicMock()
            mock_item2.text = "item2"
            mock_result = MagicMock()
            mock_result.content = [mock_item1, mock_item2]
            mock_session.call_tool = AsyncMock(return_value=mock_result)

            daemon.state.servers["test-server"] = ServerState(
                name="test-server",
                session=mock_session,
                connected=True,
            )

            result = await daemon._call_tool("test-server", "tool", {})

            assert result["result"] == ["item1", "item2"]

    @pytest.mark.asyncio
    async def test_call_tool_no_content_attribute(self, mock_config):
        """Test _call_tool when result has no content attribute."""
        with patch("mcp_launchpad.daemon.get_parent_pid", return_value=12345):
            daemon = Daemon(mock_config)

            mock_session = MagicMock()
            mock_result = "plain result"
            mock_session.call_tool = AsyncMock(return_value=mock_result)

            daemon.state.servers["test-server"] = ServerState(
                name="test-server",
                session=mock_session,
                connected=True,
            )

            result = await daemon._call_tool("test-server", "tool", {})

            assert result["result"] == "plain result"


class TestDaemonReconnectionBehavior:
    """Tests for daemon connection retry and timeout behavior.

    These tests are critical for YouTube users who may experience network issues
    or have servers that are slow to start up.
    """

    @pytest.mark.asyncio
    async def test_max_reconnect_attempts_exceeded(self, mock_config):
        """Test that daemon gives up after max reconnection attempts.

        When a server repeatedly fails to connect, the daemon should stop
        retrying after MAX_RECONNECT_ATTEMPTS to avoid infinite loops.
        """
        with patch("mcp_launchpad.daemon.get_parent_pid", return_value=12345):
            with patch("mcp_launchpad.daemon.MAX_RECONNECT_ATTEMPTS", 2):
                with patch("mcp_launchpad.daemon.RECONNECT_DELAY", 0.01):  # Fast retry
                    daemon = Daemon(mock_config)
                    daemon.state.running = True

                    # Track how many times stdio_client is called
                    call_count = 0

                    async def mock_stdio_client(*args, **kwargs):
                        nonlocal call_count
                        call_count += 1
                        raise TimeoutError("Connection timed out")

                    # Create a mock context manager
                    mock_cm = MagicMock()
                    mock_cm.__aenter__ = AsyncMock(side_effect=mock_stdio_client)
                    mock_cm.__aexit__ = AsyncMock(return_value=None)

                    with patch(
                        "mcp_launchpad.daemon.stdio_client",
                        side_effect=TimeoutError("Timeout"),
                    ):
                        # Run _connect_server directly
                        await daemon._connect_server("test-server")

                    # Should have server state with error
                    server_state = daemon.state.servers.get("test-server")
                    assert server_state is not None
                    assert server_state.connected is False
                    assert "timed out" in server_state.error.lower()

    @pytest.mark.asyncio
    async def test_file_not_found_no_retry(self, mock_config):
        """Test that FileNotFoundError does not trigger retry.

        If a command doesn't exist, retrying won't help. The daemon should
        immediately give up to provide faster feedback to users.
        """
        with patch("mcp_launchpad.daemon.get_parent_pid", return_value=12345):
            with patch("mcp_launchpad.daemon.MAX_RECONNECT_ATTEMPTS", 3):
                daemon = Daemon(mock_config)
                daemon.state.running = True

                attempt_count = 0

                def mock_stdio(*args, **kwargs):
                    nonlocal attempt_count
                    attempt_count += 1
                    raise FileNotFoundError("Command not found: echo")

                with patch(
                    "mcp_launchpad.daemon.stdio_client",
                    side_effect=FileNotFoundError("Command not found"),
                ):
                    await daemon._connect_server("test-server")

                # Should only have been called once (no retries for FileNotFoundError)
                server_state = daemon.state.servers.get("test-server")
                assert server_state is not None
                assert "Command not found" in server_state.error

    @pytest.mark.asyncio
    async def test_successful_connection_resets_attempt_counter(self, mock_config):
        """Test that successful connection resets the attempt counter.

        If a server connects successfully, subsequent failures should start
        counting from 0 again, allowing full retry attempts.
        """
        with patch("mcp_launchpad.daemon.get_parent_pid", return_value=12345):
            daemon = Daemon(mock_config)

            # Set up a server that appears connected
            daemon.state.servers["test-server"] = ServerState(
                name="test-server",
                connected=True,
                error=None,
            )

            status = daemon._get_status()
            assert status["servers"]["test-server"]["connected"] is True
            assert status["servers"]["test-server"]["error"] is None

    @pytest.mark.asyncio
    async def test_server_error_includes_details(self, mock_config):
        """Test that server errors include helpful details."""
        with patch("mcp_launchpad.daemon.get_parent_pid", return_value=12345):
            daemon = Daemon(mock_config)

            # Simulate a server with an error state
            daemon.state.servers["test-server"] = ServerState(
                name="test-server",
                connected=False,
                error="Connection refused by server",
            )

            with pytest.raises(RuntimeError) as excinfo:
                await daemon._ensure_server_connected("test-server")

            error_msg = str(excinfo.value)
            assert "test-server" in error_msg
            assert "Connection refused" in error_msg

    @pytest.mark.asyncio
    async def test_ensure_server_connected_timeout(self, mock_config):
        """Test that _ensure_server_connected times out appropriately."""
        with patch("mcp_launchpad.daemon.get_parent_pid", return_value=12345):
            with patch("mcp_launchpad.daemon.CONNECTION_TIMEOUT", 0.1):  # 100ms timeout
                daemon = Daemon(mock_config)
                daemon.state.running = True

                # Don't set up any server state - it will never connect
                with pytest.raises(RuntimeError) as excinfo:
                    await daemon._ensure_server_connected("test-server")

                assert "timed out" in str(excinfo.value).lower()


class TestDaemonOAuthHandling:
    """Tests for OAuth authentication handling in daemon.

    These tests verify that the daemon correctly detects and handles
    OAuth-requiring MCP servers (GitHub Issue #7).
    """

    @pytest.fixture
    def http_server_config(self):
        """Create a config with an HTTP server requiring OAuth."""
        return Config(
            servers={
                "oauth-server": ServerConfig(
                    name="oauth-server",
                    server_type="http",
                    url="https://api.example.com/mcp",
                    headers={},
                ),
            },
            config_path=Path("/tmp/test-config.json"),
        )

    @pytest.mark.asyncio
    async def test_oauth_required_no_retry(self, http_server_config):
        """Test that OAuth-requiring servers don't trigger retry.

        When a server returns 401 (OAuth required), retrying won't help
        because the user needs to authenticate. The daemon should not
        waste time retrying.
        """
        with patch("mcp_launchpad.daemon.get_parent_pid", return_value=12345):
            with patch("mcp_launchpad.daemon.MAX_RECONNECT_ATTEMPTS", 3):
                daemon = Daemon(http_server_config)
                daemon.state.running = True

                # Mock httpx.AsyncClient.post to return 401
                mock_response = MagicMock()
                mock_response.status_code = 401
                mock_response.headers = {
                    "WWW-Authenticate": 'Bearer realm="api"'
                }

                with patch.object(
                    httpx.AsyncClient, "post", new_callable=AsyncMock
                ) as mock_post:
                    mock_post.return_value = mock_response

                    await daemon._connect_server("oauth-server")

                # Server should have OAuth error state
                server_state = daemon.state.servers.get("oauth-server")
                assert server_state is not None
                assert server_state.connected is False
                assert "OAuth" in server_state.error
                assert "oauth-server" in server_state.error

    @pytest.mark.asyncio
    async def test_oauth_error_message_is_helpful(self, http_server_config):
        """Test that OAuth error message provides helpful guidance.

        Users should understand:
        1. What went wrong (OAuth required)
        2. Why mcpl can't handle it (tokens are client-specific)
        3. What they can do (use Claude, configure headers, wait for support)
        """
        with patch("mcp_launchpad.daemon.get_parent_pid", return_value=12345):
            daemon = Daemon(http_server_config)
            daemon.state.running = True

            mock_response = MagicMock()
            mock_response.status_code = 401
            mock_response.headers = {"WWW-Authenticate": "Bearer"}

            with patch.object(
                httpx.AsyncClient, "post", new_callable=AsyncMock
            ) as mock_post:
                mock_post.return_value = mock_response

                await daemon._connect_server("oauth-server")

            server_state = daemon.state.servers.get("oauth-server")
            error_msg = server_state.error

            # Should mention OAuth
            assert "OAuth" in error_msg

            # Should provide alternatives
            assert "Claude" in error_msg  # Suggest using Claude Code
            assert "headers" in error_msg  # Suggest static auth if available

    @pytest.mark.asyncio
    async def test_non_401_http_error_still_retries(self, http_server_config):
        """Test that non-OAuth HTTP errors still trigger retry.

        A 500 error (server error) or 503 (service unavailable) might be
        temporary, so the daemon should retry those.
        """
        with patch("mcp_launchpad.daemon.get_parent_pid", return_value=12345):
            with patch("mcp_launchpad.daemon.MAX_RECONNECT_ATTEMPTS", 2):
                with patch("mcp_launchpad.daemon.RECONNECT_DELAY", 0.01):
                    daemon = Daemon(http_server_config)
                    daemon.state.running = True

                    attempt_count = 0

                    async def mock_post(*args, **kwargs):
                        nonlocal attempt_count
                        attempt_count += 1
                        # Return 200 on preflight, then fail on actual connection
                        mock_response = MagicMock()
                        mock_response.status_code = 200
                        return mock_response

                    with patch.object(
                        httpx.AsyncClient, "post", side_effect=mock_post
                    ):
                        with patch(
                            "mcp_launchpad.daemon.streamable_http_client",
                            side_effect=httpx.ConnectError("Connection refused"),
                        ):
                            await daemon._connect_server("oauth-server")

                    # Should have retried (more than 1 attempt)
                    # Note: preflight check happens each attempt
                    assert attempt_count >= 2

    @pytest.mark.asyncio
    async def test_oauth_server_status_shows_oauth_error(self, http_server_config):
        """Test that daemon status correctly reports OAuth errors."""
        with patch("mcp_launchpad.daemon.get_parent_pid", return_value=12345):
            daemon = Daemon(http_server_config)
            daemon.state.running = True

            mock_response = MagicMock()
            mock_response.status_code = 401
            mock_response.headers = {"WWW-Authenticate": "Bearer"}

            with patch.object(
                httpx.AsyncClient, "post", new_callable=AsyncMock
            ) as mock_post:
                mock_post.return_value = mock_response

                await daemon._connect_server("oauth-server")

            # Check status includes OAuth error
            status = daemon._get_status()
            assert "oauth-server" in status["servers"]
            assert status["servers"]["oauth-server"]["connected"] is False
            assert "OAuth" in status["servers"]["oauth-server"]["error"]
