"""Tests for session client."""

import asyncio
import os
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mcp_launchpad.config import Config, ServerConfig
from mcp_launchpad.ipc import IPCMessage
from mcp_launchpad.session import SessionClient


@pytest.fixture
def mock_config():
    """Create a mock config for testing."""
    return Config(
        servers={"test": ServerConfig(name="test", command="echo")},
        config_path=Path("/tmp/test-config.json"),
    )


class TestSessionClient:
    """Tests for SessionClient class."""

    @pytest.mark.asyncio
    async def test_call_tool_sends_correct_message(self, mock_config):
        """Test that call_tool sends the correct IPC message."""
        client = SessionClient(mock_config)
        
        expected_response = IPCMessage(
            action="result",
            payload={"success": True, "result": "tool output"}
        )
        
        with patch.object(client, "_send_request", new_callable=AsyncMock) as mock_send:
            mock_send.return_value = expected_response
            
            result = await client.call_tool("server1", "tool1", {"arg": "value"})
            
            # Verify the message format
            call_args = mock_send.call_args[0][0]
            assert call_args.action == "call_tool"
            assert call_args.payload["server"] == "server1"
            assert call_args.payload["tool"] == "tool1"
            assert call_args.payload["arguments"] == {"arg": "value"}
            
            assert result == expected_response.payload

    @pytest.mark.asyncio
    async def test_list_tools_sends_correct_message(self, mock_config):
        """Test that list_tools sends the correct IPC message."""
        client = SessionClient(mock_config)
        
        expected_response = IPCMessage(
            action="result",
            payload={"tools": [{"name": "tool1", "description": "desc"}]}
        )
        
        with patch.object(client, "_send_request", new_callable=AsyncMock) as mock_send:
            mock_send.return_value = expected_response
            
            result = await client.list_tools("server1")
            
            call_args = mock_send.call_args[0][0]
            assert call_args.action == "list_tools"
            assert call_args.payload["server"] == "server1"
            
            assert result == [{"name": "tool1", "description": "desc"}]

    @pytest.mark.asyncio
    async def test_get_status_sends_correct_message(self, mock_config):
        """Test that get_status sends the correct IPC message."""
        client = SessionClient(mock_config)
        
        expected_response = IPCMessage(
            action="result",
            payload={"running": True, "servers": {}}
        )
        
        with patch.object(client, "_send_request", new_callable=AsyncMock) as mock_send:
            mock_send.return_value = expected_response
            
            result = await client.get_status()
            
            call_args = mock_send.call_args[0][0]
            assert call_args.action == "status"
            
            assert result["running"] is True

    @pytest.mark.asyncio
    async def test_shutdown_sends_correct_message(self, mock_config):
        """Test that shutdown sends the correct IPC message."""
        client = SessionClient(mock_config)
        
        with patch.object(client, "_send_request", new_callable=AsyncMock) as mock_send:
            mock_send.return_value = IPCMessage(action="result", payload={})
            
            await client.shutdown()
            
            call_args = mock_send.call_args[0][0]
            assert call_args.action == "shutdown"

    @pytest.mark.asyncio
    async def test_shutdown_ignores_connection_errors(self, mock_config):
        """Test that shutdown doesn't raise on connection errors."""
        client = SessionClient(mock_config)
        
        with patch.object(client, "_send_request", new_callable=AsyncMock) as mock_send:
            mock_send.side_effect = RuntimeError("Connection closed")
            
            # Should not raise
            await client.shutdown()

    @pytest.mark.asyncio
    async def test_send_request_raises_on_error_response(self, mock_config):
        """Test that error responses are converted to exceptions."""
        client = SessionClient(mock_config)
        
        error_response = IPCMessage(
            action="error",
            payload={"error": "Server not found"}
        )
        
        with patch.object(client, "_ensure_daemon_running", new_callable=AsyncMock):
            with patch("mcp_launchpad.session.connect_to_daemon", new_callable=AsyncMock) as mock_connect:
                mock_reader = AsyncMock()
                mock_writer = MagicMock()
                mock_writer.close = MagicMock()
                mock_writer.wait_closed = AsyncMock()
                mock_connect.return_value = (mock_reader, mock_writer)
                
                with patch("mcp_launchpad.session.write_message", new_callable=AsyncMock):
                    with patch("mcp_launchpad.session.read_message", new_callable=AsyncMock) as mock_read:
                        mock_read.return_value = error_response
                        
                        with pytest.raises(RuntimeError, match="Server not found"):
                            await client._send_request(IPCMessage(action="test", payload={}))


class TestSessionClientDaemonManagement:
    """Tests for daemon lifecycle management in SessionClient."""

    @pytest.mark.asyncio
    async def test_is_daemon_running_checks_pid_file(self, mock_config, tmp_path, monkeypatch):
        """Test that _is_daemon_running checks PID file."""
        monkeypatch.setenv("MCPL_SESSION_ID", "test-daemon-check")

        client = SessionClient(mock_config)

        # No PID file - daemon not running
        with patch("mcp_launchpad.session.get_pid_file_path") as mock_path:
            mock_path.return_value = tmp_path / "nonexistent.pid"
            result = await client._is_daemon_running()
            assert result is False

    @pytest.mark.asyncio
    async def test_start_daemon_spawns_detached_process(self, mock_config):
        """Test that _start_daemon spawns a detached subprocess."""
        client = SessionClient(mock_config)

        with patch("subprocess.Popen") as mock_popen:
            await client._start_daemon()

            mock_popen.assert_called_once()
            call_args = mock_popen.call_args

            # Should include the daemon module
            assert "-m" in call_args[0][0]
            assert "mcp_launchpad.daemon" in call_args[0][0]

    @pytest.mark.asyncio
    async def test_is_daemon_running_with_dead_process(self, mock_config, tmp_path):
        """Test _is_daemon_running with stale PID file."""
        client = SessionClient(mock_config)

        pid_file = tmp_path / "test.pid"
        pid_file.write_text("99999")  # Non-existent process

        with patch("mcp_launchpad.session.get_pid_file_path", return_value=pid_file):
            with patch("mcp_launchpad.session.is_process_alive", return_value=False):
                result = await client._is_daemon_running()
                assert result is False

    @pytest.mark.asyncio
    async def test_send_request_no_response(self, mock_config):
        """Test _send_request when daemon doesn't respond."""
        client = SessionClient(mock_config)

        with patch.object(client, "_ensure_daemon_running", new_callable=AsyncMock):
            with patch("mcp_launchpad.session.connect_to_daemon", new_callable=AsyncMock) as mock_connect:
                mock_reader = AsyncMock()
                mock_writer = MagicMock()
                mock_writer.close = MagicMock()
                mock_writer.wait_closed = AsyncMock()
                mock_connect.return_value = (mock_reader, mock_writer)

                with patch("mcp_launchpad.session.write_message", new_callable=AsyncMock):
                    with patch("mcp_launchpad.session.read_message", new_callable=AsyncMock) as mock_read:
                        mock_read.return_value = None  # No response

                        with pytest.raises(RuntimeError, match="No response"):
                            await client._send_request(IPCMessage(action="test", payload={}))

