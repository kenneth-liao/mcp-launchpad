"""Tests for session daemon."""

import asyncio
import os
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mcp_launchpad.config import Config, ServerConfig
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
                payload={"server": "test-server", "tool": "my_tool", "arguments": {}}
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
            mock_session.list_tools = AsyncMock(return_value=MagicMock(tools=[mock_tool]))
            
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

