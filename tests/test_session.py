"""Tests for session client."""

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
            action="result", payload={"success": True, "result": "tool output"}
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
            payload={"tools": [{"name": "tool1", "description": "desc"}]},
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
            action="result", payload={"running": True, "servers": {}}
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
            action="error", payload={"error": "Server not found"}
        )

        with patch.object(client, "_ensure_daemon_running", new_callable=AsyncMock):
            with patch(
                "mcp_launchpad.session.connect_to_daemon", new_callable=AsyncMock
            ) as mock_connect:
                mock_reader = AsyncMock()
                mock_writer = MagicMock()
                mock_writer.close = MagicMock()
                mock_writer.wait_closed = AsyncMock()
                mock_connect.return_value = (mock_reader, mock_writer)

                with patch(
                    "mcp_launchpad.session.write_message", new_callable=AsyncMock
                ):
                    with patch(
                        "mcp_launchpad.session.read_message", new_callable=AsyncMock
                    ) as mock_read:
                        mock_read.return_value = error_response

                        with pytest.raises(RuntimeError, match="Server not found"):
                            await client._send_request(
                                IPCMessage(action="test", payload={})
                            )


class TestSessionClientDaemonManagement:
    """Tests for daemon lifecycle management in SessionClient."""

    @pytest.mark.asyncio
    async def test_is_daemon_running_checks_pid_file(
        self, mock_config, tmp_path, monkeypatch
    ):
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
            with patch(
                "mcp_launchpad.session.connect_to_daemon", new_callable=AsyncMock
            ) as mock_connect:
                mock_reader = AsyncMock()
                mock_writer = MagicMock()
                mock_writer.close = MagicMock()
                mock_writer.wait_closed = AsyncMock()
                mock_connect.return_value = (mock_reader, mock_writer)

                with patch(
                    "mcp_launchpad.session.write_message", new_callable=AsyncMock
                ):
                    with patch(
                        "mcp_launchpad.session.read_message", new_callable=AsyncMock
                    ) as mock_read:
                        mock_read.return_value = None  # No response

                        with pytest.raises(RuntimeError, match="No response"):
                            await client._send_request(
                                IPCMessage(action="test", payload={})
                            )


class TestLegacyDaemonCleanup:
    """Tests for legacy daemon cleanup during migration."""

    @pytest.mark.asyncio
    async def test_cleanup_skips_when_no_legacy_files(self, mock_config, tmp_path, monkeypatch):
        """Test that cleanup does nothing when no legacy files exist."""
        client = SessionClient(mock_config)

        # Mock legacy paths to non-existent files
        with patch("mcp_launchpad.session.get_legacy_pid_file_path") as mock_pid_path:
            with patch("mcp_launchpad.session.get_legacy_socket_path") as mock_socket_path:
                mock_pid_path.return_value = tmp_path / "nonexistent.pid"
                mock_socket_path.return_value = tmp_path / "nonexistent.sock"

                with patch("mcp_launchpad.session.get_socket_path") as mock_new_socket:
                    mock_new_socket.return_value = tmp_path / "new.sock"

                    # Should complete without error
                    await client._cleanup_legacy_daemon()

    @pytest.mark.asyncio
    async def test_cleanup_skips_on_windows(self, mock_config):
        """Test that cleanup is skipped on Windows (returns None paths)."""
        client = SessionClient(mock_config)

        with patch("mcp_launchpad.session.get_legacy_pid_file_path", return_value=None):
            with patch("mcp_launchpad.session.get_legacy_socket_path", return_value=None):
                # Should complete without error
                await client._cleanup_legacy_daemon()

    @pytest.mark.asyncio
    async def test_cleanup_skips_when_paths_identical(self, mock_config, tmp_path):
        """Test that cleanup is skipped when legacy and new paths are identical."""
        client = SessionClient(mock_config)

        same_path = tmp_path / "same.sock"
        same_pid = tmp_path / "same.pid"

        with patch("mcp_launchpad.session.get_legacy_socket_path", return_value=same_path):
            with patch("mcp_launchpad.session.get_legacy_pid_file_path", return_value=same_pid):
                with patch("mcp_launchpad.session.get_socket_path", return_value=same_path):
                    # Should complete without error (no migration needed)
                    await client._cleanup_legacy_daemon()

    @pytest.mark.asyncio
    async def test_cleanup_removes_legacy_socket_file(self, mock_config, tmp_path):
        """Test that cleanup removes legacy socket file."""
        client = SessionClient(mock_config)

        # Create legacy socket file
        legacy_socket = tmp_path / "legacy.sock"
        legacy_socket.touch()
        legacy_pid = tmp_path / "nonexistent.pid"  # No PID file

        with patch("mcp_launchpad.session.get_legacy_socket_path", return_value=legacy_socket):
            with patch("mcp_launchpad.session.get_legacy_pid_file_path", return_value=legacy_pid):
                with patch("mcp_launchpad.session.get_socket_path") as mock_new:
                    mock_new.return_value = tmp_path / "new.sock"

                    await client._cleanup_legacy_daemon()

                    # Legacy socket should be removed
                    assert not legacy_socket.exists()

    @pytest.mark.asyncio
    async def test_cleanup_removes_legacy_pid_file(self, mock_config, tmp_path):
        """Test that cleanup removes legacy PID file."""
        client = SessionClient(mock_config)

        legacy_socket = tmp_path / "nonexistent.sock"
        legacy_pid = tmp_path / "legacy.pid"
        legacy_pid.write_text("99999")  # Non-existent process

        with patch("mcp_launchpad.session.get_legacy_socket_path", return_value=legacy_socket):
            with patch("mcp_launchpad.session.get_legacy_pid_file_path", return_value=legacy_pid):
                with patch("mcp_launchpad.session.get_socket_path") as mock_new:
                    mock_new.return_value = tmp_path / "new.sock"
                    with patch("mcp_launchpad.session.is_process_alive", return_value=False):
                        await client._cleanup_legacy_daemon()

                        # Legacy PID file should be removed
                        assert not legacy_pid.exists()

    @pytest.mark.asyncio
    async def test_cleanup_terminates_running_daemon(self, mock_config, tmp_path):
        """Test that cleanup terminates a running legacy daemon."""
        import signal

        client = SessionClient(mock_config)

        legacy_socket = tmp_path / "legacy.sock"
        legacy_pid = tmp_path / "legacy.pid"
        legacy_pid.write_text("12345")
        legacy_socket.touch()

        with patch("mcp_launchpad.session.get_legacy_socket_path", return_value=legacy_socket):
            with patch("mcp_launchpad.session.get_legacy_pid_file_path", return_value=legacy_pid):
                with patch("mcp_launchpad.session.get_socket_path") as mock_new:
                    mock_new.return_value = tmp_path / "new.sock"
                    with patch("mcp_launchpad.session.is_process_alive", return_value=True):
                        with patch("os.kill") as mock_kill:
                            await client._cleanup_legacy_daemon()

                            # Should have sent SIGTERM to the process
                            mock_kill.assert_called_once_with(12345, signal.SIGTERM)

    @pytest.mark.asyncio
    async def test_cleanup_handles_invalid_pid_file(self, mock_config, tmp_path):
        """Test that cleanup handles invalid PID file content gracefully."""
        client = SessionClient(mock_config)

        legacy_socket = tmp_path / "nonexistent.sock"
        legacy_pid = tmp_path / "legacy.pid"
        legacy_pid.write_text("not-a-number")  # Invalid content

        with patch("mcp_launchpad.session.get_legacy_socket_path", return_value=legacy_socket):
            with patch("mcp_launchpad.session.get_legacy_pid_file_path", return_value=legacy_pid):
                with patch("mcp_launchpad.session.get_socket_path") as mock_new:
                    mock_new.return_value = tmp_path / "new.sock"

                    # Should not raise, should handle gracefully
                    await client._cleanup_legacy_daemon()

                    # PID file should be removed despite invalid content
                    assert not legacy_pid.exists()

    @pytest.mark.asyncio
    async def test_ensure_daemon_running_calls_cleanup(self, mock_config):
        """Test that _ensure_daemon_running calls _cleanup_legacy_daemon."""
        client = SessionClient(mock_config)

        with patch.object(client, "_is_daemon_running", new_callable=AsyncMock) as mock_running:
            mock_running.return_value = False

            with patch.object(
                client, "_cleanup_legacy_daemon", new_callable=AsyncMock
            ) as mock_cleanup:
                with patch.object(client, "_start_daemon", new_callable=AsyncMock):
                    # Make it timeout quickly
                    with patch("mcp_launchpad.session.DAEMON_START_TIMEOUT", 0.1):
                        try:
                            await client._ensure_daemon_running()
                        except RuntimeError:
                            pass  # Expected timeout

                        # Cleanup should have been called
                        mock_cleanup.assert_called_once()


class TestDaemonVersionMismatch:
    """A daemon from a different mcpl version must be replaced, not reused (issue #36)."""

    @pytest.mark.asyncio
    async def test_matching_version_is_reused(self, mock_config):
        """A daemon reporting this client's version is used as-is."""
        from mcp_launchpad import __version__

        client = SessionClient(mock_config)

        with patch.object(
            client, "_probe_daemon", new_callable=AsyncMock,
            return_value={"version": __version__},
        ):
            with patch.object(client, "shutdown", new_callable=AsyncMock) as mock_shutdown:
                with patch.object(client, "_start_daemon", new_callable=AsyncMock) as mock_start:
                    await client._ensure_daemon_running()

                    mock_shutdown.assert_not_called()
                    mock_start.assert_not_called()

    @pytest.mark.asyncio
    async def test_older_version_is_stopped_and_restarted(self, mock_config):
        """A daemon reporting a different version is shut down and replaced."""
        from mcp_launchpad import __version__

        client = SessionClient(mock_config)

        # Probe sequence: old daemon responds, then it stops, then the new one comes up
        probes = [{"version": "0.0.1-old"}, None, {"version": __version__}]

        with patch.object(client, "_probe_daemon", new_callable=AsyncMock, side_effect=probes):
            with patch.object(client, "shutdown", new_callable=AsyncMock) as mock_shutdown:
                with patch.object(client, "_cleanup_legacy_daemon", new_callable=AsyncMock):
                    with patch.object(
                        client, "_start_daemon", new_callable=AsyncMock
                    ) as mock_start:
                        await client._ensure_daemon_running()

                        mock_shutdown.assert_called_once()
                        mock_start.assert_called_once()

    @pytest.mark.asyncio
    async def test_daemon_without_version_is_treated_as_stale(self, mock_config):
        """A pre-fix daemon reports no version and is replaced."""
        from mcp_launchpad import __version__

        client = SessionClient(mock_config)

        probes = [{"success": True}, None, {"version": __version__}]

        with patch.object(client, "_probe_daemon", new_callable=AsyncMock, side_effect=probes):
            with patch.object(client, "shutdown", new_callable=AsyncMock) as mock_shutdown:
                with patch.object(client, "_cleanup_legacy_daemon", new_callable=AsyncMock):
                    with patch.object(
                        client, "_start_daemon", new_callable=AsyncMock
                    ) as mock_start:
                        await client._ensure_daemon_running()

                        mock_shutdown.assert_called_once()
                        mock_start.assert_called_once()

    @pytest.mark.asyncio
    async def test_no_new_daemon_started_while_stale_one_still_runs(self, mock_config):
        """If the old daemon does not stop, raise instead of starting a second one."""
        client = SessionClient(mock_config)

        with patch.object(
            client, "_probe_daemon", new_callable=AsyncMock,
            return_value={"version": "0.0.1-old"},
        ):
            with patch.object(client, "shutdown", new_callable=AsyncMock):
                with patch.object(client, "_start_daemon", new_callable=AsyncMock) as mock_start:
                    with patch("mcp_launchpad.session.STALE_DAEMON_STOP_TIMEOUT", 0.05):
                        with pytest.raises(RuntimeError, match="did not stop"):
                            await client._ensure_daemon_running()

                        mock_start.assert_not_called()

    @pytest.mark.asyncio
    async def test_probe_returns_status_payload(self, mock_config):
        """_probe_daemon returns the status payload, including the version."""
        client = SessionClient(mock_config)

        response = IPCMessage(action="result", payload={"version": "1.2.3"})
        pid_file = MagicMock()
        pid_file.exists.return_value = True
        pid_file.read_text.return_value = "4242"

        writer = MagicMock()
        writer.close = MagicMock()
        writer.wait_closed = AsyncMock()

        with patch("mcp_launchpad.session.get_pid_file_path", return_value=pid_file):
            with patch("mcp_launchpad.session.is_process_alive", return_value=True):
                with patch(
                    "mcp_launchpad.session.connect_to_daemon", new_callable=AsyncMock,
                    return_value=(AsyncMock(), writer),
                ):
                    with patch("mcp_launchpad.session.write_message", new_callable=AsyncMock):
                        with patch(
                            "mcp_launchpad.session.read_message",
                            new_callable=AsyncMock,
                            return_value=response,
                        ):
                            status = await client._probe_daemon()

        assert status == {"version": "1.2.3"}
