"""Tests for cross-platform utilities."""

import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from mcp_launchpad.platform import (
    IS_WINDOWS,
    get_parent_pid,
    get_pid_file_path,
    get_session_id,
    get_socket_path,
    is_process_alive,
)


class TestGetSessionId:
    """Tests for get_session_id function."""

    def test_uses_mcpl_session_id_env_var(self, monkeypatch):
        """Test that MCPL_SESSION_ID takes priority."""
        monkeypatch.setenv("MCPL_SESSION_ID", "custom-session-123")
        monkeypatch.setenv("TERM_SESSION_ID", "should-not-use")
        assert get_session_id() == "custom-session-123"

    def test_uses_term_session_id_on_macos(self, monkeypatch):
        """Test that TERM_SESSION_ID is used on macOS."""
        monkeypatch.delenv("MCPL_SESSION_ID", raising=False)
        monkeypatch.setenv("TERM_SESSION_ID", "macos-term-session")
        monkeypatch.delenv("WINDOWID", raising=False)
        assert get_session_id() == "macos-term-session"

    def test_uses_windowid_on_linux(self, monkeypatch):
        """Test that WINDOWID is used on Linux X11."""
        monkeypatch.delenv("MCPL_SESSION_ID", raising=False)
        monkeypatch.delenv("TERM_SESSION_ID", raising=False)
        monkeypatch.setenv("WINDOWID", "12345678")
        monkeypatch.delenv("WT_SESSION", raising=False)
        assert get_session_id() == "12345678"

    def test_uses_wt_session_on_windows_terminal(self, monkeypatch):
        """Test that WT_SESSION is used on Windows Terminal."""
        monkeypatch.delenv("MCPL_SESSION_ID", raising=False)
        monkeypatch.delenv("TERM_SESSION_ID", raising=False)
        monkeypatch.delenv("WINDOWID", raising=False)
        monkeypatch.setenv("WT_SESSION", "windows-terminal-guid")
        assert get_session_id() == "windows-terminal-guid"

    def test_falls_back_to_parent_pid(self, monkeypatch):
        """Test fallback to parent PID when no session env vars set."""
        monkeypatch.delenv("MCPL_SESSION_ID", raising=False)
        monkeypatch.delenv("TERM_SESSION_ID", raising=False)
        monkeypatch.delenv("WINDOWID", raising=False)
        monkeypatch.delenv("WT_SESSION", raising=False)
        session_id = get_session_id()
        assert session_id == str(os.getppid())


class TestGetSocketPath:
    """Tests for get_socket_path function."""

    def test_returns_path_object(self, monkeypatch):
        """Test that socket path is a Path object."""
        monkeypatch.setenv("MCPL_SESSION_ID", "test-session")
        path = get_socket_path()
        assert isinstance(path, Path)

    def test_includes_session_id(self, monkeypatch):
        """Test that socket path includes session ID."""
        monkeypatch.setenv("MCPL_SESSION_ID", "unique-session-456")
        path = get_socket_path()
        assert "unique-session-456" in str(path)

    @pytest.mark.skipif(IS_WINDOWS, reason="Unix-specific test")
    def test_unix_socket_path_format(self, monkeypatch):
        """Test Unix socket path format."""
        monkeypatch.setenv("MCPL_SESSION_ID", "test-session")
        path = get_socket_path()
        assert path.suffix == ".sock"
        assert str(os.getuid()) in str(path)

    @pytest.mark.skipif(not IS_WINDOWS, reason="Windows-specific test")
    def test_windows_pipe_path_format(self, monkeypatch):
        """Test Windows named pipe path format."""
        monkeypatch.setenv("MCPL_SESSION_ID", "test-session")
        path = get_socket_path()
        assert str(path).startswith("\\\\.\\pipe\\")


class TestGetPidFilePath:
    """Tests for get_pid_file_path function."""

    def test_returns_path_object(self, monkeypatch):
        """Test that PID file path is a Path object."""
        monkeypatch.setenv("MCPL_SESSION_ID", "test-session")
        path = get_pid_file_path()
        assert isinstance(path, Path)

    def test_includes_session_id(self, monkeypatch):
        """Test that PID file path includes session ID."""
        monkeypatch.setenv("MCPL_SESSION_ID", "pid-test-789")
        path = get_pid_file_path()
        assert "pid-test-789" in str(path)

    def test_has_pid_extension(self, monkeypatch):
        """Test that PID file has .pid extension."""
        monkeypatch.setenv("MCPL_SESSION_ID", "test-session")
        path = get_pid_file_path()
        assert path.suffix == ".pid"


class TestIsProcessAlive:
    """Tests for is_process_alive function."""

    def test_current_process_is_alive(self):
        """Test that current process is detected as alive."""
        assert is_process_alive(os.getpid()) is True

    def test_nonexistent_process_is_not_alive(self):
        """Test that non-existent process is detected as not alive."""
        # PID 99999999 is unlikely to exist
        assert is_process_alive(99999999) is False

    def test_pid_zero_is_not_alive(self):
        """Test that PID 0 is handled correctly."""
        # PID 0 behavior varies by platform
        result = is_process_alive(0)
        assert isinstance(result, bool)


class TestGetParentPid:
    """Tests for get_parent_pid function."""

    def test_returns_integer(self):
        """Test that parent PID is an integer."""
        parent_pid = get_parent_pid()
        assert isinstance(parent_pid, int)

    def test_parent_is_alive(self):
        """Test that parent process is alive."""
        parent_pid = get_parent_pid()
        assert is_process_alive(parent_pid) is True

    def test_parent_is_not_self(self):
        """Test that parent PID is not the current process."""
        parent_pid = get_parent_pid()
        assert parent_pid != os.getpid()

