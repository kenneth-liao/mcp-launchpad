"""Tests for cross-platform utilities."""

import os
from pathlib import Path

import pytest

from mcp_launchpad.platform import (
    IS_WINDOWS,
    MAX_SESSION_ID_LEN,
    _get_safe_username,
    _shorten_session_id,
    get_ide_session_anchor,
    get_legacy_pid_file_path,
    get_legacy_socket_path,
    get_log_file_path,
    get_parent_pid,
    get_pid_file_path,
    get_session_id,
    get_socket_path,
    is_ide_environment,
    is_process_alive,
)


@pytest.fixture
def clear_ide_env(monkeypatch):
    """Clear all IDE-related environment variables for clean testing."""
    monkeypatch.delenv("VSCODE_GIT_IPC_HANDLE", raising=False)
    monkeypatch.delenv("CLAUDECODE", raising=False)
    monkeypatch.delenv("VSCODE_INJECTION", raising=False)
    monkeypatch.delenv("CLAUDE_CODE_SSE_PORT", raising=False)


class TestIsIdeEnvironment:
    """Tests for is_ide_environment function."""

    def test_detects_vscode_git_ipc_handle(self, monkeypatch):
        """Test detection of VS Code via VSCODE_GIT_IPC_HANDLE."""
        monkeypatch.delenv("VSCODE_GIT_IPC_HANDLE", raising=False)
        monkeypatch.delenv("CLAUDECODE", raising=False)
        monkeypatch.delenv("VSCODE_INJECTION", raising=False)
        assert is_ide_environment() is False

        monkeypatch.setenv("VSCODE_GIT_IPC_HANDLE", "/tmp/vscode-git-abc123.sock")
        assert is_ide_environment() is True

    def test_detects_claudecode_env(self, monkeypatch):
        """Test detection of Claude Code via CLAUDECODE env var."""
        monkeypatch.delenv("VSCODE_GIT_IPC_HANDLE", raising=False)
        monkeypatch.delenv("CLAUDECODE", raising=False)
        monkeypatch.delenv("VSCODE_INJECTION", raising=False)
        assert is_ide_environment() is False

        monkeypatch.setenv("CLAUDECODE", "1")
        assert is_ide_environment() is True

    def test_detects_vscode_injection(self, monkeypatch):
        """Test detection of VS Code via VSCODE_INJECTION."""
        monkeypatch.delenv("VSCODE_GIT_IPC_HANDLE", raising=False)
        monkeypatch.delenv("CLAUDECODE", raising=False)
        monkeypatch.delenv("VSCODE_INJECTION", raising=False)
        assert is_ide_environment() is False

        monkeypatch.setenv("VSCODE_INJECTION", "1")
        assert is_ide_environment() is True


class TestGetIdeSessionAnchor:
    """Tests for get_ide_session_anchor function."""

    def test_returns_none_when_no_ide(self, monkeypatch):
        """Test that None is returned when not in an IDE environment."""
        monkeypatch.delenv("VSCODE_GIT_IPC_HANDLE", raising=False)
        assert get_ide_session_anchor() is None

    def test_returns_vscode_socket_path_if_exists(self, monkeypatch, tmp_path):
        """Test that VS Code socket path is returned when it exists."""
        # Create a fake socket file
        socket_file = tmp_path / "vscode-git-abc123.sock"
        socket_file.touch()

        monkeypatch.setenv("VSCODE_GIT_IPC_HANDLE", str(socket_file))
        result = get_ide_session_anchor()
        assert result == socket_file

    def test_returns_none_if_vscode_socket_missing(self, monkeypatch, tmp_path):
        """Test that None is returned if VS Code socket doesn't exist."""
        # Point to non-existent socket
        socket_file = tmp_path / "nonexistent.sock"
        monkeypatch.setenv("VSCODE_GIT_IPC_HANDLE", str(socket_file))
        assert get_ide_session_anchor() is None


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
        # Clear VS Code/Claude Code env vars
        monkeypatch.delenv("VSCODE_GIT_IPC_HANDLE", raising=False)
        monkeypatch.delenv("CLAUDECODE", raising=False)
        monkeypatch.delenv("VSCODE_INJECTION", raising=False)
        monkeypatch.delenv("CLAUDE_CODE_SSE_PORT", raising=False)
        monkeypatch.setenv("TERM_SESSION_ID", "macos-term-session")
        monkeypatch.delenv("WINDOWID", raising=False)
        assert get_session_id() == "macos-term-session"

    def test_uses_vscode_git_ipc_session(self, monkeypatch):
        """Test that VS Code Git IPC handle is used for session ID."""
        monkeypatch.delenv("MCPL_SESSION_ID", raising=False)
        monkeypatch.delenv("TERM_SESSION_ID", raising=False)
        monkeypatch.setenv(
            "VSCODE_GIT_IPC_HANDLE", "/var/folders/xx/vscode-git-abc123def.sock"
        )
        assert get_session_id() == "vscode-abc123def"

    def test_vscode_git_ipc_no_match_falls_through(self, monkeypatch):
        """Test that non-matching VS Code Git IPC handle falls through to next check."""
        monkeypatch.delenv("MCPL_SESSION_ID", raising=False)
        monkeypatch.delenv("TERM_SESSION_ID", raising=False)
        # Set a handle that doesn't match the vscode-git-{hex}.sock pattern
        monkeypatch.setenv("VSCODE_GIT_IPC_HANDLE", "/some/other/path/socket.sock")
        # Should fall through to CLAUDE_CODE_SSE_PORT
        monkeypatch.setenv("CLAUDE_CODE_SSE_PORT", "54321")
        assert get_session_id() == "claude-54321"

    def test_uses_claude_code_sse_port(self, monkeypatch):
        """Test that Claude Code SSE port is used when no Git IPC handle."""
        monkeypatch.delenv("MCPL_SESSION_ID", raising=False)
        monkeypatch.delenv("TERM_SESSION_ID", raising=False)
        monkeypatch.delenv("VSCODE_GIT_IPC_HANDLE", raising=False)
        monkeypatch.setenv("CLAUDE_CODE_SSE_PORT", "12345")
        assert get_session_id() == "claude-12345"

    def test_uses_windowid_on_linux(self, monkeypatch):
        """Test that WINDOWID is used on Linux X11."""
        monkeypatch.delenv("MCPL_SESSION_ID", raising=False)
        monkeypatch.delenv("TERM_SESSION_ID", raising=False)
        # Clear VS Code/Claude Code env vars
        monkeypatch.delenv("VSCODE_GIT_IPC_HANDLE", raising=False)
        monkeypatch.delenv("CLAUDECODE", raising=False)
        monkeypatch.delenv("VSCODE_INJECTION", raising=False)
        monkeypatch.delenv("CLAUDE_CODE_SSE_PORT", raising=False)
        monkeypatch.setenv("WINDOWID", "12345678")
        monkeypatch.delenv("WT_SESSION", raising=False)
        assert get_session_id() == "12345678"

    def test_uses_wt_session_on_windows_terminal(self, monkeypatch):
        """Test that WT_SESSION is used on Windows Terminal."""
        monkeypatch.delenv("MCPL_SESSION_ID", raising=False)
        monkeypatch.delenv("TERM_SESSION_ID", raising=False)
        # Clear VS Code/Claude Code env vars
        monkeypatch.delenv("VSCODE_GIT_IPC_HANDLE", raising=False)
        monkeypatch.delenv("CLAUDECODE", raising=False)
        monkeypatch.delenv("VSCODE_INJECTION", raising=False)
        monkeypatch.delenv("CLAUDE_CODE_SSE_PORT", raising=False)
        monkeypatch.delenv("WINDOWID", raising=False)
        monkeypatch.setenv("WT_SESSION", "windows-terminal-guid")
        assert get_session_id() == "windows-terminal-guid"

    def test_falls_back_to_parent_pid(self, monkeypatch):
        """Test fallback to parent PID when no session env vars set."""
        monkeypatch.delenv("MCPL_SESSION_ID", raising=False)
        monkeypatch.delenv("TERM_SESSION_ID", raising=False)
        # Clear VS Code/Claude Code env vars
        monkeypatch.delenv("VSCODE_GIT_IPC_HANDLE", raising=False)
        monkeypatch.delenv("CLAUDECODE", raising=False)
        monkeypatch.delenv("VSCODE_INJECTION", raising=False)
        monkeypatch.delenv("CLAUDE_CODE_SSE_PORT", raising=False)
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
        """Test that socket path includes session ID (short IDs are preserved)."""
        # Use a short session ID (<=16 chars) to avoid hashing
        monkeypatch.setenv("MCPL_SESSION_ID", "sess-456")
        path = get_socket_path()
        assert "sess-456" in str(path)

    @pytest.mark.skipif(IS_WINDOWS, reason="Unix-specific test")
    def test_unix_socket_path_format(self, monkeypatch):
        """Test Unix socket path format."""
        monkeypatch.setenv("MCPL_SESSION_ID", "test-session")
        path = get_socket_path()
        assert path.suffix == ".sock"
        assert str(os.getuid()) in str(path)

    @pytest.mark.skipif(IS_WINDOWS, reason="Unix-specific test")
    def test_long_session_id_is_hashed(self, monkeypatch):
        """Test that long session IDs are hashed to avoid AF_UNIX path length limits."""
        # This is a typical macOS TERM_SESSION_ID with UUID
        long_session = "w0t3p0:BBB00C6D-4693-42F2-9654-7FCE4CE0B594"
        monkeypatch.setenv("MCPL_SESSION_ID", long_session)
        path = get_socket_path()
        path_str = str(path)
        # Long session ID should not appear literally in the path
        assert long_session not in path_str
        # Path should be short enough for AF_UNIX (under 108 bytes)
        assert len(path_str) < 108
        # Should use /tmp for short paths
        assert path_str.startswith("/tmp/")
        # Path should still be a valid socket path
        assert path.suffix == ".sock"

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


class TestShortenSessionId:
    """Tests for _shorten_session_id function."""

    def test_short_id_unchanged(self):
        """Test that short session IDs are not modified."""
        short_id = "abc123"
        assert _shorten_session_id(short_id) == short_id

    def test_exact_max_length_unchanged(self):
        """Test that session ID at exactly max length is not modified."""
        exact_id = "a" * MAX_SESSION_ID_LEN
        assert _shorten_session_id(exact_id) == exact_id

    def test_long_id_is_hashed(self):
        """Test that long session IDs are hashed."""
        long_id = "w0t3p0:BBB00C6D-4693-42F2-9654-7FCE4CE0B594"
        result = _shorten_session_id(long_id)
        # Should be shortened to max length
        assert len(result) == MAX_SESSION_ID_LEN
        # Original should not appear
        assert long_id not in result
        # Should be hexadecimal (MD5 hash)
        assert all(c in "0123456789abcdef" for c in result)

    def test_hashing_is_deterministic(self):
        """Test that hashing produces consistent results."""
        long_id = "some-very-long-session-id-that-exceeds-limit"
        result1 = _shorten_session_id(long_id)
        result2 = _shorten_session_id(long_id)
        assert result1 == result2

    def test_different_long_ids_produce_different_hashes(self):
        """Test that different long IDs produce different hashes."""
        id1 = "first-very-long-session-id-12345"
        id2 = "second-very-long-session-id-67890"
        result1 = _shorten_session_id(id1)
        result2 = _shorten_session_id(id2)
        assert result1 != result2

    def test_empty_string(self):
        """Test that empty string is handled correctly."""
        result = _shorten_session_id("")
        assert result == ""


class TestGetSafeUsername:
    """Tests for _get_safe_username function."""

    def test_ascii_username_unchanged(self, monkeypatch):
        """Test that ASCII-only usernames are returned unchanged."""
        if IS_WINDOWS:
            monkeypatch.setenv("USERNAME", "johndoe")
        else:
            monkeypatch.setenv("USER", "johndoe")
        result = _get_safe_username()
        assert result == "johndoe"

    def test_non_ascii_username_is_hashed(self, monkeypatch):
        """Test that non-ASCII usernames are hashed."""
        if IS_WINDOWS:
            monkeypatch.setenv("USERNAME", "Iván")
        else:
            monkeypatch.setenv("USER", "Iván")
        result = _get_safe_username()
        # Should be a 12-char hex hash
        assert len(result) == 12
        assert all(c in "0123456789abcdef" for c in result)
        # Original should not appear
        assert "Iván" not in result

    def test_username_with_space_is_hashed(self, monkeypatch):
        """Test that usernames with spaces are hashed."""
        if IS_WINDOWS:
            monkeypatch.setenv("USERNAME", "John Doe")
        else:
            monkeypatch.setenv("USER", "John Doe")
        result = _get_safe_username()
        # Should be a 12-char hex hash
        assert len(result) == 12
        assert all(c in "0123456789abcdef" for c in result)
        # Original should not appear
        assert "John Doe" not in result

    def test_non_ascii_with_space_is_hashed(self, monkeypatch):
        """Test that non-ASCII usernames with spaces are hashed."""
        if IS_WINDOWS:
            monkeypatch.setenv("USERNAME", "Iván Blanco")
        else:
            monkeypatch.setenv("USER", "Iván Blanco")
        result = _get_safe_username()
        # Should be a 12-char hex hash
        assert len(result) == 12
        assert all(c in "0123456789abcdef" for c in result)

    def test_hashing_is_deterministic(self, monkeypatch):
        """Test that hashing produces consistent results."""
        if IS_WINDOWS:
            monkeypatch.setenv("USERNAME", "用户名")
        else:
            monkeypatch.setenv("USER", "用户名")
        result1 = _get_safe_username()
        result2 = _get_safe_username()
        assert result1 == result2

    def test_different_usernames_produce_different_hashes(self, monkeypatch):
        """Test that different non-ASCII usernames produce different hashes."""
        if IS_WINDOWS:
            monkeypatch.setenv("USERNAME", "Müller")
            result1 = _get_safe_username()
            monkeypatch.setenv("USERNAME", "Müllér")
            result2 = _get_safe_username()
        else:
            monkeypatch.setenv("USER", "Müller")
            result1 = _get_safe_username()
            monkeypatch.setenv("USER", "Müllér")
            result2 = _get_safe_username()
        assert result1 != result2

    def test_default_username_when_env_not_set(self, monkeypatch):
        """Test fallback to 'user' when environment variable is not set."""
        if IS_WINDOWS:
            monkeypatch.delenv("USERNAME", raising=False)
        else:
            monkeypatch.delenv("USER", raising=False)
        result = _get_safe_username()
        assert result == "user"

    def test_cyrillic_username_is_hashed(self, monkeypatch):
        """Test that Cyrillic usernames are hashed."""
        if IS_WINDOWS:
            monkeypatch.setenv("USERNAME", "Пользователь")
        else:
            monkeypatch.setenv("USER", "Пользователь")
        result = _get_safe_username()
        assert len(result) == 12
        assert all(c in "0123456789abcdef" for c in result)

    def test_arabic_username_is_hashed(self, monkeypatch):
        """Test that Arabic usernames are hashed."""
        if IS_WINDOWS:
            monkeypatch.setenv("USERNAME", "المستخدم")
        else:
            monkeypatch.setenv("USER", "المستخدم")
        result = _get_safe_username()
        assert len(result) == 12
        assert all(c in "0123456789abcdef" for c in result)


class TestGetLegacySocketPath:
    """Tests for get_legacy_socket_path function."""

    @pytest.mark.skipif(IS_WINDOWS, reason="Unix-specific test")
    def test_returns_path_object(self, monkeypatch):
        """Test that legacy socket path is a Path object."""
        monkeypatch.setenv("MCPL_SESSION_ID", "test-session")
        path = get_legacy_socket_path()
        assert isinstance(path, Path)

    @pytest.mark.skipif(IS_WINDOWS, reason="Unix-specific test")
    def test_uses_tempdir(self, monkeypatch):
        """Test that legacy path uses tempfile.gettempdir()."""
        import tempfile

        monkeypatch.setenv("MCPL_SESSION_ID", "test-session")
        path = get_legacy_socket_path()
        # Legacy path should use tempdir, not /tmp directly
        assert str(path).startswith(tempfile.gettempdir())

    @pytest.mark.skipif(IS_WINDOWS, reason="Unix-specific test")
    def test_uses_unhashed_session_id(self, monkeypatch):
        """Test that legacy path uses unhashed session ID."""
        long_session = "w0t3p0:BBB00C6D-4693-42F2-9654-7FCE4CE0B594"
        monkeypatch.setenv("MCPL_SESSION_ID", long_session)
        path = get_legacy_socket_path()
        # Legacy path should contain the full unhashed session ID
        assert long_session in str(path)

    @pytest.mark.skipif(IS_WINDOWS, reason="Unix-specific test")
    def test_differs_from_new_socket_path(self, monkeypatch):
        """Test that legacy path differs from new path for long session IDs."""
        long_session = "w0t3p0:BBB00C6D-4693-42F2-9654-7FCE4CE0B594"
        monkeypatch.setenv("MCPL_SESSION_ID", long_session)
        legacy_path = get_legacy_socket_path()
        new_path = get_socket_path()
        assert legacy_path != new_path

    @pytest.mark.skipif(not IS_WINDOWS, reason="Windows-specific test")
    def test_returns_none_on_windows(self, monkeypatch):
        """Test that legacy socket path returns None on Windows."""
        monkeypatch.setenv("MCPL_SESSION_ID", "test-session")
        path = get_legacy_socket_path()
        assert path is None


class TestGetLegacyPidFilePath:
    """Tests for get_legacy_pid_file_path function."""

    @pytest.mark.skipif(IS_WINDOWS, reason="Unix-specific test")
    def test_returns_path_object(self, monkeypatch):
        """Test that legacy PID file path is a Path object."""
        monkeypatch.setenv("MCPL_SESSION_ID", "test-session")
        path = get_legacy_pid_file_path()
        assert isinstance(path, Path)

    @pytest.mark.skipif(IS_WINDOWS, reason="Unix-specific test")
    def test_uses_tempdir(self, monkeypatch):
        """Test that legacy path uses tempfile.gettempdir()."""
        import tempfile

        monkeypatch.setenv("MCPL_SESSION_ID", "test-session")
        path = get_legacy_pid_file_path()
        assert str(path).startswith(tempfile.gettempdir())

    @pytest.mark.skipif(IS_WINDOWS, reason="Unix-specific test")
    def test_uses_unhashed_session_id(self, monkeypatch):
        """Test that legacy path uses unhashed session ID."""
        long_session = "w0t3p0:BBB00C6D-4693-42F2-9654-7FCE4CE0B594"
        monkeypatch.setenv("MCPL_SESSION_ID", long_session)
        path = get_legacy_pid_file_path()
        assert long_session in str(path)

    @pytest.mark.skipif(IS_WINDOWS, reason="Unix-specific test")
    def test_has_pid_extension(self, monkeypatch):
        """Test that legacy PID file has .pid extension."""
        monkeypatch.setenv("MCPL_SESSION_ID", "test-session")
        path = get_legacy_pid_file_path()
        assert path.suffix == ".pid"

    @pytest.mark.skipif(not IS_WINDOWS, reason="Windows-specific test")
    def test_returns_none_on_windows(self, monkeypatch):
        """Test that legacy PID file path returns None on Windows."""
        monkeypatch.setenv("MCPL_SESSION_ID", "test-session")
        path = get_legacy_pid_file_path()
        assert path is None


class TestGetLogFilePath:
    """Tests for get_log_file_path function."""

    def test_returns_path_object(self, monkeypatch):
        """Test that log file path is a Path object."""
        monkeypatch.setenv("MCPL_SESSION_ID", "test-session")
        path = get_log_file_path()
        assert isinstance(path, Path)

    def test_has_log_extension(self, monkeypatch):
        """Test that log file has .log extension."""
        monkeypatch.setenv("MCPL_SESSION_ID", "test-session")
        path = get_log_file_path()
        assert path.suffix == ".log"

    @pytest.mark.skipif(IS_WINDOWS, reason="Unix-specific test")
    def test_unix_log_path_uses_tmp(self, monkeypatch):
        """Test Unix log path uses /tmp directory."""
        monkeypatch.setenv("MCPL_SESSION_ID", "test-session")
        path = get_log_file_path()
        assert str(path).startswith("/tmp/")

    @pytest.mark.skipif(IS_WINDOWS, reason="Unix-specific test")
    def test_long_session_id_is_hashed_in_log_path(self, monkeypatch):
        """Test that long session IDs are hashed in log path."""
        long_session = "w0t3p0:BBB00C6D-4693-42F2-9654-7FCE4CE0B594"
        monkeypatch.setenv("MCPL_SESSION_ID", long_session)
        path = get_log_file_path()
        # Long session ID should not appear in the path
        assert long_session not in str(path)


class TestPathConsistency:
    """Tests for consistency between path functions."""

    @pytest.mark.skipif(IS_WINDOWS, reason="Unix-specific test")
    def test_socket_pid_log_use_same_session_id(self, monkeypatch):
        """Test that socket, PID, and log paths use the same session ID portion."""
        monkeypatch.setenv("MCPL_SESSION_ID", "consistent-session")
        socket_path = str(get_socket_path())
        pid_path = str(get_pid_file_path())
        log_path = str(get_log_file_path())

        # Extract session ID from each path (after uid and before extension)
        uid = str(os.getuid())
        socket_session = socket_path.split(f"mcpl-{uid}-")[1].split(".sock")[0]
        pid_session = pid_path.split(f"mcpl-{uid}-")[1].split(".pid")[0]
        log_session = log_path.split(f"mcpl-{uid}-")[1].split(".log")[0]

        assert socket_session == pid_session == log_session

    @pytest.mark.skipif(IS_WINDOWS, reason="Unix-specific test")
    def test_all_paths_under_108_bytes(self, monkeypatch):
        """Test that all paths stay under AF_UNIX 108 byte limit."""
        # Use a very long session ID
        long_session = "a" * 200
        monkeypatch.setenv("MCPL_SESSION_ID", long_session)

        socket_path = str(get_socket_path())
        pid_path = str(get_pid_file_path())
        log_path = str(get_log_file_path())

        assert len(socket_path) < 108, f"Socket path too long: {len(socket_path)}"
        assert len(pid_path) < 108, f"PID path too long: {len(pid_path)}"
        assert len(log_path) < 108, f"Log path too long: {len(log_path)}"
