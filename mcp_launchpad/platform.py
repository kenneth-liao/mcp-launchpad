"""Cross-platform utilities for session management and IPC."""

from __future__ import annotations

import hashlib
import os
import sys
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass

# Platform detection
IS_WINDOWS = sys.platform == "win32"

# AF_UNIX socket path limit is 108 bytes on most Unix systems (104 on macOS).
# We need to ensure our socket paths stay well under this limit.
# Using /tmp (always short) + hash of session_id ensures we stay under ~50 chars.
MAX_SESSION_ID_LEN = 16


def is_ide_environment() -> bool:
    """Check if running in an IDE environment (VS Code, Claude Code, etc.).

    In IDE environments, the daemon should not shut down when its immediate
    parent process dies, because each terminal command runs in a separate
    subprocess. Instead, the daemon should stay alive for the entire IDE session.
    """
    # VS Code sets VSCODE_GIT_IPC_HANDLE
    if os.environ.get("VSCODE_GIT_IPC_HANDLE"):
        return True

    # Claude Code sets CLAUDECODE=1
    if os.environ.get("CLAUDECODE"):
        return True

    # VS Code injection marker
    if os.environ.get("VSCODE_INJECTION"):
        return True

    return False


def get_ide_session_anchor() -> Path | None:
    """Get the file/socket that anchors this IDE session.

    Returns a path that exists while the IDE session is active. When the IDE
    closes, this path will no longer exist. Used by the daemon to detect when
    the IDE session ends so it can shut down cleanly.

    Returns None if not in an IDE environment or no anchor can be determined.
    """
    # VS Code Git IPC socket - disappears when VS Code closes
    if git_ipc := os.environ.get("VSCODE_GIT_IPC_HANDLE"):
        path = Path(git_ipc)
        if path.exists():
            return path

    return None


def get_session_id() -> str:
    """Get a unique identifier for the current terminal session.

    This is used to scope the daemon to the current terminal session,
    allowing multiple terminals to have independent daemon instances.

    Priority order:
    1. MCPL_SESSION_ID - explicit override for testing/advanced usage
    2. TERM_SESSION_ID - macOS Terminal.app
    3. VS Code/Claude Code session - extracted from VSCODE_GIT_IPC_HANDLE
    4. WINDOWID - X11 terminals (Linux)
    5. WT_SESSION - Windows Terminal
    6. Parent PID - fallback (works everywhere)
    """
    # Explicit override
    if session_id := os.environ.get("MCPL_SESSION_ID"):
        return session_id

    # macOS Terminal.app
    if session_id := os.environ.get("TERM_SESSION_ID"):
        return session_id

    # VS Code / Claude Code - extract unique session ID from Git IPC handle
    # Format: /var/folders/.../vscode-git-{session_id}.sock
    if git_ipc := os.environ.get("VSCODE_GIT_IPC_HANDLE"):
        import re

        if match := re.search(r"vscode-git-([a-f0-9]+)\.sock", git_ipc):
            return f"vscode-{match.group(1)}"

    # Claude Code fallback - use SSE port as session identifier
    if sse_port := os.environ.get("CLAUDE_CODE_SSE_PORT"):
        return f"claude-{sse_port}"

    # X11 terminals (Linux)
    if session_id := os.environ.get("WINDOWID"):
        return session_id

    # Windows Terminal
    if session_id := os.environ.get("WT_SESSION"):
        return session_id

    # Fallback to parent PID (works everywhere but not ideal for Claude Code)
    return str(os.getppid())


def _shorten_session_id(session_id: str) -> str:
    """Shorten session ID to avoid AF_UNIX path length limits.

    AF_UNIX socket paths are limited to 108 bytes on Linux and 104 on macOS.
    Long session IDs (e.g., from TERM_SESSION_ID with UUIDs) can exceed this.
    We hash long IDs to a fixed short length while preserving uniqueness.
    """
    if len(session_id) <= MAX_SESSION_ID_LEN:
        return session_id
    # Use first 16 chars of MD5 hash - short but unique enough for session scoping
    return hashlib.md5(session_id.encode(), usedforsecurity=False).hexdigest()[:MAX_SESSION_ID_LEN]


def _get_safe_username() -> str:
    """Get a filesystem/pipe-safe username identifier.

    Windows named pipes don't support non-ASCII characters in pipe names.
    This function returns the username directly if it contains only ASCII
    characters and no spaces. Otherwise, returns a short hash of the username.
    """
    if IS_WINDOWS:
        username = os.environ.get("USERNAME", "user")
    else:
        username = os.environ.get("USER", "user")

    if username.isascii() and " " not in username:
        return username

    # Hash non-ASCII or space-containing usernames to ensure safe paths
    return hashlib.sha256(username.encode("utf-8")).hexdigest()[:12]


def get_socket_path() -> Path:
    r"""Get the path for the daemon socket/pipe.

    On Unix: /tmp/mcpl-{uid}-{session_id}.sock
    On Windows: \\.\pipe\mcpl-{username}-{session_id}

    Note: We use /tmp directly on Unix instead of tempfile.gettempdir() because
    macOS returns long paths like /var/folders/.../T/ which can exceed the
    108-byte AF_UNIX socket path limit when combined with session IDs.
    """
    session_id = _shorten_session_id(get_session_id())

    if IS_WINDOWS:
        username = _get_safe_username()
        # Windows named pipes use a special path format
        return Path(f"\\\\.\\pipe\\mcpl-{username}-{session_id}")
    else:
        uid = os.getuid()
        # Use /tmp directly - it's always short and writable.
        # tempfile.gettempdir() returns long paths on macOS (/var/folders/...)
        # which can exceed AF_UNIX 108-byte limit.
        return Path("/tmp") / f"mcpl-{uid}-{session_id}.sock"


def get_pid_file_path() -> Path:
    """Get the path for the daemon PID file.

    Uses the same shortened session ID as get_socket_path() for consistency.
    """
    session_id = _shorten_session_id(get_session_id())

    if IS_WINDOWS:
        username = _get_safe_username()
        temp_dir = Path(tempfile.gettempdir())
        return temp_dir / f"mcpl-{username}-{session_id}.pid"
    else:
        uid = os.getuid()
        # Use /tmp for consistency with socket path
        return Path("/tmp") / f"mcpl-{uid}-{session_id}.pid"


def get_log_file_path() -> Path:
    """Get the path for the daemon log file.

    Uses the same shortened session ID as get_socket_path() for consistency.
    """
    session_id = _shorten_session_id(get_session_id())

    if IS_WINDOWS:
        username = _get_safe_username()
        temp_dir = Path(tempfile.gettempdir())
        return temp_dir / f"mcpl-{username}-{session_id}.log"
    else:
        uid = os.getuid()
        # Use /tmp for consistency with socket path
        return Path("/tmp") / f"mcpl-{uid}-{session_id}.log"


def get_legacy_socket_path() -> Path | None:
    """Get old-format socket path (pre-v0.x.x) for migration detection.

    Old format used tempfile.gettempdir() and unhashed session IDs.
    Returns None on Windows (no migration needed - Windows uses named pipes).

    Used during upgrade to detect and clean up legacy daemons.
    """
    if IS_WINDOWS:
        return None  # Windows uses named pipes, no migration needed

    session_id = get_session_id()  # Raw, unhashed
    uid = os.getuid()
    return Path(tempfile.gettempdir()) / f"mcpl-{uid}-{session_id}.sock"


def get_legacy_pid_file_path() -> Path | None:
    """Get old-format PID file path (pre-v0.x.x) for migration detection.

    Old format used tempfile.gettempdir() and unhashed session IDs.
    Returns None on Windows (no migration needed).

    Used during upgrade to detect and clean up legacy daemons.
    """
    if IS_WINDOWS:
        return None  # Windows uses named pipes, no migration needed

    session_id = get_session_id()  # Raw, unhashed
    uid = os.getuid()
    return Path(tempfile.gettempdir()) / f"mcpl-{uid}-{session_id}.pid"


def is_process_alive(pid: int) -> bool:
    """Check if a process with the given PID is still running.

    Cross-platform implementation.
    """
    if IS_WINDOWS:
        return _is_process_alive_windows(pid)
    else:
        return _is_process_alive_unix(pid)


def _is_process_alive_unix(pid: int) -> bool:
    """Check if process is alive on Unix systems."""
    try:
        # Signal 0 doesn't actually send a signal, just checks if process exists
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _is_process_alive_windows(pid: int) -> bool:
    """Check if process is alive on Windows."""
    import ctypes  # noqa: PLC0415
    from ctypes import wintypes  # noqa: PLC0415

    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    STILL_ACTIVE = 259

    kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]

    handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return False

    try:
        exit_code = wintypes.DWORD()
        if kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
            return bool(exit_code.value == STILL_ACTIVE)
        return False
    finally:
        kernel32.CloseHandle(handle)


def get_parent_pid() -> int:
    """Get the parent process ID.

    On Windows, we need a different approach since os.getppid()
    may not work correctly in all cases.
    """
    if IS_WINDOWS:
        return _get_parent_pid_windows()
    else:
        return os.getppid()


def _get_parent_pid_windows() -> int:
    """Get parent PID on Windows using ctypes."""
    import ctypes  # noqa: PLC0415
    from ctypes import wintypes  # noqa: PLC0415

    TH32CS_SNAPPROCESS = 0x00000002

    class PROCESSENTRY32(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ProcessID", wintypes.DWORD),
            ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
            ("th32ModuleID", wintypes.DWORD),
            ("cntThreads", wintypes.DWORD),
            ("th32ParentProcessID", wintypes.DWORD),
            ("pcPriClassBase", ctypes.c_long),
            ("dwFlags", wintypes.DWORD),
            ("szExeFile", ctypes.c_char * 260),
        ]

    kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
    current_pid = os.getpid()

    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshot == -1:
        return os.getppid()  # Fallback

    try:
        pe32 = PROCESSENTRY32()
        pe32.dwSize = ctypes.sizeof(PROCESSENTRY32)

        if kernel32.Process32First(snapshot, ctypes.byref(pe32)):
            while True:
                if pe32.th32ProcessID == current_pid:
                    return int(pe32.th32ParentProcessID)
                if not kernel32.Process32Next(snapshot, ctypes.byref(pe32)):
                    break
    finally:
        kernel32.CloseHandle(snapshot)

    return os.getppid()  # Fallback
