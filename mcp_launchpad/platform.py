"""Cross-platform utilities for session management and IPC."""

import os
import sys
import tempfile
from abc import ABC, abstractmethod
from pathlib import Path

# Platform detection
IS_WINDOWS = sys.platform == "win32"


def get_session_id() -> str:
    """Get a unique identifier for the current terminal session.

    This is used to scope the daemon to the current terminal session,
    allowing multiple terminals to have independent daemon instances.

    Priority order:
    1. MCPL_SESSION_ID - explicit override for testing/advanced usage
    2. TERM_SESSION_ID - macOS Terminal.app
    3. WINDOWID - X11 terminals (Linux)
    4. WT_SESSION - Windows Terminal
    5. Parent PID - fallback (works everywhere)
    """
    return (
        os.environ.get("MCPL_SESSION_ID")
        or os.environ.get("TERM_SESSION_ID")
        or os.environ.get("WINDOWID")
        or os.environ.get("WT_SESSION")
        or str(os.getppid())
    )


def get_socket_path() -> Path:
    r"""Get the path for the daemon socket/pipe.

    On Unix: /tmp/mcpl-{uid}-{session_id}.sock
    On Windows: \\.\pipe\mcpl-{username}-{session_id}
    """
    session_id = get_session_id()

    if IS_WINDOWS:
        username = os.environ.get("USERNAME", "user")
        # Windows named pipes use a special path format
        return Path(f"\\\\.\\pipe\\mcpl-{username}-{session_id}")
    else:
        uid = os.getuid()
        # Use tempdir for socket file (ensures write permission)
        return Path(tempfile.gettempdir()) / f"mcpl-{uid}-{session_id}.sock"


def get_pid_file_path() -> Path:
    """Get the path for the daemon PID file."""
    session_id = get_session_id()

    if IS_WINDOWS:
        username = os.environ.get("USERNAME", "user")
        temp_dir = Path(tempfile.gettempdir())
        return temp_dir / f"mcpl-{username}-{session_id}.pid"
    else:
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
    import ctypes
    from ctypes import wintypes

    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    STILL_ACTIVE = 259

    kernel32 = ctypes.windll.kernel32

    handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return False

    try:
        exit_code = wintypes.DWORD()
        if kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
            return exit_code.value == STILL_ACTIVE
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
    import ctypes
    from ctypes import wintypes

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

    kernel32 = ctypes.windll.kernel32
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
                    return pe32.th32ParentProcessID
                if not kernel32.Process32Next(snapshot, ctypes.byref(pe32)):
                    break
    finally:
        kernel32.CloseHandle(snapshot)

    return os.getppid()  # Fallback

