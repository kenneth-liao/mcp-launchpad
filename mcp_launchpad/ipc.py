"""Cross-platform IPC for daemon communication."""

import asyncio
import json
import struct
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .platform import IS_WINDOWS, get_socket_path


# Message format: 4-byte length prefix + JSON payload
HEADER_SIZE = 4


@dataclass
class IPCMessage:
    """A message sent between CLI and daemon."""

    action: str
    payload: dict[str, Any]

    def to_bytes(self) -> bytes:
        """Serialize message to bytes with length prefix."""
        data = json.dumps({"action": self.action, "payload": self.payload}).encode()
        return struct.pack(">I", len(data)) + data

    @classmethod
    def from_bytes(cls, data: bytes) -> "IPCMessage":
        """Deserialize message from JSON bytes."""
        parsed = json.loads(data.decode())
        return cls(action=parsed["action"], payload=parsed.get("payload", {}))


async def read_message(reader: asyncio.StreamReader) -> IPCMessage | None:
    """Read a length-prefixed message from the stream."""
    header = await reader.read(HEADER_SIZE)
    if len(header) < HEADER_SIZE:
        return None

    (length,) = struct.unpack(">I", header)
    data = await reader.read(length)
    if len(data) < length:
        return None

    return IPCMessage.from_bytes(data)


async def write_message(writer: asyncio.StreamWriter, message: IPCMessage) -> None:
    """Write a length-prefixed message to the stream."""
    writer.write(message.to_bytes())
    await writer.drain()


class IPCServer(ABC):
    """Abstract base class for IPC server."""

    @abstractmethod
    async def start(self) -> None:
        """Start the server."""
        pass

    @abstractmethod
    async def stop(self) -> None:
        """Stop the server."""
        pass


class UnixIPCServer(IPCServer):
    """Unix socket-based IPC server."""

    def __init__(self, socket_path: Path, handler):
        self.socket_path = socket_path
        self.handler = handler
        self.server: asyncio.Server | None = None

    async def start(self) -> None:
        """Start listening on Unix socket."""
        # Remove stale socket file if it exists
        if self.socket_path.exists():
            self.socket_path.unlink()

        self.server = await asyncio.start_unix_server(
            self._handle_client, path=str(self.socket_path)
        )

    async def stop(self) -> None:
        """Stop the server and cleanup."""
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        if self.socket_path.exists():
            self.socket_path.unlink()

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Handle a client connection."""
        try:
            message = await read_message(reader)
            if message:
                response = await self.handler(message)
                await write_message(writer, response)
        finally:
            writer.close()
            await writer.wait_closed()


class WindowsIPCServer(IPCServer):
    """Windows named pipe-based IPC server."""

    def __init__(self, pipe_name: str, handler):
        self.pipe_name = pipe_name
        self.handler = handler
        self._running = False
        self._server_task: asyncio.Task | None = None

    async def start(self) -> None:
        """Start listening on named pipe."""
        self._running = True
        self._server_task = asyncio.create_task(self._run_server())

    async def stop(self) -> None:
        """Stop the server."""
        self._running = False
        if self._server_task:
            self._server_task.cancel()
            try:
                await self._server_task
            except asyncio.CancelledError:
                pass

    async def _run_server(self) -> None:
        """Main server loop for Windows named pipes."""
        import ctypes
        from ctypes import wintypes

        PIPE_ACCESS_DUPLEX = 0x00000003
        PIPE_TYPE_MESSAGE = 0x00000004
        PIPE_READMODE_MESSAGE = 0x00000002
        PIPE_WAIT = 0x00000000
        PIPE_UNLIMITED_INSTANCES = 255
        BUFFER_SIZE = 65536
        INVALID_HANDLE_VALUE = -1

        kernel32 = ctypes.windll.kernel32

        while self._running:
            # Create named pipe
            pipe_handle = kernel32.CreateNamedPipeW(
                self.pipe_name,
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                PIPE_UNLIMITED_INSTANCES,
                BUFFER_SIZE,
                BUFFER_SIZE,
                0,
                None,
            )

            if pipe_handle == INVALID_HANDLE_VALUE:
                await asyncio.sleep(0.1)
                continue

            try:
                # Wait for client connection (in thread to not block)
                connected = await asyncio.to_thread(
                    kernel32.ConnectNamedPipe, pipe_handle, None
                )
                if connected or kernel32.GetLastError() == 535:  # ERROR_PIPE_CONNECTED
                    await self._handle_pipe_client(kernel32, pipe_handle)
            finally:
                kernel32.CloseHandle(pipe_handle)

    async def _handle_pipe_client(self, kernel32, pipe_handle) -> None:
        """Handle a client connected via named pipe."""
        import ctypes

        BUFFER_SIZE = 65536

        # Read message
        buffer = ctypes.create_string_buffer(BUFFER_SIZE)
        bytes_read = ctypes.c_ulong(0)

        success = await asyncio.to_thread(
            kernel32.ReadFile,
            pipe_handle,
            buffer,
            BUFFER_SIZE,
            ctypes.byref(bytes_read),
            None,
        )

        if success and bytes_read.value > 0:
            # Parse message (skip length header - Windows pipes handle framing)
            data = buffer.raw[HEADER_SIZE : HEADER_SIZE + bytes_read.value - HEADER_SIZE]
            try:
                message = IPCMessage.from_bytes(
                    buffer.raw[HEADER_SIZE : bytes_read.value]
                )
                response = await self.handler(message)

                # Write response
                response_bytes = response.to_bytes()
                bytes_written = ctypes.c_ulong(0)
                await asyncio.to_thread(
                    kernel32.WriteFile,
                    pipe_handle,
                    response_bytes,
                    len(response_bytes),
                    ctypes.byref(bytes_written),
                    None,
                )
            except Exception:
                pass  # Connection error, client will retry


async def connect_to_daemon() -> tuple[asyncio.StreamReader, asyncio.StreamWriter] | None:
    """Connect to the daemon IPC endpoint.

    Returns (reader, writer) tuple or None if connection failed.
    """
    socket_path = get_socket_path()

    if IS_WINDOWS:
        return await _connect_windows(str(socket_path))
    else:
        return await _connect_unix(socket_path)


async def _connect_unix(socket_path: Path) -> tuple[asyncio.StreamReader, asyncio.StreamWriter] | None:
    """Connect to Unix socket."""
    if not socket_path.exists():
        return None

    try:
        reader, writer = await asyncio.open_unix_connection(str(socket_path))
        return reader, writer
    except (ConnectionRefusedError, FileNotFoundError):
        return None


async def _connect_windows(pipe_name: str) -> tuple[asyncio.StreamReader, asyncio.StreamWriter] | None:
    """Connect to Windows named pipe."""
    import ctypes
    from ctypes import wintypes

    GENERIC_READ = 0x80000000
    GENERIC_WRITE = 0x40000000
    OPEN_EXISTING = 3
    INVALID_HANDLE_VALUE = -1

    kernel32 = ctypes.windll.kernel32

    # Try to open the pipe
    handle = kernel32.CreateFileW(
        pipe_name,
        GENERIC_READ | GENERIC_WRITE,
        0,
        None,
        OPEN_EXISTING,
        0,
        None,
    )

    if handle == INVALID_HANDLE_VALUE:
        return None

    # Wrap handle in asyncio streams
    # Note: This is a simplified approach. For production, consider using
    # asyncio.open_connection with a custom transport or a library like aioconsole
    return _create_pipe_streams(kernel32, handle)


def _create_pipe_streams(kernel32, handle) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Create asyncio streams from a Windows pipe handle."""
    # Create a simple wrapper that provides read/write operations
    # This is a simplified implementation
    reader = asyncio.StreamReader()
    protocol = asyncio.StreamReaderProtocol(reader)

    # For Windows, we'll use a different approach in the actual implementation
    # This placeholder shows the interface we need
    class PipeWriter:
        def __init__(self, kernel32, handle):
            self.kernel32 = kernel32
            self.handle = handle

        def write(self, data: bytes) -> None:
            import ctypes
            bytes_written = ctypes.c_ulong(0)
            self.kernel32.WriteFile(
                self.handle, data, len(data), ctypes.byref(bytes_written), None
            )

        async def drain(self) -> None:
            pass

        def close(self) -> None:
            self.kernel32.CloseHandle(self.handle)

        async def wait_closed(self) -> None:
            pass

    return reader, PipeWriter(kernel32, handle)  # type: ignore


def create_ipc_server(handler) -> IPCServer:
    """Create the appropriate IPC server for the current platform."""
    socket_path = get_socket_path()

    if IS_WINDOWS:
        return WindowsIPCServer(str(socket_path), handler)
    else:
        return UnixIPCServer(socket_path, handler)

