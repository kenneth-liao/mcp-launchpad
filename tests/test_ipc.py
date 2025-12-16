"""Tests for IPC communication layer."""

import asyncio
import json
import struct
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mcp_launchpad.ipc import (
    HEADER_SIZE,
    IPCMessage,
    UnixIPCServer,
    create_ipc_server,
    read_message,
    write_message,
)
from mcp_launchpad.platform import IS_WINDOWS


class TestIPCMessage:
    """Tests for IPCMessage dataclass."""

    def test_to_bytes_serialization(self):
        """Test message serialization to bytes."""
        message = IPCMessage(action="test_action", payload={"key": "value"})
        data = message.to_bytes()
        
        # Should have 4-byte length prefix
        assert len(data) > HEADER_SIZE
        length = struct.unpack(">I", data[:HEADER_SIZE])[0]
        assert length == len(data) - HEADER_SIZE

    def test_from_bytes_deserialization(self):
        """Test message deserialization from bytes."""
        original = IPCMessage(action="call_tool", payload={"server": "test", "tool": "foo"})
        data = original.to_bytes()
        
        # Skip the length prefix when deserializing
        restored = IPCMessage.from_bytes(data[HEADER_SIZE:])
        assert restored.action == original.action
        assert restored.payload == original.payload

    def test_roundtrip(self):
        """Test that serialization and deserialization are reversible."""
        original = IPCMessage(
            action="complex_action",
            payload={"nested": {"data": [1, 2, 3]}, "unicode": "日本語"}
        )
        data = original.to_bytes()
        restored = IPCMessage.from_bytes(data[HEADER_SIZE:])
        assert restored.action == original.action
        assert restored.payload == original.payload

    def test_empty_payload(self):
        """Test message with empty payload."""
        message = IPCMessage(action="status", payload={})
        data = message.to_bytes()
        restored = IPCMessage.from_bytes(data[HEADER_SIZE:])
        assert restored.payload == {}


class TestReadWriteMessage:
    """Tests for read_message and write_message functions."""

    @pytest.mark.asyncio
    async def test_write_and_read_message(self):
        """Test writing and reading a message through streams."""
        # Create in-memory stream
        reader = asyncio.StreamReader()
        
        # Create a mock writer
        written_data = bytearray()
        mock_writer = MagicMock()
        mock_writer.write = lambda data: written_data.extend(data)
        mock_writer.drain = AsyncMock()
        
        # Write a message
        original = IPCMessage(action="test", payload={"foo": "bar"})
        await write_message(mock_writer, original)
        
        # Feed the written data to the reader
        reader.feed_data(bytes(written_data))
        reader.feed_eof()
        
        # Read it back
        restored = await read_message(reader)
        assert restored is not None
        assert restored.action == original.action
        assert restored.payload == original.payload

    @pytest.mark.asyncio
    async def test_read_message_incomplete_header(self):
        """Test reading with incomplete header returns None."""
        reader = asyncio.StreamReader()
        reader.feed_data(b"\x00\x00")  # Only 2 bytes, need 4
        reader.feed_eof()
        
        result = await read_message(reader)
        assert result is None

    @pytest.mark.asyncio
    async def test_read_message_incomplete_body(self):
        """Test reading with incomplete body returns None."""
        reader = asyncio.StreamReader()
        # Header says 100 bytes, but we only provide 10
        reader.feed_data(struct.pack(">I", 100) + b"short")
        reader.feed_eof()
        
        result = await read_message(reader)
        assert result is None


@pytest.mark.skipif(IS_WINDOWS, reason="Unix-specific tests")
class TestUnixIPCServer:
    """Tests for Unix socket IPC server."""

    @pytest.mark.asyncio
    async def test_server_start_stop(self):
        """Test server can start and stop cleanly."""
        import tempfile
        # Use a short path to avoid AF_UNIX path length limit
        socket_path = Path(tempfile.gettempdir()) / "mcpl-test.sock"

        async def handler(msg):
            return IPCMessage(action="response", payload={})

        server = UnixIPCServer(socket_path, handler)
        try:
            await server.start()
            assert socket_path.exists()
        finally:
            await server.stop()
            assert not socket_path.exists()

    @pytest.mark.asyncio
    async def test_server_handles_request(self):
        """Test server handles client requests correctly."""
        import tempfile
        # Use a short path to avoid AF_UNIX path length limit
        socket_path = Path(tempfile.gettempdir()) / "mcpl-test2.sock"

        async def handler(msg):
            return IPCMessage(action="response", payload={"received": msg.action})

        server = UnixIPCServer(socket_path, handler)
        await server.start()

        try:
            # Connect and send a message
            reader, writer = await asyncio.open_unix_connection(str(socket_path))
            request = IPCMessage(action="ping", payload={})
            await write_message(writer, request)

            response = await read_message(reader)
            assert response is not None
            assert response.action == "response"
            assert response.payload["received"] == "ping"

            writer.close()
            await writer.wait_closed()
        finally:
            await server.stop()


class TestCreateIPCServer:
    """Tests for create_ipc_server factory function."""

    def test_creates_appropriate_server(self, monkeypatch):
        """Test that factory creates platform-appropriate server."""
        monkeypatch.setenv("MCPL_SESSION_ID", "test-factory")

        async def handler(msg: IPCMessage) -> IPCMessage:
            return IPCMessage(action="response", payload={})

        server = create_ipc_server(handler)

        if IS_WINDOWS:
            from mcp_launchpad.ipc import WindowsIPCServer
            assert isinstance(server, WindowsIPCServer)
        else:
            assert isinstance(server, UnixIPCServer)


@pytest.mark.skipif(IS_WINDOWS, reason="Unix-specific tests")
class TestIPCConnectionUnix:
    """Tests for Unix socket connection."""

    @pytest.mark.asyncio
    async def test_connect_and_communicate(self):
        """Test connecting to a Unix socket server and communicating."""
        import tempfile

        socket_path = Path(tempfile.gettempdir()) / "mcpl-test-connect.sock"

        async def handler(msg: IPCMessage) -> IPCMessage:
            return IPCMessage(action="pong", payload={"echo": msg.action})

        server = UnixIPCServer(socket_path, handler)
        await server.start()

        try:
            # Connect directly
            reader, writer = await asyncio.open_unix_connection(str(socket_path))

            # Send a message
            await write_message(writer, IPCMessage(action="ping", payload={}))
            response = await read_message(reader)
            assert response is not None
            assert response.action == "pong"
            assert response.payload["echo"] == "ping"

            writer.close()
            await writer.wait_closed()
        finally:
            await server.stop()


class TestIPCMessageEdgeCases:
    """Edge case tests for IPCMessage."""

    def test_large_payload(self):
        """Test handling large payloads."""
        large_data = {"data": "x" * 100000}
        message = IPCMessage(action="large", payload=large_data)
        data = message.to_bytes()
        restored = IPCMessage.from_bytes(data[HEADER_SIZE:])
        assert restored.payload == large_data

    def test_special_characters_in_payload(self):
        """Test handling special characters."""
        special = {"chars": "!@#$%^&*()_+-=[]{}|;':\",./<>?`~"}
        message = IPCMessage(action="special", payload=special)
        data = message.to_bytes()
        restored = IPCMessage.from_bytes(data[HEADER_SIZE:])
        assert restored.payload == special

    def test_nested_payload(self):
        """Test deeply nested payloads."""
        nested = {"level1": {"level2": {"level3": {"level4": "deep"}}}}
        message = IPCMessage(action="nested", payload=nested)
        data = message.to_bytes()
        restored = IPCMessage.from_bytes(data[HEADER_SIZE:])
        assert restored.payload == nested

