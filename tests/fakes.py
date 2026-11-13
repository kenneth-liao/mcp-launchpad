"""Fake MCP sessions and transports shared by connection and daemon tests."""

import asyncio
from contextlib import asynccontextmanager
from typing import Any
from unittest.mock import AsyncMock, MagicMock


class FakeSession:
    """Stand-in for mcp.ClientSession with a configurable initialize()."""

    init_delay = 0.0

    def __init__(self, read: Any, write: Any, **kwargs: Any) -> None:
        self.kwargs = kwargs
        self.call_tool = AsyncMock(return_value="ok")

    async def initialize(self) -> None:
        await asyncio.sleep(self.init_delay)

    async def __aenter__(self) -> "FakeSession":
        return self

    async def __aexit__(self, *exc_info: Any) -> bool:
        return False


def fake_session_class(init_delay: float = 0.0) -> type[FakeSession]:
    """Create a FakeSession subclass with the given initialize() delay."""
    return type("Session", (FakeSession,), {"init_delay": init_delay})


@asynccontextmanager
async def fake_http_transport(*args: Any, **kwargs: Any):
    """Fake streamable_http_client: yields (read, write, get_session_id)."""
    yield MagicMock(), MagicMock(), MagicMock()


@asynccontextmanager
async def fake_two_stream_transport(*args: Any, **kwargs: Any):
    """Fake sse_client / stdio_client: yields (read, write)."""
    yield MagicMock(), MagicMock()
