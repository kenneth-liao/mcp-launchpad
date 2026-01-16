"""Tests for OAuth callback server."""

import asyncio

import pytest

from mcp_launchpad.oauth.callback import (
    CallbackError,
    CallbackResult,
    CallbackTimeoutError,
    LocalhostCallbackServer,
    find_available_port,
    parse_callback_url,
)


class TestParseCallbackUrl:
    """Tests for parse_callback_url function."""

    def test_parse_success_callback(self) -> None:
        """Test parsing successful OAuth callback URL."""
        url = "/callback?code=abc123&state=xyz789"
        result = parse_callback_url(url)

        assert result.code == "abc123"
        assert result.state == "xyz789"
        assert result.error is None
        assert result.is_success()

    def test_parse_error_callback(self) -> None:
        """Test parsing error OAuth callback URL."""
        url = "/callback?error=access_denied&error_description=User+denied+access&state=xyz"
        result = parse_callback_url(url)

        assert result.code is None
        assert result.error == "access_denied"
        assert result.error_description == "User denied access"
        assert result.state == "xyz"
        assert not result.is_success()

    def test_parse_empty_params(self) -> None:
        """Test parsing URL with no parameters."""
        url = "/callback"
        result = parse_callback_url(url)

        assert result.code is None
        assert result.state is None
        assert result.error is None

    def test_parse_multiple_values_takes_first(self) -> None:
        """Test that multiple values for same param uses first."""
        url = "/callback?code=first&code=second"
        result = parse_callback_url(url)

        assert result.code == "first"


class TestCallbackResult:
    """Tests for CallbackResult dataclass."""

    def test_is_success_with_code(self) -> None:
        """Test is_success returns True with code and no error."""
        result = CallbackResult(code="abc", state="xyz")
        assert result.is_success()

    def test_is_success_with_error(self) -> None:
        """Test is_success returns False when error present."""
        result = CallbackResult(code="abc", state="xyz", error="access_denied")
        assert not result.is_success()

    def test_is_success_without_code(self) -> None:
        """Test is_success returns False without code."""
        result = CallbackResult(state="xyz")
        assert not result.is_success()


class TestFindAvailablePort:
    """Tests for find_available_port function."""

    def test_returns_valid_port(self) -> None:
        """Test that a valid port number is returned."""
        port = find_available_port()
        assert isinstance(port, int)
        assert port > 0
        assert port < 65536

    def test_port_is_available(self) -> None:
        """Test that returned port can be bound."""
        import socket

        port = find_available_port()
        # Try to bind to the port
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", port))
            # If we get here, port was available


class TestLocalhostCallbackServer:
    """Tests for LocalhostCallbackServer class."""

    @pytest.mark.asyncio
    async def test_server_starts_and_stops(self) -> None:
        """Test server can start and stop cleanly."""
        server = LocalhostCallbackServer(timeout=5)
        redirect_uri = await server.start()

        assert redirect_uri.startswith("http://127.0.0.1:")
        assert "/callback" in redirect_uri
        assert server.port > 0

        await server.stop()

    @pytest.mark.asyncio
    async def test_context_manager(self) -> None:
        """Test server works as async context manager."""
        async with LocalhostCallbackServer(timeout=5) as server:
            assert server.redirect_uri.startswith("http://127.0.0.1:")
            assert server.port > 0

    @pytest.mark.asyncio
    async def test_timeout_raises_error(self) -> None:
        """Test that timeout raises CallbackTimeoutError."""
        async with LocalhostCallbackServer(timeout=1) as server:
            with pytest.raises(CallbackTimeoutError) as exc_info:
                await server.wait_for_callback()

            assert "Timeout" in str(exc_info.value)
            assert "1 seconds" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_successful_callback(self) -> None:
        """Test receiving a successful OAuth callback."""
        async with LocalhostCallbackServer(timeout=5) as server:
            # Simulate browser callback
            async def send_callback() -> None:
                await asyncio.sleep(0.1)  # Let server start
                reader, writer = await asyncio.open_connection("127.0.0.1", server.port)
                request = f"GET /callback?code=test_code&state=test_state HTTP/1.1\r\nHost: localhost\r\n\r\n"
                writer.write(request.encode())
                await writer.drain()
                # Read response
                await reader.read(1024)
                writer.close()
                await writer.wait_closed()

            # Start callback in background
            asyncio.create_task(send_callback())

            result = await server.wait_for_callback()
            assert result.code == "test_code"
            assert result.state == "test_state"
            assert result.is_success()

    @pytest.mark.asyncio
    async def test_error_callback(self) -> None:
        """Test receiving an error OAuth callback."""
        async with LocalhostCallbackServer(timeout=5) as server:

            async def send_error_callback() -> None:
                await asyncio.sleep(0.1)
                reader, writer = await asyncio.open_connection("127.0.0.1", server.port)
                request = "GET /callback?error=access_denied&error_description=User+denied&state=xyz HTTP/1.1\r\nHost: localhost\r\n\r\n"
                writer.write(request.encode())
                await writer.drain()
                await reader.read(1024)
                writer.close()
                await writer.wait_closed()

            asyncio.create_task(send_error_callback())

            result = await server.wait_for_callback()
            assert result.error == "access_denied"
            assert result.error_description == "User denied"
            assert not result.is_success()

    @pytest.mark.asyncio
    async def test_favicon_ignored(self) -> None:
        """Test that favicon requests don't trigger callback."""
        async with LocalhostCallbackServer(timeout=5) as server:

            async def send_requests() -> None:
                await asyncio.sleep(0.1)
                # Send favicon request (should be ignored)
                reader1, writer1 = await asyncio.open_connection("127.0.0.1", server.port)
                writer1.write(b"GET /favicon.ico HTTP/1.1\r\nHost: localhost\r\n\r\n")
                await writer1.drain()
                await reader1.read(1024)
                writer1.close()
                await writer1.wait_closed()

                # Send actual callback
                reader2, writer2 = await asyncio.open_connection("127.0.0.1", server.port)
                writer2.write(b"GET /callback?code=real_code&state=real_state HTTP/1.1\r\nHost: localhost\r\n\r\n")
                await writer2.drain()
                await reader2.read(1024)
                writer2.close()
                await writer2.wait_closed()

            asyncio.create_task(send_requests())

            result = await server.wait_for_callback()
            assert result.code == "real_code"

    @pytest.mark.asyncio
    async def test_wrong_path_ignored(self) -> None:
        """Test that requests to wrong path don't trigger callback."""
        async with LocalhostCallbackServer(timeout=5) as server:

            async def send_requests() -> None:
                await asyncio.sleep(0.1)
                # Send request to wrong path
                reader1, writer1 = await asyncio.open_connection("127.0.0.1", server.port)
                writer1.write(b"GET /wrong?code=wrong_code HTTP/1.1\r\nHost: localhost\r\n\r\n")
                await writer1.drain()
                await reader1.read(1024)
                writer1.close()
                await writer1.wait_closed()

                # Send actual callback
                reader2, writer2 = await asyncio.open_connection("127.0.0.1", server.port)
                writer2.write(b"GET /callback?code=right_code&state=state HTTP/1.1\r\nHost: localhost\r\n\r\n")
                await writer2.drain()
                await reader2.read(1024)
                writer2.close()
                await writer2.wait_closed()

            asyncio.create_task(send_requests())

            result = await server.wait_for_callback()
            assert result.code == "right_code"

    @pytest.mark.asyncio
    async def test_post_rejected(self) -> None:
        """Test that POST requests are rejected."""
        async with LocalhostCallbackServer(timeout=10) as server:

            async def send_requests() -> None:
                await asyncio.sleep(0.1)
                # Send POST (should be rejected)
                reader1, writer1 = await asyncio.open_connection("127.0.0.1", server.port)
                writer1.write(b"POST /callback?code=post_code HTTP/1.1\r\nHost: localhost\r\n\r\n")
                await writer1.drain()
                response = await reader1.read(1024)
                assert b"405" in response  # Method Not Allowed
                writer1.close()
                await writer1.wait_closed()

                await asyncio.sleep(0.1)  # Small delay between requests

                # Send GET (should work)
                reader2, writer2 = await asyncio.open_connection("127.0.0.1", server.port)
                writer2.write(b"GET /callback?code=get_code&state=state HTTP/1.1\r\nHost: localhost\r\n\r\n")
                await writer2.drain()
                await reader2.read(1024)
                writer2.close()
                await writer2.wait_closed()

            asyncio.create_task(send_requests())

            result = await server.wait_for_callback()
            assert result.code == "get_code"

    @pytest.mark.asyncio
    async def test_xss_prevention(self) -> None:
        """Test that error messages are HTML-escaped to prevent XSS."""
        async with LocalhostCallbackServer(timeout=5) as server:
            response_body = b""

            async def send_xss_callback() -> None:
                nonlocal response_body
                await asyncio.sleep(0.1)
                reader, writer = await asyncio.open_connection("127.0.0.1", server.port)
                # Send XSS payload in error_description
                xss_payload = "<script>alert('xss')</script>"
                request = f"GET /callback?error=test&error_description={xss_payload}&state=xyz HTTP/1.1\r\nHost: localhost\r\n\r\n"
                writer.write(request.encode())
                await writer.drain()
                response_body = await reader.read(4096)
                writer.close()
                await writer.wait_closed()

            asyncio.create_task(send_xss_callback())
            await server.wait_for_callback()

            # Verify XSS payload is escaped in response
            response_str = response_body.decode("utf-8")
            assert "<script>" not in response_str
            assert "&lt;script&gt;" in response_str or "script" not in response_str.lower()

    @pytest.mark.asyncio
    async def test_security_headers(self) -> None:
        """Test that security headers are present in response."""
        async with LocalhostCallbackServer(timeout=5) as server:
            response_headers = b""
            done_event = asyncio.Event()

            async def send_callback() -> None:
                nonlocal response_headers
                await asyncio.sleep(0.1)
                reader, writer = await asyncio.open_connection("127.0.0.1", server.port)
                writer.write(b"GET /callback?code=test&state=test HTTP/1.1\r\nHost: localhost\r\n\r\n")
                await writer.drain()
                response_headers = await reader.read(4096)
                writer.close()
                await writer.wait_closed()
                done_event.set()

            asyncio.create_task(send_callback())
            await server.wait_for_callback()
            await done_event.wait()  # Wait for response to be captured

            response_str = response_headers.decode("utf-8")
            assert "X-Content-Type-Options: nosniff" in response_str
            assert "X-Frame-Options: DENY" in response_str
            assert "Content-Security-Policy:" in response_str

    @pytest.mark.asyncio
    async def test_wait_without_start_raises_error(self) -> None:
        """Test that waiting without starting raises error."""
        server = LocalhostCallbackServer(timeout=5)
        with pytest.raises(CallbackError) as exc_info:
            await server.wait_for_callback()
        assert "not started" in str(exc_info.value)
