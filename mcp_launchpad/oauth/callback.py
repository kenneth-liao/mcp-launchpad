"""Localhost callback server for OAuth redirects.

This module provides an ephemeral HTTP server that receives OAuth
authorization callbacks. It:
- Starts on a random high port
- Receives the authorization code from the browser redirect
- Returns a user-friendly HTML page with success/error message
- Handles common edge cases (prefetch, favicon requests)
"""

import asyncio
import html
import logging
import socket
from dataclasses import dataclass
from http import HTTPStatus
from typing import Any
from urllib.parse import parse_qs, urlparse

logger = logging.getLogger(__name__)

# Port range for callback server (ephemeral ports)
MIN_PORT = 49152
MAX_PORT = 65535

# Default timeout for waiting for callback
DEFAULT_TIMEOUT = 120  # seconds


class CallbackError(Exception):
    """Error during OAuth callback handling."""

    pass


class CallbackTimeoutError(CallbackError):
    """Timeout waiting for OAuth callback."""

    pass


@dataclass
class CallbackResult:
    """Result from OAuth callback.

    Attributes:
        code: The authorization code from the callback
        state: The state parameter from the callback
        error: Error code if authorization failed
        error_description: Human-readable error description
    """

    code: str | None = None
    state: str | None = None
    error: str | None = None
    error_description: str | None = None

    def is_success(self) -> bool:
        """Check if callback was successful."""
        return self.code is not None and self.error is None


# HTML templates for callback responses
SUCCESS_HTML = """<!DOCTYPE html>
<html>
<head>
    <title>Authorization Successful</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        }}
        .card {{
            background: white;
            padding: 40px 60px;
            border-radius: 16px;
            text-align: center;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
        }}
        .icon {{ font-size: 64px; margin-bottom: 16px; }}
        h1 {{ color: #1a1a1a; margin: 0 0 8px 0; font-size: 24px; }}
        p {{ color: #666; margin: 0; }}
    </style>
</head>
<body>
    <div class="card">
        <div class="icon">✓</div>
        <h1>Authorization Successful</h1>
        <p>You can close this window and return to the terminal.</p>
    </div>
</body>
</html>"""

ERROR_HTML = """<!DOCTYPE html>
<html>
<head>
    <title>Authorization Failed</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%);
        }}
        .card {{
            background: white;
            padding: 40px 60px;
            border-radius: 16px;
            text-align: center;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            max-width: 400px;
        }}
        .icon {{ font-size: 64px; margin-bottom: 16px; }}
        h1 {{ color: #1a1a1a; margin: 0 0 8px 0; font-size: 24px; }}
        p {{ color: #666; margin: 0 0 16px 0; }}
        .error {{
            background: #fee;
            padding: 12px;
            border-radius: 8px;
            color: #c0392b;
            font-family: monospace;
            font-size: 14px;
        }}
    </style>
</head>
<body>
    <div class="card">
        <div class="icon">✗</div>
        <h1>Authorization Failed</h1>
        <p>An error occurred during authorization.</p>
        <div class="error">{error}: {description}</div>
    </div>
</body>
</html>"""


def find_available_port() -> int:
    """Find an available port in the ephemeral range.

    Returns:
        An available port number

    Raises:
        CallbackError: If no port is available
    """
    # Let the OS pick an available port
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        port: int = s.getsockname()[1]

        if MIN_PORT <= port <= MAX_PORT:
            return port

    # Fallback: try ports in range
    for port in range(MIN_PORT, MAX_PORT + 1):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(("127.0.0.1", port))
                return port
        except OSError:
            continue

    raise CallbackError("No available port found for callback server")


def parse_callback_url(url: str) -> CallbackResult:
    """Parse OAuth callback URL parameters.

    Args:
        url: The callback URL with query parameters

    Returns:
        CallbackResult with parsed parameters
    """
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    # Get first value of each parameter (or None if not present)
    def get_param(name: str) -> str | None:
        values = params.get(name, [])
        return values[0] if values else None

    return CallbackResult(
        code=get_param("code"),
        state=get_param("state"),
        error=get_param("error"),
        error_description=get_param("error_description"),
    )


class LocalhostCallbackServer:
    """Ephemeral HTTP server for OAuth callbacks.

    Creates a temporary server on localhost to receive the OAuth
    authorization callback from the browser.

    Usage:
        async with LocalhostCallbackServer() as server:
            redirect_uri = server.redirect_uri
            # Open browser with authorization URL using redirect_uri
            result = await server.wait_for_callback()
    """

    def __init__(self, timeout: int = DEFAULT_TIMEOUT, path: str = "/callback"):
        """Initialize callback server.

        Args:
            timeout: Timeout in seconds to wait for callback
            path: URL path to listen on (default "/callback")
        """
        self.timeout = timeout
        self.path = path
        self.port: int = 0
        self.redirect_uri: str = ""

        self._server: asyncio.Server | None = None
        self._result: CallbackResult | None = None
        self._result_event: asyncio.Event | None = None

    async def start(self) -> str:
        """Start the callback server.

        Uses port=0 to let the OS atomically assign an available port,
        avoiding race conditions between port discovery and binding.

        Returns:
            The redirect URI to use in the authorization request
        """
        self._result_event = asyncio.Event()

        # Use port=0 to let OS assign an available port atomically
        self._server = await asyncio.start_server(
            self._handle_connection,
            "127.0.0.1",
            0,  # Let OS assign available port
        )

        # Get the actual port assigned by the OS
        sockets = self._server.sockets
        if not sockets:
            raise CallbackError("Failed to start callback server: no sockets created")

        self.port = sockets[0].getsockname()[1]
        self.redirect_uri = f"http://127.0.0.1:{self.port}{self.path}"

        logger.debug(f"Callback server started on {self.redirect_uri}")
        return self.redirect_uri

    async def stop(self) -> None:
        """Stop the callback server."""
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
            logger.debug("Callback server stopped")

    async def wait_for_callback(self) -> CallbackResult:
        """Wait for the OAuth callback.

        Returns:
            CallbackResult with the authorization code or error

        Raises:
            CallbackTimeoutError: If timeout is reached
        """
        if self._result_event is None:
            raise CallbackError("Server not started")

        try:
            await asyncio.wait_for(self._result_event.wait(), timeout=self.timeout)
        except TimeoutError:
            raise CallbackTimeoutError(
                f"Timeout waiting for OAuth callback after {self.timeout} seconds"
            ) from None

        if self._result is None:
            raise CallbackError("No callback result received")

        return self._result

    async def _handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle incoming HTTP connection."""
        try:
            # Read HTTP request
            request_line = await reader.readline()
            request_text = request_line.decode("utf-8", errors="replace")

            # Parse request line (e.g., "GET /callback?code=xxx HTTP/1.1")
            parts = request_text.strip().split(" ")
            if len(parts) < 2:
                await self._send_response(writer, HTTPStatus.BAD_REQUEST, "Invalid request")
                return

            method, path = parts[0], parts[1]

            # Read headers (consume them but we don't need them)
            while True:
                header_line = await reader.readline()
                if header_line in (b"\r\n", b"\n", b""):
                    break

            # Handle favicon requests (browsers often request this)
            if path == "/favicon.ico":
                await self._send_response(writer, HTTPStatus.NOT_FOUND, "")
                return

            # Only accept GET requests to our callback path
            if method != "GET":
                await self._send_response(
                    writer, HTTPStatus.METHOD_NOT_ALLOWED, "Method not allowed"
                )
                return

            if not path.startswith(self.path):
                await self._send_response(writer, HTTPStatus.NOT_FOUND, "Not found")
                return

            # Parse callback parameters
            result = parse_callback_url(path)
            self._result = result

            # Send appropriate response
            if result.is_success():
                await self._send_html_response(writer, HTTPStatus.OK, SUCCESS_HTML)
            else:
                # HTML-escape error messages to prevent XSS attacks
                error_html = ERROR_HTML.format(
                    error=html.escape(result.error or "unknown_error"),
                    description=html.escape(result.error_description or "No description provided"),
                )
                await self._send_html_response(writer, HTTPStatus.OK, error_html)

            # Signal that we received a callback
            if self._result_event:
                self._result_event.set()

        except Exception as e:
            logger.warning(f"Error handling callback request: {e}")
            try:
                await self._send_response(
                    writer, HTTPStatus.INTERNAL_SERVER_ERROR, "Internal error"
                )
            except Exception:
                pass

        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _send_response(
        self,
        writer: asyncio.StreamWriter,
        status: HTTPStatus,
        body: str,
    ) -> None:
        """Send a plain text HTTP response."""
        response = (
            f"HTTP/1.1 {status.value} {status.phrase}\r\n"
            f"Content-Type: text/plain\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
            f"{body}"
        )
        writer.write(response.encode("utf-8"))
        await writer.drain()

    async def _send_html_response(
        self,
        writer: asyncio.StreamWriter,
        status: HTTPStatus,
        html_content: str,
    ) -> None:
        """Send an HTML HTTP response with security headers."""
        body = html_content.encode("utf-8")
        headers = (
            f"HTTP/1.1 {status.value} {status.phrase}\r\n"
            f"Content-Type: text/html; charset=utf-8\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"X-Content-Type-Options: nosniff\r\n"
            f"X-Frame-Options: DENY\r\n"
            f"Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        )
        writer.write(headers.encode("utf-8") + body)
        await writer.drain()

    async def __aenter__(self) -> "LocalhostCallbackServer":
        """Async context manager entry."""
        await self.start()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Async context manager exit."""
        await self.stop()
