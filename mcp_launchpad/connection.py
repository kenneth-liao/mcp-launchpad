"""MCP server connection management."""

from __future__ import annotations

import asyncio
import logging
import os
import tempfile
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any, TextIO, cast

import httpx
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamable_http_client
from mcp.types import Tool

from .config import Config, ServerConfig

# Logger for connection management
logger = logging.getLogger("mcpl.connection")


class OAuthRequiredError(Exception):
    """Raised when an MCP server requires OAuth authentication."""

    def __init__(
        self, server_name: str, url: str, www_authenticate: str | None = None
    ):
        self.server_name = server_name
        self.url = url
        self.www_authenticate = www_authenticate

        message = (
            f"Server '{server_name}' requires OAuth authentication.\n\n"
            f"URL: {url}\n\n"
            "mcpl does not currently support OAuth authentication flows.\n\n"
            "Options:\n"
            "1. Use Claude Code or Claude Desktop to authenticate first\n"
            "   (Note: OAuth tokens are tied to specific clients per MCP spec)\n"
            "2. If the server supports static API keys, configure headers:\n"
            '   Add to config: "headers": {"Authorization": "Bearer ${TOKEN}"}\n'
            "3. Wait for OAuth support in a future mcpl release\n\n"
            "See: https://github.com/kenneth-liao/mcp-launchpad/issues/7"
        )
        super().__init__(message)

# Connection timeout in seconds (configurable via MCPL_CONNECTION_TIMEOUT env var)
CONNECTION_TIMEOUT = int(os.environ.get("MCPL_CONNECTION_TIMEOUT", "45"))


@dataclass
class ServerConnection:
    """Represents an active connection to an MCP server."""

    name: str
    session: ClientSession
    tools: list[Tool] = field(default_factory=list)


@dataclass
class ToolInfo:
    """Lightweight tool information for caching and search."""

    server: str
    name: str
    description: str
    input_schema: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "server": self.server,
            "name": self.name,
            "description": self.description,
            "inputSchema": self.input_schema,
        }

    def get_required_params(self) -> list[str]:
        """Extract required parameter names from input schema."""
        required: list[str] = self.input_schema.get("required", [])
        return required

    def get_params_summary(self) -> str:
        """Get a brief summary of required and optional parameters.

        Returns a string like: "organizationSlug, query | Optional: limit, offset"
        """
        required = self.get_required_params()
        properties = self.input_schema.get("properties", {})

        # Get optional params (in properties but not required)
        optional = [p for p in properties if p not in required]

        parts = []
        if required:
            parts.append(", ".join(required))
        if optional:
            # Show first 3 optional params with "..." if more
            shown = optional[:3]
            suffix = ", ..." if len(optional) > 3 else ""
            parts.append(f"Optional: {', '.join(shown)}{suffix}")

        return " | ".join(parts) if parts else "No parameters"

    def get_example_call(self) -> str:
        """Generate an example CLI call for this tool."""
        required = self.get_required_params()
        properties = self.input_schema.get("properties", {})

        # Build example arguments
        example_args: dict[str, Any] = {}
        for param in required:
            prop = properties.get(param, {})
            param_type = prop.get("type", "string")
            if param_type == "string":
                example_args[param] = f"<{param}>"
            elif param_type == "number" or param_type == "integer":
                example_args[param] = 0
            elif param_type == "boolean":
                example_args[param] = True
            elif param_type == "array":
                example_args[param] = []
            elif param_type == "object":
                example_args[param] = {}
            else:
                example_args[param] = f"<{param}>"

        import json

        args_json = json.dumps(example_args)
        return f"mcpl call {self.server} {self.name} '{args_json}'"

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ToolInfo:
        """Create from dictionary."""
        return cls(
            server=data["server"],
            name=data["name"],
            description=data["description"],
            input_schema=data.get("inputSchema", {}),
        )


class ConnectionManager:
    """Manages lazy connections to MCP servers."""

    def __init__(self, config: Config):
        self.config = config
        self._connections: dict[str, ServerConnection] = {}

    def get_server_config(self, server_name: str) -> ServerConfig:
        """Get server configuration by name."""
        if server_name not in self.config.servers:
            available = ", ".join(sorted(self.config.servers.keys()))
            raise ValueError(
                f"Server '{server_name}' not found.\n\n"
                f"Available servers: {available}\n\n"
                f"Check your config file at: {self.config.config_path}"
            )
        return self.config.servers[server_name]

    @asynccontextmanager
    async def connect(self, server_name: str) -> AsyncGenerator[ClientSession]:
        """Connect to an MCP server and yield the session.

        This is a context manager that handles connection lifecycle.
        Supports both stdio and HTTP transport types.
        """
        server_config = self.get_server_config(server_name)

        if server_config.is_http():
            async with self._connect_http(server_name, server_config) as session:
                yield session
        else:
            async with self._connect_stdio(server_name, server_config) as session:
                yield session

    @asynccontextmanager
    async def _connect_http(
        self, server_name: str, server_config: ServerConfig
    ) -> AsyncGenerator[ClientSession]:
        """Connect to an HTTP-based MCP server."""
        url = server_config.get_resolved_url()
        headers = server_config.get_resolved_headers()
        logger.debug(f"Connecting to HTTP server '{server_name}' at {url}")

        if not url:
            raise ValueError(
                f"HTTP server '{server_name}' is missing 'url' in configuration.\n\n"
                f"Example config:\n"
                f'{{\n  "mcpServers": {{\n'
                f'    "{server_name}": {{\n'
                f'      "type": "http",\n'
                f'      "url": "https://example.com/mcp"\n'
                f"    }}\n  }}\n}}"
            )

        # Create httpx client with headers if provided
        http_client = httpx.AsyncClient(
            headers=headers,
            timeout=httpx.Timeout(CONNECTION_TIMEOUT, connect=30.0),
        )

        try:
            async with asyncio.timeout(CONNECTION_TIMEOUT):
                # Preflight check: detect OAuth-requiring servers before full connection
                # MCP servers requiring OAuth return 401 with WWW-Authenticate header
                try:
                    preflight_response = await http_client.post(
                        url,
                        json={
                            "jsonrpc": "2.0",
                            "method": "initialize",
                            "id": 0,
                            "params": {
                                "protocolVersion": "2024-11-05",
                                "capabilities": {},
                                "clientInfo": {"name": "mcpl", "version": "0.1.0"},
                            },
                        },
                        headers={"Content-Type": "application/json"},
                    )
                    if preflight_response.status_code == 401:
                        www_auth = preflight_response.headers.get("WWW-Authenticate")
                        raise OAuthRequiredError(server_name, url, www_auth)
                except httpx.RequestError:
                    # If preflight fails for network reasons, proceed and let
                    # streamable_http_client handle the error
                    pass

                # terminate_on_close=False: Skip DELETE request for session cleanup
                # Many servers (like Supabase) don't implement this endpoint and return 404
                # HTTP connections are stateless anyway, so cleanup happens naturally
                async with streamable_http_client(
                    url, http_client=http_client, terminate_on_close=False
                ) as (read, write, _get_session_id):
                    async with ClientSession(read, write) as session:
                        await session.initialize()
                        logger.debug(f"HTTP connection to '{server_name}' initialized")
                        yield session
                        logger.debug(f"HTTP connection to '{server_name}' closing")
        except OAuthRequiredError:
            # Re-raise OAuth errors without wrapping
            raise
        except TimeoutError as e:
            raise TimeoutError(
                f"Connection to '{server_name}' timed out after {CONNECTION_TIMEOUT}s.\n\n"
                f"The HTTP server may be slow or unresponsive.\n\n"
                f"URL: {url}\n\n"
                f"Try increasing timeout: export MCPL_CONNECTION_TIMEOUT=120"
            ) from e
        except httpx.HTTPStatusError as e:
            raise ValueError(
                f"HTTP error connecting to '{server_name}': {e.response.status_code}\n\n"
                f"URL: {url}\n\n"
                f"Response: {e.response.text[:500] if e.response.text else 'No response body'}"
            ) from e
        except httpx.ConnectError as e:
            raise ConnectionError(
                f"Could not connect to '{server_name}' HTTP server.\n\n"
                f"URL: {url}\n\n"
                f"Error: {e}\n\n"
                f"Check that the URL is correct and the server is running."
            ) from e
        finally:
            await http_client.aclose()

    @asynccontextmanager
    async def _connect_stdio(
        self, server_name: str, server_config: ServerConfig
    ) -> AsyncGenerator[ClientSession]:
        """Connect to a stdio-based MCP server."""
        logger.debug(
            f"Connecting to stdio server '{server_name}': "
            f"{server_config.command} {' '.join(server_config.args)}"
        )
        # Build environment with resolved variables
        env = {**os.environ, **server_config.get_resolved_env()}

        # Check for missing required env vars
        for _key, value in server_config.env.items():
            if value.startswith("${") and value.endswith("}"):
                env_var = value[2:-1]
                if not os.environ.get(env_var):
                    raise ValueError(
                        f"Missing required environment variable: {env_var}\n\n"
                        f"The '{server_name}' server requires {env_var} to be set.\n\n"
                        f"To fix this:\n"
                        f"1. Add {env_var}=your_value to your .env file\n"
                        f"2. Or set it in your environment: export {env_var}=your_value\n\n"
                        f"Searched .env locations:\n"
                        f"  ./.env\n"
                        f"  ~/.claude/.env"
                    )

        server_params = StdioServerParameters(
            command=server_config.command,
            args=server_config.get_resolved_args(),
            env=env,
        )

        # Use a temp file to capture stderr - we'll show it only on errors
        # This is needed because MCP's stdio_client requires a real file descriptor
        with tempfile.NamedTemporaryFile(
            mode="w+", suffix=".stderr", delete=True
        ) as stderr_tmp:
            # Cast to TextIO for type checker - NamedTemporaryFile in text mode is compatible
            stderr_file = cast(TextIO, stderr_tmp)
            try:
                async with asyncio.timeout(CONNECTION_TIMEOUT):
                    async with stdio_client(server_params, errlog=stderr_file) as (
                        read,
                        write,
                    ):
                        async with ClientSession(read, write) as session:
                            await session.initialize()
                            logger.debug(f"Stdio connection to '{server_name}' initialized")
                            yield session
                            logger.debug(f"Stdio connection to '{server_name}' closing")
            except TimeoutError as e:
                stderr_tmp.seek(0)
                stderr_output = stderr_tmp.read()
                stderr_info = (
                    f"\n\nServer output:\n{stderr_output}"
                    if stderr_output.strip()
                    else ""
                )
                raise TimeoutError(
                    f"Connection to '{server_name}' timed out after {CONNECTION_TIMEOUT}s.\n\n"
                    f"The server may be slow to start or unresponsive.\n\n"
                    f"Command: {server_config.command} {' '.join(server_config.args)}"
                    f"{stderr_info}\n\n"
                    f"Try running the command manually to debug."
                ) from e
            except FileNotFoundError as e:
                raise FileNotFoundError(
                    f"Could not start '{server_name}' server.\n\n"
                    f"Command not found: {server_config.command}\n\n"
                    f"Make sure the MCP server is installed:\n"
                    f"  - For uvx: uv tool install {server_config.args[0] if server_config.args else 'package-name'}\n"
                    f"  - For npx: npm install -g {server_config.args[1] if len(server_config.args) > 1 else 'package-name'}"
                ) from e
            except Exception as e:
                # For any other errors, include stderr output if available
                stderr_tmp.seek(0)
                stderr_output = stderr_tmp.read()
                if stderr_output.strip():
                    # Append stderr to the error message
                    raise type(e)(f"{e}\n\nServer output:\n{stderr_output}") from e
                raise

    async def list_tools(self, server_name: str) -> list[ToolInfo]:
        """List all tools from a specific server."""
        async with self.connect(server_name) as session:
            result = await session.list_tools()
            return [
                ToolInfo(
                    server=server_name,
                    name=tool.name,
                    description=tool.description or "",
                    input_schema=tool.inputSchema
                    if hasattr(tool, "inputSchema")
                    else {},
                )
                for tool in result.tools
            ]

    async def call_tool(
        self, server_name: str, tool_name: str, arguments: dict[str, Any]
    ) -> Any:
        """Call a tool on a specific server."""
        async with self.connect(server_name) as session:
            result = await session.call_tool(tool_name, arguments)
            return result
