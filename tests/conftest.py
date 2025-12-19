"""Shared fixtures and utilities for MCP Launchpad tests."""

import json
import os
import tempfile
from collections.abc import Generator
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mcp_launchpad.config import Config, ServerConfig
from mcp_launchpad.connection import ToolInfo


# ============================================================================
# Sample Data Fixtures
# ============================================================================


@pytest.fixture
def sample_server_config() -> ServerConfig:
    """Create a sample server configuration."""
    return ServerConfig(
        name="test-server",
        command="python",
        args=["-m", "test_mcp_server"],
        env={"TEST_TOKEN": "${TEST_TOKEN}"},
    )


@pytest.fixture
def sample_config(sample_server_config: ServerConfig) -> Config:
    """Create a sample configuration with one server."""
    return Config(
        servers={"test-server": sample_server_config},
        config_path=Path("test-config.json"),
        env_path=None,
    )


@pytest.fixture
def multi_server_config() -> Config:
    """Create a configuration with multiple servers."""
    return Config(
        servers={
            "github": ServerConfig(
                name="github",
                command="uvx",
                args=["mcp-server-github"],
                env={"GITHUB_TOKEN": "${GITHUB_TOKEN}"},
            ),
            "sentry": ServerConfig(
                name="sentry",
                command="npx",
                args=["-y", "@sentry/mcp-server"],
                env={"SENTRY_TOKEN": "${SENTRY_TOKEN}"},
            ),
            "slack": ServerConfig(
                name="slack",
                command="uvx",
                args=["mcp-server-slack"],
                env={},
            ),
        },
        config_path=Path("test-config.json"),
        env_path=None,
    )


@pytest.fixture
def sample_tools() -> list[ToolInfo]:
    """Create a list of sample tools."""
    return [
        ToolInfo(
            server="github",
            name="create_issue",
            description="Create a new issue in a GitHub repository",
            input_schema={
                "type": "object",
                "properties": {
                    "owner": {"type": "string", "description": "Repository owner"},
                    "repo": {"type": "string", "description": "Repository name"},
                    "title": {"type": "string", "description": "Issue title"},
                    "body": {"type": "string", "description": "Issue body"},
                },
                "required": ["owner", "repo", "title"],
            },
        ),
        ToolInfo(
            server="github",
            name="list_issues",
            description="List issues in a GitHub repository",
            input_schema={
                "type": "object",
                "properties": {
                    "owner": {"type": "string"},
                    "repo": {"type": "string"},
                    "state": {"type": "string", "enum": ["open", "closed", "all"]},
                },
                "required": ["owner", "repo"],
            },
        ),
        ToolInfo(
            server="sentry",
            name="search_issues",
            description="Search for issues in Sentry",
            input_schema={
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "organizationSlug": {"type": "string"},
                },
                "required": ["organizationSlug"],
            },
        ),
        ToolInfo(
            server="slack",
            name="send_message",
            description="Send a message to a Slack channel",
            input_schema={
                "type": "object",
                "properties": {
                    "channel": {"type": "string"},
                    "text": {"type": "string"},
                },
                "required": ["channel", "text"],
            },
        ),
    ]


# ============================================================================
# Temporary File Fixtures
# ============================================================================


@pytest.fixture
def temp_config_dir(tmp_path: Path) -> Path:
    """Create a temporary directory for config files."""
    return tmp_path


@pytest.fixture
def valid_config_file(temp_config_dir: Path) -> Path:
    """Create a valid config file."""
    config_data = {
        "mcpServers": {
            "test-server": {
                "command": "python",
                "args": ["-m", "test_mcp_server"],
                "env": {"TEST_TOKEN": "${TEST_TOKEN}"},
            }
        }
    }
    config_path = temp_config_dir / "mcp.json"
    config_path.write_text(json.dumps(config_data))
    return config_path


@pytest.fixture
def invalid_json_config_file(temp_config_dir: Path) -> Path:
    """Create a config file with invalid JSON."""
    config_path = temp_config_dir / "mcp.json"
    config_path.write_text("{ invalid json }")
    return config_path


@pytest.fixture
def empty_servers_config_file(temp_config_dir: Path) -> Path:
    """Create a config file with no servers."""
    config_data = {"mcpServers": {}}
    config_path = temp_config_dir / "mcp.json"
    config_path.write_text(json.dumps(config_data))
    return config_path


@pytest.fixture
def malformed_server_config_file(temp_config_dir: Path) -> Path:
    """Create a config file with malformed server config."""
    config_data = {
        "mcpServers": {
            "bad-server": {
                # Missing required "command" field
                "args": ["some-arg"],
            }
        }
    }
    config_path = temp_config_dir / "mcp.json"
    config_path.write_text(json.dumps(config_data))
    return config_path


@pytest.fixture
def env_file(temp_config_dir: Path) -> Path:
    """Create a .env file."""
    env_path = temp_config_dir / ".env"
    env_path.write_text("TEST_TOKEN=test-token-value\nOTHER_VAR=other-value\n")
    return env_path


# ============================================================================
# Mock Fixtures
# ============================================================================


@pytest.fixture
def mock_session() -> MagicMock:
    """Create a mock MCP client session."""
    session = MagicMock()
    session.initialize = AsyncMock()

    # Mock list_tools response
    mock_tool = MagicMock()
    mock_tool.name = "test_tool"
    mock_tool.description = "A test tool"
    mock_tool.inputSchema = {"type": "object", "properties": {}, "required": []}

    mock_result = MagicMock()
    mock_result.tools = [mock_tool]
    session.list_tools = AsyncMock(return_value=mock_result)

    # Mock call_tool response
    mock_content = MagicMock()
    mock_content.text = "Tool result text"
    mock_call_result = MagicMock()
    mock_call_result.content = [mock_content]
    session.call_tool = AsyncMock(return_value=mock_call_result)

    return session


@pytest.fixture
def mock_failing_session() -> MagicMock:
    """Create a mock session that fails on operations."""
    session = MagicMock()
    session.initialize = AsyncMock(side_effect=RuntimeError("Connection failed"))
    return session


# ============================================================================
# Environment Fixtures
# ============================================================================


@pytest.fixture
def clean_env() -> Generator[None, None, None]:
    """Temporarily clear test-related environment variables."""
    old_env = os.environ.copy()
    # Remove test-related vars
    for key in list(os.environ.keys()):
        if key.startswith("TEST_") or key in ("GITHUB_TOKEN", "SENTRY_TOKEN"):
            del os.environ[key]
    yield
    # Restore
    os.environ.clear()
    os.environ.update(old_env)


@pytest.fixture
def env_with_tokens() -> Generator[None, None, None]:
    """Set up environment with test tokens."""
    old_env = os.environ.copy()
    os.environ["TEST_TOKEN"] = "test-token-value"
    os.environ["GITHUB_TOKEN"] = "github-token-value"
    os.environ["SENTRY_TOKEN"] = "sentry-token-value"
    yield
    os.environ.clear()
    os.environ.update(old_env)

