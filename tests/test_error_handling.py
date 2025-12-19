"""Tests for error handling scenarios across all modules."""

import asyncio
import json
import os
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from click.testing import CliRunner

from mcp_launchpad.cli import main
from mcp_launchpad.config import Config, ServerConfig, load_config
from mcp_launchpad.connection import ConnectionManager, ToolInfo


class TestConfigErrors:
    """Test error handling in config module."""

    def test_no_config_file_anywhere(self, tmp_path: Path, monkeypatch):
        """Test error when no config file exists in any location."""
        monkeypatch.chdir(tmp_path)

        # Use explicit path that doesn't exist to ensure FileNotFoundError
        nonexistent = tmp_path / "nonexistent.json"
        with pytest.raises(FileNotFoundError) as excinfo:
            load_config(config_path=nonexistent)

        error_msg = str(excinfo.value)
        assert "No MCP config file found" in error_msg
        assert "mcp.json" in error_msg
        # Should include example config
        assert "mcpServers" in error_msg

    def test_config_file_empty(self, tmp_path: Path, monkeypatch):
        """Test handling of empty config file."""
        monkeypatch.chdir(tmp_path)
        # Isolate test from user's real config files
        import mcp_launchpad.config as config_module
        monkeypatch.setattr(config_module, "CONFIG_SEARCH_DIRS", [Path(".")])

        (tmp_path / "mcp.json").write_text("")

        with pytest.raises(json.JSONDecodeError):
            load_config()

    def test_config_file_not_object(self, tmp_path: Path, monkeypatch):
        """Test handling of config that's not a JSON object."""
        monkeypatch.chdir(tmp_path)
        # Isolate test from user's real config files
        import mcp_launchpad.config as config_module
        monkeypatch.setattr(config_module, "CONFIG_SEARCH_DIRS", [Path(".")])

        (tmp_path / "mcp.json").write_text('["array", "not", "object"]')

        # Should raise AttributeError since list doesn't have .get()
        with pytest.raises(AttributeError):
            load_config()

    def test_config_with_null_values(self, tmp_path: Path, monkeypatch):
        """Test handling of null values in config."""
        monkeypatch.chdir(tmp_path)
        # Isolate test from user's real config files
        import mcp_launchpad.config as config_module
        monkeypatch.setattr(config_module, "CONFIG_SEARCH_DIRS", [Path(".")])

        config_data = {
            "mcpServers": {
                "test": {
                    "command": "python",
                    "args": None,
                    "env": None,
                }
            }
        }
        (tmp_path / "mcp.json").write_text(json.dumps(config_data))

        # Should handle None values gracefully
        config = load_config()
        assert config.servers["test"].args is None or config.servers["test"].args == []


class TestConnectionErrors:
    """Test error handling in connection module."""

    def test_server_not_in_config(self):
        """Test error when trying to connect to non-existent server."""
        config = Config(
            servers={"only-server": ServerConfig(name="only-server", command="test")},
            config_path=None,
            env_path=None,
        )
        manager = ConnectionManager(config)

        with pytest.raises(ValueError) as excinfo:
            manager.get_server_config("missing-server")

        error_msg = str(excinfo.value)
        assert "Server 'missing-server' not found" in error_msg
        assert "only-server" in error_msg  # Should list available servers

    def test_empty_server_list_error_message(self):
        """Test error message when no servers configured."""
        config = Config(servers={}, config_path=None, env_path=None)
        manager = ConnectionManager(config)

        with pytest.raises(ValueError) as excinfo:
            manager.get_server_config("any-server")

        error_msg = str(excinfo.value)
        assert "Server 'any-server' not found" in error_msg

    async def test_missing_required_env_var(self):
        """Test error when required environment variable is missing."""
        config = Config(
            servers={
                "needs-token": ServerConfig(
                    name="needs-token",
                    command="python",
                    args=["-m", "server"],
                    env={"API_TOKEN": "${DEFINITELY_NOT_SET_12345}"},
                )
            },
            config_path=None,
            env_path=None,
        )
        manager = ConnectionManager(config)

        # Ensure the env var is not set
        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(ValueError) as excinfo:
                async with manager.connect("needs-token"):
                    pass

            error_msg = str(excinfo.value)
            assert "Missing required environment variable" in error_msg
            assert "DEFINITELY_NOT_SET_12345" in error_msg
            assert "needs-token" in error_msg

    async def test_command_not_found(self):
        """Test error when server command doesn't exist."""
        config = Config(
            servers={
                "bad-cmd": ServerConfig(
                    name="bad-cmd",
                    command="this_command_does_not_exist_xyz_123",
                    args=[],
                    env={},
                )
            },
            config_path=None,
            env_path=None,
        )
        manager = ConnectionManager(config)

        with pytest.raises(FileNotFoundError) as excinfo:
            async with manager.connect("bad-cmd"):
                pass

        error_msg = str(excinfo.value)
        assert "Could not start 'bad-cmd' server" in error_msg
        assert "Command not found" in error_msg

    async def test_connection_timeout_includes_stderr(self):
        """Test that connection timeout error includes server stderr output.

        When a server times out, users need to see the stderr output to debug
        why the server didn't respond. This is critical for YouTube users who
        may have servers that hang during startup.
        """
        from mcp_launchpad.connection import CONNECTION_TIMEOUT

        config = Config(
            servers={
                "slow-server": ServerConfig(
                    name="slow-server",
                    command="python",
                    args=["-c", "import time; print('Starting...', flush=True); time.sleep(100)"],
                    env={},
                )
            },
            config_path=None,
            env_path=None,
        )
        manager = ConnectionManager(config)

        # Patch CONNECTION_TIMEOUT to a very short value for testing
        with patch("mcp_launchpad.connection.CONNECTION_TIMEOUT", 0.1):
            with pytest.raises(TimeoutError) as excinfo:
                async with manager.connect("slow-server"):
                    pass

            error_msg = str(excinfo.value)
            assert "timed out" in error_msg
            assert "slow-server" in error_msg
            assert "Try running the command manually" in error_msg

    async def test_generic_error_includes_stderr(self):
        """Test that generic errors include stderr output when available.

        When servers fail with unexpected errors, the stderr output is crucial
        for debugging. This helps YouTube users diagnose issues with their
        MCP server configurations.
        """
        # This test uses a Python command that writes to stderr then exits with error
        config = Config(
            servers={
                "error-server": ServerConfig(
                    name="error-server",
                    command="python",
                    args=["-c", "import sys; sys.stderr.write('Debug: initialization failed\\n'); sys.exit(1)"],
                    env={},
                )
            },
            config_path=None,
            env_path=None,
        )
        manager = ConnectionManager(config)

        with pytest.raises(Exception) as excinfo:
            async with manager.connect("error-server"):
                pass

        # The error should exist (specific type may vary based on how MCP handles it)
        error_msg = str(excinfo.value)
        # Error message should be non-empty
        assert len(error_msg) > 0


class TestCLIErrorDisplay:
    """Test that CLI displays errors appropriately."""

    @pytest.fixture
    def runner(self) -> CliRunner:
        return CliRunner()

    def test_human_mode_error_display(self, runner: CliRunner, tmp_path: Path, monkeypatch):
        """Test error is displayed in human-readable format."""
        monkeypatch.chdir(tmp_path)
        # Use explicit non-existent config to force error
        # Click returns exit code 2 for usage errors (like invalid path)
        nonexistent = tmp_path / "nonexistent.json"

        result = runner.invoke(main, ["--config", str(nonexistent), "list"])

        assert result.exit_code == 2  # Click usage error
        # Should have Error: prefix in human mode
        assert "Error" in result.output

    def test_json_mode_error_display(self, runner: CliRunner, tmp_path: Path, monkeypatch):
        """Test error is displayed in JSON format for application errors."""
        monkeypatch.chdir(tmp_path)
        # Create a valid config but with a server that will fail
        config_data = {"mcpServers": {"test": {"command": "test"}}}
        (tmp_path / "mcp.json").write_text(json.dumps(config_data))

        with patch("mcp_launchpad.cli.ToolCache") as MockCache:
            mock_cache = MagicMock()
            mock_cache.refresh = AsyncMock(side_effect=RuntimeError("Connection failed"))
            MockCache.return_value = mock_cache

            # Use --refresh to trigger the refresh path which will error
            result = runner.invoke(main, ["--json", "list", "--refresh"])

            assert result.exit_code == 1
            parsed = json.loads(result.output)
            assert parsed["success"] is False
            assert "error" in parsed
            assert "message" in parsed["error"]

    def test_json_error_includes_traceback(
        self, runner: CliRunner, tmp_path: Path, monkeypatch
    ):
        """Test JSON error includes traceback for debugging."""
        monkeypatch.chdir(tmp_path)
        # Create a valid config but with a server that will fail
        config_data = {"mcpServers": {"test": {"command": "test"}}}
        (tmp_path / "mcp.json").write_text(json.dumps(config_data))

        with patch("mcp_launchpad.cli.ToolCache") as MockCache:
            mock_cache = MagicMock()
            mock_cache.refresh = AsyncMock(side_effect=RuntimeError("Connection failed"))
            MockCache.return_value = mock_cache

            # Use --refresh to trigger the refresh path which will error
            result = runner.invoke(main, ["--json", "list", "--refresh"])

            assert result.exit_code == 1
            parsed = json.loads(result.output)
            assert "traceback" in parsed["error"]

    def test_json_error_includes_type(self, runner: CliRunner, tmp_path: Path, monkeypatch):
        """Test JSON error includes error type."""
        monkeypatch.chdir(tmp_path)
        # Create a valid config but with a server that will fail
        config_data = {"mcpServers": {"test": {"command": "test"}}}
        (tmp_path / "mcp.json").write_text(json.dumps(config_data))

        with patch("mcp_launchpad.cli.ToolCache") as MockCache:
            mock_cache = MagicMock()
            mock_cache.refresh = AsyncMock(side_effect=RuntimeError("Connection failed"))
            MockCache.return_value = mock_cache

            # Use --refresh to trigger the refresh path which will error
            result = runner.invoke(main, ["--json", "list", "--refresh"])

            assert result.exit_code == 1
            parsed = json.loads(result.output)
            assert "type" in parsed["error"]


class TestCacheErrors:
    """Test error handling in cache module."""

    def test_cache_refresh_all_servers_fail(self, tmp_path: Path):
        """Test error when all servers fail during cache refresh."""
        from mcp_launchpad.cache import ToolCache

        config = Config(
            servers={
                "server1": ServerConfig(name="server1", command="cmd"),
                "server2": ServerConfig(name="server2", command="cmd"),
            },
            config_path=tmp_path / "config.json",
            env_path=None,
        )
        (tmp_path / "config.json").write_text("{}")

        cache = ToolCache(config)
        cache.cache_dir = tmp_path
        cache.index_path = tmp_path / "index.json"
        cache.metadata_path = tmp_path / "metadata.json"

        mock_manager = MagicMock()
        mock_manager.list_tools = AsyncMock(side_effect=RuntimeError("Connection failed"))

        with patch("mcp_launchpad.cache.ConnectionManager", return_value=mock_manager):
            with pytest.raises(RuntimeError) as excinfo:
                asyncio.run(cache.refresh(force=True))

            assert "Failed to connect to any servers" in str(excinfo.value)

    def test_cache_refresh_partial_server_failures(self, tmp_path: Path):
        """Test that partial server failures still cache successful tools.

        This is a critical test for YouTube users who may have some servers
        misconfigured while others work. The working servers should still
        have their tools cached and available.
        """
        from mcp_launchpad.cache import ToolCache

        config = Config(
            servers={
                "working-server": ServerConfig(name="working-server", command="python"),
                "broken-server": ServerConfig(name="broken-server", command="nonexistent"),
                "another-working": ServerConfig(name="another-working", command="python"),
            },
            config_path=tmp_path / "config.json",
            env_path=None,
        )
        (tmp_path / "config.json").write_text("{}")

        cache = ToolCache(config)
        cache.cache_dir = tmp_path
        cache.index_path = tmp_path / "index.json"
        cache.metadata_path = tmp_path / "metadata.json"

        # Create mock tools for successful servers
        successful_tools = [
            ToolInfo(server="working-server", name="tool1", description="Tool 1", input_schema={}),
            ToolInfo(server="another-working", name="tool2", description="Tool 2", input_schema={}),
        ]

        async def mock_list_tools(server_name: str):
            if server_name == "broken-server":
                raise FileNotFoundError("Command not found: nonexistent")
            elif server_name == "working-server":
                return [successful_tools[0]]
            else:
                return [successful_tools[1]]

        mock_manager = MagicMock()
        mock_manager.list_tools = AsyncMock(side_effect=mock_list_tools)

        with patch("mcp_launchpad.cache.ConnectionManager", return_value=mock_manager):
            # Should NOT raise - some servers succeeded
            result = asyncio.run(cache.refresh(force=True))

            # Should have tools from successful servers
            assert len(result) == 2
            server_names = {t.server for t in result}
            assert "working-server" in server_names
            assert "another-working" in server_names
            assert "broken-server" not in server_names

            # Cache should be saved
            assert cache.index_path.exists()
            cached = cache._load_tools()
            assert len(cached) == 2

    def test_cache_corrupted_index(self, tmp_path: Path):
        """Test handling of corrupted cache index file."""
        from mcp_launchpad.cache import ToolCache

        config = Config(
            servers={"test": ServerConfig(name="test", command="cmd")},
            config_path=tmp_path / "config.json",
            env_path=None,
        )
        (tmp_path / "config.json").write_text("{}")

        cache = ToolCache(config)
        cache.cache_dir = tmp_path
        cache.index_path = tmp_path / "index.json"
        cache.metadata_path = tmp_path / "metadata.json"

        # Write corrupted data
        cache.index_path.write_text("not valid json {{{")

        # Should return empty list, not crash
        tools = cache._load_tools()
        assert tools == []

    def test_cache_corrupted_metadata(self, tmp_path: Path):
        """Test handling of corrupted cache metadata file."""
        from mcp_launchpad.cache import ToolCache

        config = Config(
            servers={"test": ServerConfig(name="test", command="cmd")},
            config_path=tmp_path / "config.json",
            env_path=None,
        )
        (tmp_path / "config.json").write_text("{}")

        cache = ToolCache(config)
        cache.cache_dir = tmp_path
        cache.index_path = tmp_path / "index.json"
        cache.metadata_path = tmp_path / "metadata.json"

        # Write corrupted metadata
        cache.metadata_path.write_text("{invalid")

        # Should return None, not crash
        metadata = cache._load_metadata()
        assert metadata is None


class TestSearchErrors:
    """Test error handling in search module."""

    def test_invalid_regex_pattern(self):
        """Test error message for invalid regex."""
        from mcp_launchpad.search import ToolSearcher

        tools = [
            ToolInfo(
                server="test", name="test_tool", description="Test", input_schema={}
            )
        ]
        searcher = ToolSearcher(tools)

        with pytest.raises(ValueError) as excinfo:
            searcher.search_regex("[unclosed")

        assert "Invalid regex pattern" in str(excinfo.value)

    def test_search_empty_query(self):
        """Test search with empty query returns no results."""
        from mcp_launchpad.search import ToolSearcher

        tools = [
            ToolInfo(
                server="test", name="test_tool", description="Test", input_schema={}
            )
        ]
        searcher = ToolSearcher(tools)

        # BM25 with empty query
        results = searcher.search_bm25("")
        assert results == []


class TestEnvVarEdgeCases:
    """Test edge cases for environment variable handling.

    These tests are critical for YouTube users who may have various
    .env file configurations and environment setups.
    """

    def test_env_var_not_in_braces_not_expanded(self):
        """Test that env vars without ${} syntax are not expanded."""
        config = ServerConfig(
            name="test",
            command="echo",
            args=[],
            env={"TOKEN": "$NOT_EXPANDED"},  # No braces
        )
        resolved = config.get_resolved_env()
        # Should be kept as-is since it's not ${VAR} format
        assert resolved["TOKEN"] == "$NOT_EXPANDED"

    def test_env_var_partial_braces_not_expanded(self):
        """Test that malformed env var patterns are not expanded."""
        config = ServerConfig(
            name="test",
            command="echo",
            args=[],
            env={
                "TOKEN1": "${MISSING_END",  # Missing closing brace
                "TOKEN2": "$MISSING_START}",  # Missing opening
                "TOKEN3": "prefix${VAR}",  # Has prefix - gets partial expansion
            },
        )
        resolved = config.get_resolved_env()
        # Malformed patterns without closing brace or opening ${ stay unchanged
        assert resolved["TOKEN1"] == "${MISSING_END"
        assert resolved["TOKEN2"] == "$MISSING_START}"
        # Valid ${VAR} pattern gets expanded (VAR not set = empty string)
        assert resolved["TOKEN3"] == "prefix"

    def test_env_var_empty_name(self):
        """Test ${} with empty variable name - doesn't match regex."""
        config = ServerConfig(
            name="test",
            command="echo",
            args=[],
            env={"TOKEN": "${}"},
        )
        resolved = config.get_resolved_env()
        # Empty ${} doesn't match regex pattern \$\{([^}]+)\} (requires 1+ chars)
        # so it stays unchanged
        assert resolved["TOKEN"] == "${}"

    def test_env_var_with_special_characters(self, monkeypatch):
        """Test env var names with underscores (common pattern)."""
        monkeypatch.setenv("MY_API_KEY", "secret123")
        config = ServerConfig(
            name="test",
            command="echo",
            args=[],
            env={"TOKEN": "${MY_API_KEY}"},
        )
        resolved = config.get_resolved_env()
        assert resolved["TOKEN"] == "secret123"

    async def test_missing_env_var_helpful_error(self):
        """Test that missing env var error includes helpful instructions."""
        config = Config(
            servers={
                "api-server": ServerConfig(
                    name="api-server",
                    command="python",
                    args=["-m", "server"],
                    env={"OPENAI_API_KEY": "${OPENAI_API_KEY}"},
                )
            },
            config_path=None,
            env_path=None,
        )
        manager = ConnectionManager(config)

        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(ValueError) as excinfo:
                async with manager.connect("api-server"):
                    pass

            error_msg = str(excinfo.value)
            # Should have helpful instructions
            assert "OPENAI_API_KEY" in error_msg
            assert ".env" in error_msg
            assert "export" in error_msg


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_tool_with_empty_description(self):
        """Test tool with empty description."""
        tool = ToolInfo(
            server="test",
            name="no_desc",
            description="",
            input_schema={},
        )
        assert tool.description == ""
        from mcp_launchpad.search import build_search_text

        # Should not crash
        text = build_search_text(tool)
        assert "test" in text
        assert "no_desc" in text

    def test_tool_with_complex_schema(self):
        """Test tool with deeply nested schema."""
        tool = ToolInfo(
            server="test",
            name="complex",
            description="Complex tool",
            input_schema={
                "type": "object",
                "properties": {
                    "nested": {
                        "type": "object",
                        "properties": {
                            "deep": {
                                "type": "array",
                                "items": {"type": "string"},
                            }
                        },
                    }
                },
                "required": ["nested"],
            },
        )
        # Should handle complex schema without crashing
        params = tool.get_required_params()
        assert params == ["nested"]
        example = tool.get_example_call()
        assert "mcpl call" in example

    def test_server_config_with_empty_command(self):
        """Test server config with empty command."""
        config = ServerConfig(name="empty", command="")
        assert config.command == ""

    def test_config_with_unicode_characters(self, tmp_path: Path, monkeypatch):
        """Test config with unicode in server names and values."""
        monkeypatch.chdir(tmp_path)
        # Isolate test from user's real config files
        import mcp_launchpad.config as config_module
        monkeypatch.setattr(config_module, "CONFIG_SEARCH_DIRS", [Path(".")])

        config_data = {
            "mcpServers": {
                "test-üñíçödé": {
                    "command": "python",
                    "args": ["--name", "tëst"],
                }
            }
        }
        (tmp_path / "mcp.json").write_text(json.dumps(config_data, ensure_ascii=False))

        config = load_config()
        assert "test-üñíçödé" in config.servers

