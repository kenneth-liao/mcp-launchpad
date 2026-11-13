"""Tests for CLI module."""

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from click.testing import CliRunner

from mcp_launchpad.cli import main
from mcp_launchpad.config import Config, ServerConfig
from mcp_launchpad.connection import ToolInfo


@pytest.fixture
def runner() -> CliRunner:
    """Create a CLI test runner."""
    return CliRunner()


@pytest.fixture
def mock_config(sample_tools: list[ToolInfo]) -> MagicMock:
    """Create a mock config with sample tools."""
    config = Config(
        servers={
            "github": ServerConfig(
                name="github", command="uvx", args=["mcp-server-github"]
            ),
            "sentry": ServerConfig(
                name="sentry", command="npx", args=["mcp-server-sentry"]
            ),
        },
        config_path=Path("test.json"),
        env_path=None,
    )
    return config


class TestMainGroup:
    """Tests for the main CLI group."""

    def test_version(self, runner: CliRunner):
        """Test --version flag."""
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0
        assert "version" in result.output.lower()

    def test_help(self, runner: CliRunner):
        """Test --help flag."""
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "MCP Launchpad" in result.output
        assert "search" in result.output
        assert "list" in result.output
        assert "call" in result.output
        assert "inspect" in result.output


class TestSearchCommand:
    """Tests for the search command."""

    def test_search_no_config(self, runner: CliRunner, tmp_path: Path, monkeypatch):
        """Test search when no config file exists."""
        monkeypatch.chdir(tmp_path)
        # Use explicit non-existent config to force error
        # Click returns exit code 2 for usage errors (like invalid path)
        nonexistent = tmp_path / "nonexistent.json"
        result = runner.invoke(main, ["--config", str(nonexistent), "search", "test"])
        assert result.exit_code == 2  # Click usage error
        assert "does not exist" in result.output or "Error" in result.output

    def test_search_with_results(
        self,
        runner: CliRunner,
        tmp_path: Path,
        sample_tools: list[ToolInfo],
        monkeypatch,
    ):
        """Test search with results."""
        monkeypatch.chdir(tmp_path)

        # Create config file
        config_data = {"mcpServers": {"github": {"command": "test"}}}
        (tmp_path / "mcp.json").write_text(json.dumps(config_data))

        with patch("mcp_launchpad.cli.ToolCache") as MockCache:
            mock_cache = MagicMock()
            mock_cache.is_cache_valid.return_value = True
            mock_cache.get_tools.return_value = sample_tools
            MockCache.return_value = mock_cache

            result = runner.invoke(main, ["search", "github"])

            assert result.exit_code == 0
            assert "github" in result.output.lower()

    def test_search_json_mode(
        self,
        runner: CliRunner,
        tmp_path: Path,
        sample_tools: list[ToolInfo],
        monkeypatch,
    ):
        """Test search with JSON output."""
        monkeypatch.chdir(tmp_path)

        config_data = {"mcpServers": {"github": {"command": "test"}}}
        (tmp_path / "mcp.json").write_text(json.dumps(config_data))

        with patch("mcp_launchpad.cli.ToolCache") as MockCache:
            mock_cache = MagicMock()
            mock_cache.is_cache_valid.return_value = True
            mock_cache.get_tools.return_value = sample_tools
            MockCache.return_value = mock_cache

            result = runner.invoke(main, ["--json", "search", "github"])

            assert result.exit_code == 0
            parsed = json.loads(result.output)
            assert parsed["success"] is True
            assert "results" in parsed["data"]

    def test_search_no_results(
        self,
        runner: CliRunner,
        tmp_path: Path,
        sample_tools: list[ToolInfo],
        monkeypatch,
    ):
        """Test search with no matching results."""
        monkeypatch.chdir(tmp_path)

        config_data = {"mcpServers": {"github": {"command": "test"}}}
        (tmp_path / "mcp.json").write_text(json.dumps(config_data))

        with patch("mcp_launchpad.cli.ToolCache") as MockCache:
            mock_cache = MagicMock()
            mock_cache.is_cache_valid.return_value = True
            mock_cache.get_tools.return_value = sample_tools
            MockCache.return_value = mock_cache

            result = runner.invoke(main, ["search", "nonexistent_xyz_123"])

            assert "No tools found" in result.output or result.exit_code == 0

    def test_search_invalid_regex(
        self,
        runner: CliRunner,
        tmp_path: Path,
        sample_tools: list[ToolInfo],
        monkeypatch,
    ):
        """Test search with invalid regex pattern."""
        monkeypatch.chdir(tmp_path)

        config_data = {"mcpServers": {"github": {"command": "test"}}}
        (tmp_path / "mcp.json").write_text(json.dumps(config_data))

        with patch("mcp_launchpad.cli.ToolCache") as MockCache:
            mock_cache = MagicMock()
            mock_cache.is_cache_valid.return_value = True
            mock_cache.get_tools.return_value = sample_tools
            MockCache.return_value = mock_cache

            result = runner.invoke(main, ["search", "-m", "regex", "[invalid"])

            assert result.exit_code == 1
            assert "Invalid regex" in result.output or "Error" in result.output


class TestListCommand:
    """Tests for the list command."""

    def test_list_servers(
        self,
        runner: CliRunner,
        tmp_path: Path,
        sample_tools: list[ToolInfo],
        monkeypatch,
    ):
        """Test listing all servers."""
        monkeypatch.chdir(tmp_path)
        # Isolate test from user's real config files
        import mcp_launchpad.config as config_module

        monkeypatch.setattr(config_module, "CONFIG_SEARCH_DIRS", [Path(".")])

        config_data = {
            "mcpServers": {
                "github": {"command": "test"},
                "sentry": {"command": "test"},
            }
        }
        (tmp_path / "mcp.json").write_text(json.dumps(config_data))

        with patch("mcp_launchpad.cli.ToolCache") as MockCache:
            mock_cache = MagicMock()
            mock_cache.get_tools.return_value = sample_tools
            MockCache.return_value = mock_cache

            result = runner.invoke(main, ["list"])

            assert result.exit_code == 0
            assert "github" in result.output
            assert "sentry" in result.output

    def test_list_server_tools(
        self,
        runner: CliRunner,
        tmp_path: Path,
        sample_tools: list[ToolInfo],
        monkeypatch,
    ):
        """Test listing tools for a specific server."""
        monkeypatch.chdir(tmp_path)

        config_data = {"mcpServers": {"github": {"command": "test"}}}
        (tmp_path / "mcp.json").write_text(json.dumps(config_data))

        with patch("mcp_launchpad.cli.ToolCache") as MockCache:
            mock_cache = MagicMock()
            mock_cache.get_tools.return_value = sample_tools
            MockCache.return_value = mock_cache

            result = runner.invoke(main, ["list", "github"])

            assert result.exit_code == 0
            assert "create_issue" in result.output
            assert "list_issues" in result.output

    def test_list_json_mode(
        self,
        runner: CliRunner,
        tmp_path: Path,
        sample_tools: list[ToolInfo],
        monkeypatch,
    ):
        """Test list with JSON output."""
        monkeypatch.chdir(tmp_path)

        config_data = {"mcpServers": {"github": {"command": "test"}}}
        (tmp_path / "mcp.json").write_text(json.dumps(config_data))

        with patch("mcp_launchpad.cli.ToolCache") as MockCache:
            mock_cache = MagicMock()
            mock_cache.get_tools.return_value = sample_tools
            MockCache.return_value = mock_cache

            result = runner.invoke(main, ["--json", "list"])

            assert result.exit_code == 0
            parsed = json.loads(result.output)
            assert parsed["success"] is True
            assert "servers" in parsed["data"]


class TestInspectCommand:
    """Tests for the inspect command."""

    def test_inspect_from_cache(
        self,
        runner: CliRunner,
        tmp_path: Path,
        sample_tools: list[ToolInfo],
        monkeypatch,
    ):
        """Test inspecting a tool from cache."""
        monkeypatch.chdir(tmp_path)

        config_data = {"mcpServers": {"github": {"command": "test"}}}
        (tmp_path / "mcp.json").write_text(json.dumps(config_data))

        with patch("mcp_launchpad.cli.ToolCache") as MockCache:
            mock_cache = MagicMock()
            mock_cache.get_tools.return_value = sample_tools
            MockCache.return_value = mock_cache

            result = runner.invoke(
                main, ["--json", "inspect", "github", "create_issue"]
            )

            assert result.exit_code == 0
            parsed = json.loads(result.output)
            assert parsed["success"] is True
            assert parsed["data"]["name"] == "create_issue"

    def test_inspect_with_example(
        self,
        runner: CliRunner,
        tmp_path: Path,
        sample_tools: list[ToolInfo],
        monkeypatch,
    ):
        """Test inspecting a tool with --example flag."""
        monkeypatch.chdir(tmp_path)

        config_data = {"mcpServers": {"github": {"command": "test"}}}
        (tmp_path / "mcp.json").write_text(json.dumps(config_data))

        with patch("mcp_launchpad.cli.ToolCache") as MockCache:
            mock_cache = MagicMock()
            mock_cache.get_tools.return_value = sample_tools
            MockCache.return_value = mock_cache

            result = runner.invoke(
                main, ["--json", "inspect", "github", "create_issue", "--example"]
            )

            assert result.exit_code == 0
            parsed = json.loads(result.output)
            assert "exampleCall" in parsed["data"]

    def test_inspect_tool_not_found(
        self,
        runner: CliRunner,
        tmp_path: Path,
        sample_tools: list[ToolInfo],
        monkeypatch,
    ):
        """Test inspecting a non-existent tool."""
        monkeypatch.chdir(tmp_path)

        config_data = {"mcpServers": {"github": {"command": "test"}}}
        (tmp_path / "mcp.json").write_text(json.dumps(config_data))

        with (
            patch("mcp_launchpad.cli.ToolCache") as MockCache,
            patch("mcp_launchpad.cli.ConnectionManager") as MockManager,
        ):
            mock_cache = MagicMock()
            mock_cache.get_tools.return_value = sample_tools
            MockCache.return_value = mock_cache

            mock_manager = MagicMock()
            mock_manager.list_tools = AsyncMock(return_value=sample_tools[:2])
            MockManager.return_value = mock_manager

            result = runner.invoke(main, ["inspect", "github", "nonexistent_tool"])

            assert result.exit_code == 1
            assert "not found" in result.output.lower()


class TestCallCommand:
    """Tests for the call command.

    Note: The call command uses SessionClient which communicates with a daemon
    for persistent connections. We mock SessionClient for fast, isolated tests.
    """

    def test_call_with_arguments(self, runner: CliRunner, tmp_path: Path, monkeypatch):
        """Test calling a tool with arguments."""
        monkeypatch.chdir(tmp_path)

        config_data = {"mcpServers": {"github": {"command": "test"}}}
        (tmp_path / "mcp.json").write_text(json.dumps(config_data))

        with patch("mcp_launchpad.cli.SessionClient") as MockSession:
            mock_session = MagicMock()
            mock_session.call_tool = AsyncMock(
                return_value={"result": "Tool executed successfully"}
            )
            MockSession.return_value = mock_session

            result = runner.invoke(
                main,
                [
                    "--json",
                    "call",
                    "github",
                    "create_issue",
                    '{"owner": "test", "repo": "test"}',
                ],
            )

            assert result.exit_code == 0
            parsed = json.loads(result.output)
            assert parsed["success"] is True

    def test_call_no_arguments(self, runner: CliRunner, tmp_path: Path, monkeypatch):
        """Test calling a tool without arguments."""
        monkeypatch.chdir(tmp_path)

        config_data = {"mcpServers": {"test": {"command": "test"}}}
        (tmp_path / "mcp.json").write_text(json.dumps(config_data))

        with patch("mcp_launchpad.cli.SessionClient") as MockSession:
            mock_session = MagicMock()
            mock_session.call_tool = AsyncMock(return_value={"result": "Result"})
            MockSession.return_value = mock_session

            result = runner.invoke(main, ["--json", "call", "test", "simple_tool"])

            assert result.exit_code == 0

    def test_call_invalid_json_arguments(
        self, runner: CliRunner, tmp_path: Path, monkeypatch
    ):
        """Test calling with invalid JSON arguments."""
        monkeypatch.chdir(tmp_path)

        config_data = {"mcpServers": {"github": {"command": "test"}}}
        (tmp_path / "mcp.json").write_text(json.dumps(config_data))

        result = runner.invoke(
            main, ["call", "github", "create_issue", "{ not valid json }"]
        )

        assert result.exit_code == 1
        assert "JSON" in result.output or "Error" in result.output

    def test_call_server_not_found(
        self, runner: CliRunner, tmp_path: Path, monkeypatch
    ):
        """Test calling tool on non-existent server."""
        monkeypatch.chdir(tmp_path)

        config_data = {"mcpServers": {"github": {"command": "test"}}}
        (tmp_path / "mcp.json").write_text(json.dumps(config_data))

        with patch("mcp_launchpad.cli.SessionClient") as MockSession:
            mock_session = MagicMock()
            mock_session.call_tool = AsyncMock(
                side_effect=ValueError("Server 'nonexistent' not found")
            )
            MockSession.return_value = mock_session

            result = runner.invoke(main, ["call", "nonexistent", "some_tool", "{}"])

            assert result.exit_code == 1
            assert "not found" in result.output.lower()

    def test_call_connection_error(
        self, runner: CliRunner, tmp_path: Path, monkeypatch
    ):
        """Test calling tool when connection fails."""
        monkeypatch.chdir(tmp_path)

        config_data = {"mcpServers": {"github": {"command": "test"}}}
        (tmp_path / "mcp.json").write_text(json.dumps(config_data))

        with patch("mcp_launchpad.cli.SessionClient") as MockSession:
            mock_session = MagicMock()
            mock_session.call_tool = AsyncMock(
                side_effect=TimeoutError("Connection timed out")
            )
            MockSession.return_value = mock_session

            result = runner.invoke(main, ["call", "github", "create_issue", "{}"])

            assert result.exit_code == 1
            assert "timed out" in result.output.lower() or "Error" in result.output


class TestConfigErrors:
    """Tests for config-related error handling in CLI."""

    def test_invalid_json_config(self, runner: CliRunner, tmp_path: Path, monkeypatch):
        """Test error when config file has invalid JSON."""
        monkeypatch.chdir(tmp_path)
        # Isolate test from user's real config files
        import mcp_launchpad.config as config_module

        monkeypatch.setattr(config_module, "CONFIG_SEARCH_DIRS", [Path(".")])

        (tmp_path / "mcp.json").write_text("{ invalid json }")

        result = runner.invoke(main, ["list"])

        assert result.exit_code == 1
        assert "JSON" in result.output or "Error" in result.output

    def test_config_path_option(
        self,
        runner: CliRunner,
        tmp_path: Path,
        sample_tools: list[ToolInfo],
        monkeypatch,
    ):
        """Test --config option for custom config path."""
        monkeypatch.chdir(tmp_path)

        custom_config = tmp_path / "custom-config.json"
        custom_config.write_text(
            json.dumps({"mcpServers": {"test": {"command": "test"}}})
        )

        with patch("mcp_launchpad.cli.ToolCache") as MockCache:
            mock_cache = MagicMock()
            mock_cache.get_tools.return_value = []
            MockCache.return_value = mock_cache

            result = runner.invoke(main, ["--config", str(custom_config), "list"])

            assert result.exit_code == 0


class TestVerifyCommand:
    """Tests for the verify command."""

    @pytest.mark.parametrize("json_mode", [False, True])
    @pytest.mark.parametrize(
        ("failed_servers", "disabled_servers", "exit_code", "passed", "failed"),
        [
            ([], [], 0, 2, 0),
            (["first"], [], 1, 1, 1),
            (["second"], [], 1, 1, 1),
            (["first", "second"], [], 1, 0, 2),
            (["second"], ["second"], 0, 1, 0),
            (["first", "second"], ["first", "second"], 0, 0, 0),
        ],
    )
    def test_verify_exit_status(
        self,
        runner,
        tmp_path,
        monkeypatch,
        json_mode,
        failed_servers,
        disabled_servers,
        exit_code,
        passed,
        failed,
    ):
        """Failures affect the exit status after all enabled servers are checked."""
        monkeypatch.chdir(tmp_path)
        config_path = tmp_path / "mcp.json"
        config_path.write_text(
            json.dumps(
                {"mcpServers": {name: {"command": "test"} for name in ("first", "second")}}
            )
        )
        state_path = tmp_path / "server_state.json"
        state_path.write_text(json.dumps({"disabled_servers": disabled_servers}))
        monkeypatch.setattr("mcp_launchpad.state.STATE_FILE", state_path)
        checked = []

        async def list_tools(server_name):
            checked.append(server_name)
            if server_name in failed_servers:
                raise RuntimeError("Server unavailable")
            return []

        args = ["--config", str(config_path)]
        if json_mode:
            args.append("--json")
        with patch("mcp_launchpad.cli.ConnectionManager") as manager:
            manager.return_value.list_tools = list_tools
            result = runner.invoke(main, [*args, "verify"])

        assert result.exit_code == exit_code
        assert checked == [name for name in ("first", "second") if name not in disabled_servers]
        if json_mode:
            data = json.loads(result.output)["data"]
            assert data["all_passed"] is (failed == 0)
            assert data["total"] == passed + failed
            assert data["passed"] == passed
            assert data["failed"] == failed
            assert [r["server"] for r in data["results"]] == checked
        elif failed:
            assert f"Verification complete: {passed} passed, {failed} failed." in result.output
        else:
            assert f"All {passed} servers verified successfully." in result.output

    @pytest.mark.parametrize("json_mode", [False, True])
    def test_verify_timeout_bounds_unresponsive_server(
        self, runner: CliRunner, tmp_path: Path, monkeypatch, json_mode
    ):
        """--timeout must bound each server check, including list_tools.

        Regression: verify set MCPL_CONNECTION_TIMEOUT after the module had
        already read it, so --timeout had no effect, and a server that never
        answered list_tools could hang verification forever.
        """
        import asyncio

        monkeypatch.chdir(tmp_path)
        config_data = {"mcpServers": {"hung": {"command": "test"}}}
        (tmp_path / "mcp.json").write_text(json.dumps(config_data))

        async def never_responds(server_name: str):
            await asyncio.sleep(60)

        with patch("mcp_launchpad.cli.ConnectionManager") as MockManager:
            MockManager.return_value.list_tools = never_responds
            args = ["--json"] if json_mode else []
            result = runner.invoke(main, [*args, "verify", "--timeout", "1"])

        assert result.exit_code == 1
        if json_mode:
            data = json.loads(result.output)["data"]
            assert data["all_passed"] is False
            assert data["results"][0]["error"] == "Timed out after 1s"
        else:
            assert "[hung] FAILED - Timed out after 1s" in result.output
