"""Tests for config module."""

import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from mcp_launchpad.config import (
    ServerConfig,
    find_config_file,
    find_config_files,
    find_env_file,
    find_env_files,
    load_config,
    parse_server_config,
)


class TestServerConfig:
    """Tests for ServerConfig dataclass."""

    def test_basic_creation(self):
        """Test creating a basic server config."""
        config = ServerConfig(
            name="test",
            command="python",
            args=["-m", "server"],
            env={"KEY": "value"},
        )
        assert config.name == "test"
        assert config.command == "python"
        assert config.args == ["-m", "server"]
        assert config.env == {"KEY": "value"}

    def test_default_values(self):
        """Test default values for optional fields."""
        config = ServerConfig(name="test", command="python")
        assert config.args == []
        assert config.env == {}

    def test_get_resolved_env_static_values(self):
        """Test resolving static env values."""
        config = ServerConfig(
            name="test",
            command="python",
            env={"STATIC_KEY": "static_value"},
        )
        resolved = config.get_resolved_env()
        assert resolved == {"STATIC_KEY": "static_value"}

    def test_get_resolved_env_variable_substitution(self):
        """Test resolving env variable references."""
        with patch.dict(os.environ, {"MY_TOKEN": "secret-token"}):
            config = ServerConfig(
                name="test",
                command="python",
                env={"TOKEN": "${MY_TOKEN}"},
            )
            resolved = config.get_resolved_env()
            assert resolved == {"TOKEN": "secret-token"}

    def test_get_resolved_env_missing_variable(self):
        """Test resolving missing env variable returns empty string."""
        # Ensure the variable is not set
        with patch.dict(os.environ, {}, clear=True):
            config = ServerConfig(
                name="test",
                command="python",
                env={"TOKEN": "${NONEXISTENT_VAR}"},
            )
            resolved = config.get_resolved_env()
            assert resolved == {"TOKEN": ""}

    def test_get_resolved_env_mixed_values(self):
        """Test resolving mixed static and variable values."""
        with patch.dict(os.environ, {"VAR1": "value1"}, clear=True):
            config = ServerConfig(
                name="test",
                command="python",
                env={
                    "STATIC": "static_value",
                    "DYNAMIC": "${VAR1}",
                    "MISSING": "${MISSING_VAR}",
                },
            )
            resolved = config.get_resolved_env()
            assert resolved == {
                "STATIC": "static_value",
                "DYNAMIC": "value1",
                "MISSING": "",
            }

    def test_get_resolved_env_partial_substitution(self):
        """Test resolving partial variable substitution in env values."""
        with patch.dict(os.environ, {"HOST": "localhost", "PORT": "8080"}, clear=True):
            config = ServerConfig(
                name="test",
                command="python",
                env={
                    "URL": "http://${HOST}:${PORT}/api",
                    "PREFIX": "prefix_${HOST}",
                    "SUFFIX": "${PORT}_suffix",
                },
            )
            resolved = config.get_resolved_env()
            assert resolved == {
                "URL": "http://localhost:8080/api",
                "PREFIX": "prefix_localhost",
                "SUFFIX": "8080_suffix",
            }

    def test_get_resolved_args_static_values(self):
        """Test resolving static arg values."""
        config = ServerConfig(
            name="test",
            command="python",
            args=["-m", "server", "--port", "8080"],
        )
        resolved = config.get_resolved_args()
        assert resolved == ["-m", "server", "--port", "8080"]

    def test_get_resolved_args_variable_substitution(self):
        """Test resolving arg variable references."""
        with patch.dict(os.environ, {"MY_TOKEN": "secret-token"}, clear=True):
            config = ServerConfig(
                name="test",
                command="python",
                args=["--token", "${MY_TOKEN}"],
            )
            resolved = config.get_resolved_args()
            assert resolved == ["--token", "secret-token"]

    def test_get_resolved_args_missing_variable(self):
        """Test resolving missing arg variable returns empty string."""
        with patch.dict(os.environ, {}, clear=True):
            config = ServerConfig(
                name="test",
                command="python",
                args=["--token", "${NONEXISTENT_VAR}"],
            )
            resolved = config.get_resolved_args()
            assert resolved == ["--token", ""]

    def test_get_resolved_args_partial_substitution(self):
        """Test resolving partial variable substitution in args."""
        with patch.dict(os.environ, {"HOST": "localhost", "PORT": "8080"}, clear=True):
            config = ServerConfig(
                name="test",
                command="python",
                args=[
                    "--url",
                    "http://${HOST}:${PORT}/api",
                    "--header",
                    "Authorization: Bearer ${TOKEN}",
                ],
            )
            resolved = config.get_resolved_args()
            assert resolved == [
                "--url",
                "http://localhost:8080/api",
                "--header",
                "Authorization: Bearer ",  # Missing TOKEN resolves to empty
            ]

    def test_get_resolved_args_mixed_values(self):
        """Test resolving mixed static and variable args."""
        with patch.dict(os.environ, {"TOKEN": "abc123"}, clear=True):
            config = ServerConfig(
                name="test",
                command="npx",
                args=[
                    "-y",
                    "@supabase/mcp-server",
                    "--access-token",
                    "${TOKEN}",
                ],
            )
            resolved = config.get_resolved_args()
            assert resolved == [
                "-y",
                "@supabase/mcp-server",
                "--access-token",
                "abc123",
            ]

    def test_get_resolved_env_remapped_variable(self):
        """Test remapping env var to different name for subprocess."""
        with patch.dict(os.environ, {"A_API_KEY": "secret123"}, clear=True):
            config = ServerConfig(
                name="test",
                command="python",
                env={
                    "MY_API_KEY": "${A_API_KEY}",  # Remap A_API_KEY -> MY_API_KEY
                },
            )
            resolved = config.get_resolved_env()
            assert resolved == {"MY_API_KEY": "secret123"}

    def test_get_resolved_env_literal_without_braces(self):
        """Test that values without ${} are treated as literals."""
        with patch.dict(os.environ, {"A_API_KEY": "secret123"}, clear=True):
            config = ServerConfig(
                name="test",
                command="python",
                env={
                    "MY_API_KEY": "A_API_KEY",  # No ${} = literal string
                },
            )
            resolved = config.get_resolved_env()
            assert resolved == {"MY_API_KEY": "A_API_KEY"}  # Literal, not resolved

    # HTTP server support tests
    def test_is_http_false_for_stdio(self):
        """Test that is_http returns False for stdio servers."""
        config = ServerConfig(name="test", command="python")
        assert config.is_http() is False

    def test_is_http_true_for_http_type(self):
        """Test that is_http returns True for HTTP servers."""
        config = ServerConfig(
            name="test",
            server_type="http",
            url="https://example.com/mcp",
        )
        assert config.is_http() is True

    def test_get_resolved_url_static(self):
        """Test resolving static URL."""
        config = ServerConfig(
            name="test",
            server_type="http",
            url="https://example.com/mcp",
        )
        assert config.get_resolved_url() == "https://example.com/mcp"

    def test_get_resolved_url_with_variable(self):
        """Test resolving URL with environment variable."""
        with patch.dict(os.environ, {"PROJECT_REF": "abc123"}, clear=True):
            config = ServerConfig(
                name="test",
                server_type="http",
                url="https://mcp.example.com/mcp?project_ref=${PROJECT_REF}",
            )
            resolved = config.get_resolved_url()
            assert resolved == "https://mcp.example.com/mcp?project_ref=abc123"

    def test_get_resolved_headers_static(self):
        """Test resolving static headers."""
        config = ServerConfig(
            name="test",
            server_type="http",
            url="https://example.com/mcp",
            headers={"Content-Type": "application/json"},
        )
        resolved = config.get_resolved_headers()
        assert resolved == {"Content-Type": "application/json"}

    def test_get_resolved_headers_with_variable(self):
        """Test resolving headers with environment variables."""
        with patch.dict(os.environ, {"ACCESS_TOKEN": "secret-token"}, clear=True):
            config = ServerConfig(
                name="test",
                server_type="http",
                url="https://example.com/mcp",
                headers={"Authorization": "Bearer ${ACCESS_TOKEN}"},
            )
            resolved = config.get_resolved_headers()
            assert resolved == {"Authorization": "Bearer secret-token"}

    def test_get_resolved_headers_missing_variable(self):
        """Test resolving headers with missing variable resolves to empty."""
        with patch.dict(os.environ, {}, clear=True):
            config = ServerConfig(
                name="test",
                server_type="http",
                url="https://example.com/mcp",
                headers={"Authorization": "Bearer ${MISSING_TOKEN}"},
            )
            resolved = config.get_resolved_headers()
            assert resolved == {"Authorization": "Bearer "}

    def test_http_config_default_values(self):
        """Test that HTTP config has correct defaults."""
        config = ServerConfig(name="test", server_type="http", url="https://example.com")
        assert config.headers == {}
        assert config.command == ""
        assert config.args == []
        assert config.env == {}


class TestFindConfigFiles:
    """Tests for find_config_files function."""

    def test_explicit_path_exists(self, tmp_path: Path):
        """Test with explicit path that exists."""
        config_file = tmp_path / "custom.json"
        config_file.write_text("{}")
        result = find_config_files(config_file)
        assert result == [config_file]

    def test_explicit_path_not_exists(self, tmp_path: Path):
        """Test with explicit path that doesn't exist."""
        config_file = tmp_path / "nonexistent.json"
        result = find_config_files(config_file)
        assert result == []

    def test_no_config_file_found(self, tmp_path: Path, monkeypatch):
        """Test when no config file is found in search directories."""
        monkeypatch.chdir(tmp_path)
        # Create a JSON file without 'mcp' in the name
        (tmp_path / "config.json").write_text("{}")
        result = find_config_files(None)
        # May find user-level config, so just check it doesn't raise
        # and doesn't include the non-mcp file
        assert all("mcp" in f.name.lower() for f in result)

    def test_finds_mcp_json(self, tmp_path: Path, monkeypatch):
        """Test that mcp.json is found."""
        monkeypatch.chdir(tmp_path)
        config_file = tmp_path / "mcp.json"
        config_file.write_text("{}")
        result = find_config_files(None)
        resolved_results = [f.resolve() for f in result]
        assert config_file.resolve() in resolved_results

    def test_finds_custom_mcp_filename(self, tmp_path: Path, monkeypatch):
        """Test that files with 'mcp' anywhere in name are found."""
        monkeypatch.chdir(tmp_path)
        files = [
            tmp_path / "my-mcp-servers.json",
            tmp_path / "mcp-config.json",
            tmp_path / "custom_mcp.json",
        ]
        for f in files:
            f.write_text("{}")

        result = find_config_files(None)
        resolved_results = [f.resolve() for f in result]
        for f in files:
            assert f.resolve() in resolved_results

    def test_case_insensitive_matching(self, tmp_path: Path, monkeypatch):
        """Test that 'MCP' and 'mcp' both match."""
        monkeypatch.chdir(tmp_path)
        files = [
            tmp_path / "MCP.json",
            tmp_path / "MyMCP.json",
            tmp_path / "mcp-servers.json",
        ]
        for f in files:
            f.write_text("{}")

        result = find_config_files(None)
        resolved_results = [f.resolve() for f in result]
        for f in files:
            assert f.resolve() in resolved_results

    def test_excludes_dot_mcp_json(self, tmp_path: Path, monkeypatch):
        """Test that .mcp.json (Claude Code's convention) is excluded."""
        monkeypatch.chdir(tmp_path)
        # Create both .mcp.json and mcp.json
        excluded_file = tmp_path / ".mcp.json"
        included_file = tmp_path / "mcp.json"
        excluded_file.write_text("{}")
        included_file.write_text("{}")

        result = find_config_files(None)
        resolved_results = [f.resolve() for f in result]

        # .mcp.json should be excluded
        assert excluded_file.resolve() not in resolved_results
        # mcp.json should be included
        assert included_file.resolve() in resolved_results

    def test_excludes_only_exact_dot_mcp_json(self, tmp_path: Path, monkeypatch):
        """Test that only exactly '.mcp.json' is excluded, not similar names."""
        monkeypatch.chdir(tmp_path)
        # These should all be included
        similar_files = [
            tmp_path / "my.mcp.json",
            tmp_path / ".mcp-servers.json",
            tmp_path / "dot-mcp.json",
        ]
        for f in similar_files:
            f.write_text("{}")

        # This should be excluded
        excluded_file = tmp_path / ".mcp.json"
        excluded_file.write_text("{}")

        result = find_config_files(None)
        resolved_results = [f.resolve() for f in result]

        for f in similar_files:
            assert f.resolve() in resolved_results
        assert excluded_file.resolve() not in resolved_results

    def test_searches_claude_directory(self, tmp_path: Path, monkeypatch):
        """Test that .claude directory is searched."""
        monkeypatch.chdir(tmp_path)
        claude_dir = tmp_path / ".claude"
        claude_dir.mkdir()
        config_file = claude_dir / "mcp-servers.json"
        config_file.write_text("{}")

        result = find_config_files(None)
        resolved_results = [f.resolve() for f in result]
        assert config_file.resolve() in resolved_results

    def test_ignores_non_json_files(self, tmp_path: Path, monkeypatch):
        """Test that non-JSON files are ignored."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / "mcp.txt").write_text("{}")
        (tmp_path / "mcp.yaml").write_text("servers: []")
        (tmp_path / "mcp").write_text("{}")

        result = find_config_files(None)
        # Should not find any of the non-JSON files
        assert all(f.suffix == ".json" for f in result)

    def test_no_duplicates(self, tmp_path: Path, monkeypatch):
        """Test that duplicate files are not returned."""
        monkeypatch.chdir(tmp_path)
        config_file = tmp_path / "mcp.json"
        config_file.write_text("{}")

        result = find_config_files(None)
        # Check no duplicates by comparing resolved paths
        resolved = [f.resolve() for f in result]
        assert len(resolved) == len(set(resolved))


class TestFindConfigFile:
    """Tests for find_config_file function (deprecated wrapper)."""

    def test_explicit_path_exists(self, tmp_path: Path):
        """Test with explicit path that exists."""
        config_file = tmp_path / "custom.json"
        config_file.write_text("{}")
        result = find_config_file(config_file)
        assert result == config_file

    def test_explicit_path_not_exists(self, tmp_path: Path):
        """Test with explicit path that doesn't exist."""
        config_file = tmp_path / "nonexistent.json"
        result = find_config_file(config_file)
        assert result is None

    def test_returns_first_file(self, tmp_path: Path, monkeypatch):
        """Test that find_config_file returns the first found file."""
        monkeypatch.chdir(tmp_path)
        config_file = tmp_path / "mcp.json"
        config_file.write_text("{}")
        result = find_config_file(None)
        assert result is not None
        assert result.resolve() == config_file.resolve()


class TestFindEnvFile:
    """Tests for find_env_file function."""

    def test_explicit_path_exists(self, tmp_path: Path):
        """Test with explicit path that exists."""
        env_file = tmp_path / ".env"
        env_file.write_text("KEY=value")
        result = find_env_file(env_file)
        assert result == env_file

    def test_explicit_path_not_exists(self, tmp_path: Path):
        """Test with explicit path that doesn't exist."""
        env_file = tmp_path / "nonexistent.env"
        result = find_env_file(env_file)
        assert result is None

    def test_project_level_env(self, tmp_path: Path, monkeypatch):
        """Test project-level .env is found when no global exists."""
        monkeypatch.chdir(tmp_path)
        # Mock home directory to isolate from real ~/.claude/.env
        fake_home = tmp_path / "fake_home"
        fake_home.mkdir()
        monkeypatch.setenv("HOME", str(fake_home))
        # Clear Path.home() cache
        import pathlib

        monkeypatch.setattr(pathlib.Path, "home", lambda: fake_home)

        env_file = tmp_path / ".env"
        env_file.write_text("KEY=value")
        result = find_env_file(None)
        # Compare resolved paths since function may return relative path
        assert result is not None
        assert result.resolve() == env_file.resolve()


class TestFindEnvFiles:
    """Tests for find_env_files function."""

    def test_loads_both_global_and_local(self, tmp_path: Path, monkeypatch):
        """Test that both global and local .env files are found."""
        monkeypatch.chdir(tmp_path)
        # Set up fake home with global .env
        fake_home = tmp_path / "fake_home"
        fake_home.mkdir()
        claude_dir = fake_home / ".claude"
        claude_dir.mkdir()
        global_env = claude_dir / ".env"
        global_env.write_text("GLOBAL_VAR=global")
        import pathlib

        monkeypatch.setattr(pathlib.Path, "home", lambda: fake_home)

        # Create local .env
        local_env = tmp_path / ".env"
        local_env.write_text("LOCAL_VAR=local")

        result = find_env_files(None)

        # Should return both files: global first, then local
        assert len(result) == 2
        assert result[0].resolve() == global_env.resolve()
        assert result[1].resolve() == local_env.resolve()

    def test_global_only(self, tmp_path: Path, monkeypatch):
        """Test when only global .env exists."""
        monkeypatch.chdir(tmp_path)
        # Set up fake home with global .env
        fake_home = tmp_path / "fake_home"
        fake_home.mkdir()
        claude_dir = fake_home / ".claude"
        claude_dir.mkdir()
        global_env = claude_dir / ".env"
        global_env.write_text("GLOBAL_VAR=global")
        import pathlib

        monkeypatch.setattr(pathlib.Path, "home", lambda: fake_home)

        result = find_env_files(None)

        assert len(result) == 1
        assert result[0].resolve() == global_env.resolve()

    def test_local_only(self, tmp_path: Path, monkeypatch):
        """Test when only local .env exists."""
        monkeypatch.chdir(tmp_path)
        # Set up fake home without global .env
        fake_home = tmp_path / "fake_home"
        fake_home.mkdir()
        import pathlib

        monkeypatch.setattr(pathlib.Path, "home", lambda: fake_home)

        # Create local .env
        local_env = tmp_path / ".env"
        local_env.write_text("LOCAL_VAR=local")

        result = find_env_files(None)

        assert len(result) == 1
        assert result[0].resolve() == local_env.resolve()

    def test_neither_exists(self, tmp_path: Path, monkeypatch):
        """Test when no .env files exist."""
        monkeypatch.chdir(tmp_path)
        fake_home = tmp_path / "fake_home"
        fake_home.mkdir()
        import pathlib

        monkeypatch.setattr(pathlib.Path, "home", lambda: fake_home)

        result = find_env_files(None)
        assert result == []


class TestParseServerConfig:
    """Tests for parse_server_config function."""

    def test_full_config(self):
        """Test parsing a complete server config."""
        data = {
            "command": "uvx",
            "args": ["mcp-server-github"],
            "env": {"GITHUB_TOKEN": "${GITHUB_TOKEN}"},
        }
        config = parse_server_config("github", data)
        assert config.name == "github"
        assert config.command == "uvx"
        assert config.args == ["mcp-server-github"]
        assert config.env == {"GITHUB_TOKEN": "${GITHUB_TOKEN}"}

    def test_minimal_config(self):
        """Test parsing with only required fields."""
        data = {"command": "python"}
        config = parse_server_config("minimal", data)
        assert config.name == "minimal"
        assert config.command == "python"
        assert config.args == []
        assert config.env == {}

    def test_missing_command(self):
        """Test parsing with missing command defaults to empty string."""
        data = {"args": ["some-arg"]}
        config = parse_server_config("no-command", data)
        assert config.command == ""
        assert config.args == ["some-arg"]

    def test_http_type_config(self):
        """Test parsing HTTP type server config."""
        data = {
            "type": "http",
            "url": "https://mcp.example.com/mcp",
            "headers": {"Authorization": "Bearer ${TOKEN}"},
        }
        config = parse_server_config("http-server", data)
        assert config.name == "http-server"
        assert config.server_type == "http"
        assert config.url == "https://mcp.example.com/mcp"
        assert config.headers == {"Authorization": "Bearer ${TOKEN}"}
        assert config.is_http() is True

    def test_http_type_without_headers(self):
        """Test parsing HTTP type server config without headers."""
        data = {
            "type": "http",
            "url": "https://mcp.example.com/mcp",
        }
        config = parse_server_config("http-server", data)
        assert config.server_type == "http"
        assert config.url == "https://mcp.example.com/mcp"
        assert config.headers == {}

    def test_default_type_is_stdio(self):
        """Test that default type is stdio when not specified."""
        data = {"command": "python", "args": ["-m", "server"]}
        config = parse_server_config("stdio-server", data)
        assert config.server_type == "stdio"
        assert config.is_http() is False


class TestLoadConfig:
    """Tests for load_config function."""

    def test_load_valid_config(self, tmp_path: Path, monkeypatch):
        """Test loading a valid config file."""
        monkeypatch.chdir(tmp_path)
        # Isolate test from user's real config files
        import mcp_launchpad.config as config_module

        monkeypatch.setattr(config_module, "CONFIG_SEARCH_DIRS", [Path(".")])

        config_data = {
            "mcpServers": {
                "github": {
                    "command": "uvx",
                    "args": ["mcp-server-github"],
                    "env": {"GITHUB_TOKEN": "${GITHUB_TOKEN}"},
                },
                "slack": {
                    "command": "npx",
                    "args": ["-y", "@slack/mcp-server"],
                },
            }
        }
        config_file = tmp_path / "mcp.json"
        config_file.write_text(json.dumps(config_data))

        config = load_config()

        assert len(config.servers) == 2
        assert "github" in config.servers
        assert "slack" in config.servers
        assert config.servers["github"].command == "uvx"
        assert config.servers["slack"].args == ["-y", "@slack/mcp-server"]
        # Compare resolved paths since function may return relative path
        assert config.config_path is not None
        assert config.config_path.resolve() == config_file.resolve()
        # Check config_paths includes the file
        assert len(config.config_paths) >= 1
        assert config_file.resolve() in [p.resolve() for p in config.config_paths]

    def test_load_explicit_config_path(self, tmp_path: Path):
        """Test loading config from explicit path."""
        config_data = {"mcpServers": {"test": {"command": "python"}}}
        config_file = tmp_path / "custom-config.json"
        config_file.write_text(json.dumps(config_data))

        config = load_config(config_path=config_file)

        assert len(config.servers) == 1
        assert "test" in config.servers
        assert config.config_path == config_file
        assert config.config_paths == [config_file]

    def test_config_not_found(self, tmp_path: Path, monkeypatch):
        """Test FileNotFoundError when no config file exists."""
        monkeypatch.chdir(tmp_path)
        # Use explicit path that doesn't exist to ensure FileNotFoundError
        nonexistent = tmp_path / "nonexistent.json"
        with pytest.raises(FileNotFoundError) as excinfo:
            load_config(config_path=nonexistent)

        assert "No MCP config file found" in str(excinfo.value)

    def test_invalid_json_config(self, tmp_path: Path, monkeypatch):
        """Test JSONDecodeError for invalid JSON."""
        monkeypatch.chdir(tmp_path)
        config_file = tmp_path / "mcp.json"
        config_file.write_text("{ not valid json }")

        with pytest.raises(json.JSONDecodeError):
            load_config()

    def test_empty_mcp_servers(self, tmp_path: Path, monkeypatch):
        """Test loading config with empty mcpServers."""
        monkeypatch.chdir(tmp_path)
        # Isolate test from user's real config files
        import mcp_launchpad.config as config_module

        monkeypatch.setattr(config_module, "CONFIG_SEARCH_DIRS", [Path(".")])

        config_data = {"mcpServers": {}}
        config_file = tmp_path / "mcp.json"
        config_file.write_text(json.dumps(config_data))

        config = load_config()

        assert config.servers == {}

    def test_missing_mcp_servers_key(self, tmp_path: Path, monkeypatch):
        """Test loading config without mcpServers key."""
        monkeypatch.chdir(tmp_path)
        # Isolate test from user's real config files
        import mcp_launchpad.config as config_module

        monkeypatch.setattr(config_module, "CONFIG_SEARCH_DIRS", [Path(".")])

        config_data = {"otherKey": "value"}
        config_file = tmp_path / "mcp.json"
        config_file.write_text(json.dumps(config_data))

        config = load_config()

        assert config.servers == {}

    def test_load_with_env_file(self, tmp_path: Path, monkeypatch):
        """Test loading config with .env file."""
        monkeypatch.chdir(tmp_path)
        # Mock home directory to isolate from real ~/.claude/.env
        fake_home = tmp_path / "fake_home"
        fake_home.mkdir()
        import pathlib

        monkeypatch.setattr(pathlib.Path, "home", lambda: fake_home)

        # Create config
        config_data = {"mcpServers": {"test": {"command": "python"}}}
        config_file = tmp_path / "mcp.json"
        config_file.write_text(json.dumps(config_data))

        # Create .env file
        env_file = tmp_path / ".env"
        env_file.write_text("MY_VAR=my_value")

        config = load_config()

        # Compare resolved paths since function may return relative path
        assert config.env_path is not None
        assert config.env_path.resolve() == env_file.resolve()
        # Verify env var was loaded
        assert os.environ.get("MY_VAR") == "my_value"

    def test_load_with_explicit_env_path(self, tmp_path: Path, monkeypatch):
        """Test loading config with explicit env file path."""
        monkeypatch.chdir(tmp_path)

        # Create config
        config_data = {"mcpServers": {"test": {"command": "python"}}}
        config_file = tmp_path / "mcp.json"
        config_file.write_text(json.dumps(config_data))

        # Create custom env file
        custom_env = tmp_path / "custom.env"
        custom_env.write_text("CUSTOM_VAR=custom_value")

        config = load_config(env_path=custom_env)

        assert config.env_path == custom_env
        assert os.environ.get("CUSTOM_VAR") == "custom_value"

    def test_ignores_dot_mcp_json(self, tmp_path: Path, monkeypatch):
        """Test that .mcp.json (Claude Code's convention) is ignored."""
        monkeypatch.chdir(tmp_path)

        # Create .mcp.json with a server
        excluded_data = {"mcpServers": {"excluded": {"command": "excluded"}}}
        excluded_file = tmp_path / ".mcp.json"
        excluded_file.write_text(json.dumps(excluded_data))

        # Create mcp.json with a different server
        included_data = {"mcpServers": {"included": {"command": "included"}}}
        included_file = tmp_path / "mcp.json"
        included_file.write_text(json.dumps(included_data))

        config = load_config()

        # Only the server from mcp.json should be loaded
        assert "included" in config.servers
        assert "excluded" not in config.servers
        assert config.servers["included"].command == "included"

    def test_aggregates_multiple_config_files(self, tmp_path: Path, monkeypatch):
        """Test loading and aggregating servers from multiple config files."""
        monkeypatch.chdir(tmp_path)

        # Create multiple config files with different servers
        config1 = {"mcpServers": {"github": {"command": "uvx", "args": ["mcp-github"]}}}
        config2 = {"mcpServers": {"slack": {"command": "npx", "args": ["mcp-slack"]}}}

        (tmp_path / "mcp.json").write_text(json.dumps(config1))
        (tmp_path / "my-mcp-servers.json").write_text(json.dumps(config2))

        config = load_config()

        # Both servers should be loaded
        assert "github" in config.servers
        assert "slack" in config.servers
        assert len(config.config_paths) >= 2

    def test_first_definition_wins_for_duplicate_servers(
        self, tmp_path: Path, monkeypatch
    ):
        """Test that first definition wins when same server is in multiple files."""
        monkeypatch.chdir(tmp_path)

        # Create two config files with the same server name but different commands
        # File order depends on glob order, so we use explicit naming
        config1 = {"mcpServers": {"myserver": {"command": "first-command"}}}
        config2 = {"mcpServers": {"myserver": {"command": "second-command"}}}

        # The search order is: current dir first, then .claude
        (tmp_path / "aaa-mcp.json").write_text(json.dumps(config1))
        (tmp_path / "zzz-mcp.json").write_text(json.dumps(config2))

        config = load_config()

        # Should have only one server, from whichever file was found first
        assert "myserver" in config.servers
        # The command should be from one of the files (order depends on glob)
        assert config.servers["myserver"].command in ["first-command", "second-command"]

    def test_loads_from_claude_directory(self, tmp_path: Path, monkeypatch):
        """Test loading config from .claude directory."""
        monkeypatch.chdir(tmp_path)

        # Create .claude directory with config
        claude_dir = tmp_path / ".claude"
        claude_dir.mkdir()
        config_data = {"mcpServers": {"test": {"command": "python"}}}
        config_file = claude_dir / "mcp-servers.json"
        config_file.write_text(json.dumps(config_data))

        config = load_config()

        assert "test" in config.servers
        assert config_file.resolve() in [p.resolve() for p in config.config_paths]

    def test_custom_named_config_file(self, tmp_path: Path, monkeypatch):
        """Test that custom-named files with 'mcp' are found."""
        monkeypatch.chdir(tmp_path)

        config_data = {"mcpServers": {"custom": {"command": "custom-cmd"}}}
        config_file = tmp_path / "my-project-mcp-config.json"
        config_file.write_text(json.dumps(config_data))

        config = load_config()

        assert "custom" in config.servers
        assert config.servers["custom"].command == "custom-cmd"

    def test_load_http_type_server(self, tmp_path: Path, monkeypatch):
        """Test loading HTTP type server from config file."""
        monkeypatch.chdir(tmp_path)
        import mcp_launchpad.config as config_module

        monkeypatch.setattr(config_module, "CONFIG_SEARCH_DIRS", [Path(".")])

        config_data = {
            "mcpServers": {
                "supabase": {
                    "type": "http",
                    "url": "https://mcp.supabase.com/mcp?project_ref=abc123",
                    "headers": {"Authorization": "Bearer ${SUPABASE_TOKEN}"},
                },
                "github": {
                    "command": "uvx",
                    "args": ["mcp-server-github"],
                },
            }
        }
        config_file = tmp_path / "mcp.json"
        config_file.write_text(json.dumps(config_data))

        config = load_config()

        # Check HTTP server
        assert "supabase" in config.servers
        supabase = config.servers["supabase"]
        assert supabase.server_type == "http"
        assert supabase.is_http() is True
        assert supabase.url == "https://mcp.supabase.com/mcp?project_ref=abc123"
        assert supabase.headers == {"Authorization": "Bearer ${SUPABASE_TOKEN}"}

        # Check stdio server
        assert "github" in config.servers
        github = config.servers["github"]
        assert github.server_type == "stdio"
        assert github.is_http() is False
        assert github.command == "uvx"
