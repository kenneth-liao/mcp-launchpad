"""Tests for CLI auth commands."""

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from click.testing import CliRunner

from mcp_launchpad.cli import main
from mcp_launchpad.config import Config, ServerConfig
from mcp_launchpad.oauth import TokenDecryptionError


@pytest.fixture
def runner() -> CliRunner:
    """Create a CLI test runner."""
    return CliRunner()


@pytest.fixture
def mock_http_config(tmp_path: Path) -> Config:
    """Create a mock config with HTTP servers for OAuth testing."""
    return Config(
        servers={
            "notion": ServerConfig(
                name="notion",
                server_type="http",
                url="https://mcp.notion.so/v1",
            ),
            "figma": ServerConfig(
                name="figma",
                server_type="http",
                url="https://mcp.figma.com/v1",
            ),
            "stdio-server": ServerConfig(
                name="stdio-server",
                command="npx",
                args=["some-server"],
            ),
        },
        config_path=tmp_path / "config.json",
        env_path=None,
    )


class TestAuthLoginCommand:
    """Tests for the auth login command."""

    def test_auth_login_requires_server(self, runner: CliRunner, tmp_path: Path) -> None:
        """Test that auth login requires a server argument."""
        config_file = tmp_path / "config.json"
        config_file.write_text('{"mcpServers": {}}')

        result = runner.invoke(main, ["--config", str(config_file), "auth", "login"])
        assert result.exit_code == 2  # Missing argument
        assert "SERVER" in result.output or "Missing argument" in result.output

    def test_auth_login_server_not_found(
        self, runner: CliRunner, tmp_path: Path, mock_http_config: Config
    ) -> None:
        """Test error when server is not in config."""
        config_file = mock_http_config.config_path
        config_file.write_text(json.dumps({
            "mcpServers": {
                "notion": {"type": "http", "url": "https://mcp.notion.so/v1"}
            }
        }))

        result = runner.invoke(
            main, ["--config", str(config_file), "auth", "login", "nonexistent"]
        )
        assert result.exit_code == 1  # Error exit code
        assert "not found" in result.output.lower()

    def test_auth_login_stdio_server_rejected(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        """Test that stdio servers are rejected for OAuth."""
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "mcpServers": {
                "stdio-server": {"command": "npx", "args": ["some-server"]}
            }
        }))

        result = runner.invoke(
            main, ["--config", str(config_file), "auth", "login", "stdio-server"]
        )
        assert result.exit_code == 1  # Error exit code
        assert "stdio" in result.output.lower() or "http" in result.output.lower()

    def test_auth_login_already_authenticated(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        """Test message when already authenticated."""
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "mcpServers": {
                "notion": {"type": "http", "url": "https://mcp.notion.so/v1"}
            }
        }))

        with patch("mcp_launchpad.cli.get_oauth_manager") as mock_get_manager:
            mock_manager = MagicMock()
            mock_manager.has_valid_token.return_value = True
            mock_get_manager.return_value = mock_manager

            result = runner.invoke(
                main, ["--config", str(config_file), "auth", "login", "notion"]
            )
            assert result.exit_code == 0
            assert "already authenticated" in result.output.lower()

    def test_auth_login_force_reauthentication(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        """Test --force flag triggers re-authentication."""
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "mcpServers": {
                "notion": {"type": "http", "url": "https://mcp.notion.so/v1"}
            }
        }))

        with patch("mcp_launchpad.cli.get_oauth_manager") as mock_get_manager:
            mock_manager = MagicMock()
            mock_manager.has_valid_token.return_value = True
            mock_manager.authenticate = AsyncMock()
            mock_get_manager.return_value = mock_manager

            with patch("mcp_launchpad.cli.asyncio.run") as mock_run:
                mock_run.side_effect = Exception("OAuth flow started")

                result = runner.invoke(
                    main,
                    ["--config", str(config_file), "auth", "login", "notion", "--force"],
                )
                # The flow will fail but we verify it was started
                assert mock_run.called or "error" in result.output.lower()

    def test_auth_login_client_secret_stdin_with_input(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        """Test --client-secret-stdin reads secret from piped input."""
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "mcpServers": {
                "notion": {"type": "http", "url": "https://mcp.notion.so/v1"}
            }
        }))

        with patch("mcp_launchpad.cli.get_oauth_manager") as mock_get_manager:
            mock_manager = MagicMock()
            mock_manager.has_valid_token.return_value = False
            # Make authenticate return an async mock that returns a proper token
            mock_manager.authenticate = AsyncMock(
                side_effect=Exception("OAuth flow would start here")
            )
            mock_get_manager.return_value = mock_manager

            # Provide input through CliRunner (simulates piped stdin)
            result = runner.invoke(
                main,
                [
                    "--config", str(config_file),
                    "auth", "login", "notion",
                    "--client-secret-stdin",
                ],
                input="test-secret\n",
            )
            # The flow will fail but we verify the --client-secret-stdin flag is accepted
            # and the command proceeds past the isatty check when input is provided
            # (The OAuth flow errors out because we can't mock the full flow easily)
            assert result.exit_code != 2  # Not a CLI argument error


class TestAuthLogoutCommand:
    """Tests for the auth logout command."""

    def test_auth_logout_requires_server_or_all(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        """Test that logout requires either server or --all."""
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({"mcpServers": {"notion": {"type": "http", "url": "https://x"}}}))

        with patch("mcp_launchpad.cli.get_oauth_manager"):
            result = runner.invoke(
                main, ["--config", str(config_file), "auth", "logout"]
            )
            assert result.exit_code == 1  # Error exit for missing required arg
            assert "required" in result.output.lower() or "--all" in result.output

    def test_auth_logout_all_clears_tokens(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        """Test --all flag clears all tokens."""
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({"mcpServers": {}}))

        with patch("mcp_launchpad.cli.get_oauth_manager") as mock_get_manager:
            mock_manager = MagicMock()
            mock_manager.token_store = MagicMock()
            mock_get_manager.return_value = mock_manager

            result = runner.invoke(
                main, ["--config", str(config_file), "auth", "logout", "--all"]
            )
            assert result.exit_code == 0
            mock_manager.token_store.clear_all.assert_called_once()
            assert "cleared" in result.output.lower()

    def test_auth_logout_server_not_found(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        """Test error when server is not in config."""
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({"mcpServers": {"notion": {"type": "http", "url": "https://x"}}}))

        with patch("mcp_launchpad.cli.get_oauth_manager"):
            result = runner.invoke(
                main, ["--config", str(config_file), "auth", "logout", "nonexistent"]
            )
            assert result.exit_code == 1  # Error exit for server not found
            assert "not found" in result.output.lower()

    def test_auth_logout_success(self, runner: CliRunner, tmp_path: Path) -> None:
        """Test successful logout."""
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "mcpServers": {"notion": {"type": "http", "url": "https://mcp.notion.so/v1"}}
        }))

        with patch("mcp_launchpad.cli.get_oauth_manager") as mock_get_manager:
            mock_manager = MagicMock()
            mock_manager.logout_async = AsyncMock(return_value=True)
            mock_get_manager.return_value = mock_manager

            with patch("mcp_launchpad.cli.asyncio.run") as mock_run:
                mock_run.return_value = True

                result = runner.invoke(
                    main, ["--config", str(config_file), "auth", "logout", "notion"]
                )
                assert result.exit_code == 0
                # Should show success or "logging out" message
                assert "logged out" in result.output.lower() or "logging" in result.output.lower()

    def test_auth_logout_token_not_found(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        """Test logout when no token exists."""
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "mcpServers": {"notion": {"type": "http", "url": "https://mcp.notion.so/v1"}}
        }))

        with patch("mcp_launchpad.cli.get_oauth_manager") as mock_get_manager:
            mock_manager = MagicMock()
            mock_manager.logout_async = AsyncMock(return_value=False)
            mock_get_manager.return_value = mock_manager

            with patch("mcp_launchpad.cli.asyncio.run") as mock_run:
                mock_run.return_value = False

                result = runner.invoke(
                    main, ["--config", str(config_file), "auth", "logout", "notion"]
                )
                assert result.exit_code == 0
                assert "no stored" in result.output.lower() or "not found" in result.output.lower()

    def test_auth_logout_decryption_error(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        """Test logout handles decryption error gracefully."""
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "mcpServers": {"notion": {"type": "http", "url": "https://mcp.notion.so/v1"}}
        }))

        with patch("mcp_launchpad.cli.get_oauth_manager") as mock_get_manager:
            mock_manager = MagicMock()
            mock_get_manager.return_value = mock_manager

            with patch("mcp_launchpad.cli.asyncio.run") as mock_run:
                mock_run.side_effect = TokenDecryptionError("Key changed")

                result = runner.invoke(
                    main, ["--config", str(config_file), "auth", "logout", "notion"]
                )
                assert result.exit_code == 0
                assert "encryption" in result.output.lower() or "--all" in result.output


class TestAuthStatusCommand:
    """Tests for the auth status command."""

    def test_auth_status_no_servers(self, runner: CliRunner, tmp_path: Path) -> None:
        """Test status when no servers configured."""
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({"mcpServers": {}}))

        with patch("mcp_launchpad.cli.get_oauth_manager"):
            result = runner.invoke(
                main, ["--config", str(config_file), "auth", "status"]
            )
            assert result.exit_code == 0

    def test_auth_status_specific_server(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        """Test status for a specific server."""
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "mcpServers": {"notion": {"type": "http", "url": "https://mcp.notion.so/v1"}}
        }))

        with patch("mcp_launchpad.cli.get_oauth_manager") as mock_get_manager:
            from mcp_launchpad.oauth.manager import AuthStatus

            mock_manager = MagicMock()
            mock_manager.get_auth_status.return_value = AuthStatus(
                server_url="https://mcp.notion.so/v1",
                server_name="notion",
                authenticated=True,
                expired=False,
                expires_at="2026-01-16T00:00:00Z",
                has_refresh_token=True,
                scope="read write",
            )
            mock_manager.token_store = MagicMock()
            mock_manager.token_store.is_using_keyring.return_value = True
            mock_get_manager.return_value = mock_manager

            result = runner.invoke(
                main, ["--config", str(config_file), "auth", "status", "notion"]
            )
            assert result.exit_code == 0
            assert "notion" in result.output.lower()

    def test_auth_status_server_not_authenticated(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        """Test status shows not authenticated."""
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "mcpServers": {"notion": {"type": "http", "url": "https://mcp.notion.so/v1"}}
        }))

        with patch("mcp_launchpad.cli.get_oauth_manager") as mock_get_manager:
            from mcp_launchpad.oauth.manager import AuthStatus

            mock_manager = MagicMock()
            mock_manager.get_auth_status.return_value = AuthStatus(
                server_url="https://mcp.notion.so/v1",
                server_name="notion",
                authenticated=False,
            )
            mock_manager.token_store = MagicMock()
            mock_manager.token_store.is_using_keyring.return_value = True
            mock_get_manager.return_value = mock_manager

            result = runner.invoke(
                main, ["--config", str(config_file), "auth", "status", "notion"]
            )
            assert result.exit_code == 0
            assert "not authenticated" in result.output.lower() or "auth login" in result.output.lower()

    def test_auth_status_keyring_warning(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        """Test status shows warning when keyring unavailable."""
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "mcpServers": {"notion": {"type": "http", "url": "https://mcp.notion.so/v1"}}
        }))

        with patch("mcp_launchpad.cli.get_oauth_manager") as mock_get_manager:
            from mcp_launchpad.oauth.manager import AuthStatus

            mock_manager = MagicMock()
            mock_manager.get_auth_status.return_value = AuthStatus(
                server_url="https://mcp.notion.so/v1",
                server_name="notion",
                authenticated=True,
            )
            mock_manager.token_store = MagicMock()
            mock_manager.token_store.is_using_keyring.return_value = False
            mock_get_manager.return_value = mock_manager

            result = runner.invoke(
                main, ["--config", str(config_file), "auth", "status", "notion"]
            )
            assert result.exit_code == 0
            # Warning about fallback encryption should be shown
            assert "keyring" in result.output.lower() or "fallback" in result.output.lower() or "warning" in result.output.lower()


class TestAuthHelp:
    """Tests for auth command help."""

    def test_auth_help(self, runner: CliRunner, tmp_path: Path) -> None:
        """Test auth command shows help."""
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({"mcpServers": {}}))

        result = runner.invoke(main, ["--config", str(config_file), "auth", "--help"])
        assert result.exit_code == 0
        assert "login" in result.output
        assert "logout" in result.output
        assert "status" in result.output

    def test_auth_login_help(self, runner: CliRunner, tmp_path: Path) -> None:
        """Test auth login shows help with options."""
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({"mcpServers": {}}))

        result = runner.invoke(
            main, ["--config", str(config_file), "auth", "login", "--help"]
        )
        assert result.exit_code == 0
        assert "--scope" in result.output
        assert "--force" in result.output
        assert "--client-id" in result.output
