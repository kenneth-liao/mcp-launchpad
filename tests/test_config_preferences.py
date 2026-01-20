"""Tests for config_preferences module."""

import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from mcp_launchpad.config_preferences import (
    ENV_CONFIG_FILES,
    ConfigPreferences,
    ConfigPreferencesManager,
    is_interactive,
)


class TestConfigPreferences:
    """Tests for ConfigPreferences dataclass."""

    def test_default_values(self):
        """Test default values for ConfigPreferences."""
        prefs = ConfigPreferences()
        assert prefs.version == 1
        assert prefs.active_configs == []
        assert prefs.discovered_configs == []
        assert prefs.first_run_completed is False

    def test_to_dict(self):
        """Test serialization to dictionary."""
        prefs = ConfigPreferences(
            version=1,
            active_configs=["/path/to/config.json"],
            discovered_configs=["/path/to/config.json", "/path/to/other.json"],
            first_run_completed=True,
        )
        d = prefs.to_dict()
        assert d["version"] == 1
        assert d["active_configs"] == ["/path/to/config.json"]
        assert d["discovered_configs"] == ["/path/to/config.json", "/path/to/other.json"]
        assert d["first_run_completed"] is True

    def test_from_dict(self):
        """Test deserialization from dictionary."""
        d = {
            "version": 1,
            "active_configs": ["/path/to/config.json"],
            "discovered_configs": ["/path/to/config.json"],
            "first_run_completed": True,
        }
        prefs = ConfigPreferences.from_dict(d)
        assert prefs.version == 1
        assert prefs.active_configs == ["/path/to/config.json"]
        assert prefs.first_run_completed is True

    def test_from_dict_with_missing_keys(self):
        """Test deserialization handles missing keys gracefully."""
        d = {}
        prefs = ConfigPreferences.from_dict(d)
        assert prefs.version == 1
        assert prefs.active_configs == []
        assert prefs.discovered_configs == []
        assert prefs.first_run_completed is False


class TestConfigPreferencesManager:
    """Tests for ConfigPreferencesManager class."""

    def test_load_creates_default_when_no_file(self, tmp_path: Path):
        """Test that load creates default preferences when file doesn't exist."""
        prefs_file = tmp_path / "config_preferences.json"
        manager = ConfigPreferencesManager(prefs_file)

        prefs = manager.load()

        assert prefs.version == 1
        assert prefs.active_configs == []
        assert prefs.first_run_completed is False

    def test_load_reads_existing_file(self, tmp_path: Path):
        """Test that load reads from existing file."""
        prefs_file = tmp_path / "config_preferences.json"
        data = {
            "version": 1,
            "active_configs": ["/path/to/mcp.json"],
            "discovered_configs": ["/path/to/mcp.json"],
            "first_run_completed": True,
        }
        prefs_file.write_text(json.dumps(data))

        manager = ConfigPreferencesManager(prefs_file)
        prefs = manager.load()

        assert prefs.active_configs == ["/path/to/mcp.json"]
        assert prefs.first_run_completed is True

    def test_load_handles_corrupt_file(self, tmp_path: Path):
        """Test that load handles corrupt JSON file gracefully."""
        prefs_file = tmp_path / "config_preferences.json"
        prefs_file.write_text("{ not valid json")

        manager = ConfigPreferencesManager(prefs_file)
        prefs = manager.load()

        # Should return default preferences
        assert prefs.version == 1
        assert prefs.active_configs == []

    def test_save_creates_file(self, tmp_path: Path):
        """Test that save creates the preferences file."""
        prefs_file = tmp_path / "subdir" / "config_preferences.json"
        manager = ConfigPreferencesManager(prefs_file)

        manager.load()
        manager._preferences.active_configs = ["/path/to/mcp.json"]
        manager.save()

        assert prefs_file.exists()
        data = json.loads(prefs_file.read_text())
        assert data["active_configs"] == ["/path/to/mcp.json"]

    def test_get_active_configs_returns_all_when_no_prefs(self, tmp_path: Path):
        """Test that all configs are returned when no preferences set."""
        prefs_file = tmp_path / "config_preferences.json"
        manager = ConfigPreferencesManager(prefs_file)

        discovered = [
            tmp_path / "mcp.json",
            tmp_path / "backup_mcp.json",
        ]
        for f in discovered:
            f.write_text("{}")

        result = manager.get_active_configs(discovered)

        # Should return all discovered
        assert len(result) == 2

    def test_get_active_configs_filters_by_whitelist(self, tmp_path: Path):
        """Test that configs are filtered by active whitelist."""
        prefs_file = tmp_path / "config_preferences.json"
        manager = ConfigPreferencesManager(prefs_file)

        config1 = tmp_path / "mcp.json"
        config2 = tmp_path / "backup_mcp.json"
        config1.write_text("{}")
        config2.write_text("{}")

        # Set only config1 as active
        manager.set_active_configs([config1])

        result = manager.get_active_configs([config1, config2])

        assert len(result) == 1
        assert result[0] == config1

    def test_get_active_configs_handles_deleted_configs(self, tmp_path: Path):
        """Test fallback when all active configs have been deleted."""
        prefs_file = tmp_path / "config_preferences.json"
        manager = ConfigPreferencesManager(prefs_file)

        existing = tmp_path / "mcp.json"
        existing.write_text("{}")

        # Set a non-existent config as active
        manager.set_active_configs([tmp_path / "deleted.json"])

        # Only 'existing' is discovered
        result = manager.get_active_configs([existing])

        # Should fall back to all discovered
        assert len(result) == 1
        assert result[0] == existing

    def test_activate_adds_config(self, tmp_path: Path):
        """Test that activate adds a config to active list."""
        prefs_file = tmp_path / "config_preferences.json"
        manager = ConfigPreferencesManager(prefs_file)

        config = tmp_path / "mcp.json"
        config.write_text("{}")

        changed = manager.activate(config)

        assert changed is True
        prefs = manager.load()
        assert str(config) in prefs.active_configs

    def test_activate_returns_false_if_already_active(self, tmp_path: Path):
        """Test that activate returns False if config already active."""
        prefs_file = tmp_path / "config_preferences.json"
        manager = ConfigPreferencesManager(prefs_file)

        config = tmp_path / "mcp.json"
        config.write_text("{}")

        manager.activate(config)
        changed = manager.activate(config)

        assert changed is False

    def test_deactivate_removes_config(self, tmp_path: Path):
        """Test that deactivate removes a config from active list."""
        prefs_file = tmp_path / "config_preferences.json"
        manager = ConfigPreferencesManager(prefs_file)

        config = tmp_path / "mcp.json"
        config.write_text("{}")

        manager.activate(config)
        changed = manager.deactivate(config)

        assert changed is True
        prefs = manager.load()
        assert str(config) not in prefs.active_configs

    def test_deactivate_returns_false_if_not_active(self, tmp_path: Path):
        """Test that deactivate returns False if config not active."""
        prefs_file = tmp_path / "config_preferences.json"
        manager = ConfigPreferencesManager(prefs_file)

        config = tmp_path / "mcp.json"
        changed = manager.deactivate(config)

        assert changed is False

    def test_set_active_configs(self, tmp_path: Path):
        """Test setting multiple active configs at once."""
        prefs_file = tmp_path / "config_preferences.json"
        manager = ConfigPreferencesManager(prefs_file)

        configs = [
            tmp_path / "mcp.json",
            tmp_path / "other_mcp.json",
        ]
        for c in configs:
            c.write_text("{}")

        manager.set_active_configs(configs)

        prefs = manager.load()
        assert len(prefs.active_configs) == 2

    def test_mark_first_run_completed(self, tmp_path: Path):
        """Test marking first run as completed."""
        prefs_file = tmp_path / "config_preferences.json"
        manager = ConfigPreferencesManager(prefs_file)

        manager.mark_first_run_completed()

        prefs = manager.load()
        assert prefs.first_run_completed is True

    def test_reset_clears_preferences(self, tmp_path: Path):
        """Test that reset clears all preferences."""
        prefs_file = tmp_path / "config_preferences.json"
        manager = ConfigPreferencesManager(prefs_file)

        # Set some preferences
        manager.set_active_configs([tmp_path / "mcp.json"])
        manager.mark_first_run_completed()

        # Reset
        manager.reset()

        prefs = manager.load()
        assert prefs.active_configs == []
        assert prefs.first_run_completed is False

    def test_needs_first_run_prompt_true_conditions(self, tmp_path: Path, monkeypatch):
        """Test that needs_first_run_prompt returns True under right conditions."""
        prefs_file = tmp_path / "config_preferences.json"
        manager = ConfigPreferencesManager(prefs_file)

        discovered = [
            tmp_path / "mcp.json",
            tmp_path / "backup_mcp.json",
        ]

        # Mock is_interactive to return True
        monkeypatch.setattr("mcp_launchpad.config_preferences.is_interactive", lambda: True)

        # Ensure env var is not set
        monkeypatch.delenv(ENV_CONFIG_FILES, raising=False)

        result = manager.needs_first_run_prompt(discovered)

        assert result is True

    def test_needs_first_run_prompt_false_single_config(self, tmp_path: Path, monkeypatch):
        """Test that needs_first_run_prompt returns False for single config."""
        prefs_file = tmp_path / "config_preferences.json"
        manager = ConfigPreferencesManager(prefs_file)

        discovered = [tmp_path / "mcp.json"]

        monkeypatch.setattr("mcp_launchpad.config_preferences.is_interactive", lambda: True)

        result = manager.needs_first_run_prompt(discovered)

        assert result is False

    def test_needs_first_run_prompt_false_after_completed(self, tmp_path: Path, monkeypatch):
        """Test that needs_first_run_prompt returns False after first run completed."""
        prefs_file = tmp_path / "config_preferences.json"
        manager = ConfigPreferencesManager(prefs_file)

        discovered = [
            tmp_path / "mcp.json",
            tmp_path / "backup_mcp.json",
        ]

        monkeypatch.setattr("mcp_launchpad.config_preferences.is_interactive", lambda: True)
        manager.mark_first_run_completed()

        result = manager.needs_first_run_prompt(discovered)

        assert result is False

    def test_needs_first_run_prompt_false_non_interactive(self, tmp_path: Path, monkeypatch):
        """Test that needs_first_run_prompt returns False in non-interactive mode."""
        prefs_file = tmp_path / "config_preferences.json"
        manager = ConfigPreferencesManager(prefs_file)

        discovered = [
            tmp_path / "mcp.json",
            tmp_path / "backup_mcp.json",
        ]

        monkeypatch.setattr("mcp_launchpad.config_preferences.is_interactive", lambda: False)

        result = manager.needs_first_run_prompt(discovered)

        assert result is False

    def test_needs_first_run_prompt_false_with_env_var(self, tmp_path: Path, monkeypatch):
        """Test that needs_first_run_prompt returns False when env var set."""
        prefs_file = tmp_path / "config_preferences.json"
        manager = ConfigPreferencesManager(prefs_file)

        discovered = [
            tmp_path / "mcp.json",
            tmp_path / "backup_mcp.json",
        ]

        monkeypatch.setattr("mcp_launchpad.config_preferences.is_interactive", lambda: True)
        monkeypatch.setenv(ENV_CONFIG_FILES, "/path/to/override.json")

        result = manager.needs_first_run_prompt(discovered)

        assert result is False

    def test_get_env_override_returns_none_when_not_set(self, tmp_path: Path, monkeypatch):
        """Test that get_env_override returns None when env var not set."""
        prefs_file = tmp_path / "config_preferences.json"
        manager = ConfigPreferencesManager(prefs_file)

        monkeypatch.delenv(ENV_CONFIG_FILES, raising=False)

        result = manager.get_env_override()

        assert result is None

    def test_get_env_override_parses_single_path(self, tmp_path: Path, monkeypatch):
        """Test that get_env_override parses single path."""
        prefs_file = tmp_path / "config_preferences.json"
        manager = ConfigPreferencesManager(prefs_file)

        config = tmp_path / "mcp.json"
        config.write_text("{}")

        monkeypatch.setenv(ENV_CONFIG_FILES, str(config))

        result = manager.get_env_override()

        assert result is not None
        assert len(result) == 1
        assert result[0] == config.resolve()

    def test_get_env_override_parses_multiple_paths(self, tmp_path: Path, monkeypatch):
        """Test that get_env_override parses comma-separated paths."""
        prefs_file = tmp_path / "config_preferences.json"
        manager = ConfigPreferencesManager(prefs_file)

        config1 = tmp_path / "mcp.json"
        config2 = tmp_path / "backup_mcp.json"
        config1.write_text("{}")
        config2.write_text("{}")

        monkeypatch.setenv(ENV_CONFIG_FILES, f"{config1},{config2}")

        result = manager.get_env_override()

        assert result is not None
        assert len(result) == 2

    def test_get_env_override_skips_nonexistent_paths(self, tmp_path: Path, monkeypatch):
        """Test that get_env_override skips paths that don't exist."""
        prefs_file = tmp_path / "config_preferences.json"
        manager = ConfigPreferencesManager(prefs_file)

        config = tmp_path / "mcp.json"
        config.write_text("{}")
        nonexistent = tmp_path / "nonexistent.json"

        monkeypatch.setenv(ENV_CONFIG_FILES, f"{config},{nonexistent}")

        result = manager.get_env_override()

        assert result is not None
        assert len(result) == 1
        assert result[0] == config.resolve()

    def test_get_env_override_returns_none_for_empty_value(self, tmp_path: Path, monkeypatch):
        """Test that get_env_override returns None for empty env var."""
        prefs_file = tmp_path / "config_preferences.json"
        manager = ConfigPreferencesManager(prefs_file)

        monkeypatch.setenv(ENV_CONFIG_FILES, "")

        result = manager.get_env_override()

        assert result is None

    def test_update_discovered(self, tmp_path: Path):
        """Test updating the discovered configs list."""
        prefs_file = tmp_path / "config_preferences.json"
        manager = ConfigPreferencesManager(prefs_file)

        discovered = [
            tmp_path / "mcp.json",
            tmp_path / "backup_mcp.json",
        ]

        manager.update_discovered(discovered)

        prefs = manager.load()
        assert len(prefs.discovered_configs) == 2


class TestIsInteractive:
    """Tests for is_interactive function."""

    def test_returns_true_when_tty(self, monkeypatch):
        """Test that is_interactive returns True when both stdin and stdout are TTYs."""
        monkeypatch.setattr("sys.stdin.isatty", lambda: True)
        monkeypatch.setattr("sys.stdout.isatty", lambda: True)

        assert is_interactive() is True

    def test_returns_false_when_stdin_not_tty(self, monkeypatch):
        """Test that is_interactive returns False when stdin is not a TTY."""
        monkeypatch.setattr("sys.stdin.isatty", lambda: False)
        monkeypatch.setattr("sys.stdout.isatty", lambda: True)

        assert is_interactive() is False

    def test_returns_false_when_stdout_not_tty(self, monkeypatch):
        """Test that is_interactive returns False when stdout is not a TTY."""
        monkeypatch.setattr("sys.stdin.isatty", lambda: True)
        monkeypatch.setattr("sys.stdout.isatty", lambda: False)

        assert is_interactive() is False
