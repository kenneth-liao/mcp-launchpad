"""Config file preferences management for multi-config support.

This module handles the whitelist of active config files when multiple
MCP config files are discovered. It persists user preferences and handles
first-run prompts for config selection.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Preferences file location (same directory as other state)
PREFERENCES_DIR = Path.home() / ".cache" / "mcp-launchpad"
PREFERENCES_FILE = PREFERENCES_DIR / "config_preferences.json"

# Environment variable for explicit config file override
ENV_CONFIG_FILES = "MCPL_CONFIG_FILES"


@dataclass
class ConfigPreferences:
    """Preferences for which config files to use.

    Attributes:
        version: Schema version for future migrations
        active_configs: List of config file paths that are active (whitelist)
        discovered_configs: All config files that have been discovered
        first_run_completed: Whether the first-run prompt has been shown
    """

    version: int = 1
    active_configs: list[str] = field(default_factory=list)
    discovered_configs: list[str] = field(default_factory=list)
    first_run_completed: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "version": self.version,
            "active_configs": self.active_configs,
            "discovered_configs": self.discovered_configs,
            "first_run_completed": self.first_run_completed,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ConfigPreferences:
        """Create from dictionary."""
        return cls(
            version=data.get("version", 1),
            active_configs=data.get("active_configs", []),
            discovered_configs=data.get("discovered_configs", []),
            first_run_completed=data.get("first_run_completed", False),
        )


class ConfigPreferencesManager:
    """Manages config file preferences with persistence."""

    def __init__(self, preferences_file: Path | None = None):
        self.preferences_file = preferences_file or PREFERENCES_FILE
        self._preferences: ConfigPreferences | None = None

    def _ensure_dir(self) -> None:
        """Ensure preferences directory exists."""
        self.preferences_file.parent.mkdir(parents=True, exist_ok=True)

    def load(self) -> ConfigPreferences:
        """Load preferences from file, creating default if not exists."""
        if self._preferences is not None:
            return self._preferences

        if not self.preferences_file.exists():
            self._preferences = ConfigPreferences()
            return self._preferences

        try:
            with open(self.preferences_file) as f:
                data = json.load(f)
                self._preferences = ConfigPreferences.from_dict(data)
        except (json.JSONDecodeError, KeyError, OSError):
            self._preferences = ConfigPreferences()

        return self._preferences

    def save(self) -> None:
        """Save current preferences to file."""
        if self._preferences is None:
            return

        self._ensure_dir()
        with open(self.preferences_file, "w") as f:
            json.dump(self._preferences.to_dict(), f, indent=2)

    def get_active_configs(self, discovered: list[Path]) -> list[Path]:
        """Get list of active config files from discovered configs.

        This applies the whitelist filter to the discovered configs.
        If no preferences exist or all active configs have been deleted,
        returns all discovered configs (backwards compatible behavior).

        Args:
            discovered: List of discovered config file paths

        Returns:
            List of active config file paths to use
        """
        prefs = self.load()

        # If no active configs saved, return all discovered (first-run or reset)
        if not prefs.active_configs:
            return discovered

        # Filter discovered configs by active whitelist
        active_set = set(prefs.active_configs)

        # Only return configs that are both active AND still exist in discovered
        result = [p for p in discovered if str(p) in active_set]

        # If all active configs have been deleted, fall back to all discovered
        if not result and discovered:
            return discovered

        return result

    def set_active_configs(self, configs: list[Path]) -> None:
        """Set which config files should be active.

        Args:
            configs: List of config file paths to activate
        """
        prefs = self.load()
        prefs.active_configs = [str(p) for p in configs]
        self.save()

    def activate(self, config: Path) -> bool:
        """Activate a single config file.

        Returns True if the config was added, False if already active.
        """
        prefs = self.load()
        config_str = str(config)

        if config_str in prefs.active_configs:
            return False

        prefs.active_configs.append(config_str)
        self.save()
        return True

    def deactivate(self, config: Path) -> bool:
        """Deactivate a single config file.

        Returns True if the config was removed, False if not present.
        """
        prefs = self.load()
        config_str = str(config)

        if config_str not in prefs.active_configs:
            return False

        prefs.active_configs.remove(config_str)
        self.save()
        return True

    def update_discovered(self, discovered: list[Path]) -> None:
        """Update the list of discovered config files.

        Args:
            discovered: Current list of discovered config files
        """
        prefs = self.load()
        prefs.discovered_configs = [str(p) for p in discovered]
        self.save()

    def mark_first_run_completed(self) -> None:
        """Mark that the first-run prompt has been shown."""
        prefs = self.load()
        prefs.first_run_completed = True
        self.save()

    def needs_first_run_prompt(self, discovered: list[Path]) -> bool:
        """Check if we should show the first-run config selection prompt.

        Returns True only when:
        - Multiple config files discovered
        - First run not yet completed
        - Running in interactive TTY
        - No explicit config override (--config flag or env var)
        """
        prefs = self.load()

        # Already completed first run
        if prefs.first_run_completed:
            return False

        # Only one or zero configs found - no need to prompt
        if len(discovered) <= 1:
            return False

        # Not interactive - skip prompt
        if not is_interactive():
            return False

        # Environment variable set - skip prompt
        if os.environ.get(ENV_CONFIG_FILES):
            return False

        return True

    def reset(self) -> None:
        """Reset all preferences to default state."""
        self._preferences = ConfigPreferences()
        self.save()

    def get_env_override(self) -> list[Path] | None:
        """Get config files from environment variable if set.

        Returns None if env var not set, otherwise list of paths.
        """
        env_value = os.environ.get(ENV_CONFIG_FILES)
        if not env_value:
            return None

        # Parse comma-separated paths
        paths = []
        for path_str in env_value.split(","):
            path_str = path_str.strip()
            if path_str:
                path = Path(path_str).expanduser().resolve()
                if path.exists():
                    paths.append(path)

        return paths if paths else None


def is_interactive() -> bool:
    """Check if we're running in an interactive terminal."""
    return sys.stdin.isatty() and sys.stdout.isatty()


def get_config_preferences_manager() -> ConfigPreferencesManager:
    """Get the global config preferences manager instance."""
    return ConfigPreferencesManager()
