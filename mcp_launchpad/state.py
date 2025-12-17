"""Server state management for mcpl-controlled enable/disable."""

import json
from pathlib import Path
from typing import Any

from .config import Config

# State file location (same directory as cache)
STATE_DIR = Path.home() / ".cache" / "mcp-launchpad"
STATE_FILE = STATE_DIR / "server_state.json"


class ServerState:
    """Manages the enabled/disabled state of MCP servers.

    This state is managed by mcpl independently of the config file.
    By default, all servers in the config are enabled.
    """

    def __init__(self, config: Config):
        self.config = config
        self.state_file = STATE_FILE
        self._disabled_servers: set[str] = set()
        self._load()

    def _ensure_state_dir(self) -> None:
        """Ensure state directory exists."""
        STATE_DIR.mkdir(parents=True, exist_ok=True)

    def _load(self) -> None:
        """Load state from file."""
        if not self.state_file.exists():
            self._disabled_servers = set()
            return

        try:
            with open(self.state_file) as f:
                data = json.load(f)
                # Only keep disabled servers that still exist in config
                self._disabled_servers = {
                    s for s in data.get("disabled_servers", [])
                    if s in self.config.servers
                }
        except (json.JSONDecodeError, KeyError):
            self._disabled_servers = set()

    def _save(self) -> None:
        """Save state to file."""
        self._ensure_state_dir()
        with open(self.state_file, "w") as f:
            json.dump({"disabled_servers": sorted(self._disabled_servers)}, f, indent=2)

    def is_enabled(self, server_name: str) -> bool:
        """Check if a server is enabled."""
        return server_name not in self._disabled_servers

    def is_disabled(self, server_name: str) -> bool:
        """Check if a server is disabled."""
        return server_name in self._disabled_servers

    def enable(self, server_name: str) -> bool:
        """Enable a server. Returns True if state changed."""
        if server_name not in self.config.servers:
            raise ValueError(f"Server '{server_name}' not found in config")

        if server_name in self._disabled_servers:
            self._disabled_servers.remove(server_name)
            self._save()
            return True
        return False

    def disable(self, server_name: str) -> bool:
        """Disable a server. Returns True if state changed."""
        if server_name not in self.config.servers:
            raise ValueError(f"Server '{server_name}' not found in config")

        if server_name not in self._disabled_servers:
            self._disabled_servers.add(server_name)
            self._save()
            return True
        return False

    def get_enabled_servers(self) -> dict[str, Any]:
        """Get dict of enabled server names to their configs."""
        return {
            name: cfg
            for name, cfg in self.config.servers.items()
            if name not in self._disabled_servers
        }

    def get_disabled_servers(self) -> list[str]:
        """Get list of disabled server names."""
        return sorted(self._disabled_servers)

    def to_dict(self) -> dict[str, Any]:
        """Get state as a dictionary."""
        return {
            "disabled_servers": sorted(self._disabled_servers),
            "enabled_count": len(self.config.servers) - len(self._disabled_servers),
            "disabled_count": len(self._disabled_servers),
        }
