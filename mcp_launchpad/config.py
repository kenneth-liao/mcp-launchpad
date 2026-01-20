"""Config discovery and loading for MCP Launchpad."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from dotenv import load_dotenv

if TYPE_CHECKING:
    from .config_preferences import ConfigPreferencesManager


def _resolve_env_vars(value: str) -> str:
    """Resolve ${VAR} patterns in a string from environment variables.

    Handles:
    - Full replacement: "${VAR}" -> "value"
    - Partial replacement: "prefix_${VAR}_suffix" -> "prefix_value_suffix"
    - Multiple vars: "${VAR1}_${VAR2}" -> "value1_value2"
    - Missing vars resolve to empty string
    """
    if "${" not in value:
        return value

    result = value
    for match in re.finditer(r"\$\{([^}]+)\}", value):
        env_var = match.group(1)
        env_value = os.environ.get(env_var, "")
        result = result.replace(match.group(0), env_value)
    return result


@dataclass
class ServerConfig:
    """Configuration for a single MCP server.

    Supports three transport types:
    - stdio: Local process-based servers (command + args)
    - http: Remote HTTP-based servers (url + optional headers)
    - sse: Remote SSE-based servers(url + args?)
    """

    name: str
    # Stdio transport fields
    command: str = ""
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    # HTTP transport fields
    server_type: str = "stdio"  # "stdio" or "http"
    url: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    # OAuth fields (for HTTP servers)
    oauth_client_id: str | None = None
    oauth_client_secret: str | None = None
    oauth_scopes: list[str] = field(default_factory=list)
    # Static API key (alternative to OAuth for agent-friendly auth)
    api_key: str | None = None

    def is_http(self) -> bool:
        """Check if this is an HTTP-based server."""
        return self.server_type in ("http", "sse")

    def is_sse(self) -> bool:
        """Check if this is a legacy SSE server (not streamable HTTP)."""
        return self.server_type == "sse"

    def get_resolved_env(self) -> dict[str, str]:
        """Resolve environment variables, expanding ${VAR} references."""
        return {key: _resolve_env_vars(value) for key, value in self.env.items()}

    def get_resolved_args(self) -> list[str]:
        """Resolve environment variables in args, expanding ${VAR} references."""
        return [_resolve_env_vars(arg) for arg in self.args]

    def get_resolved_url(self) -> str:
        """Resolve environment variables in URL."""
        return _resolve_env_vars(self.url)

    def get_resolved_headers(self) -> dict[str, str]:
        """Resolve environment variables in headers."""
        return {key: _resolve_env_vars(value) for key, value in self.headers.items()}

    def get_resolved_oauth_client_id(self) -> str | None:
        """Resolve environment variables in OAuth client ID."""
        if self.oauth_client_id is None:
            return None
        return _resolve_env_vars(self.oauth_client_id)

    def get_resolved_oauth_client_secret(self) -> str | None:
        """Resolve environment variables in OAuth client secret."""
        if self.oauth_client_secret is None:
            return None
        return _resolve_env_vars(self.oauth_client_secret)

    def get_resolved_api_key(self) -> str | None:
        """Resolve environment variables in API key."""
        if self.api_key is None:
            return None
        return _resolve_env_vars(self.api_key)


@dataclass
class Config:
    """Complete MCP Launchpad configuration."""

    servers: dict[str, ServerConfig] = field(default_factory=dict)
    config_path: Path | None = None  # Primary config (first found)
    config_paths: list[Path] = field(default_factory=list)  # All config files loaded
    env_path: Path | None = None  # Primary env file (for display)
    env_paths: list[Path] = field(default_factory=list)  # All env files loaded


# Directories to search for config files, in priority order
CONFIG_SEARCH_DIRS = [
    Path("."),  # Current directory
    Path(".claude"),  # Project-level .claude directory
    Path.home() / ".claude",  # User-level .claude directory (macOS/Windows)
    Path.home() / ".config" / "claude",  # XDG standard (Linux)
]

# File to exclude (Claude Code's convention - avoids collision)
EXCLUDED_CONFIG_FILES = {".mcp.json"}



def discover_all_config_files() -> list[Path]:
    """Discover all MCP config files without applying preferences.

    This is the raw discovery function that finds all potential config files.
    Use find_config_files() to get filtered results based on user preferences.

    Returns:
        List of all found config file paths, ordered by search directory priority.
    """
    found_files: list[Path] = []
    seen_resolved: set[Path] = set()  # Track resolved paths to avoid duplicates

    for search_dir in CONFIG_SEARCH_DIRS:
        if not search_dir.exists() or not search_dir.is_dir():
            continue

        for json_file in search_dir.glob("*.json"):
            # Check if filename contains "mcp" (case-insensitive)
            if "mcp" not in json_file.name.lower():
                continue

            # Exclude Claude Code's .mcp.json
            if json_file.name in EXCLUDED_CONFIG_FILES:
                continue

            # Avoid duplicates (same file found via different paths)
            resolved = json_file.resolve()
            if resolved in seen_resolved:
                continue
            seen_resolved.add(resolved)

            found_files.append(resolved)

    return found_files


def find_config_files(
    explicit_path: Path | None = None,
    respect_preferences: bool = True,
    preferences_manager: ConfigPreferencesManager | None = None,
) -> list[Path]:
    """Find MCP config files with 'mcp' in the filename.

    Searches for JSON files containing 'mcp' in the filename (case-insensitive),
    excluding '.mcp.json' (Claude Code's convention) to avoid collision.

    When multiple config files exist, this function respects user preferences
    for which configs to use (unless respect_preferences=False).

    Args:
        explicit_path: If provided, returns only this path if it exists.
        respect_preferences: If True, filter by user's active config preferences.
        preferences_manager: Optional manager instance (for testing).

    Returns:
        List of found config file paths, ordered by search directory priority.
    """
    # Explicit path always takes precedence
    if explicit_path:
        if explicit_path.exists():
            return [explicit_path.resolve()]
        return []

    # Discover all potential config files
    discovered = discover_all_config_files()

    if not respect_preferences:
        return discovered

    # Check for environment variable override first
    from .config_preferences import get_config_preferences_manager

    manager = preferences_manager or get_config_preferences_manager()

    env_override = manager.get_env_override()
    if env_override is not None:
        return env_override

    # Apply user preferences to filter discovered configs
    return manager.get_active_configs(discovered)


def find_config_file(explicit_path: Path | None = None) -> Path | None:
    """Find the first MCP config file. Deprecated: use find_config_files instead."""
    files = find_config_files(explicit_path)
    return files[0] if files else None


def find_env_files(explicit_path: Path | None = None) -> list[Path]:
    """Find all .env files to load, in order (global first, then local for overrides).

    Returns files in load order: global ~/.claude/.env first, then local .env.
    This allows project-specific overrides while still getting global defaults.
    """
    if explicit_path:
        if explicit_path.exists():
            return [explicit_path.resolve()]
        return []

    found: list[Path] = []
    # Load global env first (provides defaults)
    global_env = Path.home() / ".claude" / ".env"
    if global_env.exists():
        found.append(global_env.resolve())

    # Load local env second (can override globals)
    local_env = Path(".env")
    if local_env.exists():
        found.append(local_env.resolve())

    return found


def find_env_file(explicit_path: Path | None = None) -> Path | None:
    """Find the primary .env file (for display purposes).

    Returns the first env file found. Use find_env_files() for actual loading.
    """
    files = find_env_files(explicit_path)
    return files[0] if files else None


def count_servers_in_config(config_path: Path) -> int:
    """Count the number of servers defined in a config file.

    This is a lightweight function that reads a config file and counts
    servers without parsing the full configuration.

    Args:
        config_path: Path to the config file

    Returns:
        Number of servers in the config file, or 0 if file is invalid
    """
    try:
        with open(config_path) as f:
            data = json.load(f)
        return len(data.get("mcpServers", {}))
    except (json.JSONDecodeError, OSError):
        return 0


def parse_server_config(name: str, data: dict[str, Any]) -> ServerConfig:
    """Parse a server configuration from JSON data.

    Supports both stdio and HTTP transport types:
    - stdio (default): Uses command, args, env
    - http: Uses url, headers, and optional OAuth fields
    """
    server_type = data.get("type", "stdio")

    return ServerConfig(
        name=name,
        # Stdio fields
        command=data.get("command", ""),
        args=data.get("args", []),
        env=data.get("env", {}),
        # HTTP fields
        server_type=server_type,
        url=data.get("url", ""),
        headers=data.get("headers", {}),
        # OAuth fields
        oauth_client_id=data.get("oauth_client_id"),
        oauth_client_secret=data.get("oauth_client_secret"),
        oauth_scopes=data.get("oauth_scopes", []),
        # Static API key (alternative to OAuth)
        api_key=data.get("api_key"),
    )


def load_config(
    config_path: Path | None = None,
    env_path: Path | None = None,
    respect_preferences: bool = True,
    preferences_manager: ConfigPreferencesManager | None = None,
) -> Config:
    """Load MCP configuration from discovered or explicit paths.

    Finds all JSON files with 'mcp' in the filename (excluding '.mcp.json'
    which is reserved for Claude Code) and aggregates servers from all of them.

    When multiple config files exist, respects user preferences for which
    configs to use (unless explicit config_path is provided or
    respect_preferences=False).

    Args:
        config_path: Explicit path to config file (optional, bypasses preferences)
        env_path: Explicit path to .env file (optional)
        respect_preferences: If True, filter by user's active config preferences
        preferences_manager: Optional manager instance (for testing)

    Returns:
        Config object with loaded servers from all found config files

    Raises:
        FileNotFoundError: If no config file is found
        json.JSONDecodeError: If any config file is invalid JSON
    """
    # Find and load .env files (global first, then local for overrides)
    env_files = find_env_files(env_path)
    for env_file in env_files:
        load_dotenv(env_file)

    # Find config files (explicit path bypasses preferences)
    config_files = find_config_files(
        explicit_path=config_path,
        respect_preferences=respect_preferences if config_path is None else False,
        preferences_manager=preferences_manager,
    )
    if not config_files:
        searched = ", ".join(str(p) for p in CONFIG_SEARCH_DIRS)
        raise FileNotFoundError(
            f"No MCP config file found.\n\n"
            f"Searched directories for *mcp*.json files:\n"
            f"  {searched}\n\n"
            f"Note: '.mcp.json' is excluded (reserved for Claude Code).\n\n"
            f"Create a config file with your MCP servers. Example (mcp.json):\n\n"
            f'{{\n  "mcpServers": {{\n'
            f'    "github": {{\n'
            f'      "command": "uvx",\n'
            f'      "args": ["mcp-server-github"],\n'
            f'      "env": {{"GITHUB_TOKEN": "${{GITHUB_TOKEN}}"}}\n'
            f"    }}\n  }}\n}}"
        )

    # Load and aggregate servers from all config files
    servers: dict[str, ServerConfig] = {}
    for config_file in config_files:
        with open(config_file) as f:
            data = json.load(f)

        mcp_servers = data.get("mcpServers", {})
        for name, server_data in mcp_servers.items():
            if name not in servers:  # First definition wins
                servers[name] = parse_server_config(name, server_data)

    return Config(
        servers=servers,
        config_path=config_files[0] if config_files else None,
        config_paths=config_files,
        env_path=env_files[0] if env_files else None,
        env_paths=env_files,
    )
