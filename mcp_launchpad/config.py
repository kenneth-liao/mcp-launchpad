"""Config discovery and loading for MCP Launchpad."""

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from dotenv import load_dotenv


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
    for match in re.finditer(r'\$\{([^}]+)\}', value):
        env_var = match.group(1)
        env_value = os.environ.get(env_var, "")
        result = result.replace(match.group(0), env_value)
    return result


@dataclass
class ServerConfig:
    """Configuration for a single MCP server."""

    name: str
    command: str
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)

    def get_resolved_env(self) -> dict[str, str]:
        """Resolve environment variables, expanding ${VAR} references."""
        return {key: _resolve_env_vars(value) for key, value in self.env.items()}

    def get_resolved_args(self) -> list[str]:
        """Resolve environment variables in args, expanding ${VAR} references."""
        return [_resolve_env_vars(arg) for arg in self.args]


@dataclass
class Config:
    """Complete MCP Launchpad configuration."""

    servers: dict[str, ServerConfig] = field(default_factory=dict)
    config_path: Path | None = None  # Primary config (first found)
    config_paths: list[Path] = field(default_factory=list)  # All config files loaded
    env_path: Path | None = None


# Directories to search for config files, in priority order
CONFIG_SEARCH_DIRS = [
    Path("."),                      # Current directory
    Path(".claude"),                # Project-level .claude directory
    Path.home() / ".claude",        # User-level .claude directory
]

# File to exclude (Claude Code's convention - avoids collision)
EXCLUDED_CONFIG_FILES = {".mcp.json"}

# Env file search paths in priority order
ENV_SEARCH_PATHS = [
    Path(".env"),
    Path.home() / ".claude" / ".env",
]


def find_config_files(explicit_path: Path | None = None) -> list[Path]:
    """Find all MCP config files with 'mcp' in the filename.

    Searches for JSON files containing 'mcp' in the filename (case-insensitive),
    excluding '.mcp.json' (Claude Code's convention) to avoid collision.

    Args:
        explicit_path: If provided, returns only this path if it exists.

    Returns:
        List of found config file paths, ordered by search directory priority.
    """
    if explicit_path:
        if explicit_path.exists():
            return [explicit_path]
        return []

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

            found_files.append(json_file)

    return found_files


def find_config_file(explicit_path: Path | None = None) -> Path | None:
    """Find the first MCP config file. Deprecated: use find_config_files instead."""
    files = find_config_files(explicit_path)
    return files[0] if files else None


def find_env_file(explicit_path: Path | None = None) -> Path | None:
    """Find the .env file, checking project then user level."""
    if explicit_path:
        if explicit_path.exists():
            return explicit_path
        return None

    for path in ENV_SEARCH_PATHS:
        if path.exists():
            return path
    return None


def parse_server_config(name: str, data: dict[str, Any]) -> ServerConfig:
    """Parse a server configuration from JSON data."""
    return ServerConfig(
        name=name,
        command=data.get("command", ""),
        args=data.get("args", []),
        env=data.get("env", {}),
    )


def load_config(
    config_path: Path | None = None,
    env_path: Path | None = None,
) -> Config:
    """Load MCP configuration from discovered or explicit paths.

    Finds all JSON files with 'mcp' in the filename (excluding '.mcp.json'
    which is reserved for Claude Code) and aggregates servers from all of them.

    Args:
        config_path: Explicit path to config file (optional)
        env_path: Explicit path to .env file (optional)

    Returns:
        Config object with loaded servers from all found config files

    Raises:
        FileNotFoundError: If no config file is found
        json.JSONDecodeError: If any config file is invalid JSON
    """
    # Find and load .env file first
    env_file = find_env_file(env_path)
    if env_file:
        load_dotenv(env_file)

    # Find all config files
    config_files = find_config_files(config_path)
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
        env_path=env_file,
    )

