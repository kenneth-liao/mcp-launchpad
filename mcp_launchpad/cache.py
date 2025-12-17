"""Tool index caching for fast search without connecting to servers."""

import asyncio
import json
import os
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable

from .config import Config
from .connection import ConnectionManager, ToolInfo

# Default cache TTL (24 hours)
DEFAULT_CACHE_TTL_HOURS = 24

# Cache directory
CACHE_DIR = Path.home() / ".cache" / "mcp-launchpad"


@dataclass
class CacheMetadata:
    """Metadata about the cached tool index."""

    last_updated: datetime
    config_mtime: float
    server_update_times: dict[str, str]  # server -> ISO timestamp

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "last_updated": self.last_updated.isoformat(),
            "config_mtime": self.config_mtime,
            "server_update_times": self.server_update_times,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CacheMetadata":
        """Create from dictionary."""
        return cls(
            last_updated=datetime.fromisoformat(data["last_updated"]),
            config_mtime=data.get("config_mtime", 0),
            server_update_times=data.get("server_update_times", {}),
        )


class ToolCache:
    """Manages the cached tool index."""

    def __init__(self, config: Config):
        self.config = config
        self.cache_dir = CACHE_DIR
        self.index_path = self.cache_dir / "tool_index.json"
        self.metadata_path = self.cache_dir / "index_metadata.json"

    def _ensure_cache_dir(self) -> None:
        """Ensure cache directory exists."""
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _get_config_mtime(self) -> float:
        """Get modification time of config file."""
        if self.config.config_path and self.config.config_path.exists():
            return self.config.config_path.stat().st_mtime
        return 0

    def _load_metadata(self) -> CacheMetadata | None:
        """Load cache metadata if it exists."""
        if not self.metadata_path.exists():
            return None
        try:
            with open(self.metadata_path) as f:
                return CacheMetadata.from_dict(json.load(f))
        except (json.JSONDecodeError, KeyError):
            return None

    def _save_metadata(self, metadata: CacheMetadata) -> None:
        """Save cache metadata."""
        self._ensure_cache_dir()
        with open(self.metadata_path, "w") as f:
            json.dump(metadata.to_dict(), f, indent=2)

    def _load_tools(self) -> list[ToolInfo]:
        """Load cached tools if they exist."""
        if not self.index_path.exists():
            return []
        try:
            with open(self.index_path) as f:
                data = json.load(f)
                return [ToolInfo.from_dict(t) for t in data]
        except (json.JSONDecodeError, KeyError):
            return []

    def _save_tools(self, tools: list[ToolInfo]) -> None:
        """Save tools to cache."""
        self._ensure_cache_dir()
        with open(self.index_path, "w") as f:
            json.dump([t.to_dict() for t in tools], f, indent=2)

    def is_cache_valid(self, ttl_hours: int = DEFAULT_CACHE_TTL_HOURS) -> bool:
        """Check if cache is still valid."""
        metadata = self._load_metadata()
        if not metadata:
            return False

        # Check if config file changed
        current_mtime = self._get_config_mtime()
        if current_mtime != metadata.config_mtime:
            return False

        # Check if cache is expired
        age = datetime.now() - metadata.last_updated
        if age > timedelta(hours=ttl_hours):
            return False

        return True

    def get_tools(self) -> list[ToolInfo]:
        """Get cached tools (empty list if cache invalid)."""
        if not self.is_cache_valid():
            return []
        return self._load_tools()

    async def refresh(
        self,
        force: bool = False,
        on_progress: Callable[[str, str, int | None, str | None], None] | None = None,
        servers: list[str] | None = None,
    ) -> list[ToolInfo]:
        """Refresh the tool cache by connecting to servers.

        Args:
            force: Force refresh even if cache is valid
            on_progress: Optional callback for progress updates.
                Called with (server_name, status, tool_count, error_message)
                where status is "connecting", "done", or "error"
            servers: List of server names to refresh. If None, refreshes all servers.
        """
        if not force and self.is_cache_valid():
            return self._load_tools()

        manager = ConnectionManager(self.config)
        all_tools: list[ToolInfo] = []
        server_times: dict[str, str] = {}
        errors: list[str] = []

        # Use provided servers list or default to all servers in config
        servers_to_refresh = servers if servers is not None else list(self.config.servers.keys())

        for server_name in servers_to_refresh:
            if on_progress:
                on_progress(server_name, "connecting", None, None)
            try:
                tools = await manager.list_tools(server_name)
                all_tools.extend(tools)
                server_times[server_name] = datetime.now().isoformat()
                if on_progress:
                    on_progress(server_name, "done", len(tools), None)
            except Exception as e:
                errors.append(f"{server_name}: {e}")
                if on_progress:
                    on_progress(server_name, "error", None, str(e).split("\n")[0])

        # Save cache even if some servers failed
        self._save_tools(all_tools)
        self._save_metadata(
            CacheMetadata(
                last_updated=datetime.now(),
                config_mtime=self._get_config_mtime(),
                server_update_times=server_times,
            )
        )

        if errors and not all_tools:
            raise RuntimeError(
                "Failed to connect to any servers:\n" + "\n".join(errors)
            )

        return all_tools

