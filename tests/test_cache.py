"""Tests for cache module."""

from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mcp_launchpad.cache import CacheMetadata, ToolCache
from mcp_launchpad.config import Config, ServerConfig
from mcp_launchpad.connection import ToolInfo


class TestCacheMetadata:
    """Tests for CacheMetadata dataclass."""

    def test_to_dict(self):
        """Test converting metadata to dictionary."""
        now = datetime.now()
        metadata = CacheMetadata(
            last_updated=now,
            config_mtime=12345.0,
            server_update_times={"github": "2024-01-01T00:00:00"},
        )
        d = metadata.to_dict()
        assert d["last_updated"] == now.isoformat()
        assert d["config_mtime"] == 12345.0
        assert d["server_update_times"] == {"github": "2024-01-01T00:00:00"}

    def test_from_dict(self):
        """Test creating metadata from dictionary."""
        now = datetime.now()
        data = {
            "last_updated": now.isoformat(),
            "config_mtime": 67890.0,
            "server_update_times": {"sentry": "2024-01-02T00:00:00"},
        }
        metadata = CacheMetadata.from_dict(data)
        assert metadata.last_updated == now
        assert metadata.config_mtime == 67890.0
        assert metadata.server_update_times == {"sentry": "2024-01-02T00:00:00"}

    def test_from_dict_missing_optional_fields(self):
        """Test creating metadata with missing optional fields."""
        data = {"last_updated": datetime.now().isoformat()}
        metadata = CacheMetadata.from_dict(data)
        assert metadata.config_mtime == 0
        assert metadata.server_update_times == {}


class TestToolCache:
    """Tests for ToolCache class."""

    @pytest.fixture
    def cache_with_temp_dir(self, tmp_path: Path, sample_config: Config) -> ToolCache:
        """Create a cache that uses a temp directory."""
        cache = ToolCache(sample_config)
        cache.cache_dir = tmp_path
        cache.index_path = tmp_path / "tool_index.json"
        cache.metadata_path = tmp_path / "index_metadata.json"
        return cache

    def test_ensure_cache_dir(self, tmp_path: Path, sample_config: Config):
        """Test cache directory is created."""
        cache = ToolCache(sample_config)
        cache.cache_dir = tmp_path / "new_cache_dir"
        cache._ensure_cache_dir()
        assert cache.cache_dir.exists()

    def test_save_and_load_tools(
        self, cache_with_temp_dir: ToolCache, sample_tools: list[ToolInfo]
    ):
        """Test saving and loading tools."""
        cache_with_temp_dir._save_tools(sample_tools)
        loaded = cache_with_temp_dir._load_tools()

        assert len(loaded) == len(sample_tools)
        assert loaded[0].name == sample_tools[0].name
        assert loaded[0].server == sample_tools[0].server

    def test_load_tools_no_file(self, cache_with_temp_dir: ToolCache):
        """Test loading tools when cache file doesn't exist."""
        tools = cache_with_temp_dir._load_tools()
        assert tools == []

    def test_load_tools_invalid_json(self, cache_with_temp_dir: ToolCache):
        """Test loading tools with invalid JSON."""
        cache_with_temp_dir.index_path.write_text("{ invalid json }")
        tools = cache_with_temp_dir._load_tools()
        assert tools == []

    def test_save_and_load_metadata(self, cache_with_temp_dir: ToolCache):
        """Test saving and loading metadata."""
        now = datetime.now()
        metadata = CacheMetadata(
            last_updated=now,
            config_mtime=12345.0,
            server_update_times={"test": now.isoformat()},
        )
        cache_with_temp_dir._save_metadata(metadata)
        loaded = cache_with_temp_dir._load_metadata()

        assert loaded is not None
        assert loaded.config_mtime == 12345.0

    def test_load_metadata_no_file(self, cache_with_temp_dir: ToolCache):
        """Test loading metadata when file doesn't exist."""
        metadata = cache_with_temp_dir._load_metadata()
        assert metadata is None

    def test_load_metadata_invalid_json(self, cache_with_temp_dir: ToolCache):
        """Test loading metadata with invalid JSON."""
        cache_with_temp_dir.metadata_path.write_text("{ bad json }")
        metadata = cache_with_temp_dir._load_metadata()
        assert metadata is None

    def test_load_metadata_bad_timestamp(self, cache_with_temp_dir: ToolCache):
        """A corrupt last_updated value is a cache miss, not a crash."""
        cache_with_temp_dir.metadata_path.write_text(
            '{"last_updated": "not-a-date", "config_mtime": 0, "server_update_times": {}}'
        )
        assert cache_with_temp_dir._load_metadata() is None
        assert cache_with_temp_dir.is_cache_valid() is False

    def test_load_metadata_non_object_json(self, cache_with_temp_dir: ToolCache):
        """Valid JSON that is not an object is a cache miss, not a crash."""
        cache_with_temp_dir.metadata_path.write_text("[1, 2, 3]")
        assert cache_with_temp_dir._load_metadata() is None

    def test_is_cache_valid_no_metadata(self, cache_with_temp_dir: ToolCache):
        """Test cache validity when no metadata exists."""
        assert cache_with_temp_dir.is_cache_valid() is False

    def test_is_cache_valid_expired(self, cache_with_temp_dir: ToolCache):
        """Test cache validity when expired."""
        old_time = datetime.now() - timedelta(hours=48)
        metadata = CacheMetadata(
            last_updated=old_time,
            config_mtime=0,
            server_update_times={},
        )
        cache_with_temp_dir._save_metadata(metadata)
        assert cache_with_temp_dir.is_cache_valid(ttl_hours=24) is False

    def test_is_cache_valid_config_changed(
        self, tmp_path: Path, cache_with_temp_dir: ToolCache
    ):
        """Test cache validity when config file changed."""
        # Create config file
        config_path = tmp_path / "config.json"
        config_path.write_text("{}")
        cache_with_temp_dir.config.config_path = config_path

        # Save metadata with old mtime
        metadata = CacheMetadata(
            last_updated=datetime.now(),
            config_mtime=0,  # Different from actual mtime
            server_update_times={},
        )
        cache_with_temp_dir._save_metadata(metadata)

        assert cache_with_temp_dir.is_cache_valid() is False

    def test_is_cache_valid_fresh(self, tmp_path: Path, cache_with_temp_dir: ToolCache):
        """Test cache is valid when fresh and config unchanged."""
        # Create config file
        config_path = tmp_path / "config.json"
        config_path.write_text("{}")
        cache_with_temp_dir.config.config_path = config_path

        # Save metadata with current mtime
        metadata = CacheMetadata(
            last_updated=datetime.now(),
            config_mtime=config_path.stat().st_mtime,
            server_update_times={},
        )
        cache_with_temp_dir._save_metadata(metadata)

        assert cache_with_temp_dir.is_cache_valid() is True

    def test_get_tools_valid_cache(
        self,
        cache_with_temp_dir: ToolCache,
        sample_tools: list[ToolInfo],
        tmp_path: Path,
    ):
        """Test getting tools from valid cache."""
        # Create config for mtime
        config_path = tmp_path / "config.json"
        config_path.write_text("{}")
        cache_with_temp_dir.config.config_path = config_path

        # Save tools and metadata
        cache_with_temp_dir._save_tools(sample_tools)
        metadata = CacheMetadata(
            last_updated=datetime.now(),
            config_mtime=config_path.stat().st_mtime,
            server_update_times={},
        )
        cache_with_temp_dir._save_metadata(metadata)

        tools = cache_with_temp_dir.get_tools()
        assert len(tools) == len(sample_tools)

    def test_get_tools_invalid_cache(self, cache_with_temp_dir: ToolCache):
        """Test getting tools returns empty list when cache invalid."""
        tools = cache_with_temp_dir.get_tools()
        assert tools == []


class TestToolCacheRefresh:
    """Tests for ToolCache.refresh method."""

    @pytest.fixture
    def cache_with_mock_manager(
        self, tmp_path: Path, sample_tools: list[ToolInfo]
    ) -> tuple[ToolCache, MagicMock]:
        """Create a cache with mocked connection manager."""
        config = Config(
            servers={
                "github": ServerConfig(name="github", command="cmd"),
                "sentry": ServerConfig(name="sentry", command="cmd"),
            },
            config_path=tmp_path / "config.json",
            env_path=None,
        )
        # Create the config file
        config.config_path.write_text('{"mcpServers": {}}')

        cache = ToolCache(config)
        cache.cache_dir = tmp_path
        cache.index_path = tmp_path / "tool_index.json"
        cache.metadata_path = tmp_path / "index_metadata.json"

        # Create mock manager
        mock_manager = MagicMock()
        github_tools = [t for t in sample_tools if t.server == "github"]
        sentry_tools = [t for t in sample_tools if t.server == "sentry"]

        async def mock_list_tools(server_name):
            if server_name == "github":
                return github_tools
            elif server_name == "sentry":
                return sentry_tools
            return []

        mock_manager.list_tools = AsyncMock(side_effect=mock_list_tools)

        return cache, mock_manager

    async def test_refresh_fetches_from_servers(
        self, cache_with_mock_manager: tuple[ToolCache, MagicMock]
    ):
        """Test refresh fetches tools from all servers."""
        cache, mock_manager = cache_with_mock_manager

        with patch("mcp_launchpad.cache.ConnectionManager", return_value=mock_manager):
            tools = await cache.refresh(force=True)

        assert len(tools) > 0
        assert mock_manager.list_tools.call_count == 2

    async def test_refresh_saves_cache(
        self, cache_with_mock_manager: tuple[ToolCache, MagicMock]
    ):
        """Test refresh saves tools to cache."""
        cache, mock_manager = cache_with_mock_manager

        with patch("mcp_launchpad.cache.ConnectionManager", return_value=mock_manager):
            await cache.refresh(force=True)

        # Check cache files exist
        assert cache.index_path.exists()
        assert cache.metadata_path.exists()

    async def test_refresh_skips_when_valid(
        self,
        cache_with_mock_manager: tuple[ToolCache, MagicMock],
        sample_tools: list[ToolInfo],
    ):
        """Test refresh skips when cache is valid and force=False."""
        cache, mock_manager = cache_with_mock_manager

        # Pre-populate cache
        cache._save_tools(sample_tools)
        metadata = CacheMetadata(
            last_updated=datetime.now(),
            config_mtime=cache.config.config_path.stat().st_mtime,
            server_update_times={},
        )
        cache._save_metadata(metadata)

        with patch("mcp_launchpad.cache.ConnectionManager", return_value=mock_manager):
            tools = await cache.refresh(force=False)

        # Should use cache, not call servers
        assert mock_manager.list_tools.call_count == 0
        assert len(tools) == len(sample_tools)

    async def test_refresh_handles_server_errors(self, tmp_path: Path):
        """Test refresh handles server connection errors gracefully."""
        config = Config(
            servers={
                "good": ServerConfig(name="good", command="cmd"),
                "bad": ServerConfig(name="bad", command="cmd"),
            },
            config_path=tmp_path / "config.json",
            env_path=None,
        )
        config.config_path.write_text("{}")

        cache = ToolCache(config)
        cache.cache_dir = tmp_path
        cache.index_path = tmp_path / "tool_index.json"
        cache.metadata_path = tmp_path / "index_metadata.json"

        mock_manager = MagicMock()
        good_tool = ToolInfo(
            server="good", name="good_tool", description="Good tool", input_schema={}
        )

        async def mock_list_tools(server_name):
            if server_name == "good":
                return [good_tool]
            raise RuntimeError("Connection failed")

        mock_manager.list_tools = AsyncMock(side_effect=mock_list_tools)

        with patch("mcp_launchpad.cache.ConnectionManager", return_value=mock_manager):
            tools = await cache.refresh(force=True)

        # Should have tools from the good server
        assert len(tools) == 1
        assert tools[0].name == "good_tool"

    async def test_refresh_all_servers_fail(self, tmp_path: Path):
        """Test refresh raises error when all servers fail."""
        config = Config(
            servers={
                "bad1": ServerConfig(name="bad1", command="cmd"),
                "bad2": ServerConfig(name="bad2", command="cmd"),
            },
            config_path=tmp_path / "config.json",
            env_path=None,
        )
        config.config_path.write_text("{}")

        cache = ToolCache(config)
        cache.cache_dir = tmp_path
        cache.index_path = tmp_path / "tool_index.json"
        cache.metadata_path = tmp_path / "index_metadata.json"

        mock_manager = MagicMock()
        mock_manager.list_tools = AsyncMock(side_effect=RuntimeError("Failed"))

        with patch("mcp_launchpad.cache.ConnectionManager", return_value=mock_manager):
            with pytest.raises(RuntimeError) as excinfo:
                await cache.refresh(force=True)

            assert "Failed to connect to any servers" in str(excinfo.value)
