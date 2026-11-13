"""MCP Launchpad - A lightweight CLI for efficiently discovering and executing MCP server tools."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("mcp-launchpad")
except PackageNotFoundError:
    # Not installed (e.g. running from a source checkout without package metadata):
    # use a version that cannot be mistaken for a release.
    __version__ = "0.0.0+dev"

__all__ = [
    "__version__",
    # Core modules
    "Config",
    "ServerConfig",
    "load_config",
    "ConnectionManager",
    "ToolInfo",
    "ToolCache",
    "ToolSearcher",
    "SearchMethod",
    "SearchResult",
    "OutputHandler",
    # Session/Daemon
    "SessionClient",
]


# Lazy imports to avoid circular dependencies
def __getattr__(name: str) -> object:
    """Lazy import module components."""
    if name in ("Config", "ServerConfig", "load_config"):
        from .config import Config, ServerConfig, load_config

        return {
            "Config": Config,
            "ServerConfig": ServerConfig,
            "load_config": load_config,
        }[name]
    elif name in ("ConnectionManager", "ToolInfo"):
        from .connection import ConnectionManager, ToolInfo

        return {"ConnectionManager": ConnectionManager, "ToolInfo": ToolInfo}[name]
    elif name == "ToolCache":
        from .cache import ToolCache

        return ToolCache
    elif name in ("ToolSearcher", "SearchMethod", "SearchResult"):
        from .search import SearchMethod, SearchResult, ToolSearcher

        return {
            "ToolSearcher": ToolSearcher,
            "SearchMethod": SearchMethod,
            "SearchResult": SearchResult,
        }[name]
    elif name == "OutputHandler":
        from .output import OutputHandler

        return OutputHandler
    elif name == "SessionClient":
        from .session import SessionClient

        return SessionClient
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
