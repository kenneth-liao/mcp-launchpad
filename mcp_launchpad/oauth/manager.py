"""High-level OAuth manager for MCP Launchpad.

This module provides the main interface for OAuth operations, used by
both the CLI and daemon to manage authentication for MCP servers.
"""

import logging
import threading
from dataclasses import dataclass, field
from typing import Any, Callable

from .discovery import OAuthConfig, discover_oauth_config
from .flow import OAuthFlow, OAuthFlowError, TokenExchangeError, refresh_token, revoke_token
from .store import TokenStore
from .tokens import TokenSet

logger = logging.getLogger(__name__)


@dataclass
class AuthStatus:
    """Authentication status for an MCP server.

    Attributes:
        server_url: The MCP server URL
        server_name: The friendly server name
        authenticated: Whether we have valid tokens
        expired: Whether the token is expired
        expires_at: When the token expires (ISO format string)
        has_refresh_token: Whether a refresh token is available
        scope: Granted scopes
        error: Any error message
    """

    server_url: str
    server_name: str
    authenticated: bool = False
    expired: bool = False
    expires_at: str | None = None
    has_refresh_token: bool = False
    scope: str | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "server_url": self.server_url,
            "server_name": self.server_name,
            "authenticated": self.authenticated,
            "expired": self.expired,
            "expires_at": self.expires_at,
            "has_refresh_token": self.has_refresh_token,
            "scope": self.scope,
            "error": self.error,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AuthStatus":
        """Deserialize from dictionary."""
        return cls(
            server_url=data["server_url"],
            server_name=data["server_name"],
            authenticated=data.get("authenticated", False),
            expired=data.get("expired", False),
            expires_at=data.get("expires_at"),
            has_refresh_token=data.get("has_refresh_token", False),
            scope=data.get("scope"),
            error=data.get("error"),
        )


@dataclass
class OAuthManager:
    """Manages OAuth authentication for MCP servers.

    This is the main interface for OAuth operations. It handles:
    - Checking if servers need authentication
    - Running OAuth flows for authentication
    - Managing stored tokens
    - Providing Authorization headers for HTTP requests
    - Refreshing expired tokens

    Usage:
        manager = OAuthManager()

        # Check if we have a valid token
        if manager.has_valid_token(server_url):
            header = manager.get_auth_header(server_url)

        # Run OAuth flow for new authentication
        await manager.authenticate(server_url, on_status=print)

        # Get status of all servers
        status = manager.get_auth_status(server_url, "my-server")
    """

    _store: TokenStore = field(default_factory=TokenStore)
    _oauth_configs: dict[str, OAuthConfig] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Initialize the manager."""
        # TokenStore is lazy-initialized in field default

    @property
    def token_store(self) -> TokenStore:
        """Get the token store."""
        return self._store

    def has_valid_token(self, server_url: str) -> bool:
        """Check if we have a valid (non-expired) token for a server.

        Args:
            server_url: The MCP server URL

        Returns:
            True if we have a valid token
        """
        token = self._store.get_token(server_url)
        if token is None:
            return False

        return not token.is_expired()

    def get_token(self, server_url: str) -> TokenSet | None:
        """Get the stored token for a server.

        Args:
            server_url: The MCP server URL

        Returns:
            TokenSet if found, None otherwise
        """
        return self._store.get_token(server_url)

    def get_auth_header(self, server_url: str) -> str | None:
        """Get the Authorization header value for a server.

        Args:
            server_url: The MCP server URL

        Returns:
            Authorization header value (e.g., "Bearer abc...") or None
        """
        token = self._store.get_token(server_url)
        if token is None:
            return None

        # Return header even if expired - let the server return 401
        # so we can trigger a refresh
        return token.get_auth_header()

    def get_auth_status(self, server_url: str, server_name: str) -> AuthStatus:
        """Get authentication status for a server.

        Args:
            server_url: The MCP server URL
            server_name: Friendly name for display

        Returns:
            AuthStatus with current authentication state
        """
        token = self._store.get_token(server_url)

        if token is None:
            return AuthStatus(
                server_url=server_url,
                server_name=server_name,
                authenticated=False,
            )

        return AuthStatus(
            server_url=server_url,
            server_name=server_name,
            authenticated=True,
            expired=token.is_expired(),
            expires_at=token.expires_at.isoformat() if token.expires_at else None,
            has_refresh_token=token.has_refresh_token(),
            scope=token.scope,
        )

    async def authenticate(
        self,
        server_url: str,
        client_id: str | None = None,
        client_secret: str | None = None,
        www_authenticate: str | None = None,
        scopes: list[str] | None = None,
        callback_timeout: int = 120,
        on_status: Callable[[str], None] | None = None,
        prompt_for_credentials: Callable[[], tuple[str, str | None]] | None = None,
    ) -> TokenSet:
        """Run OAuth flow to authenticate with a server.

        This is the main entry point for CLI-initiated authentication.

        Args:
            server_url: The MCP server URL
            client_id: Optional pre-configured client ID
            client_secret: Optional client secret
            www_authenticate: Optional WWW-Authenticate header from 401
            scopes: Optional scopes to request
            callback_timeout: Timeout for browser callback
            on_status: Callback for status messages
            prompt_for_credentials: Callback for manual credential entry

        Returns:
            TokenSet with new tokens

        Raises:
            OAuthFlowError: If authentication fails
        """
        flow = OAuthFlow(
            server_url=server_url,
            token_store=self._store,
            client_id=client_id,
            client_secret=client_secret,
            www_authenticate=www_authenticate,
            callback_timeout=callback_timeout,
            on_status=on_status,
        )

        token = await flow.run(
            scopes=scopes,
            prompt_for_credentials=prompt_for_credentials,
        )

        # Cache the OAuth config for future refresh operations
        if flow._oauth_config:
            self._oauth_configs[server_url] = flow._oauth_config

        return token

    async def refresh_if_needed(self, server_url: str) -> bool:
        """Refresh the token if it's expired.

        Args:
            server_url: The MCP server URL

        Returns:
            True if token was refreshed or is still valid,
            False if refresh failed or no token exists
        """
        token = self._store.get_token(server_url)
        if token is None:
            return False

        # Token is still valid
        if not token.is_expired():
            return True

        # No refresh token available
        if not token.has_refresh_token():
            logger.info(f"Token for {server_url} expired, no refresh token available")
            return False

        # Get OAuth config (may need to discover)
        oauth_config = self._oauth_configs.get(server_url)
        if oauth_config is None:
            try:
                oauth_config = await discover_oauth_config(server_url)
                self._oauth_configs[server_url] = oauth_config
            except Exception as e:
                logger.warning(f"Could not discover OAuth config for refresh: {e}")
                return False

        # Get client credentials
        auth_server = oauth_config.auth_server_metadata.issuer
        client = self._store.get_client(auth_server)
        if client is None:
            logger.warning(f"No client credentials for {auth_server}")
            return False

        # Attempt refresh
        try:
            token_response = await refresh_token(
                oauth_config.auth_server_metadata,
                client,
                token.refresh_token,  # type: ignore
                oauth_config.resource_uri,
            )

            new_token = TokenSet.from_token_response(
                token_response,
                oauth_config.resource_uri,
            )

            self._store.set_token(server_url, new_token)
            logger.info(f"Token refreshed for {server_url}")
            return True

        except TokenExchangeError as e:
            logger.warning(f"Token refresh failed for {server_url}: {e}")
            return False

    def logout(self, server_url: str) -> bool:
        """Remove stored authentication for a server (sync version).

        Note: This does not revoke tokens server-side. Use logout_async()
        for full logout with token revocation.

        Args:
            server_url: The MCP server URL

        Returns:
            True if token was deleted, False if not found
        """
        deleted = self._store.delete_token(server_url)
        if deleted:
            logger.info(f"Logged out from {server_url}")
        return deleted

    async def logout_async(self, server_url: str) -> bool:
        """Remove stored authentication with server-side token revocation.

        This method attempts to revoke tokens on the authorization server
        before deleting them locally, per RFC 7009. If revocation fails
        (e.g., server doesn't support it), local tokens are still deleted.

        Args:
            server_url: The MCP server URL

        Returns:
            True if token was deleted, False if not found
        """
        # Get token before deleting
        token = self._store.get_token(server_url)
        if token is None:
            return False

        # Try to get OAuth config for revocation
        oauth_config = self._oauth_configs.get(server_url)
        if oauth_config is None:
            try:
                oauth_config = await discover_oauth_config(server_url)
                self._oauth_configs[server_url] = oauth_config
            except Exception as e:
                logger.debug(f"Could not discover OAuth config for revocation: {e}")
                oauth_config = None

        # Attempt server-side revocation if we have config
        if oauth_config and oauth_config.auth_server_metadata.supports_revocation():
            auth_server = oauth_config.auth_server_metadata.issuer
            client = self._store.get_client(auth_server)

            if client:
                # Revoke access token
                await revoke_token(
                    oauth_config.auth_server_metadata,
                    client,
                    token.access_token,
                    token_type_hint="access_token",
                )

                # Revoke refresh token if present
                if token.has_refresh_token():
                    await revoke_token(
                        oauth_config.auth_server_metadata,
                        client,
                        token.refresh_token,  # type: ignore
                        token_type_hint="refresh_token",
                    )

        # Always delete local token
        deleted = self._store.delete_token(server_url)
        if deleted:
            logger.info(f"Logged out from {server_url}")
        return deleted

    def list_authenticated_servers(self) -> list[str]:
        """Get list of servers with stored tokens.

        Returns:
            List of server URLs with stored tokens
        """
        return self._store.list_resources()


# Global singleton for convenient access (thread-safe)
_manager: OAuthManager | None = None
_manager_lock = threading.Lock()


def get_oauth_manager() -> OAuthManager:
    """Get the global OAuth manager instance (thread-safe).

    Uses double-checked locking pattern for efficient thread-safe
    singleton initialization.

    Returns:
        The singleton OAuthManager instance
    """
    global _manager
    if _manager is None:
        with _manager_lock:
            # Double-check after acquiring lock
            if _manager is None:
                _manager = OAuthManager()
    return _manager
