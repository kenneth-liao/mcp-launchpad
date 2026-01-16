"""OAuth 2.1 authentication support for MCP Launchpad.

This package implements OAuth authorization per the MCP Authorization
Specification, enabling mcpl to authenticate with OAuth-protected
MCP servers.

Main Components:
    OAuthManager: High-level manager for OAuth operations
    OAuthFlow: Authorization code flow orchestration
    TokenStore: Encrypted token storage
    TokenSet: Token data structure

Quick Start:
    from mcp_launchpad.oauth import get_oauth_manager

    manager = get_oauth_manager()

    # Check if authenticated
    if not manager.has_valid_token(server_url):
        # Run OAuth flow
        await manager.authenticate(server_url, on_status=print)

    # Get auth header for requests
    header = manager.get_auth_header(server_url)
"""

from .callback import (
    CallbackError,
    CallbackResult,
    CallbackTimeoutError,
    LocalhostCallbackServer,
)
from .discovery import (
    AuthServerMetadata,
    DiscoveryError,
    OAuthConfig,
    ProtectedResourceMetadata,
    discover_oauth_config,
    parse_www_authenticate,
)
from .flow import (
    ClientRegistrationError,
    OAuthFlow,
    OAuthFlowError,
    TokenExchangeError,
)
from .manager import AuthStatus, OAuthManager, get_oauth_manager
from .pkce import PKCEPair, generate_code_challenge, generate_code_verifier, generate_pkce_pair
from .store import TokenDecryptionError, TokenStore, TokenStoreError
from .tokens import ClientCredentials, TokenSet

__all__ = [
    # Manager (main entry point)
    "OAuthManager",
    "AuthStatus",
    "get_oauth_manager",
    # Flow
    "OAuthFlow",
    "OAuthFlowError",
    "ClientRegistrationError",
    "TokenExchangeError",
    # Discovery
    "discover_oauth_config",
    "parse_www_authenticate",
    "OAuthConfig",
    "AuthServerMetadata",
    "ProtectedResourceMetadata",
    "DiscoveryError",
    # Tokens
    "TokenSet",
    "ClientCredentials",
    # Storage
    "TokenStore",
    "TokenStoreError",
    "TokenDecryptionError",
    # PKCE
    "generate_pkce_pair",
    "generate_code_verifier",
    "generate_code_challenge",
    "PKCEPair",
    # Callback
    "LocalhostCallbackServer",
    "CallbackResult",
    "CallbackError",
    "CallbackTimeoutError",
]
