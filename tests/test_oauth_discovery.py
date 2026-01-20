"""Tests for OAuth discovery implementation."""

from unittest.mock import AsyncMock, patch

import pytest

from mcp_launchpad.oauth.discovery import (
    AuthServerMetadata,
    DiscoveryError,
    OAuthConfig,
    ProtectedResourceMetadata,
    compute_resource_uri,
    construct_well_known_uris,
    discover_oauth_config,
    get_resource_metadata_url,
    parse_www_authenticate,
)


class TestParseWWWAuthenticate:
    """Tests for WWW-Authenticate header parsing."""

    def test_parse_basic_bearer(self):
        """Test parsing basic Bearer header."""
        header = 'Bearer resource_metadata="https://api.example.com/.well-known/oauth-protected-resource"'
        params = parse_www_authenticate(header)
        assert params["resource_metadata"] == "https://api.example.com/.well-known/oauth-protected-resource"

    def test_parse_multiple_params(self):
        """Test parsing header with multiple parameters."""
        header = 'Bearer realm="api", resource_metadata="https://api.example.com/metadata"'
        params = parse_www_authenticate(header)
        assert params["realm"] == "api"
        assert params["resource_metadata"] == "https://api.example.com/metadata"

    def test_parse_unquoted_values(self):
        """Test parsing header with unquoted values."""
        header = "Bearer error=invalid_token"
        params = parse_www_authenticate(header)
        assert params["error"] == "invalid_token"

    def test_empty_header_raises_error(self):
        """Test that empty header raises DiscoveryError."""
        with pytest.raises(DiscoveryError, match="Empty"):
            parse_www_authenticate("")

    def test_non_bearer_raises_error(self):
        """Test that non-Bearer scheme raises DiscoveryError."""
        with pytest.raises(DiscoveryError, match="Bearer"):
            parse_www_authenticate("Basic realm=api")

    def test_case_insensitive_scheme(self):
        """Test that Bearer scheme matching is case-insensitive."""
        header = 'BEARER resource_metadata="https://api.example.com/metadata"'
        params = parse_www_authenticate(header)
        assert "resource_metadata" in params


class TestGetResourceMetadataUrl:
    """Tests for extracting resource_metadata URL."""

    def test_extracts_url(self):
        """Test extracting resource_metadata URL from header."""
        header = 'Bearer resource_metadata="https://api.example.com/.well-known/oauth-protected-resource"'
        url = get_resource_metadata_url(header)
        assert url == "https://api.example.com/.well-known/oauth-protected-resource"

    def test_missing_resource_metadata_raises_error(self):
        """Test that missing resource_metadata raises DiscoveryError."""
        header = "Bearer realm=api"
        with pytest.raises(DiscoveryError, match="resource_metadata"):
            get_resource_metadata_url(header)


class TestComputeResourceUri:
    """Tests for computing canonical resource URI."""

    def test_basic_url(self):
        """Test computing resource URI from basic URL."""
        assert compute_resource_uri("https://api.example.com") == "https://api.example.com"

    def test_url_with_path(self):
        """Test computing resource URI from URL with path."""
        assert compute_resource_uri("https://api.example.com/mcp") == "https://api.example.com/mcp"

    def test_removes_trailing_slash(self):
        """Test that trailing slash is removed."""
        assert compute_resource_uri("https://api.example.com/") == "https://api.example.com"
        assert compute_resource_uri("https://api.example.com/mcp/") == "https://api.example.com/mcp"

    def test_preserves_port(self):
        """Test that port is preserved."""
        assert compute_resource_uri("https://api.example.com:8443/mcp") == "https://api.example.com:8443/mcp"


class TestConstructWellKnownUris:
    """Tests for construct_well_known_uris per RFC 8414 Section 3 with fallback."""

    def test_url_without_path_returns_single_url(self):
        """Test that URLs without path return a single URL (no fallback needed)."""
        result = construct_well_known_uris(
            "https://auth.example.com", "oauth-authorization-server"
        )
        assert result == ["https://auth.example.com/.well-known/oauth-authorization-server"]
        assert len(result) == 1

    def test_url_with_path_returns_two_urls(self):
        """Test that URLs with path return RFC 8414 compliant + fallback.

        This handles both:
        - Supabase (RFC 8414 compliant): uses /.well-known/.../mcp
        - Linear (non-compliant): uses /.well-known/... without path
        """
        result = construct_well_known_uris(
            "https://mcp.supabase.com/mcp", "oauth-authorization-server"
        )
        assert len(result) == 2
        # First: RFC 8414 compliant (path after suffix)
        assert result[0] == "https://mcp.supabase.com/.well-known/oauth-authorization-server/mcp"
        # Second: Fallback (no path, for non-compliant servers like Linear)
        assert result[1] == "https://mcp.supabase.com/.well-known/oauth-authorization-server"

    def test_url_with_nested_path(self):
        """Test well-known URL construction for URL with nested path."""
        result = construct_well_known_uris(
            "https://api.example.com/tenant/v1", "oauth-authorization-server"
        )
        assert len(result) == 2
        assert result[0] == "https://api.example.com/.well-known/oauth-authorization-server/tenant/v1"
        assert result[1] == "https://api.example.com/.well-known/oauth-authorization-server"

    def test_url_with_trailing_slash(self):
        """Test that trailing slash is stripped before constructing URL."""
        result = construct_well_known_uris(
            "https://mcp.supabase.com/mcp/", "oauth-authorization-server"
        )
        assert len(result) == 2
        assert result[0] == "https://mcp.supabase.com/.well-known/oauth-authorization-server/mcp"
        assert result[1] == "https://mcp.supabase.com/.well-known/oauth-authorization-server"

    def test_url_with_port(self):
        """Test well-known URL construction preserves port."""
        result = construct_well_known_uris(
            "https://api.example.com:8443/mcp", "oauth-authorization-server"
        )
        assert len(result) == 2
        assert result[0] == "https://api.example.com:8443/.well-known/oauth-authorization-server/mcp"
        assert result[1] == "https://api.example.com:8443/.well-known/oauth-authorization-server"

    def test_openid_configuration_suffix(self):
        """Test with openid-configuration suffix."""
        result = construct_well_known_uris(
            "https://auth.example.com/tenant", "openid-configuration"
        )
        assert len(result) == 2
        assert result[0] == "https://auth.example.com/.well-known/openid-configuration/tenant"
        assert result[1] == "https://auth.example.com/.well-known/openid-configuration"

    def test_oauth_protected_resource_suffix(self):
        """Test with oauth-protected-resource suffix."""
        result = construct_well_known_uris(
            "https://api.example.com/mcp", "oauth-protected-resource"
        )
        assert len(result) == 2
        assert result[0] == "https://api.example.com/.well-known/oauth-protected-resource/mcp"
        assert result[1] == "https://api.example.com/.well-known/oauth-protected-resource"

    def test_linear_case_no_path(self):
        """Test Linear case: URL without path returns single URL."""
        # Linear's actual URL is https://mcp.linear.app (no /mcp path in their config)
        # But their config has /mcp, so we test both scenarios
        result = construct_well_known_uris(
            "https://mcp.linear.app", "oauth-authorization-server"
        )
        assert result == ["https://mcp.linear.app/.well-known/oauth-authorization-server"]

    def test_linear_with_mcp_path_fallback(self):
        """Test Linear case: URL with /mcp path tries both, fallback works.

        Linear's MCP config uses https://mcp.linear.app/mcp but their well-known
        endpoint is at the root. The fallback URL should work.
        """
        result = construct_well_known_uris(
            "https://mcp.linear.app/mcp", "oauth-authorization-server"
        )
        assert len(result) == 2
        # First try (RFC 8414 compliant) - will 404 on Linear
        assert result[0] == "https://mcp.linear.app/.well-known/oauth-authorization-server/mcp"
        # Fallback (non-compliant) - works on Linear
        assert result[1] == "https://mcp.linear.app/.well-known/oauth-authorization-server"


class TestProtectedResourceMetadata:
    """Tests for ProtectedResourceMetadata dataclass."""

    def test_from_dict_basic(self):
        """Test creating metadata from basic dictionary."""
        data = {
            "resource": "https://api.example.com",
            "authorization_servers": ["https://auth.example.com"],
        }
        metadata = ProtectedResourceMetadata.from_dict(data, "https://api.example.com")
        assert metadata.resource == "https://api.example.com"
        assert metadata.authorization_servers == ["https://auth.example.com"]

    def test_from_dict_with_optional_fields(self):
        """Test creating metadata with optional fields."""
        data = {
            "resource": "https://api.example.com",
            "authorization_servers": ["https://auth.example.com"],
            "scopes_supported": ["read", "write"],
            "bearer_methods_supported": ["header"],
        }
        metadata = ProtectedResourceMetadata.from_dict(data, "https://api.example.com")
        assert metadata.scopes_supported == ["read", "write"]
        assert metadata.bearer_methods_supported == ["header"]


class TestAuthServerMetadata:
    """Tests for AuthServerMetadata dataclass."""

    def test_from_dict_basic(self):
        """Test creating metadata from basic dictionary."""
        data = {
            "issuer": "https://auth.example.com",
            "authorization_endpoint": "https://auth.example.com/authorize",
            "token_endpoint": "https://auth.example.com/token",
        }
        metadata = AuthServerMetadata.from_dict(data)
        assert metadata.issuer == "https://auth.example.com"
        assert metadata.authorization_endpoint == "https://auth.example.com/authorize"
        assert metadata.token_endpoint == "https://auth.example.com/token"

    def test_from_dict_with_dcr(self):
        """Test creating metadata with DCR endpoint."""
        data = {
            "issuer": "https://auth.example.com",
            "authorization_endpoint": "https://auth.example.com/authorize",
            "token_endpoint": "https://auth.example.com/token",
            "registration_endpoint": "https://auth.example.com/register",
        }
        metadata = AuthServerMetadata.from_dict(data)
        assert metadata.registration_endpoint == "https://auth.example.com/register"
        assert metadata.supports_dcr()

    def test_supports_pkce(self):
        """Test PKCE support detection."""
        data = {
            "issuer": "https://auth.example.com",
            "authorization_endpoint": "https://auth.example.com/authorize",
            "token_endpoint": "https://auth.example.com/token",
            "code_challenge_methods_supported": ["S256", "plain"],
        }
        metadata = AuthServerMetadata.from_dict(data)
        assert metadata.supports_pkce()

    def test_no_pkce_support(self):
        """Test detection of no PKCE support."""
        data = {
            "issuer": "https://auth.example.com",
            "authorization_endpoint": "https://auth.example.com/authorize",
            "token_endpoint": "https://auth.example.com/token",
            "code_challenge_methods_supported": ["plain"],
        }
        metadata = AuthServerMetadata.from_dict(data)
        assert not metadata.supports_pkce()

    def test_default_pkce_support(self):
        """Test that S256 is in default code_challenge_methods_supported."""
        data = {
            "issuer": "https://auth.example.com",
            "authorization_endpoint": "https://auth.example.com/authorize",
            "token_endpoint": "https://auth.example.com/token",
        }
        metadata = AuthServerMetadata.from_dict(data)
        assert metadata.supports_pkce()  # S256 is default

    def test_supports_dcr_false_when_no_endpoint(self):
        """Test that supports_dcr returns False when no registration endpoint."""
        data = {
            "issuer": "https://auth.example.com",
            "authorization_endpoint": "https://auth.example.com/authorize",
            "token_endpoint": "https://auth.example.com/token",
        }
        metadata = AuthServerMetadata.from_dict(data)
        assert not metadata.supports_dcr()


# Fixtures for TestDiscoverOAuthConfig
def valid_protected_resource_metadata() -> ProtectedResourceMetadata:
    """Standard RFC 9728 metadata."""
    return ProtectedResourceMetadata(
        resource="https://api.example.com",
        authorization_servers=["https://auth.example.com"],
        scopes_supported=["read", "write"],
    )


def valid_auth_server_metadata() -> AuthServerMetadata:
    """Standard auth server metadata with PKCE support."""
    return AuthServerMetadata(
        issuer="https://auth.example.com",
        authorization_endpoint="https://auth.example.com/authorize",
        token_endpoint="https://auth.example.com/token",
        registration_endpoint="https://auth.example.com/register",
        code_challenge_methods_supported=["S256"],
        scopes_supported=["read", "write"],
    )


def auth_server_metadata_no_pkce() -> AuthServerMetadata:
    """Auth server without S256 PKCE support."""
    return AuthServerMetadata(
        issuer="https://auth.example.com",
        authorization_endpoint="https://auth.example.com/authorize",
        token_endpoint="https://auth.example.com/token",
        code_challenge_methods_supported=["plain"],
    )


class TestDiscoverOAuthConfig:
    """Tests for discover_oauth_config function."""

    @pytest.mark.asyncio
    @patch("mcp_launchpad.oauth.discovery.fetch_auth_server_metadata")
    @patch("mcp_launchpad.oauth.discovery.fetch_protected_resource_metadata")
    async def test_successful_rfc9728_discovery(
        self, mock_fetch_prm, mock_fetch_asm
    ):
        """Test RFC 9728 success path (no fallback)."""
        mock_fetch_prm.return_value = valid_protected_resource_metadata()
        mock_fetch_asm.return_value = valid_auth_server_metadata()

        config = await discover_oauth_config("https://api.example.com")

        assert isinstance(config, OAuthConfig)
        assert config.resource_uri == "https://api.example.com"
        assert config.resource_metadata.resource == "https://api.example.com"
        assert config.auth_server_metadata.issuer == "https://auth.example.com"
        assert config.auth_server_metadata.supports_pkce()

        # Verify RFC 9728 path was taken
        mock_fetch_prm.assert_called_once()
        mock_fetch_asm.assert_called_once_with(
            "https://auth.example.com",
            mock_fetch_asm.call_args[0][1],  # http_client
            30.0,
        )

    @pytest.mark.asyncio
    @patch("mcp_launchpad.oauth.discovery.fetch_auth_server_metadata")
    @patch("mcp_launchpad.oauth.discovery.fetch_protected_resource_metadata")
    async def test_rfc8414_fallback_success(self, mock_fetch_prm, mock_fetch_asm):
        """Test RFC 8414 fallback works when RFC 9728 fails."""
        # RFC 9728 fails
        mock_fetch_prm.side_effect = DiscoveryError("RFC 9728 not supported")
        # RFC 8414 succeeds
        mock_fetch_asm.return_value = valid_auth_server_metadata()

        config = await discover_oauth_config("https://api.example.com")

        assert isinstance(config, OAuthConfig)
        # Verify synthetic ProtectedResourceMetadata was created
        assert config.resource_metadata.resource == "https://api.example.com"
        assert config.resource_metadata.authorization_servers == [
            "https://auth.example.com"
        ]
        # Verify resource_uri is computed correctly
        assert config.resource_uri == "https://api.example.com"
        assert config.auth_server_metadata.issuer == "https://auth.example.com"

        # Verify fallback path was taken
        mock_fetch_prm.assert_called_once()
        # fetch_auth_server_metadata called with server_url for fallback
        mock_fetch_asm.assert_called_once()

    @pytest.mark.asyncio
    @patch("mcp_launchpad.oauth.discovery.fetch_auth_server_metadata")
    @patch("mcp_launchpad.oauth.discovery.fetch_protected_resource_metadata")
    async def test_rfc8414_fallback_from_www_authenticate(
        self, mock_fetch_prm, mock_fetch_asm
    ):
        """Test fallback works when RFC 9728 via www_authenticate fails."""
        # RFC 9728 fails
        mock_fetch_prm.side_effect = DiscoveryError("RFC 9728 not supported")
        # RFC 8414 succeeds
        mock_fetch_asm.return_value = valid_auth_server_metadata()

        www_authenticate = (
            'Bearer resource_metadata="https://api.example.com/.well-known/oauth-protected-resource"'
        )
        config = await discover_oauth_config(
            "https://api.example.com", www_authenticate=www_authenticate
        )

        assert isinstance(config, OAuthConfig)
        assert config.resource_uri == "https://api.example.com"
        assert config.auth_server_metadata.issuer == "https://auth.example.com"

    @pytest.mark.asyncio
    @patch("mcp_launchpad.oauth.discovery.fetch_auth_server_metadata")
    @patch("mcp_launchpad.oauth.discovery.fetch_protected_resource_metadata")
    async def test_both_discovery_methods_fail(self, mock_fetch_prm, mock_fetch_asm):
        """Test error when both RFC 9728 and RFC 8414 fail."""
        mock_fetch_prm.side_effect = DiscoveryError("RFC 9728 error: not found")
        mock_fetch_asm.side_effect = DiscoveryError("RFC 8414 error: not found")

        with pytest.raises(DiscoveryError) as exc_info:
            await discover_oauth_config("https://api.example.com")

        error_message = str(exc_info.value)
        # Verify error contains context from both failures
        assert "RFC 9728" in error_message
        assert "RFC 8414" in error_message
        assert "api.example.com" in error_message

    @pytest.mark.asyncio
    @patch("mcp_launchpad.oauth.discovery.fetch_auth_server_metadata")
    @patch("mcp_launchpad.oauth.discovery.fetch_protected_resource_metadata")
    async def test_rfc8414_fallback_rejects_no_pkce(
        self, mock_fetch_prm, mock_fetch_asm
    ):
        """Test PKCE validation in fallback path."""
        # RFC 9728 fails
        mock_fetch_prm.side_effect = DiscoveryError("RFC 9728 not supported")
        # RFC 8414 returns metadata without S256 PKCE support
        mock_fetch_asm.return_value = auth_server_metadata_no_pkce()

        with pytest.raises(DiscoveryError) as exc_info:
            await discover_oauth_config("https://api.example.com")

        error_message = str(exc_info.value)
        assert "PKCE" in error_message or "S256" in error_message

    @pytest.mark.asyncio
    @patch("mcp_launchpad.oauth.discovery.fetch_auth_server_metadata")
    @patch("mcp_launchpad.oauth.discovery.fetch_protected_resource_metadata")
    async def test_missing_authorization_servers(self, mock_fetch_prm, mock_fetch_asm):
        """Test validation for empty auth servers in RFC 9728 path."""
        # Return metadata with empty authorization_servers
        mock_fetch_prm.return_value = ProtectedResourceMetadata(
            resource="https://api.example.com",
            authorization_servers=[],  # Empty!
        )

        with pytest.raises(DiscoveryError) as exc_info:
            await discover_oauth_config("https://api.example.com")

        error_message = str(exc_info.value)
        assert "authorization_servers" in error_message.lower()

    @pytest.mark.asyncio
    @patch("mcp_launchpad.oauth.discovery.fetch_auth_server_metadata")
    @patch("mcp_launchpad.oauth.discovery.fetch_protected_resource_metadata")
    async def test_rfc9728_path_rejects_no_pkce(self, mock_fetch_prm, mock_fetch_asm):
        """Test PKCE validation in normal RFC 9728 path."""
        mock_fetch_prm.return_value = valid_protected_resource_metadata()
        # Auth server metadata without S256 support
        mock_fetch_asm.return_value = auth_server_metadata_no_pkce()

        with pytest.raises(DiscoveryError) as exc_info:
            await discover_oauth_config("https://api.example.com")

        error_message = str(exc_info.value)
        assert "PKCE" in error_message or "S256" in error_message
