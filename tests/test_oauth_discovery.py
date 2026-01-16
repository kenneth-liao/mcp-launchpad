"""Tests for OAuth discovery implementation."""

import pytest

from mcp_launchpad.oauth.discovery import (
    AuthServerMetadata,
    DiscoveryError,
    ProtectedResourceMetadata,
    compute_resource_uri,
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
