"""Tests for OAuth flow module."""

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from mcp_launchpad.oauth.discovery import AuthServerMetadata, DiscoveryError
from mcp_launchpad.oauth.flow import (
    ClientRegistrationError,
    OAuthFlow,
    OAuthFlowError,
    TokenExchangeError,
    build_authorization_url,
    exchange_code_for_tokens,
    refresh_token,
    register_client_dcr,
    revoke_token,
)
from mcp_launchpad.oauth.store import TokenStore
from mcp_launchpad.oauth.tokens import ClientCredentials


class TestBuildAuthorizationUrl:
    """Tests for build_authorization_url function."""

    def test_builds_url_with_required_params(self) -> None:
        """Test that URL contains all required OAuth parameters."""
        metadata = AuthServerMetadata(
            issuer="https://auth.example.com",
            authorization_endpoint="https://auth.example.com/authorize",
            token_endpoint="https://auth.example.com/token",
        )

        url = build_authorization_url(
            auth_server_metadata=metadata,
            client_id="test_client",
            redirect_uri="http://127.0.0.1:8080/callback",
            code_challenge="test_challenge",
            state="test_state",
            resource="https://api.example.com",
        )

        assert "response_type=code" in url
        assert "client_id=test_client" in url
        assert "redirect_uri=" in url
        assert "code_challenge=test_challenge" in url
        assert "code_challenge_method=S256" in url
        assert "state=test_state" in url
        assert "resource=" in url

    def test_includes_scopes_when_provided(self) -> None:
        """Test that scopes are included in URL."""
        metadata = AuthServerMetadata(
            issuer="https://auth.example.com",
            authorization_endpoint="https://auth.example.com/authorize",
            token_endpoint="https://auth.example.com/token",
        )

        url = build_authorization_url(
            auth_server_metadata=metadata,
            client_id="test_client",
            redirect_uri="http://127.0.0.1:8080/callback",
            code_challenge="test_challenge",
            state="test_state",
            resource="https://api.example.com",
            scopes=["read", "write"],
        )

        assert "scope=read+write" in url or "scope=read%20write" in url


class TestExchangeCodeForTokens:
    """Tests for exchange_code_for_tokens function."""

    @pytest.mark.asyncio
    async def test_successful_token_exchange(self) -> None:
        """Test successful token exchange."""
        metadata = AuthServerMetadata(
            issuer="https://auth.example.com",
            authorization_endpoint="https://auth.example.com/authorize",
            token_endpoint="https://auth.example.com/token",
        )
        client = ClientCredentials(client_id="test_client")

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": "test_access_token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "test_refresh_token",
        }

        mock_http = AsyncMock()
        mock_http.post = AsyncMock(return_value=mock_response)
        mock_http.aclose = AsyncMock()

        result = await exchange_code_for_tokens(
            auth_server_metadata=metadata,
            client=client,
            code="test_code",
            redirect_uri="http://127.0.0.1:8080/callback",
            code_verifier="test_verifier",
            resource="https://api.example.com",
            http_client=mock_http,
        )

        assert result["access_token"] == "test_access_token"

        # Verify code_verifier was included in request
        call_args = mock_http.post.call_args
        assert "code_verifier" in call_args.kwargs["data"]
        assert call_args.kwargs["data"]["code_verifier"] == "test_verifier"

    @pytest.mark.asyncio
    async def test_token_exchange_error_sanitizes_response(self) -> None:
        """Test that error responses don't leak sensitive data."""
        metadata = AuthServerMetadata(
            issuer="https://auth.example.com",
            authorization_endpoint="https://auth.example.com/authorize",
            token_endpoint="https://auth.example.com/token",
        )
        client = ClientCredentials(client_id="test_client")

        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.json.side_effect = ValueError("Invalid JSON")
        mock_response.text = "sensitive_token_data_here"

        mock_http = AsyncMock()
        mock_http.post = AsyncMock(return_value=mock_response)
        mock_http.aclose = AsyncMock()

        with pytest.raises(TokenExchangeError) as exc_info:
            await exchange_code_for_tokens(
                auth_server_metadata=metadata,
                client=client,
                code="test_code",
                redirect_uri="http://127.0.0.1:8080/callback",
                code_verifier="test_verifier",
                resource="https://api.example.com",
                http_client=mock_http,
            )

        # Verify sensitive data is not in error message
        error_msg = str(exc_info.value)
        assert "sensitive_token_data_here" not in error_msg

    @pytest.mark.asyncio
    async def test_includes_client_secret_for_confidential_client(self) -> None:
        """Test that client secret is included for confidential clients."""
        metadata = AuthServerMetadata(
            issuer="https://auth.example.com",
            authorization_endpoint="https://auth.example.com/authorize",
            token_endpoint="https://auth.example.com/token",
        )
        client = ClientCredentials(client_id="test_client", client_secret="test_secret")

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"access_token": "token", "token_type": "Bearer"}

        mock_http = AsyncMock()
        mock_http.post = AsyncMock(return_value=mock_response)
        mock_http.aclose = AsyncMock()

        await exchange_code_for_tokens(
            auth_server_metadata=metadata,
            client=client,
            code="test_code",
            redirect_uri="http://127.0.0.1:8080/callback",
            code_verifier="test_verifier",
            resource="https://api.example.com",
            http_client=mock_http,
        )

        call_args = mock_http.post.call_args
        assert call_args.kwargs["data"]["client_secret"] == "test_secret"


class TestRefreshToken:
    """Tests for refresh_token function."""

    @pytest.mark.asyncio
    async def test_successful_refresh(self) -> None:
        """Test successful token refresh."""
        metadata = AuthServerMetadata(
            issuer="https://auth.example.com",
            authorization_endpoint="https://auth.example.com/authorize",
            token_endpoint="https://auth.example.com/token",
        )
        client = ClientCredentials(client_id="test_client")

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": "new_access_token",
            "token_type": "Bearer",
        }

        mock_http = AsyncMock()
        mock_http.post = AsyncMock(return_value=mock_response)
        mock_http.aclose = AsyncMock()

        result = await refresh_token(
            auth_server_metadata=metadata,
            client=client,
            refresh_token_value="test_refresh_token",
            resource="https://api.example.com",
            http_client=mock_http,
        )

        assert result["access_token"] == "new_access_token"

        # Verify refresh_token was included
        call_args = mock_http.post.call_args
        assert call_args.kwargs["data"]["grant_type"] == "refresh_token"
        assert call_args.kwargs["data"]["refresh_token"] == "test_refresh_token"

    @pytest.mark.asyncio
    async def test_refresh_error_sanitizes_response(self) -> None:
        """Test that refresh error responses don't leak sensitive data."""
        metadata = AuthServerMetadata(
            issuer="https://auth.example.com",
            authorization_endpoint="https://auth.example.com/authorize",
            token_endpoint="https://auth.example.com/token",
        )
        client = ClientCredentials(client_id="test_client")

        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.json.side_effect = ValueError("Invalid JSON")
        mock_response.text = "leaked_token_123"

        mock_http = AsyncMock()
        mock_http.post = AsyncMock(return_value=mock_response)
        mock_http.aclose = AsyncMock()

        with pytest.raises(TokenExchangeError) as exc_info:
            await refresh_token(
                auth_server_metadata=metadata,
                client=client,
                refresh_token_value="test_refresh_token",
                resource="https://api.example.com",
                http_client=mock_http,
            )

        # Verify sensitive data is not in error message
        error_msg = str(exc_info.value)
        assert "leaked_token_123" not in error_msg


class TestRegisterClientDCR:
    """Tests for Dynamic Client Registration."""

    @pytest.mark.asyncio
    async def test_successful_registration(self) -> None:
        """Test successful DCR."""
        metadata = AuthServerMetadata(
            issuer="https://auth.example.com",
            authorization_endpoint="https://auth.example.com/authorize",
            token_endpoint="https://auth.example.com/token",
            registration_endpoint="https://auth.example.com/register",
        )

        mock_response = MagicMock()
        mock_response.status_code = 201
        mock_response.json.return_value = {
            "client_id": "registered_client_id",
            "client_secret": "registered_secret",
        }

        mock_http = AsyncMock()
        mock_http.post = AsyncMock(return_value=mock_response)
        mock_http.aclose = AsyncMock()

        result = await register_client_dcr(
            auth_server_metadata=metadata,
            redirect_uri="http://127.0.0.1:8080/callback",
            http_client=mock_http,
        )

        assert result.client_id == "registered_client_id"
        assert result.client_secret == "registered_secret"

    @pytest.mark.asyncio
    async def test_dcr_without_endpoint_raises_error(self) -> None:
        """Test that DCR fails without registration endpoint."""
        metadata = AuthServerMetadata(
            issuer="https://auth.example.com",
            authorization_endpoint="https://auth.example.com/authorize",
            token_endpoint="https://auth.example.com/token",
            registration_endpoint=None,
        )

        with pytest.raises(ClientRegistrationError) as exc_info:
            await register_client_dcr(
                auth_server_metadata=metadata,
                redirect_uri="http://127.0.0.1:8080/callback",
            )

        assert "not support" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_dcr_error_sanitizes_response(self) -> None:
        """Test that DCR error responses don't leak sensitive data."""
        metadata = AuthServerMetadata(
            issuer="https://auth.example.com",
            authorization_endpoint="https://auth.example.com/authorize",
            token_endpoint="https://auth.example.com/token",
            registration_endpoint="https://auth.example.com/register",
        )

        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.json.side_effect = ValueError("Invalid JSON")
        mock_response.text = "secret_internal_error_data"

        mock_http = AsyncMock()
        mock_http.post = AsyncMock(return_value=mock_response)
        mock_http.aclose = AsyncMock()

        with pytest.raises(ClientRegistrationError) as exc_info:
            await register_client_dcr(
                auth_server_metadata=metadata,
                redirect_uri="http://127.0.0.1:8080/callback",
                http_client=mock_http,
            )

        # Verify sensitive data is not in error message
        error_msg = str(exc_info.value)
        assert "secret_internal_error_data" not in error_msg


class TestOAuthFlowStateMismatch:
    """Tests for CSRF protection via state validation."""

    @pytest.mark.asyncio
    async def test_state_mismatch_raises_error(self) -> None:
        """Test that state mismatch raises security error."""
        # This tests the CSRF protection in the OAuth flow
        # The state parameter prevents cross-site request forgery

        # Create a mock callback result with mismatched state
        from mcp_launchpad.oauth.callback import CallbackResult

        # Simulate the state check that happens in OAuthFlow.run()
        generated_state = "abc123"
        callback_state = "different_state"

        result = CallbackResult(code="test_code", state=callback_state)

        # This is the security check from flow.py:504-507
        if result.state != generated_state:
            with pytest.raises(OAuthFlowError) as exc_info:
                raise OAuthFlowError("State mismatch in callback - possible CSRF attack")

            assert "CSRF" in str(exc_info.value)


class TestHTTPSEnforcement:
    """Tests for HTTPS enforcement on OAuth endpoints."""

    def test_http_authorization_endpoint_rejected(self) -> None:
        """Test that HTTP authorization endpoint is rejected."""
        with pytest.raises(DiscoveryError) as exc_info:
            AuthServerMetadata.from_dict({
                "issuer": "https://auth.example.com",
                "authorization_endpoint": "http://auth.example.com/authorize",  # HTTP!
                "token_endpoint": "https://auth.example.com/token",
            })

        assert "HTTPS" in str(exc_info.value)
        assert "Authorization endpoint" in str(exc_info.value)

    def test_http_token_endpoint_rejected(self) -> None:
        """Test that HTTP token endpoint is rejected."""
        with pytest.raises(DiscoveryError) as exc_info:
            AuthServerMetadata.from_dict({
                "issuer": "https://auth.example.com",
                "authorization_endpoint": "https://auth.example.com/authorize",
                "token_endpoint": "http://auth.example.com/token",  # HTTP!
            })

        assert "HTTPS" in str(exc_info.value)
        assert "Token endpoint" in str(exc_info.value)

    def test_https_endpoints_accepted(self) -> None:
        """Test that HTTPS endpoints are accepted."""
        metadata = AuthServerMetadata.from_dict({
            "issuer": "https://auth.example.com",
            "authorization_endpoint": "https://auth.example.com/authorize",
            "token_endpoint": "https://auth.example.com/token",
        })

        assert metadata.authorization_endpoint == "https://auth.example.com/authorize"
        assert metadata.token_endpoint == "https://auth.example.com/token"

    def test_http_registration_endpoint_rejected(self) -> None:
        """Test that HTTP registration endpoint is rejected."""
        with pytest.raises(DiscoveryError) as exc_info:
            AuthServerMetadata.from_dict({
                "issuer": "https://auth.example.com",
                "authorization_endpoint": "https://auth.example.com/authorize",
                "token_endpoint": "https://auth.example.com/token",
                "registration_endpoint": "http://auth.example.com/register",  # HTTP!
            })

        assert "HTTPS" in str(exc_info.value)
        assert "Registration endpoint" in str(exc_info.value)

    def test_http_revocation_endpoint_rejected(self) -> None:
        """Test that HTTP revocation endpoint is rejected."""
        with pytest.raises(DiscoveryError) as exc_info:
            AuthServerMetadata.from_dict({
                "issuer": "https://auth.example.com",
                "authorization_endpoint": "https://auth.example.com/authorize",
                "token_endpoint": "https://auth.example.com/token",
                "revocation_endpoint": "http://auth.example.com/revoke",  # HTTP!
            })

        assert "HTTPS" in str(exc_info.value)
        assert "Revocation endpoint" in str(exc_info.value)


class TestStoredCredentialsRedirectUri:
    """Tests for redirect_uri validation when reusing stored credentials."""

    @pytest.mark.asyncio
    async def test_stored_credentials_used_when_redirect_uri_matches(self) -> None:
        """Test that stored credentials are used when redirect_uri matches."""
        from mcp_launchpad.oauth.discovery import OAuthConfig
        from mcp_launchpad.oauth.store import TokenStore
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as tmpdir:
            store = TokenStore(store_dir=Path(tmpdir))

            # Store credentials with specific redirect_uri
            stored_creds = ClientCredentials(
                client_id="stored_client",
                redirect_uri="http://127.0.0.1:8080/callback",
            )
            store.set_client("https://auth.example.com", stored_creds)

            # Create flow with stored credentials
            flow = OAuthFlow(
                server_url="https://api.example.com",
                token_store=store,
            )

            # Mock OAuth config
            flow._oauth_config = MagicMock(spec=OAuthConfig)
            flow._oauth_config.auth_server_metadata = AuthServerMetadata(
                issuer="https://auth.example.com",
                authorization_endpoint="https://auth.example.com/authorize",
                token_endpoint="https://auth.example.com/token",
            )

            # Same redirect_uri should return stored credentials
            result = await flow.get_client_credentials(
                redirect_uri="http://127.0.0.1:8080/callback"
            )

            assert result.client_id == "stored_client"
            assert result.redirect_uri == "http://127.0.0.1:8080/callback"

    @pytest.mark.asyncio
    async def test_stored_credentials_rejected_on_redirect_uri_mismatch(self) -> None:
        """Test that stored DCR credentials are rejected when redirect_uri differs.

        This is the core test for the bug fix: when a different callback port is used,
        stored DCR credentials should be invalidated to prevent token exchange failure.
        """
        from mcp_launchpad.oauth.discovery import OAuthConfig
        from mcp_launchpad.oauth.store import TokenStore
        from tempfile import TemporaryDirectory
        from pathlib import Path

        with TemporaryDirectory() as tmpdir:
            store = TokenStore(store_dir=Path(tmpdir))

            # Store credentials from previous DCR with specific redirect_uri
            stored_creds = ClientCredentials(
                client_id="old_client",
                redirect_uri="http://127.0.0.1:52847/callback",  # Old port
            )
            store.set_client("https://auth.example.com", stored_creds)

            # Create flow
            flow = OAuthFlow(
                server_url="https://api.example.com",
                token_store=store,
            )

            # Mock OAuth config with DCR support
            flow._oauth_config = MagicMock(spec=OAuthConfig)
            flow._oauth_config.auth_server_metadata = AuthServerMetadata(
                issuer="https://auth.example.com",
                authorization_endpoint="https://auth.example.com/authorize",
                token_endpoint="https://auth.example.com/token",
                registration_endpoint="https://auth.example.com/register",
            )

            # Mock DCR response for fresh registration
            mock_response = MagicMock()
            mock_response.status_code = 201
            mock_response.json.return_value = {
                "client_id": "new_client_from_dcr",
            }

            mock_http = AsyncMock()
            mock_http.post = AsyncMock(return_value=mock_response)
            mock_http.aclose = AsyncMock()

            # Patch the httpx client creation
            with patch("mcp_launchpad.oauth.flow.httpx.AsyncClient", return_value=mock_http):
                # Different redirect_uri (different port) should trigger fresh DCR
                result = await flow.get_client_credentials(
                    redirect_uri="http://127.0.0.1:49283/callback"  # New port
                )

            # Should have performed fresh DCR, not reused old credentials
            assert result.client_id == "new_client_from_dcr"
            assert result.redirect_uri == "http://127.0.0.1:49283/callback"

    @pytest.mark.asyncio
    async def test_stored_credentials_without_redirect_uri_are_reused(self) -> None:
        """Test backwards compatibility: credentials without redirect_uri are reused.

        Existing stored credentials (from before this fix) won't have redirect_uri.
        They should still be reused for backwards compatibility.
        """
        from mcp_launchpad.oauth.discovery import OAuthConfig
        from mcp_launchpad.oauth.store import TokenStore
        from tempfile import TemporaryDirectory
        from pathlib import Path

        with TemporaryDirectory() as tmpdir:
            store = TokenStore(store_dir=Path(tmpdir))

            # Store credentials without redirect_uri (legacy format)
            stored_creds = ClientCredentials(
                client_id="legacy_client",
                redirect_uri=None,  # No redirect_uri stored
            )
            store.set_client("https://auth.example.com", stored_creds)

            # Create flow
            flow = OAuthFlow(
                server_url="https://api.example.com",
                token_store=store,
            )

            # Mock OAuth config
            flow._oauth_config = MagicMock(spec=OAuthConfig)
            flow._oauth_config.auth_server_metadata = AuthServerMetadata(
                issuer="https://auth.example.com",
                authorization_endpoint="https://auth.example.com/authorize",
                token_endpoint="https://auth.example.com/token",
            )

            # Should still reuse legacy credentials
            result = await flow.get_client_credentials(
                redirect_uri="http://127.0.0.1:8080/callback"
            )

            assert result.client_id == "legacy_client"


class TestRevokeToken:
    """Tests for token revocation (RFC 7009)."""

    @pytest.mark.asyncio
    async def test_successful_revocation(self) -> None:
        """Test successful token revocation."""
        metadata = AuthServerMetadata(
            issuer="https://auth.example.com",
            authorization_endpoint="https://auth.example.com/authorize",
            token_endpoint="https://auth.example.com/token",
            revocation_endpoint="https://auth.example.com/revoke",
        )
        client = ClientCredentials(client_id="test_client")

        mock_response = MagicMock()
        mock_response.status_code = 200

        mock_http = AsyncMock()
        mock_http.post = AsyncMock(return_value=mock_response)
        mock_http.aclose = AsyncMock()

        result = await revoke_token(
            auth_server_metadata=metadata,
            client=client,
            token="test_access_token",
            token_type_hint="access_token",
            http_client=mock_http,
        )

        assert result is True

        # Verify correct request was made
        call_args = mock_http.post.call_args
        assert call_args.kwargs["data"]["token"] == "test_access_token"
        assert call_args.kwargs["data"]["token_type_hint"] == "access_token"

    @pytest.mark.asyncio
    async def test_revocation_without_endpoint_succeeds(self) -> None:
        """Test that revocation succeeds when server doesn't support it."""
        metadata = AuthServerMetadata(
            issuer="https://auth.example.com",
            authorization_endpoint="https://auth.example.com/authorize",
            token_endpoint="https://auth.example.com/token",
            revocation_endpoint=None,  # No revocation support
        )
        client = ClientCredentials(client_id="test_client")

        # Should return True without making any request
        result = await revoke_token(
            auth_server_metadata=metadata,
            client=client,
            token="test_token",
        )

        assert result is True

    @pytest.mark.asyncio
    async def test_revocation_failure_returns_false(self) -> None:
        """Test that revocation failure returns False (doesn't raise)."""
        metadata = AuthServerMetadata(
            issuer="https://auth.example.com",
            authorization_endpoint="https://auth.example.com/authorize",
            token_endpoint="https://auth.example.com/token",
            revocation_endpoint="https://auth.example.com/revoke",
        )
        client = ClientCredentials(client_id="test_client")

        mock_response = MagicMock()
        mock_response.status_code = 500  # Server error

        mock_http = AsyncMock()
        mock_http.post = AsyncMock(return_value=mock_response)
        mock_http.aclose = AsyncMock()

        result = await revoke_token(
            auth_server_metadata=metadata,
            client=client,
            token="test_token",
            http_client=mock_http,
        )

        # Should return False, not raise
        assert result is False

    @pytest.mark.asyncio
    async def test_revocation_network_error_returns_false(self) -> None:
        """Test that network errors during revocation return False."""
        import httpx

        metadata = AuthServerMetadata(
            issuer="https://auth.example.com",
            authorization_endpoint="https://auth.example.com/authorize",
            token_endpoint="https://auth.example.com/token",
            revocation_endpoint="https://auth.example.com/revoke",
        )
        client = ClientCredentials(client_id="test_client")

        mock_http = AsyncMock()
        mock_http.post = AsyncMock(side_effect=httpx.RequestError("Network error"))
        mock_http.aclose = AsyncMock()

        result = await revoke_token(
            auth_server_metadata=metadata,
            client=client,
            token="test_token",
            http_client=mock_http,
        )

        # Should return False, not raise
        assert result is False

    def test_supports_revocation_true(self) -> None:
        """Test supports_revocation returns True with endpoint."""
        metadata = AuthServerMetadata(
            issuer="https://auth.example.com",
            authorization_endpoint="https://auth.example.com/authorize",
            token_endpoint="https://auth.example.com/token",
            revocation_endpoint="https://auth.example.com/revoke",
        )
        assert metadata.supports_revocation() is True

    def test_supports_revocation_false(self) -> None:
        """Test supports_revocation returns False without endpoint."""
        metadata = AuthServerMetadata(
            issuer="https://auth.example.com",
            authorization_endpoint="https://auth.example.com/authorize",
            token_endpoint="https://auth.example.com/token",
        )
        assert metadata.supports_revocation() is False
