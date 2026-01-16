"""OAuth authorization code flow with PKCE.

This module orchestrates the complete OAuth authorization flow:
1. Discover OAuth configuration
2. Register client dynamically (if needed)
3. Generate PKCE pair
4. Start localhost callback server
5. Build authorization URL and open browser
6. Wait for callback with authorization code
7. Exchange code for tokens
8. Store tokens securely
"""

import hmac
import logging
import webbrowser
from typing import Any, Callable
from urllib.parse import urlencode

import httpx

from .callback import CallbackError, CallbackResult, LocalhostCallbackServer
from .discovery import AuthServerMetadata, DiscoveryError, OAuthConfig, discover_oauth_config
from .pkce import generate_pkce_pair, generate_state
from .store import TokenStore
from .tokens import ClientCredentials, TokenSet

logger = logging.getLogger(__name__)


class OAuthFlowError(Exception):
    """Error during OAuth flow."""

    pass


class ClientRegistrationError(OAuthFlowError):
    """Error during Dynamic Client Registration."""

    pass


class TokenExchangeError(OAuthFlowError):
    """Error during token exchange."""

    pass


# mcpl client info for Dynamic Client Registration
MCPL_CLIENT_NAME = "mcpl"
MCPL_CLIENT_URI = "https://github.com/kenneth-liao/mcp-launchpad"


async def register_client_dcr(
    auth_server_metadata: AuthServerMetadata,
    redirect_uri: str,
    http_client: httpx.AsyncClient | None = None,
) -> ClientCredentials:
    """Register a client using Dynamic Client Registration (RFC 7591).

    Args:
        auth_server_metadata: Authorization server metadata
        redirect_uri: The redirect URI to register
        http_client: Optional HTTP client

    Returns:
        ClientCredentials with client_id and optional client_secret

    Raises:
        ClientRegistrationError: If DCR fails
    """
    if not auth_server_metadata.supports_dcr():
        raise ClientRegistrationError(
            "Authorization server does not support Dynamic Client Registration"
        )

    registration_endpoint = auth_server_metadata.registration_endpoint
    if not registration_endpoint:
        raise ClientRegistrationError("No registration endpoint available")

    client = http_client or httpx.AsyncClient(timeout=30.0)
    should_close = http_client is None

    try:
        # Build registration request per RFC 7591
        registration_request = {
            "client_name": MCPL_CLIENT_NAME,
            "redirect_uris": [redirect_uri],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",  # Public client
            "client_uri": MCPL_CLIENT_URI,
        }

        response = await client.post(
            registration_endpoint,
            json=registration_request,
            headers={"Content-Type": "application/json"},
        )

        if response.status_code not in (200, 201):
            error_detail = ""
            try:
                error_data = response.json()
                # Only extract safe error fields, not arbitrary response data
                error_detail = f": {error_data.get('error', '')} - {error_data.get('error_description', '')}"
            except Exception:
                # Don't include raw response body - it might contain secrets
                error_detail = ""

            raise ClientRegistrationError(
                f"Dynamic Client Registration failed (HTTP {response.status_code}){error_detail}"
            )

        data = response.json()

        if "client_id" not in data:
            raise ClientRegistrationError("DCR response missing client_id")

        return ClientCredentials(
            client_id=data["client_id"],
            client_secret=data.get("client_secret"),
        )

    except httpx.RequestError as e:
        raise ClientRegistrationError(f"Network error during DCR: {e}") from e
    finally:
        if should_close:
            await client.aclose()


def build_authorization_url(
    auth_server_metadata: AuthServerMetadata,
    client_id: str,
    redirect_uri: str,
    code_challenge: str,
    state: str,
    resource: str,
    scopes: list[str] | None = None,
) -> str:
    """Build the authorization URL for browser redirect.

    Args:
        auth_server_metadata: Authorization server metadata
        client_id: The client ID
        redirect_uri: The callback URI
        code_challenge: PKCE code challenge
        state: State parameter for CSRF protection
        resource: Resource URI for RFC 8707
        scopes: Optional list of scopes to request

    Returns:
        Complete authorization URL
    """
    params: dict[str, str] = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "state": state,
        "resource": resource,
    }

    if scopes:
        params["scope"] = " ".join(scopes)
    elif auth_server_metadata.scopes_supported:
        # Use default scopes if server specifies them
        params["scope"] = " ".join(auth_server_metadata.scopes_supported)

    auth_url = auth_server_metadata.authorization_endpoint
    return f"{auth_url}?{urlencode(params)}"


async def exchange_code_for_tokens(
    auth_server_metadata: AuthServerMetadata,
    client: ClientCredentials,
    code: str,
    redirect_uri: str,
    code_verifier: str,
    resource: str,
    http_client: httpx.AsyncClient | None = None,
) -> dict[str, Any]:
    """Exchange authorization code for tokens.

    Args:
        auth_server_metadata: Authorization server metadata
        client: Client credentials
        code: Authorization code from callback
        redirect_uri: The redirect URI used in authorization
        code_verifier: PKCE code verifier
        resource: Resource URI for RFC 8707

    Returns:
        Token endpoint response as dictionary

    Raises:
        TokenExchangeError: If token exchange fails
    """
    http = http_client or httpx.AsyncClient(timeout=30.0)
    should_close = http_client is None

    try:
        # Build token request
        token_request: dict[str, str] = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "code_verifier": code_verifier,
            "client_id": client.client_id,
            "resource": resource,
        }

        # Add client_secret for confidential clients
        if client.is_confidential():
            token_request["client_secret"] = client.client_secret  # type: ignore

        response = await http.post(
            auth_server_metadata.token_endpoint,
            data=token_request,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

        if response.status_code != 200:
            error_detail = ""
            try:
                error_data = response.json()
                # Only extract safe error fields, not arbitrary response data
                error_detail = f": {error_data.get('error', '')} - {error_data.get('error_description', '')}"
            except Exception:
                # Don't include raw response body - it might contain tokens or secrets
                error_detail = ""

            raise TokenExchangeError(
                f"Token exchange failed (HTTP {response.status_code}){error_detail}"
            )

        result: dict[str, Any] = response.json()
        return result

    except httpx.RequestError as e:
        raise TokenExchangeError(f"Network error during token exchange: {e}") from e
    finally:
        if should_close:
            await http.aclose()


async def refresh_token(
    auth_server_metadata: AuthServerMetadata,
    client: ClientCredentials,
    refresh_token_value: str,
    resource: str,
    http_client: httpx.AsyncClient | None = None,
) -> dict[str, Any]:
    """Refresh an expired access token.

    Args:
        auth_server_metadata: Authorization server metadata
        client: Client credentials
        refresh_token_value: The refresh token
        resource: Resource URI for RFC 8707

    Returns:
        Token endpoint response as dictionary

    Raises:
        TokenExchangeError: If refresh fails
    """
    http = http_client or httpx.AsyncClient(timeout=30.0)
    should_close = http_client is None

    try:
        token_request: dict[str, str] = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token_value,
            "client_id": client.client_id,
            "resource": resource,
        }

        if client.is_confidential():
            token_request["client_secret"] = client.client_secret  # type: ignore

        response = await http.post(
            auth_server_metadata.token_endpoint,
            data=token_request,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

        if response.status_code != 200:
            error_detail = ""
            try:
                error_data = response.json()
                # Only extract safe error fields, not arbitrary response data
                error_detail = f": {error_data.get('error', '')} - {error_data.get('error_description', '')}"
            except Exception:
                # Don't include raw response body - it might contain tokens or secrets
                error_detail = ""

            raise TokenExchangeError(
                f"Token refresh failed (HTTP {response.status_code}){error_detail}"
            )

        result: dict[str, Any] = response.json()
        return result

    except httpx.RequestError as e:
        raise TokenExchangeError(f"Network error during token refresh: {e}") from e
    finally:
        if should_close:
            await http.aclose()


async def revoke_token(
    auth_server_metadata: AuthServerMetadata,
    client: ClientCredentials,
    token: str,
    token_type_hint: str = "access_token",
    http_client: httpx.AsyncClient | None = None,
) -> bool:
    """Revoke an OAuth token per RFC 7009.

    Token revocation invalidates a token on the server side, preventing
    its future use even if it hasn't expired yet.

    Args:
        auth_server_metadata: Authorization server metadata
        client: Client credentials
        token: The token to revoke (access or refresh token)
        token_type_hint: Hint about token type ("access_token" or "refresh_token")
        http_client: Optional HTTP client

    Returns:
        True if revocation succeeded or server doesn't support revocation,
        False if revocation failed

    Note:
        Per RFC 7009, the revocation endpoint returns 200 OK even if the
        token was already invalid. Errors are only returned for malformed
        requests or server errors.
    """
    if not auth_server_metadata.supports_revocation():
        logger.debug("Server does not support token revocation")
        return True  # Not an error - server just doesn't support it

    http = http_client or httpx.AsyncClient(timeout=30.0)
    should_close = http_client is None

    try:
        revocation_request: dict[str, str] = {
            "token": token,
            "token_type_hint": token_type_hint,
            "client_id": client.client_id,
        }

        if client.is_confidential():
            revocation_request["client_secret"] = client.client_secret  # type: ignore

        response = await http.post(
            auth_server_metadata.revocation_endpoint,  # type: ignore
            data=revocation_request,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

        # RFC 7009: 200 OK means success (even if token was already invalid)
        if response.status_code == 200:
            logger.debug(f"Token revoked successfully ({token_type_hint})")
            return True

        # Log error but don't raise - revocation failure shouldn't block logout
        logger.warning(
            f"Token revocation returned HTTP {response.status_code}"
        )
        return False

    except httpx.RequestError as e:
        logger.warning(f"Network error during token revocation: {e}")
        return False
    finally:
        if should_close:
            await http.aclose()


class OAuthFlow:
    """Orchestrates the complete OAuth authorization code flow.

    This class handles:
    1. OAuth discovery
    2. Client registration (DCR or manual)
    3. PKCE generation
    4. Browser-based authorization
    5. Token exchange
    6. Token storage

    Usage:
        flow = OAuthFlow(server_url, token_store)
        token = await flow.run()
    """

    def __init__(
        self,
        server_url: str,
        token_store: TokenStore,
        client_id: str | None = None,
        client_secret: str | None = None,
        www_authenticate: str | None = None,
        callback_timeout: int = 120,
        on_status: Callable[[str], None] | None = None,
    ):
        """Initialize OAuth flow.

        Args:
            server_url: The MCP server URL requiring OAuth
            token_store: Token storage instance
            client_id: Optional pre-configured client ID
            client_secret: Optional client secret
            www_authenticate: Optional WWW-Authenticate header from 401
            callback_timeout: Timeout for waiting for callback
            on_status: Optional callback for status messages
        """
        self.server_url = server_url
        self.token_store = token_store
        self.client_id = client_id
        self.client_secret = client_secret
        self.www_authenticate = www_authenticate
        self.callback_timeout = callback_timeout
        self.on_status = on_status or (lambda msg: None)

        self._oauth_config: OAuthConfig | None = None

    def _emit_status(self, message: str) -> None:
        """Emit a status message."""
        logger.info(message)
        self.on_status(message)

    async def discover(self) -> OAuthConfig:
        """Discover OAuth configuration for the server.

        Returns:
            OAuthConfig with server and auth server metadata
        """
        self._emit_status("Discovering OAuth configuration...")

        self._oauth_config = await discover_oauth_config(
            self.server_url,
            www_authenticate=self.www_authenticate,
        )

        auth_server = self._oauth_config.auth_server_metadata.issuer
        self._emit_status(f"Authorization server: {auth_server}")

        return self._oauth_config

    async def get_client_credentials(
        self,
        redirect_uri: str,
        prompt_for_credentials: Callable[[], tuple[str, str | None]] | None = None,
    ) -> ClientCredentials:
        """Get client credentials via config, DCR, or user input.

        Args:
            redirect_uri: The redirect URI for this flow
            prompt_for_credentials: Optional callback to prompt user for credentials

        Returns:
            ClientCredentials

        Raises:
            OAuthFlowError: If credentials cannot be obtained
        """
        # 1. Check for pre-configured credentials
        if self.client_id:
            self._emit_status("Using configured client credentials")
            return ClientCredentials(self.client_id, self.client_secret)

        if self._oauth_config is None:
            raise OAuthFlowError("OAuth configuration not discovered")

        auth_server = self._oauth_config.auth_server_metadata.issuer

        # 2. Check for stored DCR credentials
        stored = self.token_store.get_client(auth_server)
        if stored:
            self._emit_status("Using stored client credentials")
            return stored

        # 3. Try Dynamic Client Registration
        if self._oauth_config.auth_server_metadata.supports_dcr():
            self._emit_status("Attempting Dynamic Client Registration...")
            try:
                credentials = await register_client_dcr(
                    self._oauth_config.auth_server_metadata,
                    redirect_uri,
                )
                # Store for future use
                self.token_store.set_client(auth_server, credentials)
                self._emit_status("Client registered successfully")
                return credentials
            except ClientRegistrationError as e:
                logger.warning(f"DCR failed: {e}")
                self._emit_status(f"DCR not available: {e}")

        # 4. Prompt user for credentials
        if prompt_for_credentials:
            self._emit_status("Manual client registration required")
            client_id, client_secret = prompt_for_credentials()
            credentials = ClientCredentials(client_id, client_secret)
            self.token_store.set_client(auth_server, credentials)
            return credentials

        raise OAuthFlowError(
            f"Could not obtain client credentials for {auth_server}.\n"
            f"Dynamic Client Registration is not available.\n"
            f"Please provide client_id in configuration or use --client-id option."
        )

    async def run(
        self,
        scopes: list[str] | None = None,
        prompt_for_credentials: Callable[[], tuple[str, str | None]] | None = None,
    ) -> TokenSet:
        """Execute the complete OAuth flow.

        Args:
            scopes: Optional list of scopes to request
            prompt_for_credentials: Optional callback for manual client registration

        Returns:
            TokenSet with access and refresh tokens

        Raises:
            OAuthFlowError: If the flow fails at any step
        """
        try:
            # Step 1: Discover OAuth configuration
            oauth_config = await self.discover()

            # Step 2: Start callback server
            async with LocalhostCallbackServer(
                timeout=self.callback_timeout
            ) as callback_server:
                redirect_uri = callback_server.redirect_uri

                # Step 3: Get client credentials
                client = await self.get_client_credentials(
                    redirect_uri, prompt_for_credentials
                )

                # Step 4: Generate PKCE and state
                pkce = generate_pkce_pair()
                state = generate_state()

                # Step 5: Build authorization URL
                auth_url = build_authorization_url(
                    oauth_config.auth_server_metadata,
                    client.client_id,
                    redirect_uri,
                    pkce.challenge,
                    state,
                    oauth_config.resource_uri,
                    scopes,
                )

                # Step 6: Open browser
                self._emit_status(f"Opening browser for authorization...")
                self._emit_status(f"Waiting for callback on {redirect_uri}")

                if not webbrowser.open(auth_url):
                    self._emit_status(
                        f"Could not open browser. Please open this URL manually:\n{auth_url}"
                    )

                # Step 7: Wait for callback
                result: CallbackResult = await callback_server.wait_for_callback()

                # Step 8: Validate callback
                if not result.is_success():
                    raise OAuthFlowError(
                        f"Authorization failed: {result.error} - {result.error_description}"
                    )

                # Use constant-time comparison to prevent timing attacks
                if not hmac.compare_digest(result.state or "", state):
                    raise OAuthFlowError(
                        "State mismatch in callback - possible CSRF attack"
                    )

                if result.code is None:
                    raise OAuthFlowError("No authorization code in callback")

                # Step 9: Exchange code for tokens
                self._emit_status("Exchanging code for tokens...")

                token_response = await exchange_code_for_tokens(
                    oauth_config.auth_server_metadata,
                    client,
                    result.code,
                    redirect_uri,
                    pkce.verifier,
                    oauth_config.resource_uri,
                )

                # Step 10: Create and store token
                token = TokenSet.from_token_response(
                    token_response,
                    oauth_config.resource_uri,
                )

                self.token_store.set_token(oauth_config.resource_uri, token)
                self._emit_status("Successfully authenticated!")

                return token

        except (DiscoveryError, CallbackError, TokenExchangeError) as e:
            raise OAuthFlowError(str(e)) from e

    async def refresh_existing(self) -> TokenSet | None:
        """Attempt to refresh an existing token.

        Returns:
            New TokenSet if refresh succeeded, None otherwise
        """
        if self._oauth_config is None:
            await self.discover()

        if self._oauth_config is None:
            return None

        # Get existing token
        token = self.token_store.get_token(self._oauth_config.resource_uri)
        if token is None or not token.has_refresh_token():
            return None

        # Get client credentials
        auth_server = self._oauth_config.auth_server_metadata.issuer
        client = self.token_store.get_client(auth_server)
        if client is None:
            return None

        try:
            self._emit_status("Refreshing token...")

            token_response = await refresh_token(
                self._oauth_config.auth_server_metadata,
                client,
                token.refresh_token,  # type: ignore
                self._oauth_config.resource_uri,
            )

            new_token = TokenSet.from_token_response(
                token_response,
                self._oauth_config.resource_uri,
            )

            self.token_store.set_token(self._oauth_config.resource_uri, new_token)
            self._emit_status("Token refreshed successfully")

            return new_token

        except TokenExchangeError as e:
            logger.warning(f"Token refresh failed: {e}")
            return None
