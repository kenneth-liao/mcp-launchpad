"""OAuth discovery implementation per RFC 9728 and RFC 8414.

This module handles:
- Parsing WWW-Authenticate headers from 401 responses
- Fetching Protected Resource Metadata (RFC 9728)
- Fetching Authorization Server Metadata (RFC 8414)
"""

import logging
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

logger = logging.getLogger(__name__)


def _http_status_hint(status_code: int) -> str:
    """Get a user-friendly hint for common HTTP status codes."""
    hints = {
        401: "Server requires authentication - you may need to authenticate first",
        403: "Access forbidden - check if you have permission to access this resource",
        404: "Endpoint not found - the server may not support OAuth discovery at this URL",
        500: "Server error - the authorization server may be experiencing issues",
        502: "Bad gateway - there may be a proxy or network issue",
        503: "Service unavailable - the server may be temporarily down",
    }
    return hints.get(status_code, "")


class DiscoveryError(Exception):
    """Error during OAuth metadata discovery."""

    pass


def _require_https(url: str, context: str) -> None:
    """Validate that a URL uses HTTPS.

    OAuth endpoints must use HTTPS to prevent man-in-the-middle attacks
    that could intercept authorization codes or tokens.

    Args:
        url: The URL to validate
        context: Description of what this URL is for (used in error message)

    Raises:
        DiscoveryError: If the URL doesn't use HTTPS
    """
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise DiscoveryError(
            f"{context} must use HTTPS for security, got: {url}"
        )


@dataclass
class ProtectedResourceMetadata:
    """OAuth 2.0 Protected Resource Metadata per RFC 9728.

    Contains information about the MCP server as an OAuth resource server,
    including which authorization servers can issue tokens for it.
    """

    resource: str
    authorization_servers: list[str]
    scopes_supported: list[str] | None = None
    bearer_methods_supported: list[str] | None = None
    resource_documentation: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any], resource_url: str) -> "ProtectedResourceMetadata":
        """Create from JSON response."""
        return cls(
            resource=data.get("resource", resource_url),
            authorization_servers=data.get("authorization_servers", []),
            scopes_supported=data.get("scopes_supported"),
            bearer_methods_supported=data.get("bearer_methods_supported"),
            resource_documentation=data.get("resource_documentation"),
        )


@dataclass
class AuthServerMetadata:
    """OAuth 2.0 Authorization Server Metadata per RFC 8414.

    Contains information about the authorization server's endpoints
    and capabilities.
    """

    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    registration_endpoint: str | None = None
    revocation_endpoint: str | None = None
    scopes_supported: list[str] | None = None
    response_types_supported: list[str] = field(default_factory=lambda: ["code"])
    grant_types_supported: list[str] = field(
        default_factory=lambda: ["authorization_code", "refresh_token"]
    )
    code_challenge_methods_supported: list[str] = field(default_factory=lambda: ["S256"])
    token_endpoint_auth_methods_supported: list[str] | None = None

    def supports_pkce(self) -> bool:
        """Check if the server supports PKCE with S256."""
        return "S256" in self.code_challenge_methods_supported

    def supports_dcr(self) -> bool:
        """Check if the server supports Dynamic Client Registration."""
        return self.registration_endpoint is not None

    def supports_revocation(self) -> bool:
        """Check if the server supports token revocation (RFC 7009)."""
        return self.revocation_endpoint is not None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AuthServerMetadata":
        """Create from JSON response.

        Validates that critical OAuth endpoints use HTTPS.

        Raises:
            DiscoveryError: If authorization or token endpoint doesn't use HTTPS
        """
        # Validate critical endpoints use HTTPS
        auth_endpoint = data["authorization_endpoint"]
        token_endpoint = data["token_endpoint"]
        _require_https(auth_endpoint, "Authorization endpoint")
        _require_https(token_endpoint, "Token endpoint")

        # Registration endpoint is optional, but if present must use HTTPS
        registration_endpoint = data.get("registration_endpoint")
        if registration_endpoint:
            _require_https(registration_endpoint, "Registration endpoint")

        # Revocation endpoint is optional (RFC 7009), but if present must use HTTPS
        revocation_endpoint = data.get("revocation_endpoint")
        if revocation_endpoint:
            _require_https(revocation_endpoint, "Revocation endpoint")

        return cls(
            issuer=data["issuer"],
            authorization_endpoint=auth_endpoint,
            token_endpoint=token_endpoint,
            registration_endpoint=registration_endpoint,
            revocation_endpoint=revocation_endpoint,
            scopes_supported=data.get("scopes_supported"),
            response_types_supported=data.get("response_types_supported", ["code"]),
            grant_types_supported=data.get(
                "grant_types_supported", ["authorization_code", "refresh_token"]
            ),
            code_challenge_methods_supported=data.get(
                "code_challenge_methods_supported", ["S256"]
            ),
            token_endpoint_auth_methods_supported=data.get(
                "token_endpoint_auth_methods_supported"
            ),
        )


@dataclass
class OAuthConfig:
    """Complete OAuth configuration for an MCP server.

    Combines resource metadata and auth server metadata with
    the computed resource URI for RFC 8707 resource indicators.
    """

    resource_metadata: ProtectedResourceMetadata
    auth_server_metadata: AuthServerMetadata
    resource_uri: str  # The canonical resource URI for RFC 8707


def parse_www_authenticate(header: str) -> dict[str, str]:
    """Parse WWW-Authenticate header from 401 response.

    MCP servers return WWW-Authenticate headers in the format:
    Bearer resource_metadata="https://..."

    Args:
        header: The WWW-Authenticate header value

    Returns:
        Dictionary of parsed parameters

    Raises:
        DiscoveryError: If the header format is invalid
    """
    if not header:
        raise DiscoveryError("Empty WWW-Authenticate header")

    # Check for Bearer scheme
    if not header.lower().startswith("bearer"):
        raise DiscoveryError(f"Expected Bearer auth scheme, got: {header}")

    # Parse key="value" pairs
    params: dict[str, str] = {}
    # Match key="value" or key=value patterns
    pattern = r'(\w+)=(?:"([^"]+)"|([^\s,]+))'

    for match in re.finditer(pattern, header):
        key = match.group(1).lower()
        value = match.group(2) or match.group(3)
        params[key] = value

    return params


def get_resource_metadata_url(www_authenticate: str) -> str:
    """Extract resource_metadata URL from WWW-Authenticate header.

    Args:
        www_authenticate: The WWW-Authenticate header value

    Returns:
        The resource_metadata URL

    Raises:
        DiscoveryError: If resource_metadata is not found or doesn't use HTTPS
    """
    params = parse_www_authenticate(www_authenticate)

    if "resource_metadata" not in params:
        raise DiscoveryError(
            f"WWW-Authenticate header missing resource_metadata parameter: {www_authenticate}"
        )

    url = params["resource_metadata"]
    _require_https(url, "Resource metadata URL")
    return url


def compute_resource_uri(server_url: str) -> str:
    """Compute the canonical resource URI for RFC 8707.

    Per the MCP spec, the resource URI should be the base URL of the
    MCP server without trailing slashes or fragments.

    Args:
        server_url: The MCP server URL

    Returns:
        Canonical resource URI
    """
    parsed = urlparse(server_url)

    # Build canonical URI: scheme + netloc + path (without trailing slash)
    path = parsed.path.rstrip("/")
    resource = f"{parsed.scheme}://{parsed.netloc}{path}"

    return resource


async def fetch_protected_resource_metadata(
    url: str,
    http_client: httpx.AsyncClient | None = None,
    timeout: float = 30.0,
) -> ProtectedResourceMetadata:
    """Fetch Protected Resource Metadata from an MCP server.

    Args:
        url: The resource_metadata URL from WWW-Authenticate header,
             OR the MCP server base URL (will append well-known path)
        http_client: Optional HTTP client to use
        timeout: Request timeout in seconds

    Returns:
        ProtectedResourceMetadata instance

    Raises:
        DiscoveryError: If metadata cannot be fetched or parsed, or URL is not HTTPS
    """
    # If URL doesn't contain well-known path, construct it
    if "/.well-known/oauth-protected-resource" not in url:
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        url = urljoin(base_url, "/.well-known/oauth-protected-resource")

    # Validate HTTPS for security
    _require_https(url, "Protected resource metadata URL")

    client = http_client or httpx.AsyncClient(timeout=timeout)
    should_close = http_client is None

    logger.debug(f"Fetching protected resource metadata from {url}")

    try:
        response = await client.get(url)

        if response.status_code != 200:
            hint = _http_status_hint(response.status_code)
            error_msg = (
                f"Failed to fetch protected resource metadata from {url}: "
                f"HTTP {response.status_code}"
            )
            if hint:
                error_msg += f". {hint}"
            raise DiscoveryError(error_msg)

        # Parse JSON response
        try:
            data = response.json()
        except (ValueError, TypeError) as e:
            raise DiscoveryError(
                f"Protected resource metadata response was not valid JSON: {e}"
            ) from e

        logger.debug(f"Successfully fetched protected resource metadata from {url}")
        return ProtectedResourceMetadata.from_dict(data, url)

    except httpx.ConnectError as e:
        raise DiscoveryError(
            f"Could not connect to {url}: {e}. "
            f"Check that the URL is correct and the server is reachable."
        ) from e
    except httpx.TimeoutException as e:
        raise DiscoveryError(
            f"Timeout fetching resource metadata from {url}: {e}. "
            f"The server may be slow or unresponsive."
        ) from e
    except httpx.RequestError as e:
        raise DiscoveryError(f"Network error fetching resource metadata: {e}") from e
    except KeyError as e:
        raise DiscoveryError(
            f"Protected resource metadata missing required field: {e}"
        ) from e
    finally:
        if should_close:
            await client.aclose()


async def fetch_auth_server_metadata(
    issuer: str,
    http_client: httpx.AsyncClient | None = None,
    timeout: float = 30.0,
) -> AuthServerMetadata:
    """Fetch Authorization Server Metadata per RFC 8414.

    Tries both OAuth 2.0 and OIDC discovery endpoints.

    Args:
        issuer: The authorization server issuer URL
        http_client: Optional HTTP client to use
        timeout: Request timeout in seconds

    Returns:
        AuthServerMetadata instance

    Raises:
        DiscoveryError: If metadata cannot be fetched or parsed, or URL is not HTTPS
    """
    # Validate issuer uses HTTPS
    _require_https(issuer, "Authorization server issuer")

    client = http_client or httpx.AsyncClient(timeout=timeout)
    should_close = http_client is None

    # Try OAuth 2.0 metadata endpoint first, then OIDC
    parsed = urlparse(issuer)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    endpoints = [
        urljoin(base_url, "/.well-known/oauth-authorization-server"),
        urljoin(base_url, "/.well-known/openid-configuration"),
    ]

    errors: list[tuple[str, str]] = []  # (endpoint, error_message)

    try:
        for endpoint in endpoints:
            logger.debug(f"Trying auth server metadata endpoint: {endpoint}")
            try:
                response = await client.get(endpoint)

                if response.status_code == 200:
                    try:
                        data = response.json()
                    except (ValueError, TypeError) as e:
                        errors.append((endpoint, f"Invalid JSON response: {e}"))
                        continue

                    logger.debug(f"Successfully fetched auth server metadata from {endpoint}")
                    return AuthServerMetadata.from_dict(data)
                else:
                    hint = _http_status_hint(response.status_code)
                    error_msg = f"HTTP {response.status_code}"
                    if hint:
                        error_msg += f" ({hint})"
                    errors.append((endpoint, error_msg))

            except httpx.ConnectError as e:
                errors.append((endpoint, f"Connection failed: {e}"))
            except httpx.TimeoutException as e:
                errors.append((endpoint, f"Timeout: {e}"))
            except httpx.RequestError as e:
                errors.append((endpoint, f"Network error: {e}"))
            except KeyError as e:
                errors.append((endpoint, f"Missing required field: {e}"))

        # Build detailed error message
        error_details = "\n".join(f"  - {ep}: {err}" for ep, err in errors)
        raise DiscoveryError(
            f"Failed to fetch auth server metadata from {issuer}.\n"
            f"Tried the following endpoints:\n{error_details}\n\n"
            f"The server may not support OAuth 2.0/OIDC discovery, "
            f"or the URL may be incorrect."
        )

    finally:
        if should_close:
            await client.aclose()


async def discover_oauth_config(
    server_url: str,
    www_authenticate: str | None = None,
    http_client: httpx.AsyncClient | None = None,
    timeout: float = 30.0,
) -> OAuthConfig:
    """Perform full OAuth discovery for an MCP server.

    This is the main entry point for OAuth discovery. It:
    1. Fetches Protected Resource Metadata (or uses WWW-Authenticate header)
    2. Fetches Authorization Server Metadata
    3. Computes the resource URI for token binding

    Args:
        server_url: The MCP server URL
        www_authenticate: Optional WWW-Authenticate header from 401 response
        http_client: Optional HTTP client to use
        timeout: Request timeout in seconds

    Returns:
        OAuthConfig with all necessary OAuth information

    Raises:
        DiscoveryError: If discovery fails at any step
    """
    client = http_client or httpx.AsyncClient(timeout=timeout)
    should_close = http_client is None

    try:
        # Step 1: Get resource metadata
        if www_authenticate:
            metadata_url = get_resource_metadata_url(www_authenticate)
            resource_metadata = await fetch_protected_resource_metadata(
                metadata_url, client, timeout
            )
        else:
            resource_metadata = await fetch_protected_resource_metadata(
                server_url, client, timeout
            )

        # Step 2: Validate we have at least one auth server
        if not resource_metadata.authorization_servers:
            raise DiscoveryError(
                f"Resource metadata for {server_url} does not specify any authorization servers. "
                f"The server's /.well-known/oauth-protected-resource must include "
                f"an 'authorization_servers' field."
            )

        # Step 3: Fetch auth server metadata (use first auth server)
        auth_server_url = resource_metadata.authorization_servers[0]
        auth_server_metadata = await fetch_auth_server_metadata(
            auth_server_url, client, timeout
        )

        # Step 4: Validate PKCE support (required by MCP spec)
        if not auth_server_metadata.supports_pkce():
            raise DiscoveryError(
                f"Authorization server {auth_server_url} does not support PKCE with S256, "
                f"which is required by the MCP specification"
            )

        # Step 5: Get resource URI from Protected Resource Metadata (RFC 9728)
        # The resource metadata's "resource" field is authoritative - it tells us
        # what resource identifier to use for RFC 8707 resource indicators.
        # Only fall back to computing from URL if metadata doesn't specify it.
        resource_uri = resource_metadata.resource or compute_resource_uri(server_url)

        return OAuthConfig(
            resource_metadata=resource_metadata,
            auth_server_metadata=auth_server_metadata,
            resource_uri=resource_uri,
        )

    finally:
        if should_close:
            await client.aclose()
