"""OAuth token data structures and utilities.

This module provides the TokenSet dataclass for representing OAuth tokens
with their metadata, including expiry handling and serialization.
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class TokenSet:
    """OAuth token set with metadata.

    Stores access token, optional refresh token, and associated metadata
    per the OAuth 2.1 specification.

    Attributes:
        access_token: The access token string
        token_type: Token type (typically "Bearer")
        resource: The resource URI this token is bound to (RFC 8707)
        refresh_token: Optional refresh token for obtaining new access tokens
        expires_at: When the access token expires (UTC datetime)
        scope: Space-separated list of granted scopes
        issued_at: When the token was issued (UTC datetime)
    """

    access_token: str
    token_type: str
    resource: str
    refresh_token: str | None = None
    expires_at: datetime | None = None
    scope: str | None = None
    issued_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def is_expired(self, buffer_seconds: int = 30) -> bool:
        """Check if the access token is expired or nearly expired.

        Args:
            buffer_seconds: Consider token expired this many seconds before
                actual expiry to allow for clock skew and request latency.
                Default is 30 seconds.

        Returns:
            True if token is expired or will expire within buffer_seconds
        """
        if self.expires_at is None:
            # No expiry information - assume token is still valid
            # The server will return 401 if it's actually expired
            logger.debug(
                f"Token for {self.resource} has no expires_at - assuming valid. "
                f"Server will return 401 if token is actually expired."
            )
            return False

        now = datetime.now(timezone.utc)
        # Ensure expires_at is timezone-aware for comparison
        expires_at = self.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        # Check if token expires within the buffer period
        is_expired = now >= (expires_at - timedelta(seconds=buffer_seconds))

        # Log warning if token expired very quickly (possible clock skew)
        if is_expired and self.issued_at:
            token_lifetime = (expires_at - self.issued_at).total_seconds()
            time_since_issue = (now - self.issued_at).total_seconds()
            # If token "expired" within a very short time after issuance,
            # there may be clock skew between client and server
            if time_since_issue < 60 and token_lifetime > 60:
                logger.warning(
                    f"Token for {self.resource} appears expired only {time_since_issue:.0f}s "
                    f"after issuance (lifetime: {token_lifetime:.0f}s). "
                    f"This may indicate clock skew between client and server."
                )

        return is_expired

    def has_refresh_token(self) -> bool:
        """Check if this token set has a refresh token."""
        return self.refresh_token is not None and len(self.refresh_token) > 0

    def to_dict(self) -> dict[str, Any]:
        """Serialize token set to dictionary for storage.

        Returns:
            Dictionary representation suitable for JSON serialization
        """
        data: dict[str, Any] = {
            "access_token": self.access_token,
            "token_type": self.token_type,
            "resource": self.resource,
            "issued_at": self.issued_at.isoformat(),
        }

        if self.refresh_token:
            data["refresh_token"] = self.refresh_token

        if self.expires_at:
            data["expires_at"] = self.expires_at.isoformat()

        if self.scope:
            data["scope"] = self.scope

        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TokenSet":
        """Deserialize token set from dictionary.

        Args:
            data: Dictionary from storage (via to_dict)

        Returns:
            TokenSet instance
        """
        # Parse datetime fields
        expires_at = None
        if "expires_at" in data and data["expires_at"]:
            expires_at = datetime.fromisoformat(data["expires_at"])
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)

        issued_at = datetime.now(timezone.utc)
        if "issued_at" in data and data["issued_at"]:
            issued_at = datetime.fromisoformat(data["issued_at"])
            if issued_at.tzinfo is None:
                issued_at = issued_at.replace(tzinfo=timezone.utc)

        return cls(
            access_token=data["access_token"],
            token_type=data.get("token_type", "Bearer"),
            resource=data["resource"],
            refresh_token=data.get("refresh_token"),
            expires_at=expires_at,
            scope=data.get("scope"),
            issued_at=issued_at,
        )

    @classmethod
    def from_token_response(
        cls,
        response: dict[str, Any],
        resource: str,
    ) -> "TokenSet":
        """Create TokenSet from OAuth token endpoint response.

        Args:
            response: JSON response from token endpoint
            resource: The resource URI this token is for

        Returns:
            TokenSet instance
        """
        now = datetime.now(timezone.utc)

        # Calculate expiry time from expires_in if provided
        expires_at = None
        if "expires_in" in response:
            expires_at = now + timedelta(seconds=int(response["expires_in"]))

        return cls(
            access_token=response["access_token"],
            token_type=response.get("token_type", "Bearer"),
            resource=resource,
            refresh_token=response.get("refresh_token"),
            expires_at=expires_at,
            scope=response.get("scope"),
            issued_at=now,
        )

    def get_auth_header(self) -> str:
        """Get the Authorization header value for this token.

        Returns:
            Authorization header value (e.g., "Bearer abc123...")
        """
        # Always use "Bearer" (capital B) per RFC 6750, regardless of
        # what token_type the OAuth server returned (some return lowercase)
        return f"Bearer {self.access_token}"


@dataclass
class ClientCredentials:
    """OAuth client credentials.

    Stores client_id and optional client_secret for OAuth flows.
    Public clients (like CLIs) may not have a client_secret.

    For DCR-obtained credentials, redirect_uri tracks the URI registered
    with the authorization server. This is needed because DCR binds the
    client to specific redirect URIs, and using a different URI will
    cause token exchange to fail.
    """

    client_id: str
    client_secret: str | None = None
    redirect_uri: str | None = None

    def is_confidential(self) -> bool:
        """Check if this is a confidential client (has a secret)."""
        return self.client_secret is not None and len(self.client_secret) > 0

    def to_dict(self) -> dict[str, Any]:
        """Serialize credentials to dictionary."""
        data: dict[str, Any] = {"client_id": self.client_id}
        if self.client_secret:
            data["client_secret"] = self.client_secret
        if self.redirect_uri:
            data["redirect_uri"] = self.redirect_uri
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ClientCredentials":
        """Deserialize credentials from dictionary."""
        return cls(
            client_id=data["client_id"],
            client_secret=data.get("client_secret"),
            redirect_uri=data.get("redirect_uri"),
        )
