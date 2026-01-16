"""Tests for OAuth token data structures."""

from datetime import datetime, timedelta, timezone

import pytest

from mcp_launchpad.oauth.tokens import ClientCredentials, TokenSet


class TestTokenSet:
    """Tests for TokenSet dataclass."""

    def test_create_basic_token(self):
        """Test creating a basic token set."""
        token = TokenSet(
            access_token="test_access_token",
            token_type="Bearer",
            resource="https://api.example.com",
        )
        assert token.access_token == "test_access_token"
        assert token.token_type == "Bearer"
        assert token.resource == "https://api.example.com"

    def test_optional_fields(self):
        """Test optional fields have correct defaults."""
        token = TokenSet(
            access_token="test",
            token_type="Bearer",
            resource="https://api.example.com",
        )
        assert token.refresh_token is None
        assert token.expires_at is None
        assert token.scope is None
        assert token.issued_at is not None  # Auto-set

    def test_is_expired_no_expiry(self):
        """Test that tokens without expiry are considered valid."""
        token = TokenSet(
            access_token="test",
            token_type="Bearer",
            resource="https://api.example.com",
            expires_at=None,
        )
        assert not token.is_expired()

    def test_is_expired_future(self):
        """Test that future expiry tokens are valid."""
        future = datetime.now(timezone.utc) + timedelta(hours=1)
        token = TokenSet(
            access_token="test",
            token_type="Bearer",
            resource="https://api.example.com",
            expires_at=future,
        )
        assert not token.is_expired()

    def test_is_expired_past(self):
        """Test that past expiry tokens are expired."""
        past = datetime.now(timezone.utc) - timedelta(hours=1)
        token = TokenSet(
            access_token="test",
            token_type="Bearer",
            resource="https://api.example.com",
            expires_at=past,
        )
        assert token.is_expired()

    def test_is_expired_buffer(self):
        """Test expiry buffer period."""
        # Token expires in 20 seconds but buffer is 30 seconds
        near_future = datetime.now(timezone.utc) + timedelta(seconds=20)
        token = TokenSet(
            access_token="test",
            token_type="Bearer",
            resource="https://api.example.com",
            expires_at=near_future,
        )
        # Should be considered expired due to buffer
        assert token.is_expired(buffer_seconds=30)
        # But not without buffer
        assert not token.is_expired(buffer_seconds=10)

    def test_has_refresh_token(self):
        """Test has_refresh_token method."""
        token_with = TokenSet(
            access_token="test",
            token_type="Bearer",
            resource="https://api.example.com",
            refresh_token="refresh123",
        )
        token_without = TokenSet(
            access_token="test",
            token_type="Bearer",
            resource="https://api.example.com",
        )
        token_empty = TokenSet(
            access_token="test",
            token_type="Bearer",
            resource="https://api.example.com",
            refresh_token="",
        )

        assert token_with.has_refresh_token()
        assert not token_without.has_refresh_token()
        assert not token_empty.has_refresh_token()

    def test_to_dict(self):
        """Test serialization to dictionary."""
        issued = datetime.now(timezone.utc)
        expires = issued + timedelta(hours=1)
        token = TokenSet(
            access_token="access123",
            token_type="Bearer",
            resource="https://api.example.com",
            refresh_token="refresh456",
            expires_at=expires,
            scope="read write",
            issued_at=issued,
        )

        data = token.to_dict()
        assert data["access_token"] == "access123"
        assert data["token_type"] == "Bearer"
        assert data["resource"] == "https://api.example.com"
        assert data["refresh_token"] == "refresh456"
        assert data["scope"] == "read write"
        assert "expires_at" in data
        assert "issued_at" in data

    def test_from_dict(self):
        """Test deserialization from dictionary."""
        now = datetime.now(timezone.utc)
        data = {
            "access_token": "access123",
            "token_type": "Bearer",
            "resource": "https://api.example.com",
            "refresh_token": "refresh456",
            "expires_at": (now + timedelta(hours=1)).isoformat(),
            "scope": "read write",
            "issued_at": now.isoformat(),
        }

        token = TokenSet.from_dict(data)
        assert token.access_token == "access123"
        assert token.token_type == "Bearer"
        assert token.resource == "https://api.example.com"
        assert token.refresh_token == "refresh456"
        assert token.scope == "read write"

    def test_from_token_response(self):
        """Test creating token from OAuth token endpoint response."""
        response = {
            "access_token": "new_access_token",
            "token_type": "Bearer",
            "refresh_token": "new_refresh_token",
            "expires_in": 3600,
            "scope": "read write",
        }

        token = TokenSet.from_token_response(response, "https://api.example.com")
        assert token.access_token == "new_access_token"
        assert token.token_type == "Bearer"
        assert token.refresh_token == "new_refresh_token"
        assert token.resource == "https://api.example.com"
        assert token.scope == "read write"
        assert token.expires_at is not None
        # Should expire in about an hour
        time_until_expiry = token.expires_at - datetime.now(timezone.utc)
        assert 3590 < time_until_expiry.total_seconds() < 3610

    def test_get_auth_header(self):
        """Test generating Authorization header."""
        token = TokenSet(
            access_token="abc123",
            token_type="Bearer",
            resource="https://api.example.com",
        )
        assert token.get_auth_header() == "Bearer abc123"


class TestClientCredentials:
    """Tests for ClientCredentials dataclass."""

    def test_create_public_client(self):
        """Test creating public client (no secret)."""
        client = ClientCredentials(client_id="my_client_id")
        assert client.client_id == "my_client_id"
        assert client.client_secret is None
        assert not client.is_confidential()

    def test_create_confidential_client(self):
        """Test creating confidential client (with secret)."""
        client = ClientCredentials(
            client_id="my_client_id",
            client_secret="my_secret",
        )
        assert client.client_id == "my_client_id"
        assert client.client_secret == "my_secret"
        assert client.is_confidential()

    def test_empty_secret_not_confidential(self):
        """Test that empty secret is treated as public client."""
        client = ClientCredentials(client_id="my_client_id", client_secret="")
        assert not client.is_confidential()

    def test_to_dict(self):
        """Test serialization to dictionary."""
        client = ClientCredentials(
            client_id="my_client_id",
            client_secret="my_secret",
        )
        data = client.to_dict()
        assert data["client_id"] == "my_client_id"
        assert data["client_secret"] == "my_secret"

    def test_to_dict_no_secret(self):
        """Test serialization without secret."""
        client = ClientCredentials(client_id="my_client_id")
        data = client.to_dict()
        assert data["client_id"] == "my_client_id"
        assert "client_secret" not in data

    def test_from_dict(self):
        """Test deserialization from dictionary."""
        data = {
            "client_id": "my_client_id",
            "client_secret": "my_secret",
        }
        client = ClientCredentials.from_dict(data)
        assert client.client_id == "my_client_id"
        assert client.client_secret == "my_secret"
