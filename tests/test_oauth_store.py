"""Tests for encrypted token storage."""

import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

from mcp_launchpad.oauth.store import TokenStore, TokenStoreError
from mcp_launchpad.oauth.tokens import ClientCredentials, TokenSet


class TestTokenStore:
    """Tests for TokenStore class."""

    @pytest.fixture
    def temp_store(self):
        """Create a token store in a temporary directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            store = TokenStore(store_dir=Path(tmpdir))
            yield store

    def test_initialization(self, temp_store):
        """Test that store initializes correctly."""
        assert temp_store.store_dir.exists()
        assert temp_store._cipher is not None

    def test_store_and_retrieve_token(self, temp_store):
        """Test storing and retrieving a token."""
        token = TokenSet(
            access_token="test_access_token",
            token_type="Bearer",
            resource="https://api.example.com",
            refresh_token="test_refresh_token",
            scope="read write",
        )

        temp_store.set_token("https://api.example.com", token)
        retrieved = temp_store.get_token("https://api.example.com")

        assert retrieved is not None
        assert retrieved.access_token == "test_access_token"
        assert retrieved.refresh_token == "test_refresh_token"
        assert retrieved.scope == "read write"

    def test_get_nonexistent_token(self, temp_store):
        """Test retrieving a token that doesn't exist."""
        result = temp_store.get_token("https://nonexistent.example.com")
        assert result is None

    def test_delete_token(self, temp_store):
        """Test deleting a token."""
        token = TokenSet(
            access_token="test",
            token_type="Bearer",
            resource="https://api.example.com",
        )
        temp_store.set_token("https://api.example.com", token)

        # Delete should succeed
        assert temp_store.delete_token("https://api.example.com")

        # Token should be gone
        assert temp_store.get_token("https://api.example.com") is None

        # Deleting again should return False
        assert not temp_store.delete_token("https://api.example.com")

    def test_list_resources(self, temp_store):
        """Test listing resources with stored tokens."""
        # Initially empty
        assert temp_store.list_resources() == []

        # Add some tokens
        for i in range(3):
            token = TokenSet(
                access_token=f"token_{i}",
                token_type="Bearer",
                resource=f"https://api{i}.example.com",
            )
            temp_store.set_token(f"https://api{i}.example.com", token)

        resources = temp_store.list_resources()
        assert len(resources) == 3

    def test_get_token_info(self, temp_store):
        """Test getting non-sensitive token info."""
        expires = datetime.now(timezone.utc) + timedelta(hours=1)
        token = TokenSet(
            access_token="secret_token",
            token_type="Bearer",
            resource="https://api.example.com",
            refresh_token="secret_refresh",
            expires_at=expires,
            scope="read write",
        )
        temp_store.set_token("https://api.example.com", token)

        info = temp_store.get_token_info("https://api.example.com")

        assert info is not None
        # Should not contain secret tokens
        assert "secret_token" not in str(info)
        assert "secret_refresh" not in str(info)
        # Should contain metadata
        assert info["scope"] == "read write"
        assert info["has_refresh_token"] is True
        assert info["is_expired"] is False

    def test_resource_normalization(self, temp_store):
        """Test that resources are normalized for consistent lookup."""
        token = TokenSet(
            access_token="test",
            token_type="Bearer",
            resource="https://api.example.com",
        )

        # Store with trailing slash
        temp_store.set_token("https://api.example.com/", token)

        # Retrieve without trailing slash
        retrieved = temp_store.get_token("https://api.example.com")
        assert retrieved is not None

    def test_store_and_retrieve_client(self, temp_store):
        """Test storing and retrieving client credentials."""
        client = ClientCredentials(
            client_id="my_client_id",
            client_secret="my_secret",
        )

        temp_store.set_client("https://auth.example.com", client)
        retrieved = temp_store.get_client("https://auth.example.com")

        assert retrieved is not None
        assert retrieved.client_id == "my_client_id"
        assert retrieved.client_secret == "my_secret"

    def test_delete_client(self, temp_store):
        """Test deleting client credentials."""
        client = ClientCredentials(client_id="my_client_id")
        temp_store.set_client("https://auth.example.com", client)

        assert temp_store.delete_client("https://auth.example.com")
        assert temp_store.get_client("https://auth.example.com") is None

    def test_clear_all(self, temp_store):
        """Test clearing all stored data."""
        # Add token and client
        token = TokenSet(
            access_token="test",
            token_type="Bearer",
            resource="https://api.example.com",
        )
        client = ClientCredentials(client_id="test")

        temp_store.set_token("https://api.example.com", token)
        temp_store.set_client("https://auth.example.com", client)

        # Clear all
        temp_store.clear_all()

        # Everything should be gone
        assert temp_store.get_token("https://api.example.com") is None
        assert temp_store.get_client("https://auth.example.com") is None

    def test_encryption_at_rest(self, temp_store):
        """Test that tokens are encrypted on disk."""
        token = TokenSet(
            access_token="my_secret_token_value",
            token_type="Bearer",
            resource="https://api.example.com",
        )
        temp_store.set_token("https://api.example.com", token)

        # Read the raw file content
        tokens_file = temp_store.store_dir / "tokens.json"
        raw_content = tokens_file.read_text()

        # The access token should NOT be visible in plaintext
        assert "my_secret_token_value" not in raw_content


class TestTokenStoreKeyringFallback:
    """Tests for keyring fallback behavior."""

    def test_uses_fallback_when_keyring_fails(self):
        """Test that store falls back to derived key when keyring fails."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Mock keyring to fail
            with patch("mcp_launchpad.oauth.store.keyring.get_password", side_effect=Exception("No keyring")):
                store = TokenStore(store_dir=Path(tmpdir))

                # Store should still work with fallback encryption
                assert not store.is_using_keyring()
                assert store._cipher is not None

                # Should still be able to store and retrieve tokens
                token = TokenSet(
                    access_token="test",
                    token_type="Bearer",
                    resource="https://api.example.com",
                )
                store.set_token("https://api.example.com", token)
                retrieved = store.get_token("https://api.example.com")
                assert retrieved is not None
