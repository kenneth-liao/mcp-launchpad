"""Tests for PKCE (Proof Key for Code Exchange) implementation."""

import base64
import hashlib
import re

import pytest

from mcp_launchpad.oauth.pkce import (
    DEFAULT_VERIFIER_LENGTH,
    MAX_VERIFIER_LENGTH,
    MIN_VERIFIER_LENGTH,
    VERIFIER_CHARS,
    PKCEPair,
    generate_code_challenge,
    generate_code_verifier,
    generate_pkce_pair,
    generate_state,
)


class TestGenerateCodeVerifier:
    """Tests for code verifier generation."""

    def test_default_length(self):
        """Test that default verifier length is 64 characters."""
        verifier = generate_code_verifier()
        assert len(verifier) == DEFAULT_VERIFIER_LENGTH

    def test_custom_length(self):
        """Test generating verifier with custom length."""
        verifier = generate_code_verifier(length=80)
        assert len(verifier) == 80

    def test_minimum_length(self):
        """Test generating verifier with minimum allowed length."""
        verifier = generate_code_verifier(length=MIN_VERIFIER_LENGTH)
        assert len(verifier) == MIN_VERIFIER_LENGTH

    def test_maximum_length(self):
        """Test generating verifier with maximum allowed length."""
        verifier = generate_code_verifier(length=MAX_VERIFIER_LENGTH)
        assert len(verifier) == MAX_VERIFIER_LENGTH

    def test_too_short_raises_error(self):
        """Test that length below minimum raises ValueError."""
        with pytest.raises(ValueError, match="must be between"):
            generate_code_verifier(length=MIN_VERIFIER_LENGTH - 1)

    def test_too_long_raises_error(self):
        """Test that length above maximum raises ValueError."""
        with pytest.raises(ValueError, match="must be between"):
            generate_code_verifier(length=MAX_VERIFIER_LENGTH + 1)

    def test_uses_valid_characters(self):
        """Test that verifier only uses unreserved URI characters."""
        verifier = generate_code_verifier()
        for char in verifier:
            assert char in VERIFIER_CHARS

    def test_randomness(self):
        """Test that verifiers are random (not deterministic)."""
        verifiers = [generate_code_verifier() for _ in range(10)]
        # All should be unique
        assert len(set(verifiers)) == 10


class TestGenerateCodeChallenge:
    """Tests for S256 code challenge generation."""

    def test_produces_base64url_encoded_string(self):
        """Test that challenge is valid base64url without padding."""
        verifier = "test_verifier_string_that_is_long_enough_for_testing"
        challenge = generate_code_challenge(verifier)

        # Should not have padding
        assert "=" not in challenge

        # Should be valid base64url (add padding back for decode)
        padded = challenge + "=" * (4 - len(challenge) % 4)
        base64.urlsafe_b64decode(padded)  # Should not raise

    def test_s256_algorithm(self):
        """Test that challenge uses SHA256 hash."""
        verifier = "test_verifier"
        challenge = generate_code_challenge(verifier)

        # Manually compute expected challenge
        expected_hash = hashlib.sha256(verifier.encode("ascii")).digest()
        expected_challenge = base64.urlsafe_b64encode(expected_hash).decode("ascii").rstrip("=")

        assert challenge == expected_challenge

    def test_deterministic(self):
        """Test that same verifier produces same challenge."""
        verifier = generate_code_verifier()
        challenge1 = generate_code_challenge(verifier)
        challenge2 = generate_code_challenge(verifier)
        assert challenge1 == challenge2

    def test_different_verifiers_different_challenges(self):
        """Test that different verifiers produce different challenges."""
        verifier1 = generate_code_verifier()
        verifier2 = generate_code_verifier()
        challenge1 = generate_code_challenge(verifier1)
        challenge2 = generate_code_challenge(verifier2)
        assert challenge1 != challenge2


class TestPKCEPair:
    """Tests for PKCEPair dataclass."""

    def test_default_method_is_s256(self):
        """Test that default method is S256."""
        pair = PKCEPair(verifier="test", challenge="test")
        assert pair.method == "S256"

    def test_stores_verifier_and_challenge(self):
        """Test that pair stores both verifier and challenge."""
        pair = PKCEPair(verifier="my_verifier", challenge="my_challenge")
        assert pair.verifier == "my_verifier"
        assert pair.challenge == "my_challenge"


class TestGeneratePKCEPair:
    """Tests for generating complete PKCE pairs."""

    def test_generates_valid_pair(self):
        """Test that generate_pkce_pair produces valid verifier/challenge."""
        pair = generate_pkce_pair()

        # Verifier should be valid
        assert len(pair.verifier) == DEFAULT_VERIFIER_LENGTH
        for char in pair.verifier:
            assert char in VERIFIER_CHARS

        # Challenge should match verifier
        expected_challenge = generate_code_challenge(pair.verifier)
        assert pair.challenge == expected_challenge

        # Method should be S256
        assert pair.method == "S256"

    def test_custom_length(self):
        """Test generating pair with custom verifier length."""
        pair = generate_pkce_pair(length=100)
        assert len(pair.verifier) == 100


class TestGenerateState:
    """Tests for state parameter generation."""

    def test_generates_hex_string(self):
        """Test that state is a valid hex string."""
        state = generate_state()
        # Should be 32 hex characters (16 bytes)
        assert len(state) == 32
        assert re.match(r"^[0-9a-f]+$", state)

    def test_randomness(self):
        """Test that state values are random."""
        states = [generate_state() for _ in range(10)]
        assert len(set(states)) == 10
