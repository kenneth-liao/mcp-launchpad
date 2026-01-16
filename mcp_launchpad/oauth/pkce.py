"""PKCE (Proof Key for Code Exchange) implementation per RFC 7636.

PKCE is required by the MCP Authorization Specification for all OAuth flows
to protect authorization codes from interception attacks.
"""

import base64
import hashlib
import secrets
from dataclasses import dataclass


# PKCE code verifier length constraints per RFC 7636
MIN_VERIFIER_LENGTH = 43
MAX_VERIFIER_LENGTH = 128
DEFAULT_VERIFIER_LENGTH = 64

# Allowed characters for code verifier (unreserved URI characters)
VERIFIER_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"


@dataclass
class PKCEPair:
    """PKCE code verifier and challenge pair.

    The verifier is a cryptographically random string sent in the token request.
    The challenge is a SHA256 hash of the verifier sent in the authorization request.
    """

    verifier: str
    challenge: str
    method: str = "S256"


def generate_code_verifier(length: int = DEFAULT_VERIFIER_LENGTH) -> str:
    """Generate a cryptographically random code verifier.

    Per RFC 7636 Section 4.1, the code verifier must be:
    - Between 43 and 128 characters
    - Use only unreserved URI characters: [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"

    Args:
        length: Length of the verifier (default 64, must be 43-128)

    Returns:
        Cryptographically random code verifier string

    Raises:
        ValueError: If length is outside allowed range
    """
    if length < MIN_VERIFIER_LENGTH or length > MAX_VERIFIER_LENGTH:
        raise ValueError(
            f"Code verifier length must be between {MIN_VERIFIER_LENGTH} "
            f"and {MAX_VERIFIER_LENGTH}, got {length}"
        )

    return "".join(secrets.choice(VERIFIER_CHARS) for _ in range(length))


def generate_code_challenge(verifier: str) -> str:
    """Generate S256 code challenge from verifier.

    Per RFC 7636 Section 4.2:
    code_challenge = BASE64URL(SHA256(code_verifier))

    The MCP spec requires S256 method when technically capable.

    Args:
        verifier: The code verifier string

    Returns:
        Base64URL-encoded SHA256 hash of the verifier
    """
    # SHA256 hash of the verifier bytes
    digest = hashlib.sha256(verifier.encode("ascii")).digest()

    # Base64URL encode without padding (per RFC 7636)
    challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")

    return challenge


def generate_pkce_pair(length: int = DEFAULT_VERIFIER_LENGTH) -> PKCEPair:
    """Generate a complete PKCE pair (verifier + challenge).

    This is the main entry point for PKCE generation.

    Args:
        length: Length of the code verifier (default 64)

    Returns:
        PKCEPair with verifier, challenge, and method (always "S256")
    """
    verifier = generate_code_verifier(length)
    challenge = generate_code_challenge(verifier)

    return PKCEPair(verifier=verifier, challenge=challenge, method="S256")


def generate_state() -> str:
    """Generate a cryptographically random state parameter.

    The state parameter protects against CSRF attacks by ensuring
    the authorization response came from a request we initiated.

    Returns:
        32-character random hex string
    """
    return secrets.token_hex(16)
