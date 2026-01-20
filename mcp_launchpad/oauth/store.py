"""Encrypted token storage for OAuth tokens.

This module provides secure storage for OAuth tokens using:
- Fernet symmetric encryption (AES-128-CBC + HMAC)
- OS keyring for encryption key storage (Keychain, libsecret, DPAPI)
- File permissions for defense in depth
- File locking to prevent race conditions
"""

import base64
import hashlib
import json
import logging
import os
import stat
import sys
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Generator

import keyring
from cryptography.fernet import Fernet, InvalidToken

from .tokens import ClientCredentials, TokenSet

logger = logging.getLogger(__name__)

# File locking support
if sys.platform != "win32":
    import fcntl

    @contextmanager
    def _file_lock(filepath: Path, exclusive: bool = True) -> Generator[None, None, None]:
        """Acquire a file lock (Unix implementation using fcntl).

        Args:
            filepath: Path to the file to lock
            exclusive: If True, acquire exclusive lock; otherwise shared lock
        """
        lock_path = filepath.with_suffix(filepath.suffix + ".lock")
        lock_path.touch(exist_ok=True)

        with open(lock_path, "r") as lock_file:
            try:
                if exclusive:
                    fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
                else:
                    fcntl.flock(lock_file.fileno(), fcntl.LOCK_SH)
                yield
            finally:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
else:
    # Windows: use msvcrt for file locking
    import msvcrt

    @contextmanager
    def _file_lock(filepath: Path, exclusive: bool = True) -> Generator[None, None, None]:
        """Acquire a file lock (Windows implementation using msvcrt).

        Args:
            filepath: Path to the file to lock
            exclusive: If True, acquire exclusive lock; otherwise shared lock
        """
        lock_path = filepath.with_suffix(filepath.suffix + ".lock")
        lock_path.touch(exist_ok=True)

        with open(lock_path, "r+") as lock_file:
            try:
                if exclusive:
                    msvcrt.locking(lock_file.fileno(), msvcrt.LK_LOCK, 1)
                else:
                    # Windows doesn't have true shared locks with msvcrt
                    msvcrt.locking(lock_file.fileno(), msvcrt.LK_LOCK, 1)
                yield
            finally:
                try:
                    msvcrt.locking(lock_file.fileno(), msvcrt.LK_UNLCK, 1)
                except OSError:
                    pass


# Keyring service name for mcpl
KEYRING_SERVICE = "mcp-launchpad"
KEYRING_USERNAME = "oauth-encryption-key"

# Default storage location
DEFAULT_STORE_DIR = Path.home() / ".cache" / "mcp-launchpad" / "oauth"

# File names
TOKENS_FILE = "tokens.json"
CLIENTS_FILE = "clients.json"


class TokenStoreError(Exception):
    """Error in token storage operations."""

    pass


class TokenDecryptionError(TokenStoreError):
    """Failed to decrypt token storage file.

    This error indicates the encryption key has changed (e.g., keyring cleared,
    different machine) and existing tokens cannot be read. The caller should
    handle this by either:
    - Prompting the user to re-authenticate
    - Clearing existing tokens with clear_all()
    """

    pass


def _derive_fallback_key() -> bytes:
    """Derive a fallback encryption key from machine-specific data.

    Used when keyring is not available. Less secure than keyring but
    still provides encryption at rest.

    Returns:
        32-byte key suitable for Fernet
    """
    # Gather machine-specific data
    components = []

    # Machine ID (Linux)
    machine_id_path = Path("/etc/machine-id")
    if machine_id_path.exists():
        components.append(machine_id_path.read_text().strip())

    # Home directory (all platforms)
    components.append(str(Path.home()))

    # Username
    components.append(os.environ.get("USER", os.environ.get("USERNAME", "mcpl")))

    # Combine and hash
    combined = ":".join(components)
    key_bytes = hashlib.sha256(combined.encode()).digest()

    # Fernet requires base64-encoded 32-byte key
    return base64.urlsafe_b64encode(key_bytes)


class TokenStore:
    """Encrypted storage for OAuth tokens.

    Tokens are encrypted using Fernet (AES-128-CBC + HMAC) with the
    encryption key stored in the OS keyring for maximum security.

    Token files are stored in ~/.cache/mcp-launchpad/oauth/ with
    restricted file permissions (0600).
    """

    def __init__(self, store_dir: Path | None = None):
        """Initialize token store.

        Args:
            store_dir: Optional custom storage directory
        """
        self.store_dir = store_dir or DEFAULT_STORE_DIR
        self._cipher: Fernet | None = None
        self._using_keyring = False

        self._init_storage()
        self._init_encryption()

    def _init_storage(self) -> None:
        """Initialize storage directory with secure permissions."""
        self.store_dir.mkdir(parents=True, exist_ok=True)

        # Set directory permissions to 0700 (owner only)
        try:
            self.store_dir.chmod(stat.S_IRWXU)
        except OSError as e:
            logger.warning(f"Could not set directory permissions: {e}")

    def _init_encryption(self) -> None:
        """Initialize encryption using keyring or fallback."""
        try:
            # Try to get key from keyring
            key = keyring.get_password(KEYRING_SERVICE, KEYRING_USERNAME)

            if key is None:
                # Generate new key and store in keyring
                key = Fernet.generate_key().decode("ascii")
                keyring.set_password(KEYRING_SERVICE, KEYRING_USERNAME, key)
                logger.debug("Generated new encryption key in keyring")

            self._cipher = Fernet(key.encode("ascii"))
            self._using_keyring = True
            logger.debug("Using keyring for encryption key storage")

        except Exception as e:
            # Fallback to derived key if keyring fails
            error_type = type(e).__name__
            logger.warning(
                f"Keyring not available: {error_type}: {e}. "
                f"Using fallback encryption (machine-derived key). "
                f"Tokens are still encrypted but with reduced security. "
                f"To use keyring: ensure a keyring backend is installed "
                f"(e.g., gnome-keyring on Linux, Keychain on macOS)."
            )
            logger.debug(f"Full keyring error: {e!r}")
            fallback_key = _derive_fallback_key()
            self._cipher = Fernet(fallback_key)
            self._using_keyring = False

    def _encrypt(self, data: str) -> str:
        """Encrypt a string.

        Args:
            data: Plaintext string to encrypt

        Returns:
            Base64-encoded ciphertext
        """
        if self._cipher is None:
            raise TokenStoreError("Encryption not initialized")
        return self._cipher.encrypt(data.encode("utf-8")).decode("ascii")

    def _decrypt(self, data: str) -> str:
        """Decrypt a string.

        Args:
            data: Base64-encoded ciphertext

        Returns:
            Decrypted plaintext string

        Raises:
            TokenStoreError: If decryption fails
        """
        if self._cipher is None:
            raise TokenStoreError("Encryption not initialized")
        try:
            return self._cipher.decrypt(data.encode("ascii")).decode("utf-8")
        except InvalidToken as e:
            raise TokenStoreError(
                "Failed to decrypt token data. The encryption key may have changed."
            ) from e

    def _read_encrypted_file(self, filename: str) -> dict[str, Any]:
        """Read and decrypt a JSON file with file locking.

        Uses shared (read) lock to allow concurrent reads but block writes.

        Args:
            filename: Name of file in store directory

        Returns:
            Decrypted JSON data as dictionary

        Raises:
            TokenDecryptionError: If decryption fails (key changed, corrupted data)
        """
        filepath = self.store_dir / filename

        if not filepath.exists():
            return {}

        try:
            with _file_lock(filepath, exclusive=False):  # Shared lock for reading
                encrypted_data = filepath.read_text()
                decrypted_json = self._decrypt(encrypted_data)
                result: dict[str, Any] = json.loads(decrypted_json)
                return result
        except TokenStoreError as e:
            # Decryption failed - raise so caller can decide how to handle
            raise TokenDecryptionError(
                f"Cannot decrypt {filename}. The encryption key may have changed. "
                f"Run 'mcpl auth logout --all' to clear stored tokens and re-authenticate."
            ) from e
        except json.JSONDecodeError as e:
            # Data decrypted but is not valid JSON - file may be corrupted
            raise TokenDecryptionError(
                f"Token file {filename} is corrupted. "
                f"Run 'mcpl auth logout --all' to clear and re-authenticate."
            ) from e

    def _write_encrypted_file(self, filename: str, data: dict[str, Any]) -> None:
        """Encrypt and write a JSON file with secure permissions and file locking.

        Uses exclusive (write) lock to prevent concurrent reads/writes.

        Args:
            filename: Name of file in store directory
            data: Dictionary to serialize and encrypt
        """
        filepath = self.store_dir / filename

        json_data = json.dumps(data, indent=2)
        encrypted_data = self._encrypt(json_data)

        # Write with exclusive lock and secure permissions
        with _file_lock(filepath, exclusive=True):  # Exclusive lock for writing
            filepath.write_text(encrypted_data)
            try:
                filepath.chmod(stat.S_IRUSR | stat.S_IWUSR)  # 0600
            except OSError as e:
                logger.warning(f"Could not set file permissions: {e}")

    def _normalize_resource(self, resource: str) -> str:
        """Normalize a resource URL for consistent key lookup.

        Args:
            resource: Resource URL or server name

        Returns:
            Normalized key for storage lookup
        """
        # Remove trailing slashes and convert to lowercase for consistency
        return resource.rstrip("/").lower()

    # Token operations

    def get_token(self, resource: str) -> TokenSet | None:
        """Get token for a resource.

        Args:
            resource: The resource URL

        Returns:
            TokenSet if found, None otherwise
        """
        key = self._normalize_resource(resource)
        tokens_data = self._read_encrypted_file(TOKENS_FILE)

        if key not in tokens_data:
            return None

        try:
            return TokenSet.from_dict(tokens_data[key])
        except (KeyError, ValueError) as e:
            logger.warning(f"Invalid token data for {resource}: {e}")
            return None

    def set_token(self, resource: str, token: TokenSet) -> None:
        """Store token for a resource.

        Args:
            resource: The resource URL
            token: The token set to store
        """
        key = self._normalize_resource(resource)
        tokens_data = self._read_encrypted_file(TOKENS_FILE)

        tokens_data[key] = token.to_dict()
        self._write_encrypted_file(TOKENS_FILE, tokens_data)

        logger.debug(f"Stored token for {resource}")

    def delete_token(self, resource: str) -> bool:
        """Delete token for a resource.

        Args:
            resource: The resource URL

        Returns:
            True if token was deleted, False if not found
        """
        key = self._normalize_resource(resource)
        tokens_data = self._read_encrypted_file(TOKENS_FILE)

        if key not in tokens_data:
            return False

        del tokens_data[key]
        self._write_encrypted_file(TOKENS_FILE, tokens_data)

        logger.debug(f"Deleted token for {resource}")
        return True

    def list_resources(self) -> list[str]:
        """List all resources with stored tokens.

        Returns:
            List of resource URLs
        """
        tokens_data = self._read_encrypted_file(TOKENS_FILE)
        return list(tokens_data.keys())

    def get_token_info(self, resource: str) -> dict[str, Any] | None:
        """Get non-sensitive token info for display.

        Args:
            resource: The resource URL

        Returns:
            Dictionary with token metadata (no secrets), or None
        """
        token = self.get_token(resource)
        if token is None:
            return None

        info: dict[str, Any] = {
            "resource": resource,
            "token_type": token.token_type,
            "has_refresh_token": token.has_refresh_token(),
            "issued_at": token.issued_at.isoformat() if token.issued_at else None,
            "expires_at": token.expires_at.isoformat() if token.expires_at else None,
            "is_expired": token.is_expired(),
            "scope": token.scope,
        }

        return info

    # Client credentials operations

    def get_client(self, auth_server: str) -> ClientCredentials | None:
        """Get client credentials for an authorization server.

        Used for storing DCR-obtained or manually configured client credentials.

        Args:
            auth_server: The authorization server URL

        Returns:
            ClientCredentials if found, None otherwise
        """
        key = self._normalize_resource(auth_server)
        clients_data = self._read_encrypted_file(CLIENTS_FILE)

        if key not in clients_data:
            return None

        try:
            return ClientCredentials.from_dict(clients_data[key])
        except (KeyError, ValueError) as e:
            logger.warning(f"Invalid client data for {auth_server}: {e}")
            return None

    def set_client(self, auth_server: str, client: ClientCredentials) -> None:
        """Store client credentials for an authorization server.

        Args:
            auth_server: The authorization server URL
            client: The client credentials to store
        """
        key = self._normalize_resource(auth_server)
        clients_data = self._read_encrypted_file(CLIENTS_FILE)

        clients_data[key] = client.to_dict()
        self._write_encrypted_file(CLIENTS_FILE, clients_data)

        logger.debug(f"Stored client credentials for {auth_server}")

    def delete_client(self, auth_server: str) -> bool:
        """Delete client credentials for an authorization server.

        Args:
            auth_server: The authorization server URL

        Returns:
            True if deleted, False if not found
        """
        key = self._normalize_resource(auth_server)
        clients_data = self._read_encrypted_file(CLIENTS_FILE)

        if key not in clients_data:
            return False

        del clients_data[key]
        self._write_encrypted_file(CLIENTS_FILE, clients_data)

        logger.debug(f"Deleted client credentials for {auth_server}")
        return True

    # Utility methods

    def clear_all(self) -> None:
        """Clear all stored tokens and client credentials.

        Use with caution - this deletes all authentication data.
        """
        tokens_file = self.store_dir / TOKENS_FILE
        clients_file = self.store_dir / CLIENTS_FILE

        if tokens_file.exists():
            tokens_file.unlink()
        if clients_file.exists():
            clients_file.unlink()

        logger.info("Cleared all stored authentication data")

    def is_using_keyring(self) -> bool:
        """Check if keyring is being used for encryption key storage.

        Returns:
            True if using OS keyring, False if using fallback
        """
        return self._using_keyring
