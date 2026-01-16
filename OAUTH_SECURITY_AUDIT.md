# OAuth Security Audit - Final Review

## Executive Summary

This audit covers the OAuth 2.1 implementation in PR #14 for MCP Launchpad. The implementation follows security best practices with PKCE, state validation, and encrypted token storage. However, several security gaps and edge cases require attention before this goes to production with thousands of users.

**Overall Assessment:** Good foundation with critical issues to address

---

## PR #14 Review Summary

### Previously Identified & Fixed Issues

The code review identified 5 issues, all addressed in commit `2931d65`:

| Issue | Severity | Status |
|-------|----------|--------|
| Client secret input not masked | Medium | Fixed |
| Client secret exposed in process listing (`ps aux`) | High | Fixed |
| Weak fallback encryption key derivation | Medium | Fixed (warnings added) |
| Race condition in port allocation | Medium | Fixed |
| Silent data loss on decryption failure | High | Fixed |

---

## New Security Findings

### CRITICAL Priority

#### 1. XSS Vulnerability in Callback Server

**File:** `mcp_launchpad/oauth/callback.py:338-341`

**Issue:** OAuth error messages are interpolated directly into HTML without escaping:
```python
error_html = ERROR_HTML.format(
    error=result.error or "unknown_error",
    description=result.error_description or "No description provided",
)
```

**Attack Vector:**
- Attacker configures malicious OAuth server or intercepts redirect
- Sets `error_description` to `<script>alert(document.cookie)</script>`
- User sees XSS payload rendered in browser

**Risk:** An attacker could steal session cookies or execute arbitrary JavaScript in the user's browser context.

**Fix:**
```python
import html

error_html = ERROR_HTML.format(
    error=html.escape(result.error or "unknown_error"),
    description=html.escape(result.error_description or "No description provided"),
)
```

---

#### 2. No HTTPS Enforcement on OAuth Endpoints

**Files:** `mcp_launchpad/oauth/discovery.py`, `mcp_launchpad/oauth/flow.py`

**Issue:** OAuth metadata discovery and token exchange don't validate that endpoints use HTTPS. A malicious server could provide HTTP endpoints, allowing man-in-the-middle attacks.

**Attack Vector:**
- Attacker performs DNS spoofing or network interception
- Returns OAuth metadata with HTTP token endpoint
- Intercepts authorization code and exchanges it for tokens
- User tokens are stolen

**Affected Locations:**
- `discovery.py:218-219`: Fetching protected resource metadata
- `discovery.py:276`: Fetching auth server metadata
- `flow.py:215-216`: Token endpoint request
- `flow.py:278-279`: Refresh token request

**Fix:** Add HTTPS validation:
```python
def _validate_https_url(url: str, context: str) -> None:
    """Validate that a URL uses HTTPS."""
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise DiscoveryError(
            f"{context} must use HTTPS, got: {url}"
        )
```

---

#### 3. Authorization URL Not Validated Before Opening

**File:** `mcp_launchpad/oauth/flow.py:490`

**Issue:** The authorization URL from server metadata is opened in browser without validation. A malicious or compromised OAuth metadata response could redirect users to a phishing site.

**Attack Vector:**
1. Attacker compromises OAuth metadata endpoint or performs MITM
2. Returns `authorization_endpoint: "https://evil-phishing-site.com/login"`
3. User is directed to fake login page
4. Credentials harvested

**Fix:**
- Validate authorization endpoint matches expected domain
- Warn if domain differs significantly from resource URL
- Consider implementing a domain allowlist for known providers

---

### HIGH Priority

#### 4. Token Leakage in Error Messages

**File:** `mcp_launchpad/oauth/flow.py:223-227, 287-290`

**Issue:** Error responses may contain tokens in the response body, which is logged and included in error messages:
```python
error_detail = f": {response.text[:200]}"
```

**Risk:** If an auth server returns an error with token data in the body, it could leak to logs.

**Fix:** Sanitize error responses:
```python
def _safe_error_detail(response: httpx.Response) -> str:
    """Extract error detail without sensitive data."""
    try:
        data = response.json()
        return f": {data.get('error', '')} - {data.get('error_description', '')}"
    except Exception:
        # Don't include raw response body
        return f" (HTTP {response.status_code})"
```

---

#### 5. No Token Revocation on Logout

**File:** `mcp_launchpad/oauth/manager.py:294-306`

**Issue:** The `logout()` method only deletes local tokens. Server-side tokens remain valid until expiry.

**Security Impact:** If a user's machine is compromised and they run `mcpl auth logout`, the attacker could still use previously extracted tokens.

**Fix:** Implement RFC 7009 token revocation:
```python
async def logout(self, server_url: str) -> bool:
    """Revoke and remove stored authentication."""
    token = self._store.get_token(server_url)
    if token:
        # Attempt server-side revocation
        await self._revoke_token(server_url, token)
    return self._store.delete_token(server_url)
```

---

#### 6. Missing Test Coverage for Critical Paths

**Current Coverage Gaps:**

| Module | Test File | Coverage |
|--------|-----------|----------|
| `callback.py` | None | 0% |
| `flow.py` | None | 0% |
| `manager.py` | None | 0% |
| CLI auth commands | None | 0% |

**Critical untested paths:**
- Complete OAuth flow execution
- Callback server HTTP handling
- State validation (CSRF protection)
- Token refresh logic
- Error handling in token exchange

**Fix:** Add comprehensive tests (see Test Plan section below)

---

### MEDIUM Priority

#### 7. Race Condition in Token Storage

**File:** `mcp_launchpad/oauth/store.py:267-278`

**Issue:** Token storage uses read-modify-write without locking:
```python
tokens_data = self._read_encrypted_file(TOKENS_FILE)
tokens_data[key] = token.to_dict()
self._write_encrypted_file(TOKENS_FILE, tokens_data)
```

**Risk:** Concurrent OAuth flows (e.g., parallel `mcpl auth login` in different terminals) could lose tokens.

**Fix:** Use file locking:
```python
import fcntl

def _write_encrypted_file(self, filename: str, data: dict) -> None:
    filepath = self.store_dir / filename
    with open(filepath, 'w') as f:
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        try:
            json_data = json.dumps(data, indent=2)
            encrypted_data = self._encrypt(json_data)
            f.write(encrypted_data)
        finally:
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)
```

---

#### 8. Singleton OAuthManager Not Thread-Safe

**File:** `mcp_launchpad/oauth/manager.py:318-330`

**Issue:** The global `_manager` singleton is not protected for concurrent access.

**Fix:** Use threading lock:
```python
import threading
_manager_lock = threading.Lock()

def get_oauth_manager() -> OAuthManager:
    global _manager
    with _manager_lock:
        if _manager is None:
            _manager = OAuthManager()
        return _manager
```

---

#### 9. Insufficient Input Validation in WWW-Authenticate Parsing

**File:** `mcp_launchpad/oauth/discovery.py:137`

**Issue:** The regex pattern for parsing WWW-Authenticate doesn't validate URL format:
```python
pattern = r'(\w+)=(?:"([^"]+)"|([^\s,]+))'
```

**Risk:** Malformed URLs could be accepted and cause issues downstream.

**Fix:** Add URL validation after parsing:
```python
def get_resource_metadata_url(www_authenticate: str) -> str:
    params = parse_www_authenticate(www_authenticate)
    url = params.get("resource_metadata")
    if not url:
        raise DiscoveryError("...")

    # Validate URL format
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        raise DiscoveryError(f"Invalid resource_metadata URL: {url}")

    return url
```

---

#### 10. Client Credentials Reused Across Redirect URIs

**File:** `mcp_launchpad/oauth/flow.py:404-407`

**Issue:** Stored DCR credentials can be reused with any redirect URI without validation.

**Risk:** If an attacker can trigger an OAuth flow with a different redirect URI, they could potentially capture authorization codes.

**Fix:** Store redirect_uri with credentials and validate on reuse.

---

### LOW Priority

#### 11. No Rate Limiting on Callback Server

**File:** `mcp_launchpad/oauth/callback.py:289-362`

**Issue:** The callback server accepts unlimited connections without rate limiting.

**Fix:** Add connection limiting or use `asyncio.Semaphore`.

---

#### 12. Token Expiry Buffer May Be Insufficient

**File:** `mcp_launchpad/oauth/tokens.py:37-62`

**Issue:** The 30-second expiry buffer might be too short for slow networks or during refresh operations.

**Fix:** Make buffer configurable, consider 60-120 seconds for production.

---

#### 13. No Audit Logging for Authentication Events

**Issue:** Authentication successes/failures are logged at DEBUG level but should be at INFO for audit purposes.

**Fix:** Add INFO-level logging for security events:
```python
logger.info(f"OAuth authentication successful for {server_url}")
logger.warning(f"OAuth authentication failed for {server_url}: {error}")
```

---

#### 14. Potential Path Confusion in Resource Normalization

**File:** `mcp_launchpad/oauth/store.py:232-242`

**Issue:** Resource URL normalization doesn't handle all edge cases:
```python
return resource.rstrip("/").lower()
```

**Examples of potential confusion:**
- `https://example.com/api` vs `https://example.com/api/`
- `https://EXAMPLE.COM/API` vs `https://example.com/api`
- `https://example.com:443/api` vs `https://example.com/api`

**Fix:** Use more robust URL normalization.

---

#### 15. Missing Security Headers in Callback Response

**File:** `mcp_launchpad/oauth/callback.py:382-398`

**Issue:** HTML responses don't include security headers.

**Fix:** Add security headers:
```python
headers = (
    f"HTTP/1.1 {status.value} {status.phrase}\r\n"
    f"Content-Type: text/html; charset=utf-8\r\n"
    f"Content-Length: {len(body)}\r\n"
    f"X-Content-Type-Options: nosniff\r\n"
    f"X-Frame-Options: DENY\r\n"
    f"Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'\r\n"
    f"Connection: close\r\n"
    f"\r\n"
)
```

---

## Test Plan

### Required New Tests

#### 1. Callback Server Tests (`tests/test_oauth_callback.py`)

```python
class TestCallbackServer:
    async def test_successful_callback_returns_code()
    async def test_error_callback_returns_error()
    async def test_state_parameter_extracted()
    async def test_rejects_non_get_requests()
    async def test_handles_favicon_request()
    async def test_handles_wrong_path()
    async def test_timeout_raises_error()
    async def test_xss_prevention_in_error_display()  # Critical
    async def test_multiple_callbacks_handled()
```

#### 2. OAuth Flow Tests (`tests/test_oauth_flow.py`)

```python
class TestOAuthFlow:
    async def test_full_flow_success()
    async def test_state_mismatch_raises_error()  # CSRF protection
    async def test_pkce_verifier_sent_in_token_request()
    async def test_resource_uri_included()
    async def test_dcr_registration()
    async def test_manual_credentials_prompt()
    async def test_token_exchange_error_handling()
    async def test_https_required_for_endpoints()  # Critical
```

#### 3. Manager Tests (`tests/test_oauth_manager.py`)

```python
class TestOAuthManager:
    async def test_authenticate_stores_token()
    async def test_refresh_expired_token()
    async def test_refresh_without_refresh_token()
    async def test_logout_removes_token()
    async def test_has_valid_token()
    async def test_get_auth_header()
```

#### 4. CLI Integration Tests (`tests/test_cli_auth.py`)

```python
class TestCLIAuth:
    def test_auth_login_requires_http_server()
    def test_auth_login_masks_secret_input()
    def test_auth_login_reads_stdin_secret()
    def test_auth_logout_clears_tokens()
    def test_auth_status_shows_expiry()
    def test_keyring_warning_displayed()
```

---

## Implementation Priority

### Phase 1: Critical Security Fixes (Before Merge) - COMPLETED

1. **Fix XSS in callback server** - `callback.py:338-341` - DONE
   - Added `html.escape()` for error messages
   - Added security headers (X-Content-Type-Options, X-Frame-Options, CSP)
2. **Add HTTPS enforcement** - `discovery.py`, `flow.py` - DONE
   - Added `_require_https()` validation function
   - Enforced HTTPS for auth, token, and registration endpoints
3. **Add callback server tests** - Basic coverage for critical paths - DONE
   - 20 new tests in `test_oauth_callback.py`
   - Tests for XSS prevention, security headers, HTTP methods
4. **Sanitize error messages** - Remove potential token leakage - DONE
   - Removed raw response.text from error messages
   - Only extract safe error/error_description fields

### Phase 2: High Priority (Before Production) - COMPLETED

5. **Token revocation on logout** - RFC 7009 - DONE
   - Added `revoke_token()` function to flow.py
   - Added `logout_async()` method to OAuthManager
   - CLI now calls async logout for server-side revocation
   - 7 new tests for revocation functionality
6. **File locking for token storage** - Race condition fix - DONE
   - Added cross-platform file locking (fcntl/msvcrt)
   - Read operations use shared locks
   - Write operations use exclusive locks
7. **Thread-safe OAuthManager singleton** - DONE
   - Added threading.Lock with double-checked locking pattern
8. **Add revocation_endpoint support** - DONE
   - Added to AuthServerMetadata with HTTPS validation
   - Added `supports_revocation()` method

### Phase 3: Medium Priority (Next Sprint)

9. **Add file locking** - Token storage race condition
10. **Thread-safe singleton** - OAuthManager
11. **URL validation** - WWW-Authenticate parsing
12. **Security headers** - Callback responses

### Phase 4: Low Priority (Future)

13. **Rate limiting** - Callback server
14. **Configurable expiry buffer** - Token refresh
15. **Audit logging** - Authentication events
16. **Robust URL normalization** - Resource storage

---

## Verification Checklist

Before merging to production:

- [ ] XSS vulnerability fixed and tested
- [ ] HTTPS enforcement added
- [ ] Test coverage > 80% for OAuth package
- [ ] All 67 existing tests still pass
- [ ] Manual test with real OAuth server (Notion/Figma)
- [ ] Security review of error messages (no token leakage)
- [ ] Keyring fallback warnings display correctly
- [ ] `mcpl auth logout --all` clears all data

---

## Appendix: Security Model Summary

### What's Working Well

1. **PKCE Implementation** - RFC 7636 compliant, S256 enforced
2. **State Parameter** - CSRF protection with validation
3. **Token Encryption** - Fernet (AES-128-CBC + HMAC)
4. **Key Management** - OS keyring with machine-specific fallback
5. **File Permissions** - 0700 directory, 0600 files
6. **Resource Binding** - RFC 8707 token isolation
7. **Localhost Callback** - Only binds to 127.0.0.1

### Attack Surface

| Vector | Mitigation | Gap |
|--------|------------|-----|
| Token interception | PKCE | None |
| CSRF | State parameter | None |
| Token theft (disk) | Fernet encryption | Fallback key derivation is weak |
| Token theft (memory) | N/A | Tokens in memory during flow |
| MITM | None | **HTTPS not enforced** |
| XSS | None | **Error messages not escaped** |
| Phishing | None | **Auth URL not validated** |

---

*Generated: 2026-01-15*
*Author: Claude Code Security Audit*
