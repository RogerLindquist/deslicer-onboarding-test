# API key rotation and server-status checking.
# Imported by _enrollment.py and deslicer_ai_insights_helper.py.

import json
import logging
import os
import re
import subprocess
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Optional

KEY_EXPIRY_WARNING_DAYS = 7

_REDACTED = "[REDACTED]"
_BEARER_PATTERN = re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._\-+/=]+")
_SENSITIVE_JSON_FIELDS = (
    "api_key",
    "api_token",
    "access_token",
    "refresh_token",
    "secret",
    "password",
    "token",
    "new_key",
    "key",
)
_JSON_FIELD_PATTERN = re.compile(
    r'(?i)("(?:' + "|".join(_SENSITIVE_JSON_FIELDS) + r')"\s*:\s*")[^"]*(")'
)


def _scrub_secrets(text: str, *secrets: str) -> str:
    """Redact credential material from untrusted subprocess output."""
    if not text:
        return text
    cleaned = text
    for secret in secrets:
        if secret and len(secret) >= 4:
            cleaned = cleaned.replace(secret, _REDACTED)
    cleaned = _BEARER_PATTERN.sub(r"\1" + _REDACTED, cleaned)
    cleaned = _JSON_FIELD_PATTERN.sub(r"\1" + _REDACTED + r"\2", cleaned)
    return cleaned


def _truthy(value) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def _allow_tls_insecure() -> bool:
    return os.environ.get("DESLICER_ALLOW_TLS_INSECURE", "").lower() in (
        "1",
        "true",
        "yes",
    )


def observer_tls_child_env(
    creds: dict, child_env: dict, logger: logging.Logger
) -> None:
    """Mirror collector TLS env for key-status / rotation subprocesses."""
    observer_url = creds.get("observer_api_url", "")
    if observer_url.startswith("http://"):
        logger.warning(
            "Observer URL uses plain HTTP (dev/test only). "
            "Use https:// in production and Splunk Cloud."
        )
        child_env["INSECURE_HTTP"] = "true"
        child_env["DAP_ENV"] = "local"
        return

    ca_cert_path = creds.get("observer_ca_cert_path", "")
    if ca_cert_path:
        child_env["OBSERVER_API_CA_CERT_PATH"] = ca_cert_path
        logger.debug(
            "Using custom CA certificate for TLS verification: %s",
            ca_cert_path,
        )

    if _truthy(creds.get("observer_tls_insecure_skip_verify")):
        if not _allow_tls_insecure():
            logger.error(
                "observer_tls_insecure_skip_verify=true is set but "
                "DESLICER_ALLOW_TLS_INSECURE is not enabled on this host; ignoring."
            )
            return
        logger.warning(
            "observer_tls_insecure_skip_verify=true AND "
            "DESLICER_ALLOW_TLS_INSECURE=1 — TLS certificate verification "
            "will be DISABLED for the Observer connection."
        )
        child_env["INSECURE_HTTP"] = "true"
        child_env["DAP_ENV"] = "local"


def parse_rotation_expires_at(data: dict) -> str:
    """Return expiry from rotation JSON or enrolled credential store."""
    return (data.get("api_key_expires_at") or data.get("expires_at") or "").strip()


def key_needs_rotation(creds: dict, logger: logging.Logger) -> bool:
    expires_at = creds.get("api_key_expires_at", "")
    if not expires_at:
        return False
    try:
        ts = expires_at.replace("Z", "+00:00")
        # Python < 3.11 only supports up to 6 fractional digits (microseconds).
        # Rust/Go timestamps may include 9 digits (nanoseconds) — truncate.
        ts = re.sub(r"(\.\d{6})\d+", r"\1", ts)
        expiry = datetime.fromisoformat(ts)
        now = datetime.now(tz=timezone.utc)
        days = (expiry - now).days
        if days < 0:
            logger.warning("API key has expired (%s) — re-enrolling", expires_at)
            return True
        if days <= KEY_EXPIRY_WARNING_DAYS:
            logger.warning("API key expires in %d day(s) — rotating", days)
            return True
        return False
    except Exception:
        logger.debug("Could not parse expiry '%s'", expires_at, exc_info=True)
        return False


KEY_STATUS_INTERVAL_MIN_SECS = 300
KEY_STATUS_INTERVAL_MAX_SECS = 900


def next_key_status_interval_secs() -> int:
    """Jittered poll interval so fleet key-status traffic does not align."""
    import random

    return random.randint(  # noqa: S311
        KEY_STATUS_INTERVAL_MIN_SECS, KEY_STATUS_INTERVAL_MAX_SECS
    )


def check_observer_health(creds: dict, logger: logging.Logger) -> bool:
    """Check unauthenticated Observer health before authenticated key-status."""
    api_url = creds.get("observer_api_url", "")
    if not api_url:
        return False

    req = urllib.request.Request(  # noqa: S310
        f"{api_url.rstrip('/')}/health",
        headers={"Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310
            return 200 <= resp.status < 300
    except urllib.error.HTTPError as exc:
        logger.debug("Observer health check HTTP %d", exc.code)
    except Exception as exc:
        logger.debug("Observer health check failed: %s", exc)
    return False


def check_server_key_status(
    creds: dict,
    logger: logging.Logger,
) -> Optional[str]:
    """Poll GET /api/v1/key-status. Returns 'rotate', 'revoked', or None."""
    api_url = creds.get("observer_api_url", "")
    api_key = creds.get("api_token", "")
    if not api_url or not api_key:
        return None

    if not check_observer_health(creds, logger):
        return None

    url = f"{api_url.rstrip('/')}/api/v1/key-status"
    req = urllib.request.Request(  # noqa: S310
        url,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Accept": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310
            data = json.loads(resp.read().decode())
            if data.get("needs_rotation"):
                server_expiry = data.get("expires_at", "")
                logger.info(
                    "Server signaled rotation (expires %s)", server_expiry or "?"
                )
                if server_expiry:
                    creds["api_key_expires_at"] = server_expiry
                return "rotate"
            if not data.get("is_active"):
                logger.warning("Server reports key is revoked/inactive")
                return "revoked"
    except urllib.error.HTTPError as e:
        if e.code == 401:
            logger.warning("Key-status: 401 (key revoked or expired)")
            return "revoked"
        logger.debug("Key-status HTTP %d", e.code)
    except Exception as exc:
        logger.debug("Key-status check failed: %s", exc)
    return None


def run_key_rotation(
    session_key: str,
    creds: dict,
    binary: str,
    logger: logging.Logger,
    write_fn,
) -> Optional[dict]:
    """Invoke binary --rotate-key and update credentials in store."""
    api_url = creds.get("observer_api_url", "")
    api_key = creds.get("api_token", "")
    if not api_url:
        logger.warning("Cannot rotate key: observer_api_url is missing")
        return None
    if not api_key:
        logger.warning("Cannot rotate key: no current API key")
        return None

    # Pass credentials via env only so argv does not expose secrets in ps(1).
    cmd = [binary, "--rotate-key", "--api-url", api_url]
    child_env = os.environ.copy()
    child_env["NO_COLOR"] = "1"
    child_env["OBSERVER_API_KEY"] = api_key
    observer_tls_child_env(creds, child_env, logger)

    logger.info("Starting key rotation")
    try:
        result = subprocess.run(  # noqa: S603
            cmd,
            capture_output=True,
            text=True,
            timeout=60,
            env=child_env,
        )
    except subprocess.TimeoutExpired:
        logger.warning("Key rotation timed out after 60s")
        return None
    except OSError as e:
        logger.warning("Key rotation binary execution failed: %s", e)
        return None

    if result.returncode != 0:
        stderr_raw = result.stderr.strip() if result.stderr else ""
        stderr_safe = (
            _scrub_secrets(stderr_raw, api_key) if stderr_raw else "no stderr"
        )
        logger.warning(
            "Key rotation failed (exit %d): %s",
            result.returncode,
            stderr_safe,
        )
        return None

    stdout = result.stdout.strip()
    if not stdout:
        logger.warning("Key rotation returned empty response")
        return None

    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        logger.warning(
            "Key rotation returned invalid JSON: %s",
            _scrub_secrets(stdout[:200], api_key),
        )
        return None

    new_key = data.get("api_key", "")
    new_tenant = data.get("tenant_id", "") or creds.get("tenant_id", "")
    new_expires_at = parse_rotation_expires_at(data)

    if not new_key:
        logger.warning("Key rotation response missing api_key")
        return None

    try:
        write_fn(
            session_key,
            "enrolled_account",
            new_key,
            new_tenant,
            api_url,
            logger,
            expires_at=new_expires_at,
        )
    except Exception:
        logger.exception("Failed to persist rotated key")
        return None

    logger.info(
        "Key rotation successful: expires=%s",
        new_expires_at or "never",
    )
    return {
        "api_token": new_key,
        "tenant_id": new_tenant,
        "observer_api_url": api_url,
        "api_key_expires_at": new_expires_at,
    }
