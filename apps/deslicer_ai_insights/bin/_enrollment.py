# Enrollment, credential store helpers.
# Imported by deslicer_ai_insights_helper.py.

import configparser as ini_parser
import fcntl
import hashlib
import json
import logging
import os
import re
import subprocess
import tempfile

import splunklib.client as splunk_client
from solnlib import conf_manager

from _key_management import run_key_rotation as _run_key_rotation  # noqa: F401
from _log_throttle import ENROLLMENT_RECOVERY_LOG_KEY, log_throttled

# Patterns we redact from binary stderr before forwarding to splunkd.log.
# The enrollment binary should not echo secrets, but defence-in-depth: if any
# future build does, scrub it here so it never reaches durable Splunk logs
# (REQ-LOG-007 — never log secrets).
_SECRET_REDACTION_PATTERNS = [
    # Generic key=value style: token=..., api_key=..., authorization: bearer ...
    (
        re.compile(
            r"((?:enrollment[_-]?token|token|api[_-]?key|authorization|bearer|"
            r"password|secret|private[_-]?key)\s*[:=]\s*)"
            r"(['\"]?)([^\s'\",;]+)(\2)",
            re.IGNORECASE,
        ),
        r"\1\2<redacted>\4",
    ),
    # JSON-shaped fields: "api_key":"...", 'token': '...' (key already in
    # quotes, so the generic key=value rule above can't match it).
    (
        re.compile(
            r"(['\"](?:enrollment[_-]?token|token|api[_-]?key|authorization|"
            r"bearer|password|secret|private[_-]?key)['\"]\s*:\s*)"
            r"(['\"])([^'\"\\]*)(['\"])",
            re.IGNORECASE,
        ),
        r"\1\2<redacted>\4",
    ),
    # Bearer-style headers without explicit key prefix: "Bearer abc123..."
    (
        re.compile(r"\b(Bearer\s+)([A-Za-z0-9._\-]{8,})", re.IGNORECASE),
        r"\1<redacted>",
    ),
    # JWT-shaped tokens (three base64url segments separated by `.`).
    (
        re.compile(
            r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"
        ),
        "<redacted-jwt>",
    ),
    # PEM private key blocks.
    (
        re.compile(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
            re.DOTALL,
        ),
        "<redacted-pem>",
    ),
]


def _redact_secrets_in_log_line(line: str) -> str:
    """Return `line` with any obvious credential material redacted.

    Best-effort only — designed to catch the patterns the Rust binary or
    its dependencies are likely to print on enrollment failures. False
    negatives are still possible for novel formats; callers should treat
    enrollment-binary stderr as untrusted log content.
    """
    if not line:
        return line
    redacted = line
    for pattern, replacement in _SECRET_REDACTION_PATTERNS:
        redacted = pattern.sub(replacement, redacted)
    return redacted

ADDON_NAME = "deslicer_ai_insights"
ACCOUNT_CONF = f"{ADDON_NAME}_account"
CREDENTIAL_REALM = f"__REST_CREDENTIAL__#{ADDON_NAME}#configs/conf-{ACCOUNT_CONF}"


def get_app_dir() -> str:
    splunk_home = os.environ.get("SPLUNK_HOME", "/opt/splunk")
    return os.path.join(splunk_home, "etc", "apps", ADDON_NAME)


def _allow_http_observer() -> bool:
    return os.environ.get("DESLICER_ALLOW_HTTP_OBSERVER", "").lower() in (
        "1",
        "true",
        "yes",
    )


def _validate_observer_url(url: str, logger: logging.Logger) -> bool:
    """Return True if the URL is acceptable; log and return False otherwise."""
    if url.startswith("http://"):
        if not _allow_http_observer():
            logger.error(
                "Observer URL '%s' uses plain HTTP. HTTPS required. "
                "Set DESLICER_ALLOW_HTTP_OBSERVER=1 only for local dev/test.",
                url,
            )
            return False
        logger.warning(
            "Observer URL '%s' uses plain HTTP (dev/test only). "
            "Use https:// in production and Splunk Cloud.",
            url,
        )
        return True
    if url.startswith("https://"):
        return True
    logger.error(
        "Observer URL '%s' has unsupported scheme. HTTPS required.",
        url,
    )
    return False


def read_account_enrollment(
    session_key: str, account_name: str, logger: logging.Logger
):
    """Read enrollment token from UCC account config (encrypted credential store)."""
    try:
        cfm = conf_manager.ConfManager(
            session_key,
            ADDON_NAME,
            realm=CREDENTIAL_REALM,
        )
        stanza = cfm.get_conf(ACCOUNT_CONF).get(account_name)
        if not stanza:
            logger.error("Connection '%s' not found in credential store", account_name)
            return None
        enrollment_token = (stanza.get("enrollment_token") or "").strip()
        observer_url = (stanza.get("observer_api_url") or "").strip()
        if not observer_url:
            logger.error(
                "Observer URL is not configured. Set it in Configuration > Connections."
            )
            return None
        if not _validate_observer_url(observer_url, logger):
            return None
        if not enrollment_token:
            logger.debug("Connection '%s' missing token, fallback", account_name)
            return None
        return {
            "token": enrollment_token,
            "observer_api_url": observer_url,
            "source": "ucc_ui",
        }
    except Exception as exc:
        logger.debug("Could not read connection '%s': %s", account_name, exc)
        return None


def read_enrollment_token(logger: logging.Logger, *, log_found: bool = True):
    """Read enrollment token from enrollment.conf (if present)."""
    app_dir = get_app_dir()
    for layer in ("local", "default"):
        path = os.path.join(app_dir, layer, "enrollment.conf")
        if not os.path.isfile(path):
            continue
        try:
            cp = ini_parser.ConfigParser()
            cp.read(path)
            token = cp.get("enrollment", "token", fallback="").strip()
            api_url = cp.get("enrollment", "observer_api_url", fallback="").strip()
            if not _validate_observer_url(api_url, logger):
                continue
            if token:
                if log_found:
                    log_throttled(
                        logger,
                        logging.INFO,
                        ENROLLMENT_RECOVERY_LOG_KEY,
                        "Enrollment token found in %s",
                        path,
                    )
                return {"token": token, "observer_api_url": api_url}
        except Exception:
            logger.debug("Cannot parse %s", path, exc_info=True)
    return None


def run_enrollment(
    session_key: str,
    enrollment: dict,
    binary: str,
    logger: logging.Logger,
):
    """Invoke the binary in --enroll mode and store returned credentials.

    Uses a file-based lock so concurrent input restarts don't race.
    """
    lock_path = os.path.join(
        os.environ.get("SPLUNK_HOME", "/opt/splunk"),
        "var",
        "run",
        "deslicer_ai_insights",
        ".enrollment.lock",
    )
    os.makedirs(os.path.dirname(lock_path), mode=0o700, exist_ok=True)

    try:
        lock_fd = open(lock_path, "w")
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except (OSError, BlockingIOError):
        logger.info("Another enrollment in progress, waiting...")
        lock_fd = open(lock_path, "w")
        fcntl.flock(lock_fd, fcntl.LOCK_EX)

    try:
        return _do_enrollment(session_key, enrollment, binary, logger)
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        lock_fd.close()


def _glob_enrollment_temp_files(runtime_dir: str):
    try:
        return [
            os.path.join(runtime_dir, f)
            for f in os.listdir(runtime_dir)
            if f.startswith(".enrollment_temp_") and f.endswith(".conf")
        ]
    except OSError:
        return []


def _do_enrollment(
    session_key: str,
    enrollment: dict,
    binary: str,
    logger: logging.Logger,
):
    """Execute binary --enroll, parse stdout JSON, write to credential store."""
    splunk_home = os.environ.get("SPLUNK_HOME", "/opt/splunk")
    temp_conf = None

    if enrollment.get("source") == "ucc_ui":
        runtime_dir = os.path.join(splunk_home, "var", "run", "deslicer_ai_insights")
        os.makedirs(runtime_dir, mode=0o700, exist_ok=True)

        for stale in _glob_enrollment_temp_files(runtime_dir):
            try:
                os.unlink(stale)
            except OSError:
                pass

        # Write only the non-sensitive URL to the temp conf file.
        # The token is passed via DESLICER_ENROLLMENT_TOKEN env var so it
        # never touches the filesystem (binary reads env var first).
        fd, temp_conf = tempfile.mkstemp(
            prefix=".enrollment_temp_",
            suffix=".conf",
            dir=runtime_dir,
        )
        os.chmod(temp_conf, 0o600)
        # Write only the non-sensitive URL; the token is delivered via
        # DESLICER_ENROLLMENT_TOKEN env var and never written to disk.
        content = (
            f"[enrollment]\n"
            f"observer_api_url = {enrollment['observer_api_url']}\n"
        )
        with os.fdopen(fd, "w") as f:
            f.write(content)
        enrollment_conf = temp_conf
    else:
        enrollment_conf = None
        for layer in ("local", "default"):
            p = os.path.join(get_app_dir(), layer, "enrollment.conf")
            if os.path.isfile(p):
                enrollment_conf = p
                break
        if not enrollment_conf:
            logger.error("Cannot enroll: enrollment.conf not found")
            return None

    cmd = [
        binary,
        "--enroll",
        "--enrollment-config",
        enrollment_conf,
        "--splunk-home",
        splunk_home,
    ]
    child_env = os.environ.copy()
    child_env["NO_COLOR"] = "1"
    if enrollment.get("source") == "ucc_ui" and enrollment.get("token"):
        child_env["DESLICER_ENROLLMENT_TOKEN"] = enrollment["token"]
    # Allow plain HTTP observer URLs in dev/test environments.
    if enrollment.get("observer_api_url", "").startswith("http://"):
        child_env.setdefault("DESLICER_ALLOW_HTTP_OBSERVER", "1")
        child_env["INSECURE_HTTP"] = "true"
        child_env["DAP_ENV"] = "local"

    logger.info("Starting enrollment")
    try:
        result = subprocess.run(  # noqa: S603
            cmd,
            capture_output=True,
            text=True,
            timeout=60,
            env=child_env,
        )
    except subprocess.TimeoutExpired:
        logger.error("Enrollment timed out after 60s")
        return None
    except OSError as e:
        logger.error("Enrollment binary execution failed: %s", e)
        return None
    finally:
        if temp_conf and os.path.isfile(temp_conf):
            os.unlink(temp_conf)

    if result.returncode != 0:
        # Log stderr line-by-line so the actual error is visible in Splunk logs
        # (not buried after the startup banner). Every line is run through
        # `_redact_secrets_in_log_line` first so an accidental
        # token / api key / bearer / private key echo from the enrollment
        # binary does not get persisted to splunkd.log in cleartext.
        stderr_lines = (result.stderr or "").strip().splitlines()
        _ENROLLMENT_ERROR_KWS = (
            "ERROR", "WARN", "error", "failed", "Failed", "Could not", "panic"
        )
        error_lines = [
            _redact_secrets_in_log_line(ln) for ln in stderr_lines
            if any(kw in ln for kw in _ENROLLMENT_ERROR_KWS)
        ]
        detail = (
            "\n".join(error_lines)
            if error_lines
            else (
                _redact_secrets_in_log_line(stderr_lines[-1])
                if stderr_lines
                else "no output"
            )
        )
        logger.error(
            "Enrollment failed (exit %d): %s",
            result.returncode,
            detail,
        )
        if error_lines:
            for ln in error_lines:
                logger.error("  enrollment error: %s", ln.strip())
        return None

    stdout = result.stdout.strip()
    if not stdout:
        logger.error("Enrollment returned empty response")
        return None

    try:
        cred_data = json.loads(stdout)
    except json.JSONDecodeError:
        # The enrollment binary should only emit a JSON credential blob on
        # stdout, but if a future version (or a partial / mixed write) leaks
        # a token, api_key, bearer header, JWT, or PEM block in the payload
        # we MUST NOT persist that to splunkd.log in cleartext (REQ-LOG-007).
        # Run the snippet through the same redactor used for stderr lines
        # before logging.
        logger.error(
            "Enrollment returned invalid JSON: %s",
            _redact_secrets_in_log_line(stdout[:200]),
        )
        return None

    api_key = cred_data.get("api_key", "")
    tenant_id = cred_data.get("tenant_id", "")
    observer_url = enrollment["observer_api_url"]
    expires_at = cred_data.get("api_key_expires_at", "")

    if not api_key or not tenant_id:
        logger.error("Enrollment response missing api_key or tenant_id")
        return None

    try:
        write_credentials_to_store(
            session_key,
            "enrolled_account",
            api_key,
            tenant_id,
            observer_url,
            logger,
            expires_at=expires_at,
        )
    except Exception:
        logger.exception("Failed to write enrolled credentials to store")
        return None

    clear_enrollment_block(logger)
    # SECURITY: never log any portion of the API key (not even a prefix);
    # Splunk indexes log lines and prefixes are still secret material.
    logger.info(
        "Enrollment successful: tenant=%s, expires=%s",
        tenant_id,
        expires_at or "never",
    )
    return {
        "api_token": api_key,
        "tenant_id": tenant_id,
        "observer_api_url": observer_url,
        "api_key_expires_at": expires_at,
    }


def write_credentials_to_store(
    session_key: str,
    account_name: str,
    api_key: str,
    tenant_id: str,
    observer_api_url: str,
    logger: logging.Logger,
    expires_at: str = "",
):
    service = splunk_client.connect(token=session_key, app=ADDON_NAME)
    realm = f"{ADDON_NAME}_enrollment"
    payload: dict = {
        "api_key": api_key,
        "tenant_id": tenant_id,
        "observer_api_url": observer_api_url,
    }
    if expires_at:
        payload["api_key_expires_at"] = expires_at
    content = json.dumps(payload)

    existing = None
    for pwd in service.storage_passwords:
        if pwd.realm == realm and pwd.username == account_name:
            existing = pwd
            break

    if existing:
        existing.update(password=content)
        logger.info("Updated existing enrollment credentials in store")
    else:
        service.storage_passwords.create(content, account_name, realm)
        logger.info("Created enrollment credentials in store")


def enrollment_blocked_path() -> str:
    splunk_home = os.environ.get("SPLUNK_HOME", "/opt/splunk")
    return os.path.join(
        splunk_home, "var", "run", "deslicer_ai_insights", ".enrollment_blocked"
    )


def block_enrollment_token(token: str, logger: logging.Logger):
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    marker = enrollment_blocked_path()
    os.makedirs(os.path.dirname(marker), mode=0o700, exist_ok=True)
    with open(marker, "w") as f:
        f.write(token_hash)
    os.chmod(marker, 0o600)
    logger.info("Enrollment blocked until a new token is provided")


def is_enrollment_blocked(token: str, logger: logging.Logger) -> bool:
    marker = enrollment_blocked_path()
    if not os.path.isfile(marker):
        return False
    try:
        with open(marker) as f:
            blocked_hash = f.read().strip()
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        if token_hash == blocked_hash:
            log_throttled(
                logger,
                logging.WARNING,
                ENROLLMENT_RECOVERY_LOG_KEY,
                "Enrollment blocked: same token as revoked session. "
                "Push a new enrollment token to recover.",
            )
            return True
        logger.info("New enrollment token detected, unblocking")
        os.unlink(marker)
        return False
    except Exception:
        logger.debug("Error checking enrollment block", exc_info=True)
        return False


def clear_enrollment_block(logger: logging.Logger):
    marker = enrollment_blocked_path()
    if os.path.isfile(marker):
        os.unlink(marker)
        logger.info("Enrollment block cleared")


def clear_revoked_credentials(session_key: str, logger: logging.Logger):
    try:
        service = splunk_client.connect(token=session_key, app=ADDON_NAME)
        realm = f"{ADDON_NAME}_enrollment"
        for pwd in service.storage_passwords:
            if pwd.realm == realm and pwd.username == "enrolled_account":
                pwd.delete()
                logger.info("Cleared revoked credentials from store")
                return
    except Exception:
        logger.debug("Could not clear revoked credentials", exc_info=True)


def resolve_credentials(
    session_key: str,
    account_name: str,
    binary: str,
    logger: logging.Logger,
):
    """Priority chain: enrolled creds → UCC account → enrollment.conf."""
    enrolled_creds = read_enrolled_credentials(session_key, logger)
    if enrolled_creds:
        return enrolled_creds

    if account_name:
        enrollment = read_account_enrollment(session_key, account_name, logger)
        if enrollment:
            if is_enrollment_blocked(enrollment["token"], logger):
                return None
            logger.info("Token from connection config, enrolling")
            return run_enrollment(session_key, enrollment, binary, logger)

    enrollment = read_enrollment_token(logger, log_found=False)
    if enrollment:
        if is_enrollment_blocked(enrollment["token"], logger):
            return None
        logger.info("Token from enrollment.conf, enrolling")
        return run_enrollment(session_key, enrollment, binary, logger)

    return None


def read_enrolled_credentials(session_key: str, logger: logging.Logger):
    try:
        service = splunk_client.connect(token=session_key, app=ADDON_NAME)
        realm = f"{ADDON_NAME}_enrollment"
        for pwd in service.storage_passwords:
            if pwd.realm == realm and pwd.username == "enrolled_account":
                data = json.loads(pwd.clear_password)
                api_key = data.get("api_key", "")
                tenant_id = data.get("tenant_id", "")
                observer_url = data.get("observer_api_url", "")
                expires_at = data.get("api_key_expires_at", "")
                if api_key and tenant_id:
                    if observer_url and not _validate_observer_url(
                        observer_url, logger
                    ):
                        logger.warning(
                            "Stored observer URL '%s' failed validation; "
                            "re-enrollment required.",
                            observer_url,
                        )
                        return None
                    logger.info("Using current enrolled credentials")
                    creds = {
                        "api_token": api_key,
                        "tenant_id": tenant_id,
                        "observer_api_url": observer_url,
                        "api_key_expires_at": expires_at,
                    }
                    # Augment with observer_ca_cert_path from the local
                    # conf file, if present.  This allows the binary to trust
                    # self-signed / private CA certs without disabling TLS.
                    try:
                        splunk_home = os.environ.get("SPLUNK_HOME", "/opt/splunk")
                        local_conf = os.path.join(
                            splunk_home,
                            "etc", "apps", ADDON_NAME,
                            "local", f"{ADDON_NAME}.conf",
                        )
                        if os.path.isfile(local_conf):
                            parser = ini_parser.ConfigParser()
                            parser.read(local_conf)
                            ca_path = (
                                parser.get(
                                    "default", "observer_ca_cert_path", fallback=""
                                )
                                or parser.get(
                                    "api", "observer_ca_cert_path", fallback=""
                                )
                            )
                            if ca_path:
                                creds["observer_ca_cert_path"] = ca_path
                    except Exception:  # noqa: S110
                        pass
                    return creds
    except Exception:
        logger.debug("Could not read enrolled credentials", exc_info=True)
    return None
