# Deslicer AI Insights - modular input supervisor.
# Launches the Rust collector binary as a subprocess, streams its output to
# Splunk, and restarts on crash with exponential backoff.
# Credentials are read from Splunk's encrypted credential store at runtime.
# ruff: noqa: I001 — import_declare_test must precede third-party imports (sys.path side-effect)

import hashlib
import logging
import os
import queue
import re
import signal
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from typing import Dict, Optional

import import_declare_test  # noqa: F401 (side-effect: configures sys.path)
from solnlib import conf_manager, log
from splunklib import modularinput as smi

from _collector_process import (
    file_checksum,
    find_binary,
    kill_stale_collector,
    prepare_runtime_binary,
)
from _enrollment import (
    ADDON_NAME,
    block_enrollment_token,
    clear_revoked_credentials,
    read_account_enrollment,
    read_enrollment_token,
    resolve_credentials,
    run_enrollment,
    write_credentials_to_store,
)
from _key_management import (
    check_server_key_status,
    next_key_status_interval_secs,
    key_needs_rotation,
    observer_tls_child_env,
    run_key_rotation as _rotate,
)
from _log_throttle import ENROLLMENT_RECOVERY_LOG_KEY, log_throttled

NODE_EVENT_TIMESTAMP_RE = re.compile(
    r"^\d{2}-\d{2}-\d{4} \d{2}:\d{2}:\d{2}\.\d{3} \+0000 "
)


def run_key_rotation(session_key, creds, binary, logger):
    return _rotate(session_key, creds, binary, logger, write_credentials_to_store)


def _node_event_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%m-%d-%Y %H:%M:%S.%f")[:23] + " +0000"


def _format_node_event_line(line: str) -> str:
    if NODE_EVENT_TIMESTAMP_RE.match(line):
        return line
    return (
        f"{_node_event_timestamp()} ERROR supervisor "
        f"[{os.getpid()} child-output] - {line}"
    )


def _prepare_collector_credentials(
    session_key,
    account_name,
    binary,
    creds,
    logger,
):
    """Re-read credstore, verify with Observer, and rotate before start.

    Returns (creds, error) where error is None, "revoked", or "rotation_failed".
    """
    refreshed = resolve_credentials(session_key, account_name, binary, logger)
    if refreshed:
        creds = refreshed

    key_action = check_server_key_status(creds, logger)
    if key_action == "revoked":
        return None, "revoked"

    must_rotate = key_action == "rotate" or key_needs_rotation(creds, logger)
    if must_rotate:
        rotated = run_key_rotation(session_key, creds, binary, logger)
        if rotated:
            return rotated, None
        logger.warning(
            "Credential rotation failed; refusing to start collector with stale key"
        )
        return None, "rotation_failed"

    return creds, None


def _read_active_enrollment(session_key, account_name, logger):
    if account_name:
        enrollment = read_account_enrollment(session_key, account_name, logger)
        if enrollment:
            return enrollment
    return read_enrollment_token(logger, log_found=False)


def _enrollment_token_hash(enrollment) -> Optional[str]:
    if not enrollment:
        return None
    token = (enrollment.get("token") or "").strip()
    if not token:
        return None
    return hashlib.sha256(token.encode()).hexdigest()


def _maybe_reenroll_from_updated_token(
    session_key,
    account_name,
    binary,
    logger,
    known_token_hash,
):
    enrollment = _read_active_enrollment(session_key, account_name, logger)
    current_token_hash = _enrollment_token_hash(enrollment)
    if not current_token_hash or current_token_hash == known_token_hash:
        return None, known_token_hash, False

    logger.info("New enrollment token detected while collector is running")
    updated = run_enrollment(session_key, enrollment, binary, logger)
    if not updated:
        logger.warning(
            "New enrollment token could not be exchanged; keeping current API key"
        )
        return None, current_token_hash, False

    logger.info("Enrollment token exchanged; restarting collector with new API key")
    return updated, current_token_hash, True


SETTINGS_CONF = f"{ADDON_NAME}_settings"

MAX_RESTART_DELAY = 300
INITIAL_RESTART_DELAY = 5
UPDATE_CHECK_INTERVAL = 30
CREDENTIAL_UPDATE_CHECK_INTERVAL = 60


def logger_for_input(input_name: str) -> logging.Logger:
    return log.Logs().get_logger(f"{ADDON_NAME.lower()}_{input_name}")


# Bounds for MAX_PAYLOAD_SIZE_MB. The Rust collector multiplies this by
# 1 MiB to size its in-memory batch buffer, so an unvalidated huge value
# would cause OOMs and a tiny one would silently truncate every payload.
_MAX_PAYLOAD_DEFAULT_MB = 2
_MAX_PAYLOAD_MIN_MB = 1
_MAX_PAYLOAD_MAX_MB = 64


def _coerce_max_payload_size_mb(raw, logger: logging.Logger) -> int:
    """Coerce an inputs.conf max_payload_size value into a safe MiB integer.

    Splunk delivers stanza fields as strings (or None). We previously passed
    the raw value straight through to the Rust binary's MAX_PAYLOAD_SIZE_MB
    env var, which would crash or misbehave for non-numeric / negative /
    extreme inputs. Clamp to [1, 64] MiB and fall back to the default on
    any parse error.
    """
    if raw is None or (isinstance(raw, str) and not raw.strip()):
        return _MAX_PAYLOAD_DEFAULT_MB
    try:
        value = int(str(raw).strip())
    except (TypeError, ValueError):
        logger.warning(
            "max_payload_size=%r is not an integer; falling back to %d MB",
            raw,
            _MAX_PAYLOAD_DEFAULT_MB,
        )
        return _MAX_PAYLOAD_DEFAULT_MB
    if value < _MAX_PAYLOAD_MIN_MB:
        logger.warning(
            "max_payload_size=%d below minimum (%d MB); clamping",
            value,
            _MAX_PAYLOAD_MIN_MB,
        )
        return _MAX_PAYLOAD_MIN_MB
    if value > _MAX_PAYLOAD_MAX_MB:
        logger.warning(
            "max_payload_size=%d above maximum (%d MB); clamping",
            value,
            _MAX_PAYLOAD_MAX_MB,
        )
        return _MAX_PAYLOAD_MAX_MB
    return value


def _truthy(value) -> bool:
    """Lenient truthiness check for credential / stanza fields stored as text."""
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def _allow_tls_insecure() -> bool:
    """Operator opt-in for skipping Observer TLS verification.

    Hard-gates `observer_tls_insecure_skip_verify`: even if an admin sets
    that flag in the credential store, the modular input refuses to
    propagate it unless the host explicitly sets
    `DESLICER_ALLOW_TLS_INSECURE=1` in the environment. This makes the
    flag impossible to enable on a stock Splunk Cloud / production deploy.
    """
    return os.environ.get("DESLICER_ALLOW_TLS_INSECURE", "").lower() in (
        "1",
        "true",
        "yes",
    )


def _sanitize_conf_value(name: str, value) -> str:
    """Return `value` as a single-line string safe to write into a Splunk conf.

    Splunk INI parsers treat newlines as stanza/key delimiters, so a value
    containing CR/LF could inject arbitrary stanzas or keys. Reject any
    control characters (including embedded NULs) instead of silently
    escaping them — a credential field with newlines indicates either
    misconfiguration or active tampering.
    """
    if value is None:
        text = ""
    else:
        text = str(value)
    for ch in text:
        if ch == "\r" or ch == "\n" or ord(ch) < 0x20 or ord(ch) == 0x7F:
            raise ValueError(
                f"Refusing to write {name!r}: value contains control characters"
            )
    return text


def _normalize_scope_list(raw) -> str:
    """Collapse a UI-entered comma/newline list into a single comma string.

    The UCC textarea fields can contain commas, newlines, or both. The
    Rust collector expects a flat comma-separated list. Whitespace around
    each entry is stripped; blank entries are dropped. Returning the
    empty string is significant: it lets a UI clear propagate through to
    the runtime conf as an EMPTY value (vs the stanza being absent),
    which the agent treats as "operator explicitly cleared the scope".
    """
    if raw is None:
        return ""
    text = str(raw)
    parts = []
    for chunk in text.replace("\r", "\n").split("\n"):
        for item in chunk.split(","):
            item = item.strip()
            if item:
                parts.append(item)
    return ", ".join(parts)


def _write_runtime_config(
    creds: dict,
    runtime_dir: str,
    observation_scope: Optional[Dict[str, str]] = None,
) -> str:
    """Write the config file the Rust binary expects.

    api_token is intentionally omitted — injected at process start via
    the API_KEY env var.  Uses atomic write so the binary never reads a
    half-written file.

    `observation_scope` is an optional dict with keys `exclude_apps` and
    `exclude_path_glob` (operator-entered lists). Both keys are ALWAYS
    written into the [observation_scope] stanza, even when their values
    are empty strings, so that a UI clear is honored end-to-end (the
    agent treats a missing stanza as "no opinion" but an empty key as
    "operator cleared the list").
    """
    os.makedirs(runtime_dir, mode=0o700, exist_ok=True)
    splunk_home = os.environ.get("SPLUNK_HOME", "/opt/splunk")
    config_path = os.path.join(runtime_dir, "deslicer_ai_insights.conf")
    # SECURITY: sanitize every field interpolated into the conf to prevent
    # stanza/key injection via embedded CR/LF in credential values.
    observer_api_url = _sanitize_conf_value(
        "observer_api_url", creds.get("observer_api_url", "")
    )
    tenant_id = _sanitize_conf_value("tenant_id", creds.get("tenant_id", ""))
    safe_splunk_home = _sanitize_conf_value("splunk_home", splunk_home)

    scope = observation_scope or {}
    exclude_apps = _sanitize_conf_value(
        "exclude_apps", _normalize_scope_list(scope.get("exclude_apps"))
    )
    exclude_path_glob = _sanitize_conf_value(
        "exclude_path_glob", _normalize_scope_list(scope.get("exclude_path_glob"))
    )

    content = (
        "# Auto-generated by modular input at runtime. Do not edit.\n\n"
        "[api]\n"
        "observer_api_url = {observer_api_url}\n\n"
        "[identifiers]\n"
        "tenant_id = {tenant_id}\n\n"
        "[collection]\n"
        "splunk_home = {splunk_home}\n\n"
        # Always emit the [observation_scope] stanza with both keys so an
        # operator clearing the UI textarea propagates as an explicit
        # empty value (NOT a missing stanza) into the runtime conf and on
        # to the agent's digest header.
        "[observation_scope]\n"
        "exclude_apps = {exclude_apps}\n"
        "exclude_path_glob = {exclude_path_glob}\n"
    ).format(
        observer_api_url=observer_api_url,
        tenant_id=tenant_id,
        splunk_home=safe_splunk_home,
        exclude_apps=exclude_apps,
        exclude_path_glob=exclude_path_glob,
    )
    tmp_fd, tmp_path = tempfile.mkstemp(dir=runtime_dir, suffix=".tmp", prefix=".conf_")
    try:
        with os.fdopen(tmp_fd, "w") as f:
            f.write(content)
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, config_path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
    return config_path


def _remove_runtime_config(config_path: str, logger: logging.Logger) -> None:
    try:
        if os.path.isfile(config_path):
            os.unlink(config_path)
            logger.info("Removed runtime config: %s", config_path)
    except OSError as exc:
        logger.debug("Could not remove runtime config: %s", exc)


def validate_input(definition: smi.ValidationDefinition) -> None:
    """Validate that the selected account exists and has credentials."""
    return


def stream_events(inputs: smi.InputDefinition, event_writer: smi.EventWriter) -> None:
    """Supervisor: launch the Rust collector binary and stream its output."""
    for input_name, input_item in inputs.inputs.items():
        normalized = input_name.split("/")[-1]
        logger = logger_for_input(normalized)

        session_key = inputs.metadata.get("session_key")
        if not session_key:
            logger.error("No session key available")
            return

        try:
            log_level_str = conf_manager.get_log_level(
                logger=logger,
                session_key=session_key,
                app_name=ADDON_NAME,
                conf_name=SETTINGS_CONF,
            )
            logger.setLevel(log_level_str)
        except Exception:
            logger.debug("Could not read log level setting, using default")

        account_name = input_item.get("account", "")
        binary_log_level = input_item.get("log_level", "info") or "info"

        # Operator-defined observation scope. Captured here (once per
        # modular-input lifecycle) and threaded into every runtime-conf
        # write below so a UI clear or a deployer-pushed inputs.conf
        # update reaches the agent on the next restart cycle. Empty
        # values are preserved (NOT dropped) — see _write_runtime_config.
        observation_scope = {
            "exclude_apps": input_item.get("exclude_apps", "") or "",
            "exclude_path_glob": input_item.get("exclude_path_glob", "") or "",
        }

        log.modular_input_start(logger, normalized)

        source_binary = find_binary(
            os.path.join(
                os.environ.get("SPLUNK_HOME", "/opt/splunk"), "etc", "apps", ADDON_NAME
            )
        )
        if not source_binary:
            logger.warning(
                "Collector binary not found. Install the binary in bin/. "
                "Input '%s' will retry on next Splunk restart.",
                normalized,
            )
            return

        creds = resolve_credentials(session_key, account_name, source_binary, logger)
        if not creds:
            log_throttled(
                logger,
                logging.ERROR,
                ENROLLMENT_RECOVERY_LOG_KEY,
                "Cannot start collector: no credentials available. "
                "Configure a connection with an enrollment token in the UI, "
                "or place an enrollment token in local/enrollment.conf.",
            )
            return

        if key_needs_rotation(creds, logger):
            rotated = run_key_rotation(session_key, creds, source_binary, logger)
            if rotated:
                creds = rotated

        splunk_home = os.environ.get("SPLUNK_HOME", "/opt/splunk")
        runtime_dir = os.path.join(
            splunk_home, "var", "run", "deslicer_ai_insights", normalized
        )
        config_path = _write_runtime_config(creds, runtime_dir, observation_scope)
        runtime_binary = prepare_runtime_binary(source_binary, runtime_dir)
        buffer_dir = os.path.join(runtime_dir, "buffer")
        os.makedirs(buffer_dir, mode=0o700, exist_ok=True)
        source_checksum = file_checksum(source_binary)
        observed_enrollment_token_hash = _enrollment_token_hash(
            _read_active_enrollment(session_key, account_name, logger)
        )

        logger.info(
            "Starting collector: binary=%s config=%s account=%s",
            runtime_binary,
            config_path,
            account_name,
        )

        restart_delay = INITIAL_RESTART_DELAY
        state = {"child": None}

        def _handle_signal(signum, _frame, _log=logger, _st=state, _cp=config_path):
            _log.info("Received signal %s, stopping collector", signum)
            proc = _st["child"]
            if proc and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
            _remove_runtime_config(_cp, _log)
            _log.info(
                "Supervisor exiting after signal %s; Splunk will restart this "
                "input on the next splunkd start when the stanza is enabled",
                signum,
            )
            sys.exit(0)

        signal.signal(signal.SIGTERM, _handle_signal)
        signal.signal(signal.SIGINT, _handle_signal)

        while True:
            creds, cred_error = _prepare_collector_credentials(
                session_key, account_name, source_binary, creds, logger
            )
            if cred_error == "rotation_failed":
                logger.warning(
                    "Delaying collector restart for %ds after rotation failure",
                    restart_delay,
                )
                time.sleep(restart_delay)
                restart_delay = min(restart_delay * 2, MAX_RESTART_DELAY)
                continue

            if cred_error == "revoked":
                logger.error(
                    "API key revoked or expired. Stopping collector and "
                    "waiting for a new enrollment token."
                )
                enrollment = read_account_enrollment(
                    session_key, account_name, logger
                ) or read_enrollment_token(logger)
                if enrollment:
                    block_enrollment_token(enrollment["token"], logger)
                clear_revoked_credentials(session_key, logger)
                _remove_runtime_config(config_path, logger)

                revoke_poll_delay = INITIAL_RESTART_DELAY
                while True:
                    logger.info(
                        "Waiting %ds for new enrollment token…",
                        revoke_poll_delay,
                    )
                    time.sleep(revoke_poll_delay)
                    creds = resolve_credentials(
                        session_key, account_name, source_binary, logger
                    )
                    if creds:
                        logger.info("New credentials obtained, resuming collector")
                        config_path = _write_runtime_config(
                            creds, runtime_dir, observation_scope
                        )
                        restart_delay = INITIAL_RESTART_DELAY
                        break
                    revoke_poll_delay = min(
                        revoke_poll_delay * 2, MAX_RESTART_DELAY
                    )
                continue

            _write_runtime_config(creds, runtime_dir, observation_scope)

            cmd = [
                runtime_binary,
                "--config",
                config_path,
                "--buffer-dir",
                buffer_dir,
                "--log-level",
                binary_log_level,
                "--watch",
            ]

            child_env = os.environ.copy()
            child_env["NO_COLOR"] = "1"
            child_env["API_KEY"] = creds["api_token"]
            child_env["SPLUNK_INPUT_NAME"] = normalized
            child_env["MAX_PAYLOAD_SIZE_MB"] = str(
                _coerce_max_payload_size_mb(
                    input_item.get("max_payload_size"), logger
                )
            )
            # Optional: align client timeout with Observer data-plane limit
            # (OBSERVER_HTTP_TIMEOUT_SECS on the Splunk host or in server.conf).
            timeout_secs = os.environ.get("OBSERVER_HTTP_TIMEOUT_SECS", "").strip()
            if timeout_secs:
                child_env["OBSERVER_HTTP_TIMEOUT_SECS"] = timeout_secs
            observer_tls_child_env(creds, child_env, logger)

            kill_stale_collector(runtime_dir, logger)

            try:
                proc = subprocess.Popen(  # noqa: S603
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    bufsize=1,
                    universal_newlines=True,
                    env=child_env,
                )
            except OSError as e:
                logger.error("Failed to start collector binary: %s", e)
                return

            state["child"] = proc
            logger.info("Collector PID %d started", proc.pid)

            last_update_check = time.time()
            last_key_status_check = time.time()
            key_status_interval_secs = next_key_status_interval_secs()
            last_credential_update_check = time.time()

            line_q: queue.Queue = queue.Queue()

            def _stdout_reader(stdout, q):
                try:
                    for raw_line in stdout:
                        q.put(raw_line)
                finally:
                    q.put(None)

            reader_thread = threading.Thread(
                target=_stdout_reader, args=(proc.stdout, line_q), daemon=True
            )
            reader_thread.start()

            while True:
                try:
                    raw = line_q.get(timeout=60.0)
                except queue.Empty:
                    raw = ""

                if raw is None:
                    break

                if raw:
                    line = raw.rstrip("\n\r")
                    if line:
                        event_line = _format_node_event_line(line)
                        event = smi.Event(
                            data=event_line,
                            sourcetype="deslicer:insights:node",
                            source="deslicer_ai_insights",
                        )
                        try:
                            event_writer.write_event(event)
                        except Exception:
                            logger.debug("EventWriter closed, output: %s", event_line)

                now = time.time()
                if now - last_update_check >= UPDATE_CHECK_INTERVAL:
                    last_update_check = now
                    new_checksum = file_checksum(source_binary)
                    if new_checksum and new_checksum != source_checksum:
                        logger.info("Binary update detected, restarting")
                        proc.terminate()
                        try:
                            proc.wait(timeout=10)
                        except subprocess.TimeoutExpired:
                            proc.kill()
                        prepare_runtime_binary(source_binary, runtime_dir)
                        source_checksum = new_checksum
                        restart_delay = INITIAL_RESTART_DELAY
                        break

                if (
                    now - last_credential_update_check
                    >= CREDENTIAL_UPDATE_CHECK_INTERVAL
                ):
                    last_credential_update_check = now
                    (
                        updated_creds,
                        observed_enrollment_token_hash,
                        should_restart_for_creds,
                    ) = _maybe_reenroll_from_updated_token(
                        session_key,
                        account_name,
                        source_binary,
                        logger,
                        observed_enrollment_token_hash,
                    )
                    if should_restart_for_creds and updated_creds:
                        creds = updated_creds
                        proc.terminate()
                        try:
                            proc.wait(timeout=10)
                        except subprocess.TimeoutExpired:
                            proc.kill()
                        restart_delay = INITIAL_RESTART_DELAY
                        break

                if now - last_key_status_check >= key_status_interval_secs:
                    last_key_status_check = now
                    key_status_interval_secs = next_key_status_interval_secs()
                    key_action = check_server_key_status(creds, logger)

                    if key_action == "rotate":
                        logger.info("Server signaled rotation, rotating key")
                        rotated = run_key_rotation(
                            session_key, creds, source_binary, logger
                        )
                        if rotated:
                            creds = rotated
                            logger.info("Rotation complete, restarting binary")
                        else:
                            logger.warning(
                                "Server-signaled rotation failed; "
                                "will re-prepare credentials before restart"
                            )
                        proc.terminate()
                        try:
                            proc.wait(timeout=10)
                        except subprocess.TimeoutExpired:
                            proc.kill()
                        restart_delay = INITIAL_RESTART_DELAY
                        break

                    if key_action == "revoked":
                        logger.error(
                            "API key revoked. Stopping collector and "
                            "waiting for a new enrollment token."
                        )
                        proc.terminate()
                        try:
                            proc.wait(timeout=10)
                        except subprocess.TimeoutExpired:
                            proc.kill()
                        state["child"] = None
                        enrollment = read_account_enrollment(
                            session_key, account_name, logger
                        ) or read_enrollment_token(logger)
                        if enrollment:
                            block_enrollment_token(enrollment["token"], logger)
                        clear_revoked_credentials(session_key, logger)
                        _remove_runtime_config(config_path, logger)

                        revoke_poll_delay = INITIAL_RESTART_DELAY
                        while True:
                            logger.info(
                                "Waiting %ds for new enrollment token…",
                                revoke_poll_delay,
                            )
                            time.sleep(revoke_poll_delay)
                            creds = resolve_credentials(
                                session_key, account_name,
                                source_binary, logger,
                            )
                            if creds:
                                logger.info(
                                    "New credentials obtained, resuming collector"
                                )
                                config_path = _write_runtime_config(
                                    creds, runtime_dir, observation_scope,
                                )
                                restart_delay = INITIAL_RESTART_DELAY
                                break
                            revoke_poll_delay = min(
                                revoke_poll_delay * 2, MAX_RESTART_DELAY,
                            )
                        break

            exit_code = proc.wait()
            state["child"] = None

            if exit_code not in (0, 2):
                creds, cred_error = _prepare_collector_credentials(
                    session_key, account_name, source_binary, creds, logger
                )
                if cred_error in ("revoked", "rotation_failed"):
                    restart_delay = INITIAL_RESTART_DELAY
                    continue

            if exit_code in (0, 2):
                restart_delay = INITIAL_RESTART_DELAY
            else:
                logger.warning(
                    "Collector exited with code %d, restarting in %ds",
                    exit_code,
                    restart_delay,
                )

            time.sleep(restart_delay)

            if exit_code not in (0, 2):
                restart_delay = min(restart_delay * 2, MAX_RESTART_DELAY)

            prepare_runtime_binary(source_binary, runtime_dir)
            source_checksum = file_checksum(source_binary)

        log.modular_input_end(logger, normalized)
