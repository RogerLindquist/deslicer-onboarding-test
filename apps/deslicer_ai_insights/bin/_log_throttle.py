# Persisted log throttling for enrollment recovery paths.
# Splunk restarts the supervisor on every exit (interval=0), so in-memory
# throttles reset each process; state is stored under var/run instead.

import json
import logging
import os
import time

ENROLLMENT_LOG_THROTTLE_SECS = 15 * 60
ENROLLMENT_RECOVERY_LOG_KEY = "enrollment_recovery_required"


def _throttle_dir() -> str:
    splunk_home = os.environ.get("SPLUNK_HOME", "/opt/splunk")
    return os.path.join(splunk_home, "var", "run", "deslicer_ai_insights")


def _throttle_file() -> str:
    return os.path.join(_throttle_dir(), ".log_throttle.json")


def should_emit_log(
    key: str,
    interval_secs: int = ENROLLMENT_LOG_THROTTLE_SECS,
) -> bool:
    """Return True when a log line for *key* should be emitted."""
    path = _throttle_file()
    now = time.time()
    state = {}
    if os.path.isfile(path):
        try:
            with open(path) as fh:
                loaded = json.load(fh)
            if isinstance(loaded, dict):
                state = {str(k): float(v) for k, v in loaded.items()}
        except (json.JSONDecodeError, OSError, TypeError, ValueError):
            state = {}

    last = state.get(key, 0.0)
    if now - last < interval_secs:
        return False

    state[key] = now
    try:
        os.makedirs(_throttle_dir(), mode=0o700, exist_ok=True)
        tmp_path = f"{path}.tmp"
        with open(tmp_path, "w") as fh:
            json.dump(state, fh)
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, path)
    except OSError:
        return True
    return True


def log_throttled(
    logger: logging.Logger,
    level: int,
    key: str,
    message: str,
    *args,
    interval_secs: int = ENROLLMENT_LOG_THROTTLE_SECS,
) -> bool:
    """Emit *message* at most once per *interval_secs* for *key*."""
    if not should_emit_log(key, interval_secs=interval_secs):
        return False
    logger.log(level, message, *args)
    return True


def reset_throttle_state() -> None:
    """Clear persisted throttle state (tests only)."""
    path = _throttle_file()
    try:
        os.unlink(path)
    except OSError:
        pass
