# Binary management, stale-PID cleanup, and process identity helpers.
# Imported by deslicer_ai_insights_helper.py.

import hashlib
import logging
import os
import platform
import shutil
import signal
import subprocess
import time

BINARY_NAMES_BY_ARCH = {
    "x86_64": "deslicer-insights-node-linux-amd64",
    "amd64": "deslicer-insights-node-linux-amd64",
    "aarch64": "deslicer-insights-node-linux-arm64",
    "arm64": "deslicer-insights-node-linux-arm64",
}
BINARY_FALLBACK = "deslicer-insights-node"


def file_checksum(path: str) -> str:
    try:
        h = hashlib.md5()  # noqa: S324 — non-security checksum for binary change detection
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return ""


def find_binary(app_dir: str) -> str:
    """Find the architecture-appropriate collector binary."""
    machine = platform.machine().lower()
    arch_name = BINARY_NAMES_BY_ARCH.get(machine)

    app_bin = os.path.join(app_dir, "bin")
    script_bin = os.path.dirname(os.path.abspath(__file__))

    for search_dir in (app_bin, script_bin):
        if arch_name:
            candidate = os.path.join(search_dir, arch_name)
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return candidate
        fallback = os.path.join(search_dir, BINARY_FALLBACK)
        if os.path.isfile(fallback) and os.access(fallback, os.X_OK):
            return fallback
    return ""


def prepare_runtime_binary(source: str, runtime_dir: str) -> str:
    """Copy binary to runtime dir to avoid 'Text file busy' on updates."""
    os.makedirs(runtime_dir, mode=0o700, exist_ok=True)
    dest = os.path.join(runtime_dir, "deslicer-insights-node")
    if file_checksum(source) != file_checksum(dest):
        shutil.copy2(source, dest)
        os.chmod(dest, 0o700)
    return dest


def is_collector_process(pid: int) -> bool:
    """Return False if *pid* is definitely NOT the collector; True otherwise.

    Reads /proc/<pid>/comm on Linux (fast, atomic).  Falls back to ps(1) on
    other platforms.  Returns False on any check failure so the caller
    fails closed — an unidentifiable process is never signalled.
    """
    comm_path = "/proc/{}/comm".format(pid)
    if os.path.exists(comm_path):
        try:
            with open(comm_path) as fh:
                comm = fh.read().strip()
            return "deslicer" in comm or "insights-node" in comm
        except OSError:
            return False  # can't read — fail closed, don't kill unknown process

    try:
        ps_bin = "/bin/ps" if os.path.isfile("/bin/ps") else "/usr/bin/ps"
        result = subprocess.run(  # noqa: S603
            [ps_bin, "-p", str(pid), "-o", "comm="],
            capture_output=True,
            text=True,
            timeout=3,
        )
        comm = result.stdout.strip()
        if not comm:
            return False  # process gone or unreadable — fail closed
        return "deslicer" in comm or "insights" in comm
    except (OSError, subprocess.TimeoutExpired):
        return False  # can't check — fail closed


def kill_stale_collector(runtime_dir: str, logger: logging.Logger) -> None:
    """Kill any existing collector process recorded in the PID file.

    Guards against PID reuse: verifies process identity before signalling.
    Only removes the stale PID file when identity check fails.
    """
    pid_path = os.path.join(runtime_dir, "collector.pid")
    if not os.path.exists(pid_path):
        return

    try:
        with open(pid_path) as fh:
            raw = fh.read().strip()
        if not raw:
            os.remove(pid_path)
            return
        stale_pid = int(raw)
    except (OSError, ValueError):
        try:
            os.remove(pid_path)
        except OSError:
            pass
        return

    try:
        os.kill(stale_pid, 0)
    except OSError:
        logger.debug(
            "PID file present but process %d is gone — removing stale file",
            stale_pid,
        )
        try:
            os.remove(pid_path)
        except OSError:
            pass
        return

    if not is_collector_process(stale_pid):
        logger.warning(
            "PID %d in stale pid file belongs to a different process — "
            "skipping kill to avoid harming an unrelated process; "
            "removing stale pid file",
            stale_pid,
        )
        try:
            os.remove(pid_path)
        except OSError:
            pass
        return

    logger.warning("Stale collector process %d detected — sending SIGTERM", stale_pid)
    try:
        os.kill(stale_pid, signal.SIGTERM)
    except OSError as exc:
        logger.debug("SIGTERM to %d failed: %s", stale_pid, exc)

    deadline = time.time() + 5
    while time.time() < deadline:
        try:
            os.kill(stale_pid, 0)
        except OSError:
            break
        time.sleep(0.25)
    else:
        logger.warning(
            "Stale process %d did not exit after SIGTERM — sending SIGKILL",
            stale_pid,
        )
        try:
            os.kill(stale_pid, signal.SIGKILL)
        except OSError:
            pass

    try:
        os.remove(pid_path)
    except OSError:
        pass
    logger.info("Stale collector process %d cleaned up", stale_pid)
