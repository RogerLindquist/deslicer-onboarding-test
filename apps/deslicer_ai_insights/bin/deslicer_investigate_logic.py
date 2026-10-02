# encoding = utf-8
"""Custom alert action: POST Splunk alert context to Deslicer AI for investigation.

UCC wires this module via globalConfig alerts[].customScript. The generated
wrapper calls process_event(helper, ...) with a ModularAlertBase instance.
"""

from __future__ import print_function

import csv
import json
import os
import socket
import ssl

try:
    from urllib.error import HTTPError, URLError
    from urllib.parse import urlparse
    from urllib.request import Request, urlopen
except ImportError:  # pragma: no cover - Python 2 leftover path
    from urllib2 import HTTPError, Request, URLError, urlopen  # type: ignore
    from urlparse import urlparse  # type: ignore

SCHEMA_VERSION = 1
MAX_RESULT_ROWS = 20
HTTP_TIMEOUT_SECONDS = 30
USER_AGENT = "deslicer_ai_insights/deslicer_investigate"


def _safe_str(value):
    if value is None:
        return None
    if isinstance(value, str):
        return value
    try:
        return str(value)
    except Exception:
        return None


def _hostname_from_results_link(results_link):
    if not results_link:
        return None
    try:
        parsed = urlparse(results_link)
        host = parsed.hostname
        return _safe_str(host)
    except Exception:
        return None


def _read_server_name_from_conf():
    """Best-effort serverName from server.conf (local overrides system)."""
    splunk_home = os.environ.get("SPLUNK_HOME")
    if not splunk_home:
        return None
    candidates = (
        os.path.join(splunk_home, "etc", "system", "local", "server.conf"),
        os.path.join(splunk_home, "etc", "system", "default", "server.conf"),
    )
    for path in candidates:
        if not os.path.isfile(path):
            continue
        server_name = _parse_server_name_from_conf_path(path)
        if server_name:
            return server_name
    return None


def _parse_server_name_from_conf_path(path):
    """Return serverName from one conf file, or None if unreadable/missing."""
    try:
        in_general = False
        with open(path, "r") as handle:
            for raw_line in handle:
                line = raw_line.strip()
                if not line or line.startswith("#") or line.startswith(";"):
                    continue
                if line.startswith("[") and line.endswith("]"):
                    in_general = line[1:-1].strip().lower() == "general"
                    continue
                if not in_general or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                if key.strip().lower() == "servername":
                    return _safe_str(value.strip().strip('"'))
    except (OSError, IOError, UnicodeError):
        return None
    return None


def resolve_server_host(settings, results_link):
    """Identify the Splunk instance sending the alert (search head)."""
    settings = settings or {}
    for key in ("server_host", "serverName", "server_name"):
        value = _safe_str(settings.get(key))
        if value:
            return value

    from_link = _hostname_from_results_link(results_link)
    if from_link:
        return from_link

    from_conf = _read_server_name_from_conf()
    if from_conf:
        return from_conf

    try:
        return _safe_str(socket.gethostname())
    except Exception:
        return None


_LOCAL_HTTP_HOST_PREFIXES = (
    "http://localhost",
    "http://127.0.0.1",
    "http://host.docker.internal",
    "http://[::1]",
)


def _validate_endpoint_url(endpoint_url):
    """Require HTTPS in production; allow HTTP only for local receiver hosts."""
    if not endpoint_url:
        return "endpoint_url is required"
    url = endpoint_url.strip()
    if url.startswith("https://"):
        return None
    lowered = url.lower()
    for prefix in _LOCAL_HTTP_HOST_PREFIXES:
        if lowered.startswith(prefix):
            # Allow optional :port after the host prefix.
            rest = lowered[len(prefix) :]
            if rest == "" or rest.startswith(":") or rest.startswith("/"):
                return None
    return (
        "endpoint_url must start with https:// "
        "(http:// allowed only for localhost / 127.0.0.1 / host.docker.internal)"
    )


def _events_from_helper(helper):
    """Return up to MAX_RESULT_ROWS events from the modular alert helper."""
    events = []
    try:
        raw_events = helper.get_events()
    except Exception as exc:
        helper.log_warning("get_events failed: {}".format(exc))
        raw_events = None

    if raw_events:
        for event in raw_events:
            if len(events) >= MAX_RESULT_ROWS:
                break
            if isinstance(event, dict):
                events.append(event)
            else:
                events.append({"value": _safe_str(event)})
        return events

    settings = getattr(helper, "settings", None) or {}
    results_file = settings.get("results_file")
    if results_file and os.path.isfile(results_file):
        try:
            with open(results_file, "r") as handle:
                reader = csv.DictReader(handle)
                for row in reader:
                    if len(events) >= MAX_RESULT_ROWS:
                        break
                    events.append(dict(row))
        except Exception as exc:
            helper.log_warning("Failed reading results_file: {}".format(exc))
    return events


def build_payload(helper, events):
    """Build the Deslicer schema_version=1 alert payload."""
    settings = getattr(helper, "settings", None) or {}
    search_name = (
        helper.get_param("search_name")
        or settings.get("search_name")
        or settings.get("searchName")
    )
    sid = settings.get("sid") or settings.get("sid_id")
    owner = settings.get("owner")
    app = settings.get("app")
    results_link = settings.get("results_link") or settings.get("results_url")
    trigger_time = settings.get("trigger_time") or settings.get("trigger_time_rendered")
    results_link_str = _safe_str(results_link)
    server_host = resolve_server_host(settings, results_link_str)

    first = events[0] if events else {}
    return {
        "schema_version": SCHEMA_VERSION,
        "source": "deslicer_ai_insights",
        "search_name": _safe_str(search_name),
        "sid": _safe_str(sid),
        "server_host": server_host,
        "owner": _safe_str(owner),
        "app": _safe_str(app),
        "results_link": results_link_str,
        "trigger_time": _safe_str(trigger_time),
        "result": first,
        "results": events,
        "result_count": len(events),
    }


def post_to_deslicer(endpoint_url, api_token, payload):
    """POST JSON payload with Bearer auth. Returns (ok, status_code, error_message)."""
    body = json.dumps(payload).encode("utf-8")
    headers = {
        "Authorization": "Bearer {}".format(api_token.strip()),
        "Content-Type": "application/json",
        "User-Agent": USER_AGENT,
        "Accept": "application/json",
    }
    # data= implies POST on urllib; avoid Request(method=...) for older Splunk Pythons
    request = Request(endpoint_url.strip(), data=body, headers=headers)
    context = ssl.create_default_context()
    try:
        response = urlopen(request, timeout=HTTP_TIMEOUT_SECONDS, context=context)
        status = getattr(response, "status", None) or response.getcode()
        response.read()
        if 200 <= int(status) < 300:
            return True, int(status), None
        return False, int(status), "Unexpected HTTP status {}".format(status)
    except HTTPError as exc:
        try:
            detail = exc.read()
            detail_text = detail.decode("utf-8", errors="replace")[:500]
        except Exception:
            detail_text = ""
        return False, int(exc.code), "HTTP {}: {}".format(exc.code, detail_text)
    except URLError as exc:
        return False, None, "URL error: {}".format(exc.reason)
    except Exception as exc:
        return False, None, "Request failed: {}".format(exc)


def process_event(helper, *args, **kwargs):
    helper.log_info("Alert action deslicer_investigate started.")

    endpoint_url = helper.get_param("endpoint_url")
    api_token = helper.get_param("api_token")

    url_error = _validate_endpoint_url(endpoint_url)
    if url_error:
        helper.log_error(url_error)
        return 3
    if not api_token or not str(api_token).strip():
        helper.log_error("api_token is required")
        return 3

    events = _events_from_helper(helper)
    payload = build_payload(helper, events)
    helper.log_info(
        "Posting alert to Deslicer search_name={} result_count={}".format(
            payload.get("search_name"),
            payload.get("result_count"),
        )
    )

    ok, status, error = post_to_deslicer(endpoint_url, api_token, payload)
    if ok:
        helper.log_info("Deslicer accepted alert HTTP {}".format(status))
        return 0

    helper.log_error(
        "Deslicer investigate POST failed status={} error={}".format(status, error)
    )
    return 2
