"""Agent tools: use other vault keys without ever holding a credential.

* ``keysrs_keys`` lists the vault's key names and providers (never a value).
* ``keysrs_request`` makes one HTTP call to a key's provider through the
  local Keysrs gateway. The first call for a key asks Keysrs for a short,
  scoped grant: one Touch ID on the Mac, whose prompt names the task Hermes
  gave. The plugin keeps the grant token in memory and puts it on the
  request itself, so the model sees the provider's answer and nothing else:
  no key, no grant token.

A grant covers one HTTP method and the path prefix the agent asked for,
lasts at most an hour (default 15 minutes), allows at most 100 calls, and
dies with screen lock or a Keysrs restart. The user can limit which keys
the agent may ask for with ``secrets.keysrs.agent_keys``.
"""

from __future__ import annotations

import datetime as _dt
import json
import logging
import re
import threading
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from agent.secret_sources.base import run_secret_cli

from .keysrs_source import (
    GRANT_REDACTION_PATTERN,
    KEYS_ALLOW_ENV,
    REDACTED,
    TOKEN_REDACTION_PATTERN,
    _as_dict,
    _now,
    config_flag,
    helper_timeout,
    is_loopback_http_url,
    parse_expiry,
    read_hermes_config,
    resolve_keys_binary,
    scrub,
    valid_name,
)

logger = logging.getLogger(__name__)

TOOLSET = "keysrs"
# Long enough for the user to reach the Mac and touch the sensor.
GRANT_TIMEOUT_SECONDS = 120.0
REQUEST_TIMEOUT_SECONDS = 60.0
DEFAULT_MINUTES = 15
MAX_MINUTES = 60
MAX_REQUESTS = 100
MAX_BODY_CHARS = 20000
METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE")
# Headers the agent may not set: credentials go on only from the held grant.
_BLOCKED_HEADERS = {
    "authorization", "x-api-key", "x-goog-api-key", "api-key", "proxy-authorization",
    "cookie", "host", "content-length", "transfer-encoding", "connection",
    "x-http-method-override", "x-http-method", "x-method-override",
}
_BLOCKED_HEADER_PREFIXES = ("x-ksf-", "x-keysrs-", "proxy-")
_GRANT_TOKEN_RE = re.compile(f"{GRANT_REDACTION_PATTERN}|{TOKEN_REDACTION_PATTERN}")
# Keysrs refuses a task longer than this (Grants.swift GrantRequest.validated).
_TASK_LIMIT = 120
_PATH_RE = re.compile(r"^/[A-Za-z0-9._~!$&'()*+,;=:@%/-]*$")


def _hermes_home() -> Path:
    from hermes_constants import get_hermes_home

    return Path(get_hermes_home())


def _section() -> Dict[str, Any]:
    cfg = read_hermes_config(_hermes_home())
    return _as_dict(_as_dict(_as_dict(cfg).get("secrets")).get("keysrs"))


def _allowed_keys(cfg: dict) -> Optional[set]:
    """``secrets.keysrs.agent_keys``: a list limits which keys the agent may use."""
    raw = cfg.get("agent_keys")
    if isinstance(raw, list):
        return {k for k in raw if isinstance(k, str) and valid_name(k)}
    return None


def available() -> bool:
    """check_fn: offer the tools only when Keysrs is set up and agent access is on."""
    try:
        cfg = _section()
        return config_flag(cfg.get("enabled"), False) and config_flag(cfg.get("agent_access"), True)
    except Exception:  # noqa: BLE001
        return False


@dataclass
class Grant:
    key: str
    method: str
    path_prefix: str
    base_url: str
    auth_header: str
    expires_at: Optional[_dt.datetime]
    grant_id: str = ""
    token: str = field(default="", repr=False)

    def covers(self, method: str, path: str) -> bool:
        if self.expires_at is not None and self.expires_at <= _now() + _dt.timedelta(seconds=15):
            return False
        return method == self.method and _under(path, self.path_prefix)


def _under(path: str, prefix: str) -> bool:
    if prefix in ("", "/"):
        return True
    p = prefix.rstrip("/")
    return path == p or path.startswith(p + "/") or path.startswith(p + "?")


_lock = threading.Lock()
_grants: Dict[str, List[Grant]] = {}
# One Touch ID prompt at a time per key: parallel tool calls wait for the first grant.
_issue_locks: Dict[str, threading.Lock] = {}


def _issue_lock(key: str) -> threading.Lock:
    with _lock:
        return _issue_locks.setdefault(key, threading.Lock())


def _held(key: str, method: str, path: str) -> Optional[Grant]:
    with _lock:
        live = [g for g in _grants.get(key, []) if g.expires_at is None or g.expires_at > _now()]
        _grants[key] = live
        for g in live:
            if g.covers(method, path):
                return g
    return None


def _keep(grant: Grant) -> None:
    with _lock:
        _grants.setdefault(grant.key, []).append(grant)


def _drop(grant: Grant) -> None:
    with _lock:
        _grants[grant.key] = [g for g in _grants.get(grant.key, []) if g is not grant]


def held_grants() -> List[Grant]:
    with _lock:
        return [g for gs in _grants.values() for g in gs]


def revoke_all(cfg: dict) -> Tuple[int, int]:
    """Revoke every grant this process holds (``keys revoke <id>``, no Touch ID).

    Returns ``(revoked, failed)``. Held grants are forgotten either way.
    """
    with _lock:
        grants = [g for gs in _grants.values() for g in gs]
        _grants.clear()
    if not grants:
        return 0, 0
    binary = resolve_keys_binary(cfg)
    revoked = failed = 0
    for g in grants:
        if binary is None or not re.fullmatch(r"[0-9a-f]{8}", g.grant_id or ""):
            failed += 1
            continue
        try:
            proc = run_secret_cli([str(binary), "revoke", g.grant_id], allow_env=KEYS_ALLOW_ENV, timeout=helper_timeout(cfg))
        except RuntimeError:
            failed += 1
            continue
        if proc.returncode == 0:
            revoked += 1
        else:
            failed += 1
    return revoked, failed


def _key_kind(cfg: dict, key: str) -> Optional[str]:
    """The vault key's kind (runtime / billing / ...) or None if not found."""
    binary = resolve_keys_binary(cfg)
    if binary is None:
        return None
    try:
        proc = run_secret_cli([str(binary), "list", "--json"], allow_env=KEYS_ALLOW_ENV, timeout=helper_timeout(cfg))
        rows = json.loads(proc.stdout or "[]") if proc.returncode == 0 else []
    except (RuntimeError, ValueError):
        return None
    for row in rows if isinstance(rows, list) else []:
        if isinstance(row, dict) and row.get("name") == key:
            return str(row.get("kind") or "runtime")
    return None


def _err(message: str, **extra: Any) -> str:
    return json.dumps({"ok": False, "error": message, **extra})


def _redact(text: str) -> str:
    return _GRANT_TOKEN_RE.sub(REDACTED, text)


def prompt_task(method: str, scope: str, task: str) -> str:
    """The Touch ID prompt's task line: the real method and scope first, so the
    user approves what will run, not only the agent's own description of it."""
    head = f"Hermes {method} {scope or '/'}: "
    if len(head) >= _TASK_LIMIT - 8:
        head = head[: _TASK_LIMIT - 9] + "…: "
    room = _TASK_LIMIT - len(head)
    return head + (task if len(task) <= room else task[: room - 1] + "…")


# ---------------------------------------------------------------------------
# keysrs_keys
# ---------------------------------------------------------------------------

KEYS_SCHEMA = {
    "name": "keysrs_keys",
    "description": (
        "List the API keys in the user's Keysrs vault that you may ask to use: name, provider "
        "and API host. Never returns a key value. Use keysrs_request to call one of them."
    ),
    "parameters": {"type": "object", "properties": {}, "required": []},
}


def keysrs_keys(args: Optional[dict] = None, **_: Any) -> str:
    try:
        cfg = _section()
        binary = resolve_keys_binary(cfg)
        if binary is None:
            return _err("Keysrs CLI not found")
        try:
            proc = run_secret_cli([str(binary), "list", "--json"], allow_env=KEYS_ALLOW_ENV, timeout=helper_timeout(cfg))
        except RuntimeError as exc:
            return _err(scrub(str(exc)))
        if proc.returncode != 0:
            return _err(f"keys list exited {proc.returncode}")
        try:
            rows = json.loads(proc.stdout or "[]")
        except ValueError:
            return _err("keys list printed malformed JSON")
        allowed = _allowed_keys(cfg)
        out = []
        for row in rows if isinstance(rows, list) else []:
            if not isinstance(row, dict) or not valid_name(str(row.get("name", ""))):
                continue
            if allowed is not None and row["name"] not in allowed:
                continue
            if row.get("kind") not in (None, "runtime"):
                continue  # billing / signing keys are not for agents
            out.append({
                "name": row["name"],
                "provider": scrub(str(row.get("provider") or ""), limit=40),
                "host": scrub(str(row.get("host") or ""), limit=80),
            })
        return json.dumps({"ok": True, "keys": out, "note": "Each first use asks the user for Touch ID on their Mac."})
    except Exception as exc:  # noqa: BLE001 - a tool must answer, not crash the turn
        return _err(f"keysrs_keys failed ({type(exc).__name__})")


# ---------------------------------------------------------------------------
# keysrs_request
# ---------------------------------------------------------------------------

REQUEST_SCHEMA = {
    "name": "keysrs_request",
    "description": (
        "Call an API with a key from the user's Keysrs vault, without seeing the key. "
        "The first call for a key/method/path asks the user to approve with Touch ID on their "
        "Mac (the prompt shows your `task`), then calls within that scope run without asking "
        "for up to `minutes`. `path` is relative to the provider's API root (e.g. GitHub: "
        "/user/repos; Stripe: /v1/customers). Returns the HTTP status and response body."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "key": {"type": "string", "description": "Vault key name from keysrs_keys"},
            "method": {"type": "string", "enum": list(METHODS)},
            "path": {"type": "string", "description": "Path (and optional ?query) under the provider's API root, starting with /"},
            "task": {"type": "string", "description": "One short line saying why, shown to the user in the Touch ID prompt"},
            "body": {"description": "JSON body (object/array) or a string", "type": ["object", "array", "string", "null"]},
            "headers": {"type": "object", "description": "Extra non-auth headers, e.g. Accept"},
            "scope": {"type": "string", "description": "Path prefix to ask access for (default: the path itself). Wider scope = fewer prompts."},
            "minutes": {"type": "integer", "description": f"Grant lifetime, 1-{MAX_MINUTES} (default {DEFAULT_MINUTES})"},
        },
        "required": ["key", "method", "path", "task"],
    },
}


def _valid_path(path: Any) -> bool:
    if not isinstance(path, str) or not path.startswith("/") or path.startswith("//"):
        return False
    bare = path.split("?", 1)[0]
    if not _PATH_RE.match(bare):
        return False
    return ".." not in bare.split("/")


def _issue(cfg: dict, key: str, method: str, scope: str, task: str, minutes: int) -> Tuple[Optional[Grant], str]:
    binary = resolve_keys_binary(cfg)
    if binary is None:
        return None, "Keysrs CLI not found"
    argv = [
        str(binary), "grant", key,
        "--task", prompt_task(method, scope, task),
        "--minutes", str(minutes),
        "--methods", method,
        "--max-requests", str(MAX_REQUESTS),
        "--json",
    ]
    if scope not in ("", "/"):
        argv[-1:-1] = ["--paths", scope]
    try:
        proc = run_secret_cli(argv, allow_env=KEYS_ALLOW_ENV, timeout=GRANT_TIMEOUT_SECONDS)
    except RuntimeError as exc:
        return None, f"no answer from Keysrs ({scrub(str(exc))}); the user may not have approved"
    if proc.returncode != 0:
        detail = scrub(proc.stderr or proc.stdout or "", limit=200)
        return None, f"the user declined or Keysrs refused the grant (keys exited {proc.returncode}: {detail})"
    try:
        obj = json.loads((proc.stdout or "").strip().splitlines()[0])
    except (ValueError, IndexError):
        return None, "keys grant printed malformed JSON"
    token = obj.get("token") if isinstance(obj, dict) else None
    base_url = obj.get("base_url") if isinstance(obj, dict) else None
    if not isinstance(token, str) or not token.startswith("ksf_") or any(c.isspace() for c in token):
        return None, "keys grant returned no grant token"
    if not isinstance(base_url, str) or not is_loopback_http_url(base_url):
        return None, "keys grant returned a gateway URL that is not on this Mac"
    header = obj.get("auth_header") if isinstance(obj.get("auth_header"), str) else "Authorization"
    if header.lower() not in ("authorization", "x-api-key", "x-goog-api-key", "api-key"):
        header = "Authorization"
    grant = Grant(
        key=key, method=method, path_prefix=scope, base_url=base_url.rstrip("/"),
        auth_header=header, expires_at=parse_expiry(obj.get("expires_at")),
        grant_id=str(obj.get("id") or "")[:16], token=token,
    )
    return grant, ""


def _send(grant: Grant, method: str, path: str, body: Any, headers: Dict[str, str]) -> Tuple[int, str, str, str]:
    """(status, content_type, body_text, x-keysrs-source)."""
    url = grant.base_url + path
    data: Optional[bytes] = None
    send_headers = {k: v for k, v in headers.items()}
    if body is not None and method != "GET":
        if isinstance(body, (dict, list)):
            data = json.dumps(body).encode()
            send_headers.setdefault("content-type", "application/json")
        else:
            data = str(body).encode()
    value = f"Bearer {grant.token}" if grant.auth_header.lower() == "authorization" else grant.token
    send_headers[grant.auth_header] = value
    req = urllib.request.Request(url, data=data, method=method, headers=send_headers)
    # Loopback only: never follow a redirect off the Mac with the grant attached.
    opener = urllib.request.build_opener(_NoRedirect, urllib.request.ProxyHandler({}))
    try:
        with opener.open(req, timeout=REQUEST_TIMEOUT_SECONDS) as resp:
            raw = resp.read(MAX_BODY_CHARS * 4 + 1)
            return resp.status, resp.headers.get("Content-Type", ""), raw.decode("utf-8", "replace"), resp.headers.get("X-Keysrs-Source", "")
    except urllib.error.HTTPError as exc:
        raw = exc.read(MAX_BODY_CHARS * 4 + 1) if exc.fp else b""
        return exc.code, exc.headers.get("Content-Type", "") if exc.headers else "", raw.decode("utf-8", "replace"), (exc.headers.get("X-Keysrs-Source", "") if exc.headers else "")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None


def keysrs_request(args: Optional[dict] = None, **_: Any) -> str:
    try:
        args = _as_dict(args)
        cfg = _section()
        if not config_flag(cfg.get("enabled"), False) or not config_flag(cfg.get("agent_access"), True):
            return _err("Keysrs agent access is turned off (secrets.keysrs.agent_access)")
        key = args.get("key")
        method = str(args.get("method") or "").upper()
        path = args.get("path")
        task = " ".join(str(args.get("task") or "").split())[:120]
        if not isinstance(key, str) or not valid_name(key):
            return _err("`key` must be a vault key name from keysrs_keys")
        allowed = _allowed_keys(cfg)
        if allowed is not None and key not in allowed:
            return _err(f"the user has not allowed agent access to {key!r} (secrets.keysrs.agent_keys)")
        if key == cfg.get("key"):
            return _err(f"{key!r} is Hermes's own model key; it is only for chat, not for keysrs_request")
        if method not in METHODS:
            return _err(f"`method` must be one of {', '.join(METHODS)}")
        if not _valid_path(path):
            return _err("`path` must start with / and stay under the API root (no scheme, host or ..)")
        if not task:
            return _err("`task` is required: one line the user sees in the Touch ID prompt")
        scope = args.get("scope") if args.get("scope") is not None else path.split("?", 1)[0]
        if not (scope in ("", "/") or _valid_path(scope)) or "?" in str(scope):
            return _err("`scope` must be a path prefix starting with /")
        if not _under(path.split("?", 1)[0], scope):
            return _err("`path` is not under `scope`")
        if method == "DELETE" and scope != path.split("?", 1)[0]:
            return _err("a DELETE grant covers exactly one path: leave `scope` unset")
        try:
            minutes = int(args.get("minutes") or DEFAULT_MINUTES)
        except (TypeError, ValueError):
            minutes = DEFAULT_MINUTES
        minutes = max(1, min(MAX_MINUTES, minutes))
        headers: Dict[str, str] = {}
        for name, value in _as_dict(args.get("headers")).items():
            if not isinstance(name, str) or not isinstance(value, str):
                continue
            low = name.lower()
            if low in _BLOCKED_HEADERS or low.startswith(_BLOCKED_HEADER_PREFIXES) or not re.match(r"^[A-Za-z0-9-]{1,64}$", name) or any(c in value for c in "\r\n"):
                continue
            headers[low] = value[:1024]

        asked = False
        with _issue_lock(key):
            grant = _held(key, method, path.split("?", 1)[0])
            if grant is None:
                kind = _key_kind(cfg, key)
                if kind is None:
                    return _err(f"no vault key {key!r}; call keysrs_keys for the names")
                if kind != "runtime":
                    return _err(f"{key!r} is a {kind} key, which agents may not use")
                grant, problem = _issue(cfg, key, method, scope, task, minutes)
                if grant is None:
                    return _err(problem, key=key)
                _keep(grant)
                asked = True
            logger.warning("Keysrs: grant %s for %s %s %s (task: %s)", grant.grant_id, key, method, scope or "/", task)

        status, ctype, text, source = _send(grant, method, path, args.get("body"), headers)
        if source == "gateway" and status in (401, 403, 404, 429):
            # The grant ended (expired, revoked, screen lock, out of scope, limit): forget it.
            _drop(grant)
        text = _redact(text)
        truncated = len(text) > MAX_BODY_CHARS
        result: Dict[str, Any] = {
            "ok": 200 <= status < 300,
            "status": status,
            "content_type": scrub(ctype, limit=80),
            "body": text[:MAX_BODY_CHARS],
        }
        if truncated:
            result["truncated"] = True
        if source == "gateway" and status >= 400:
            result["refused_by"] = "Keysrs gateway (the grant's scope, expiry or limits); call again to ask the user for a new grant"
        if asked:
            result["note"] = f"the user approved access to {key} {method} {scope or '/'} for {minutes} min"
        return json.dumps(result)
    except Exception as exc:  # noqa: BLE001 - a tool must answer, not crash the turn
        return _err(f"keysrs_request failed ({type(exc).__name__})")


def register(ctx) -> None:
    register_tool = getattr(ctx, "register_tool", None)
    if not callable(register_tool):
        return
    for schema, handler, emoji in (
        (KEYS_SCHEMA, keysrs_keys, "🔑"),
        (REQUEST_SCHEMA, keysrs_request, "🔐"),
    ):
        register_tool(
            name=schema["name"],
            toolset=TOOLSET,
            schema=schema,
            handler=handler,
            check_fn=available,
            description=schema["description"],
            emoji=emoji,
        )


def _reset_for_tests() -> None:
    with _lock:
        _grants.clear()
        _issue_locks.clear()
