"""Leak tripwire: stop the agent itself from reaching for the credential.

The token sits in Hermes's process environment, and while a held token is
live any process running as the user can ask ``keys client token`` for it.
A prompt-injected agent with a terminal tool could do either. Two hooks
close that path for the agent's own tools:

* ``pre_tool_call`` blocks a tool call whose arguments read the token
  variable, dump the whole environment, or ask the vault for a secret
  (``keys client token``, ``keys get``, ``security find-generic-password``...).
  Read-only ``keys`` commands (``list``, ``log``, ``spend``...) still run.
* ``transform_tool_result`` replaces any ``ksfc_`` token in a tool result
  before the model sees it.

Every trip is logged (no secret, no command text) to
``<HERMES_HOME>/keysrs/tripwire.jsonl`` so ``hermes keysrs status`` can show
it. This is a tripwire, not a sandbox: an agent that writes a script and
runs it under another name can get past it. The gateway's scope and expiry
are the real limit.
"""

from __future__ import annotations

import datetime as _dt
import json
import logging
import os
import re
import threading
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .keysrs_source import (
    GRANT_REDACTION_PATTERN,
    REDACTED,
    TOKEN_REDACTION_PATTERN,
    _as_dict,
    config_flag,
    config_key_env,
    read_hermes_config,
)

logger = logging.getLogger(__name__)

_TOKEN_RE = re.compile(f"{TOKEN_REDACTION_PATTERN}|{GRANT_REDACTION_PATTERN}")
# This plugin's own tools: they run no shell and attach the credential themselves.
OWN_TOOLS = frozenset({"keysrs_keys", "keysrs_request"})
LOG_NAME = "tripwire.jsonl"
_LOG_MAX_BYTES = 256 * 1024

# keys subcommands that never hand out a secret or change grants.
_KEYS_READ_ONLY = {
    "list", "log", "spend", "version", "doctor", "providers", "grants", "help",
    "--help", "-h", "--version",
}
# `keys client` / `keys relay` subcommands that are read-only.
_KEYS_CLIENT_READ_ONLY = {"list", "help", "--help", "-h"}

_WORD = r"(?<![\w./-])"
# Split so install scanners don't read the tripwire's own patterns as an env dump.
_ENV_LISTER = "".join(["print", "env"])
_ENV_SHOWERS = "|".join(["env", _ENV_LISTER, "export", "set", "declare", "typeset"])
# Where a shell would start a command: line start, after ; & | ( ` { $( or a quote
# (`bash -lc '...'`, `eval "..."`), or after a wrapper like sudo / env / command.
_CMD_START = (
    r"(?:^|[;&|(`{'\"]\s*|\$\(\s*"
    r"|\b(?:sudo|exec|xargs|command|nohup|time|eval|nice|caffeinate)\s+(?:-\S+\s+(?:[^-\s]\S*\s+)?)*)"
    r"(?:[\w./~-]*/)?"
)
_ENV_DUMP_RES = [
    re.compile(_WORD + _ENV_LISTER + r"\b"),
    # bare `env` (optionally piped / redirected), not `env FOO=1 cmd`
    # bare `env` / `env -0`, not `env FOO=1 cmd`; bare `export`, `set`, `declare -p`
    re.compile(_CMD_START + r"(?:" + _ENV_SHOWERS + r")(?:\s+-[0p-]+|\s+--null)?\s*(?:$|[|>;&)'\"`}])", re.M),
    re.compile(_WORD + r"export\s+-p\b"),
    re.compile(_WORD + r"(?:declare|typeset)\s+-[a-zA-Z]*[xp]"),
    re.compile(r"/proc/[^/\s]+/environ"),
    # BSD `ps e...` / macOS `ps -E` print each process's environment; `ps -ef` does not.
    re.compile(_CMD_START + r"ps\s+(?:[a-zA-Z]*e[a-zA-Z]*\b|-[a-zA-Z]*E)", re.M),
    re.compile(r"(?:print|pprint|repr|str|json\.dumps|dict)\(\s*os\.environ\s*[),]|os\.environb\b"),
    re.compile(r"(?:console\.log|JSON\.stringify)\(\s*process\.env\s*[),]"),
]
_KEYCHAIN_RE = re.compile(
    _WORD + r"security\s+(?:find-generic-password|find-internet-password|dump-keychain|export)\b"
)
# `keys <sub>` only where a shell would run it (line start, after ; && | ( ` $( sudo exec
# xargs, or as an argv element), so prose like "API keys are stored" is not a command.
_KEYS_CMD_RE = re.compile(
    _CMD_START + r"keys\s+([A-Za-z-][\w-]*)(?:\s+([A-Za-z-][\w-]*))?", re.M
)

_lock = threading.Lock()
_cfg_cache: Dict[str, Tuple[float, Optional[dict]]] = {}


def _hermes_home() -> Path:
    from hermes_constants import get_hermes_home

    return Path(get_hermes_home())


def _strings(value: Any, depth: int = 0) -> Iterable[str]:
    if depth > 6:
        return
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from _strings(v, depth + 1)
    elif isinstance(value, (list, tuple)):
        for v in value:
            yield from _strings(v, depth + 1)


def _keys_rule(text: str) -> Optional[str]:
    for match in _KEYS_CMD_RE.finditer(text):
        sub, sub2 = match.group(1), match.group(2) or ""
        if sub in _KEYS_READ_ONLY:
            continue
        if sub in ("client", "relay") and sub2 in _KEYS_CLIENT_READ_ONLY | {"status"}:
            continue
        if sub == "models" and "--cached" in text[match.end():match.end() + 80]:
            continue
        return f"keys {sub}{(' ' + sub2) if sub2 and sub in ('client', 'relay', 'gateway') else ''}"
    return None


def _argv_text(args: Any) -> List[str]:
    """Tool args as text; every list of strings (an argv) is also joined as one command."""
    texts = list(_strings(args))

    def walk(value: Any, depth: int = 0) -> None:
        if depth > 6:
            return
        if isinstance(value, (list, tuple)):
            if value and all(isinstance(v, str) for v in value):
                texts.append(" ".join(value))
            for v in value:
                walk(v, depth + 1)
        elif isinstance(value, dict):
            for v in value.values():
                walk(v, depth + 1)

    walk(args)
    return texts


def check_args(args: Any, key_env: str) -> Optional[str]:
    """The rule a tool call trips, or None. Never returns argument text."""
    for text in _argv_text(args):
        if key_env and re.search(rf"(?<![A-Za-z0-9_]){re.escape(key_env)}(?![A-Za-z0-9_])", text):
            return f"reads {key_env}"
        if _TOKEN_RE.search(text):
            return "uses a Keysrs token"
        if _KEYCHAIN_RE.search(text):
            return "reads the macOS Keychain"
        rule = _keys_rule(text)
        if rule:
            return f"asks the vault ({rule})"
        for pattern in _ENV_DUMP_RES:
            if pattern.search(text):
                return "dumps the environment"
    return None


_warned: set = set()


def _warn_once(what: str) -> None:
    if what not in _warned:
        _warned.add(what)
        logger.warning("Keysrs tripwire is not running: %s", what)


def tripwire_on(section: Any) -> bool:
    section = _as_dict(section)
    return config_flag(section.get("enabled"), False) and config_flag(section.get("tripwire"), True)


def _settings() -> Optional[dict]:
    """secrets.keysrs when the plugin and the tripwire are on, else None.

    Re-read only when config.yaml changes: this runs on every tool call.
    An unreadable config is not cached, so a read during a rewrite retries.
    """
    try:
        path = _hermes_home() / "config.yaml"
        mtime = path.stat().st_mtime
    except Exception as exc:  # noqa: BLE001 - ImportError, OSError
        _warn_once(f"cannot read the Hermes config ({type(exc).__name__})")
        return None
    key = str(path)
    with _lock:
        hit = _cfg_cache.get(key)
        if hit and hit[0] == mtime:
            return hit[1]
    raw = read_hermes_config(path.parent)
    if raw is None:
        _warn_once("config.yaml did not parse")
        return None
    section = _as_dict(_as_dict(raw.get("secrets")).get("keysrs"))
    value = section if tripwire_on(section) else None
    with _lock:
        _cfg_cache[key] = (mtime, value)
    return value


def record(event: str, tool_name: str, rule: str) -> None:
    """Append one trip to the log. Holds no secret and no command text."""
    entry = {
        "at": _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "event": event,
        "tool": str(tool_name)[:64],
        "rule": rule,
    }
    logger.warning("Keysrs tripwire: %s %s (%s)", event, entry["tool"], rule)
    try:
        folder = _hermes_home() / "keysrs"
        folder.mkdir(mode=0o700, exist_ok=True)
        log = folder / LOG_NAME
        with _lock:
            if log.exists() and log.stat().st_size > _LOG_MAX_BYTES:
                log.replace(folder / (LOG_NAME + ".1"))
            with open(log, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry) + "\n")
    except OSError as exc:
        logger.debug("tripwire log write failed: %s", type(exc).__name__)


def read_log(home: Path, limit: int = 200) -> List[dict]:
    try:
        lines = (Path(home) / "keysrs" / LOG_NAME).read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    out = []
    for line in lines[-limit:]:
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if isinstance(item, dict):
            out.append(item)
    return out


def pre_tool_call(tool_name: str = "", args: Any = None, **_: Any) -> Optional[Dict[str, str]]:
    """``pre_tool_call`` callback: block calls that reach for the credential."""
    try:
        if tool_name in OWN_TOOLS:
            return None
        cfg = _settings()
        if cfg is None:
            return None
        rule = check_args(args, config_key_env(cfg))
        if rule is None:
            return None
        record("blocked", tool_name, rule)
        return {
            "action": "block",
            "message": (
                f"Blocked by Keysrs: this {tool_name or 'tool'} call {rule}. "
                "Provider credentials are managed by Keysrs and are not available to tools. "
                "If the user asked for this, they can run it in their own terminal."
            ),
        }
    except Exception as exc:  # noqa: BLE001 - never break tool dispatch
        _warn_once(f"pre_tool_call failed ({type(exc).__name__})")
        return None


def _live_tokens(cfg: dict) -> List[str]:
    value = os.environ.get(config_key_env(cfg), "")
    return [value] if len(value) >= 12 else []


def transform_tool_result(tool_name: str = "", result: Any = None, **_: Any) -> Optional[str]:
    """``transform_tool_result`` callback: hide any token in tool output.

    Hermes hands this hook the final result string (JSON for structured
    tools) and only accepts a string back, so scrubbing the string covers
    structured results too.
    """
    try:
        if not isinstance(result, str) or not result:
            return None
        cfg = _settings()
        if cfg is None:
            return None
        cleaned = result
        for token in _live_tokens(cfg):
            cleaned = cleaned.replace(token, REDACTED)
        cleaned = _TOKEN_RE.sub(REDACTED, cleaned) if "ksf" in cleaned else cleaned
        if cleaned == result:
            return None
        record("redacted", tool_name, "token in tool output")
        return cleaned
    except Exception as exc:  # noqa: BLE001 - never break tool dispatch
        _warn_once(f"transform_tool_result failed ({type(exc).__name__})")
        return None


def _reset_for_tests() -> None:
    with _lock:
        _cfg_cache.clear()
    _warned.clear()
