"""Hermes lifecycle hooks for the Keysrs plugin.

``transform_api_error_classification``: when the Keysrs gateway refuses a
call, Hermes's own classifier gets it wrong. A gateway with no key loaded
(the Keysrs app restarted) answers ``404 not_found``, which Hermes reads as
"model not found" and answers by switching models. A refused client token
answers ``401 client_required``, which Hermes retries and tries to refresh
as if it were a provider key. Neither recovers on its own: both need the
user (``keys gateway on <key>`` or ``hermes keysrs setup``). This hook
claims those two refusals for the Keysrs provider only, marks them as
permanent auth failures so Hermes stops retrying, and asks ``keys client
token`` (no prompt) which fix applies.

The hook never sees or logs the token, and never logs the provider error
body (it may echo request details).
"""

from __future__ import annotations

import json
import logging
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from .keysrs_source import (
    _as_dict,
    config_flag,
    config_provider_name,
    lookup_token,
    read_hermes_config,
)

logger = logging.getLogger(__name__)

# The Keysrs gateway's own refusal bodies (Keysreallysafe Gateway.swift).
_GATEWAY_OFF_MARKER = "with the gateway on"
_CLIENT_REFUSED_MARKER = "client_required"

# One `keys client token` per refusal burst, not one per retry.
_DIAGNOSIS_TTL_SECONDS = 30.0
_cache_lock = threading.Lock()
_cache: Dict[str, Tuple[float, str]] = {}
_announced: set = set()


def _hermes_home() -> Path:
    from hermes_constants import get_hermes_home

    return Path(get_hermes_home())


def _plugin_cfg(hermes_cfg: Optional[dict]) -> Optional[dict]:
    section = _as_dict(_as_dict(_as_dict(hermes_cfg).get("secrets")).get("keysrs"))
    if not config_flag(section.get("enabled"), False):
        return None
    return section


def _is_our_provider(provider: str, provider_name: str) -> bool:
    p = (provider or "").strip().lower()
    # Hermes reports a named custom provider as "custom:<name>" on some paths
    # and as plain "custom" (with the entry's base_url) on others.
    return p in ("custom", f"custom:{provider_name}")


def _error_text(error_message: str, error_body: Any) -> str:
    parts = [error_message or ""]
    if error_body is not None:
        try:
            parts.append(json.dumps(error_body, default=str))
        except (TypeError, ValueError):
            parts.append(str(error_body))
    return " ".join(parts)


def refusal_kind(status_code: Optional[int], error_message: str, error_body: Any) -> Optional[str]:
    """``"gateway_off"``, ``"client_refused"`` or None (not a Keysrs refusal)."""
    text = _error_text(error_message, error_body)
    if status_code == 404 and _GATEWAY_OFF_MARKER in text:
        return "gateway_off"
    if status_code == 401 and _CLIENT_REFUSED_MARKER in text:
        return "client_refused"
    return None


def diagnose(cfg: dict, kind: str) -> str:
    """One line saying what is wrong and the command that fixes it."""
    key = cfg.get("key") if isinstance(cfg.get("key"), str) and cfg.get("key") else "<vault-key>"
    setup = f"hermes keysrs setup --key {key}"
    lookup = lookup_token(cfg)
    if lookup.ok:
        if kind == "gateway_off":
            # keys says the gateway is on now: it came back between the call and the check.
            return f"Keysrs gateway had no key {key!r} loaded; it is back now, so send the message again."
        return (
            "Keysrs refused the token for this call (likely out of its scope: "
            f"{_scope(lookup.meta)}). Run `hermes keysrs status`; rerun `{setup}` with a wider scope if needed."
        )
    # lookup.error is token-free by construction (see keysrs_source.lookup_token).
    message = lookup.error or "Keysrs refused the call"
    if "gateway on" in message:
        return f"Keysrs restarted and its gateway has not loaded key {key!r}. Run `keys gateway on {key}` (one Touch ID)."
    if "expired" in message or "revoked" in message or "no held" in message:
        return f"{message}. Run `{setup}` (one Touch ID)."
    return f"{message}. Run `hermes keysrs status`."


def _scope(meta: dict) -> str:
    methods = meta.get("methods")
    methods_s = ",".join(m for m in methods if isinstance(m, str)) if isinstance(methods, list) else "?"
    prefix = meta.get("path_prefix") if isinstance(meta.get("path_prefix"), str) else "any path"
    return f"{methods_s} {prefix}"


def _cached_diagnosis(cfg: dict, kind: str) -> str:
    cache_key = f"{cfg.get('label', '')}|{kind}"
    now = time.monotonic()
    with _cache_lock:
        hit = _cache.get(cache_key)
        if hit and now - hit[0] < _DIAGNOSIS_TTL_SECONDS:
            return hit[1]
    hint = diagnose(cfg, kind)
    with _cache_lock:
        _cache[cache_key] = (now, hint)
    return hint


def _announce(hint: str) -> None:
    """Show the fix once per process in an interactive terminal.

    Hermes prints the gateway's own error text, which names a generic
    `keys grant` fix; this line names the one that applies.
    """
    logger.warning("Keysrs: %s", hint)
    if hint in _announced:
        return
    _announced.add(hint)
    stream = sys.stderr
    try:
        if stream is not None and stream.isatty():
            print(f"🔑 Keysrs: {hint}", file=stream, flush=True)
    except (OSError, ValueError):
        pass


def classify_api_error(
    provider: str = "",
    status_code: Optional[int] = None,
    error_message: str = "",
    error_body: Any = None,
    **_: Any,
) -> Optional[Dict[str, Any]]:
    """``transform_api_error_classification`` callback."""
    try:
        kind = refusal_kind(status_code, error_message, error_body)
        if kind is None:
            return None
        hermes_cfg = read_hermes_config(_hermes_home())
        cfg = _plugin_cfg(hermes_cfg)
        if cfg is None or not _is_our_provider(provider, config_provider_name(cfg)):
            return None
        hint = _cached_diagnosis(cfg, kind)
        _announce(hint)
        return {
            "reason": "auth_permanent",
            "retryable": False,
            "should_rotate_credential": False,
            "should_compress": False,
            "message": hint,
            "error_context": {"keysrs": kind},
        }
    except Exception as exc:  # noqa: BLE001 - a hook must never break Hermes's classifier
        logger.debug("keysrs error hook failed: %s", type(exc).__name__)
        return None


def _reset_for_tests() -> None:
    with _cache_lock:
        _cache.clear()
    _announced.clear()
