"""``/keysrs`` in a Hermes session, including from a messaging platform.

    /keysrs            token scope and expiry, gateway state, today's calls and
                       spend for the key, refusals, tripwire trips
    /keysrs revoke     kill switch: revoke Hermes's held token now (no Touch ID);
                       every later call is refused at the gateway
    /keysrs help

The only route to Keysrs is the ``keys`` CLI through Hermes's
``run_secret_cli`` (argument list, no shell, minimal environment). Nothing
here prints a token. Re-arming after a revoke needs ``hermes keysrs setup``
on the Mac, with Touch ID, on purpose: a chat message can cut access off but
never grant it.
"""

from __future__ import annotations

import datetime as _dt
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from agent.secret_sources.base import run_secret_cli

from .keysrs_source import (
    KEYS_ALLOW_ENV,
    KeysrsSource,
    _as_dict,
    _now,
    config_flag,
    config_label,
    helper_timeout,
    lookup_token,
    parse_expiry,
    read_hermes_config,
    resolve_keys_binary,
    scrub,
    valid_name,
)
from .tripwire import read_log, tripwire_on

logger = logging.getLogger(__name__)

HELP = (
    "/keysrs — Keysrs status: token scope and expiry, gateway, today's calls and spend\n"
    "/keysrs revoke — revoke Hermes's token now (no Touch ID); re-arm on the Mac with "
    "`hermes keysrs setup` (Touch ID)"
)


def _hermes_home() -> Path:
    from hermes_constants import get_hermes_home

    return Path(get_hermes_home())


def _section() -> Dict[str, Any]:
    cfg = read_hermes_config(_hermes_home())
    return _as_dict(_as_dict(_as_dict(cfg).get("secrets")).get("keysrs"))


def _keys_json(cfg: dict, argv: List[str]) -> Optional[Any]:
    """Run a read-only ``keys`` command and parse its JSON, or None."""
    binary = resolve_keys_binary(cfg)
    if binary is None:
        return None
    try:
        proc = run_secret_cli([str(binary), *argv], allow_env=KEYS_ALLOW_ENV, timeout=helper_timeout(cfg))
    except RuntimeError:
        return None
    if proc.returncode != 0:
        return None
    text = (proc.stdout or "").strip()
    try:
        return json.loads(text)
    except ValueError:
        rows = []
        for line in text.splitlines():
            try:
                rows.append(json.loads(line))
            except ValueError:
                continue
        return rows


def _today_strings() -> set:
    return {_dt.date.today().isoformat(), _now().date().isoformat()}


def _spend_today(cfg: dict, key: str) -> str:
    data = _keys_json(cfg, ["spend", "--json", "--by", "key"])
    if not isinstance(data, dict):
        return "unavailable"
    days = _today_strings()
    calls, usd, priced = 0, 0.0, False
    for row in data.get("daily") or []:
        if not isinstance(row, dict) or row.get("day") not in days:
            continue
        if row.get("model") != key and row.get("key") != key:
            continue
        calls += int(row.get("model_calls") or 0)
        for field in ("usd", "usd_estimate"):
            if isinstance(row.get(field), (int, float)):
                usd += float(row[field])
                priced = True
                break
    money = f"${usd:.2f}" if priced else "no price reported"
    return f"{calls} calls, {money}"


def _refusals_today(cfg: dict, key: str) -> str:
    rows = _keys_json(cfg, ["log", "--key", key, "--failed", "--limit", "200", "--json"])
    if not isinstance(rows, list):
        return "unavailable"
    days = _today_strings()
    today = [r for r in rows if isinstance(r, dict) and str(r.get("ts", ""))[:10] in days]
    refused = [r for r in today if r.get("kind") != "call" or r.get("reason") != "upstream_status"]
    if not refused:
        return "none today"
    reasons: Dict[str, int] = {}
    for r in refused:
        reason = scrub(str(r.get("reason") or "?"), limit=40)
        reasons[reason] = reasons.get(reason, 0) + 1
    parts = ", ".join(f"{n}× {reason}" for reason, n in sorted(reasons.items(), key=lambda kv: -kv[1]))
    return f"{len(refused)} today ({parts})"


def _tripwire_line(cfg: dict) -> str:
    if not tripwire_on(cfg):
        return "off"
    events = read_log(_hermes_home())
    blocked = sum(1 for e in events if e.get("event") == "blocked")
    hidden = sum(1 for e in events if e.get("event") == "redacted")
    line = f"on; recent: {blocked} blocked, {hidden} hidden"
    if events:
        last = events[-1]
        line += f" (last: {last.get('tool', '?')} {last.get('rule', '')})"
    return line


def status_text() -> str:
    cfg = _section()
    if not config_flag(cfg.get("enabled"), False):
        return "Keysrs is not set up for this Hermes. On the Mac: `hermes keysrs setup --key <vault key> --use`."
    key = cfg.get("key") if isinstance(cfg.get("key"), str) and cfg.get("key") else "?"
    lines = [f"🔑 Keysrs — key {key}, label {config_label(cfg)}"]
    lookup = lookup_token(cfg)
    if not lookup.ok:
        lines.append(f"token: unavailable — {lookup.error}")
        hint = KeysrsSource().remediation(lookup.error_kind, cfg)
        if hint:
            lines.append(f"fix: {hint}")
    else:
        meta = lookup.meta
        expires = parse_expiry(meta.get("expires_at"))
        if expires is not None:
            hours = max(0, int((expires - _now()).total_seconds() // 3600))
            left = f"{hours // 24}d {hours % 24}h" if hours >= 24 else f"{hours}h"
            lines.append(f"token: live, expires in {left}" + (" ⚠️ renew soon: `hermes keysrs setup`" if hours < 24 else ""))
        else:
            lines.append("token: live")
        methods = meta.get("methods")
        methods_s = ",".join(str(m) for m in methods) if isinstance(methods, list) and methods else "any method"
        lines.append(f"scope: {methods_s} {meta.get('path_prefix') or 'any path'} on this Mac only")
        lines.append("gateway: key loaded" if meta.get("gateway_on") is True else f"gateway: key NOT loaded — run `keys gateway on {key}`")
    if key != "?" and valid_name(key):
        lines.append(f"today: {_spend_today(cfg, key)}")
        lines.append(f"refusals: {_refusals_today(cfg, key)}")
    lines.append(f"tripwire: {_tripwire_line(cfg)}")
    return "\n".join(lines)


def revoke_text() -> str:
    cfg = _section()
    if not config_flag(cfg.get("enabled"), False):
        return "Keysrs is not set up for this Hermes; nothing to revoke."
    lookup = lookup_token(cfg)
    meta = lookup.meta
    client_id = meta.get("client_id")
    key = meta.get("key") if isinstance(meta.get("key"), str) else ""
    if not lookup.ok and not (isinstance(client_id, int) and key):
        return f"No live Keysrs token to revoke ({lookup.error}). Hermes is already cut off."
    if not isinstance(client_id, int) or client_id <= 0 or not valid_name(key):
        return "Keysrs did not report a client id for this token; revoke it on the Mac with `keys client list`."
    binary = resolve_keys_binary(cfg)
    if binary is None:
        return "Keysrs CLI not found; revoke it on the Mac."
    try:
        proc = run_secret_cli(
            [str(binary), "client", "revoke", key, str(client_id)],
            allow_env=KEYS_ALLOW_ENV,
            timeout=helper_timeout(cfg),
        )
    except RuntimeError as exc:
        return f"Revoke failed: {scrub(str(exc))}. Run `keys client revoke {key} {client_id}` on the Mac."
    if proc.returncode != 0:
        return f"Revoke failed (keys exited {proc.returncode}): {scrub(proc.stderr)}"
    logger.warning("Keysrs: client #%s for key %s revoked from a /keysrs command", client_id, key)
    return (
        f"🛑 Revoked Keysrs client #{client_id} for {key}. Every call Hermes makes with it is now refused "
        "at the gateway. To re-arm, run `hermes keysrs setup` on the Mac (Touch ID)."
    )


def handle(raw_args: str = "") -> str:
    """``/keysrs`` handler. Never raises, never returns a token."""
    try:
        words = (raw_args or "").strip().lower().split()
        sub = words[0] if words else "status"
        if sub in ("status", "s"):
            return status_text()
        if sub == "revoke":
            return revoke_text()
        if sub in ("help", "-h", "--help", "?"):
            return HELP
        return f"Unknown /keysrs command {scrub(sub, limit=20)!r}.\n{HELP}"
    except Exception as exc:  # noqa: BLE001 - a slash command must not crash the session
        logger.debug("keysrs command failed: %s", type(exc).__name__)
        return f"/keysrs failed ({type(exc).__name__}). Try `hermes keysrs status` on the Mac."
