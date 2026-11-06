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

import asyncio
import datetime as _dt
import json
import logging
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Dict, List, Optional

from agent.secret_sources.base import ErrorKind, run_secret_cli

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


# A slash command waits on these; keep each well under Hermes's 30s bound.
_COMMAND_TIMEOUT_SECONDS = 8.0


def _keys_json(cfg: dict, argv: List[str], *, jsonl: bool = False) -> Optional[Any]:
    """Run a read-only ``keys`` command and parse its JSON (or JSON lines), or None."""
    binary = resolve_keys_binary(cfg)
    if binary is None:
        return None
    try:
        proc = run_secret_cli(
            [str(binary), *argv],
            allow_env=KEYS_ALLOW_ENV,
            timeout=min(helper_timeout(cfg), _COMMAND_TIMEOUT_SECONDS),
        )
    except RuntimeError:
        return None
    if proc.returncode != 0:
        return None
    text = (proc.stdout or "").strip()
    if not jsonl:
        try:
            return json.loads(text)
        except ValueError:
            return None
    rows = []
    for line in text.splitlines():
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if isinstance(row, dict):
            rows.append(row)
    return rows


def _int(value: Any) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return 0


def _local_day(ts: Any) -> str:
    """The Mac's local calendar day of a UTC log timestamp (Keysrs buckets spend by local day)."""
    parsed = parse_expiry(ts)
    return parsed.astimezone().date().isoformat() if parsed else ""


def _today() -> str:
    return _dt.date.today().isoformat()


def _spend_today(cfg: dict, key: str) -> str:
    data = _keys_json(cfg, ["spend", "--json", "--by", "key"])
    if not isinstance(data, dict):
        return "unavailable"
    today = _today()
    calls, usd, priced = 0, 0.0, False
    for row in data.get("daily") or []:
        if not isinstance(row, dict) or row.get("day") != today:
            continue
        if row.get("model") != key and row.get("key") != key:
            continue
        calls += _int(row.get("model_calls"))
        for field in ("usd", "usd_estimate"):
            if isinstance(row.get(field), (int, float)):
                usd += float(row[field])
                priced = True
                break
    money = f"${usd:.2f}" if priced else "no price reported"
    return f"{calls} calls, {money}"


def _refusals_today(cfg: dict, key: str) -> str:
    """Calls the gateway refused today (scope, revoked, gateway off...).

    Transport failures and provider errors are calls that went out, not refusals.
    """
    rows = _keys_json(cfg, ["log", "--key", key, "--failed", "--limit", "200", "--json"], jsonl=True)
    if rows is None:
        return "unavailable"
    today = _today()
    refused = [r for r in rows if r.get("kind") != "call" and _local_day(r.get("ts")) == today]
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


def _cfg_key(cfg: dict) -> str:
    key = cfg.get("key")
    return key if isinstance(key, str) and valid_name(key) else ""


def status_text() -> str:
    cfg = _section()
    if not config_flag(cfg.get("enabled"), False):
        return "Keysrs is not set up for this Hermes. On the Mac: `hermes keysrs setup --key <vault key> --use`."
    key = _cfg_key(cfg)
    with ThreadPoolExecutor(max_workers=3) as pool:
        lookup_f = pool.submit(lookup_token, cfg)
        spend_f = pool.submit(_spend_today, cfg, key) if key else None
        refusals_f = pool.submit(_refusals_today, cfg, key) if key else None
        lookup = lookup_f.result()
        spend = spend_f.result() if spend_f else None
        refusals = refusals_f.result() if refusals_f else None

    lines = [f"🔑 Keysrs — key {key or '?'}, label {config_label(cfg)}"]
    if not lookup.ok:
        lines.append(f"token: unavailable — {lookup.error}")
        hint = KeysrsSource().remediation(lookup.error_kind, cfg)
        if hint:
            lines.append(f"fix: {hint}")
    else:
        # A successful lookup means the gateway has the key loaded (see _parse_success).
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
        lines.append("gateway: key loaded")
    if spend is not None:
        lines.append(f"today: {spend}")
    if refusals is not None:
        lines.append(f"refusals: {refusals}")
    lines.append(f"tripwire: {_tripwire_line(cfg)}")
    return "\n".join(lines)


def revoke_text() -> str:
    cfg = _section()
    if not config_flag(cfg.get("enabled"), False):
        return "Keysrs is not set up for this Hermes; nothing to revoke."
    grants_line = _revoke_grants(cfg)
    return _revoke_client(cfg) + grants_line


def _revoke_grants(cfg: dict) -> str:
    from .access import revoke_all

    revoked, failed = revoke_all(cfg)
    if not revoked and not failed:
        return ""
    line = f"\nAlso revoked {revoked} agent grant(s) for other keys."
    if failed:
        line += f" ⚠️ {failed} could not be revoked; on the Mac run `keys revoke --all`."
    return line


def _revoke_client(cfg: dict) -> str:
    lookup = lookup_token(cfg)
    meta = lookup.meta
    client_id = meta.get("client_id")
    key = meta.get("key") if isinstance(meta.get("key"), str) and valid_name(meta.get("key")) else _cfg_key(cfg)
    if not (isinstance(client_id, int) and client_id > 0):
        # Only a definite "no live token" answer from keys means Hermes is cut off.
        error = lookup.error or ""
        if lookup.error_kind in (ErrorKind.AUTH_EXPIRED, ErrorKind.NOT_CONFIGURED) and (
            "expired" in error or "revoked" in error or "no held" in error
        ):
            return f"No live Keysrs token to revoke ({error}). Hermes is already cut off."
        where = f"`keys client list {key}` then `keys client revoke {key} <id>`" if key else "`keys client list <key>`"
        return (
            f"⚠️ NOT revoked: could not get the token's client id from Keysrs ({error or 'no client id'}). "
            f"On the Mac run {where}, or `keys revoke --all`."
        )
    if not key:
        return f"⚠️ NOT revoked: Keysrs did not say which key client #{client_id} belongs to. On the Mac run `keys client list <key>`."
    binary = resolve_keys_binary(cfg)
    if binary is None:
        return f"⚠️ NOT revoked: Keysrs CLI not found. On the Mac run `keys client revoke {key} {client_id}`."
    try:
        proc = run_secret_cli(
            [str(binary), "client", "revoke", key, str(client_id)],
            allow_env=KEYS_ALLOW_ENV,
            timeout=min(helper_timeout(cfg), _COMMAND_TIMEOUT_SECONDS),
        )
    except RuntimeError as exc:
        return f"⚠️ NOT revoked: {scrub(str(exc))}. On the Mac run `keys client revoke {key} {client_id}`."
    if proc.returncode != 0:
        return (
            f"⚠️ NOT revoked (keys exited {proc.returncode}: {scrub(proc.stderr)}). "
            f"On the Mac run `keys client revoke {key} {client_id}`."
        )
    logger.warning("Keysrs: client #%s for key %s revoked from a /keysrs command", client_id, key)
    return (
        f"🛑 Revoked Keysrs client #{client_id} for {key}. Every call Hermes makes with it is now refused "
        "at the gateway. To re-arm, run `hermes keysrs setup` on the Mac (Touch ID)."
    )


def handle_sync(raw_args: str = "") -> str:
    """The command itself. Never raises, never returns a token."""
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


async def handle(raw_args: str = "") -> str:
    """``/keysrs`` handler. Async so the messaging gateway's event loop never
    waits on a ``keys`` subprocess; Hermes awaits it in the CLI and gateway."""
    return await asyncio.to_thread(handle_sync, raw_args)
