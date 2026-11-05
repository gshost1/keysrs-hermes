"""``hermes keysrs`` subcommands: setup, status, disable.

Hermes hardcodes the ``hermes secrets <bundled-source>`` subparsers, so a
plugin source gets its own top-level command through
``ctx.register_cli_command`` instead.

``setup`` is the only interactive path: it runs
``keys client issue <key> --hold --json``, which asks for Touch ID in the
Keysrs app. It then writes non-secret settings (label, key name, provider,
path to ``keys``) to ``secrets.keysrs`` in config.yaml. The token itself
stays in Keysrs; nothing here prints or stores it.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from agent.secret_sources.base import run_secret_cli

from .keysrs_source import (
    CUSTOM_PROVIDER,
    KEYS_ALLOW_ENV,
    PROVIDERS,
    SOURCE_NAME,
    KeysrsSource,
    _executable,
    _now,
    config_label,
    config_provider,
    lookup_token,
    parse_expiry,
    resolve_env_names,
    resolve_keys_binary,
    scrub,
    valid_name,
)
from .keysrs_source import DEFAULT_LABEL, DEFAULT_PROVIDER

# Long enough for the user to find the Keysrs window and touch the sensor.
ISSUE_TIMEOUT_SECONDS = 180.0
DEFAULT_DAYS = 7
DEFAULT_METHODS = ("POST",)


def _load_config() -> Dict[str, Any]:
    from hermes_cli.config import load_config

    return load_config()


def _save_config(cfg: Dict[str, Any]) -> None:
    from hermes_cli.config import save_config

    save_config(cfg)


def _section(cfg: Dict[str, Any]) -> Dict[str, Any]:
    secrets = cfg.get("secrets")
    if not isinstance(secrets, dict):
        return {}
    section = secrets.get(SOURCE_NAME)
    return section if isinstance(section, dict) else {}


def _out(msg: str = "") -> None:
    print(msg, flush=True)


def _err(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


# ---------------------------------------------------------------------------
# argparse
# ---------------------------------------------------------------------------


def setup_parser(parser: argparse.ArgumentParser) -> None:
    sub = parser.add_subparsers(dest="keysrs_command")

    s = sub.add_parser(
        "setup",
        help="Issue a held Keysrs client token (one Touch ID) and enable the source",
        description=(
            "Runs `keys client issue <key> --label <label> --days N --hold --json`. "
            "Keysrs asks for Touch ID once and keeps the token; Hermes stores only "
            "the label, key name, provider and path to `keys` in config.yaml."
        ),
    )
    s.add_argument("--key", required=True, help="Keysrs vault key name (e.g. openrouter)")
    s.add_argument("--label", default=None, help=f"Token label (default: {DEFAULT_LABEL})")
    s.add_argument("--days", type=int, default=DEFAULT_DAYS, help=f"Token lifetime in days (default: {DEFAULT_DAYS})")
    s.add_argument(
        "--provider",
        choices=[*PROVIDERS, CUSTOM_PROVIDER],
        default=None,
        help=f"Which Hermes provider env vars to fill (default: {DEFAULT_PROVIDER})",
    )
    s.add_argument("--base-url-env", default=None, help="Env var for the gateway URL (custom provider)")
    s.add_argument("--api-key-env", default=None, help="Env var for the client token (custom provider)")
    s.add_argument(
        "--method",
        action="append",
        default=None,
        help="HTTP method the token may use; repeatable (default: POST)",
    )
    scope = s.add_mutually_exclusive_group()
    scope.add_argument(
        "--path-prefix",
        default=None,
        help=(
            "Path prefix the token may call (default: chat/completions for openrouter, "
            "responses for openai; required for custom unless --any-path)"
        ),
    )
    scope.add_argument("--any-path", action="store_true", help="Do not restrict the path")
    s.add_argument("--keys-path", default=None, help="Absolute path to the keys CLI")

    sub.add_parser("status", help="Show the held token's label, key, expiry and gateway state (never the token)")
    sub.add_parser("disable", help="Turn the Keysrs source off (the token stays in Keysrs)")

    parser.set_defaults(func=dispatch)


def dispatch(args: argparse.Namespace) -> int:
    cmd = getattr(args, "keysrs_command", None)
    if cmd == "setup":
        return cmd_setup(args)
    if cmd == "status":
        return cmd_status(args)
    if cmd == "disable":
        return cmd_disable(args)
    _out("usage: hermes keysrs {setup,status,disable}")
    return 0


# ---------------------------------------------------------------------------
# setup
# ---------------------------------------------------------------------------


def build_issue_argv(
    binary: Path, key: str, label: str, days: int, methods: List[str], path_prefix: Optional[str]
) -> List[str]:
    argv = [str(binary), "client", "issue", key, "--label", label, "--days", str(days)]
    for method in methods:
        argv += ["--method", method]
    if path_prefix:
        argv += ["--path-prefix", path_prefix]
    argv += ["--hold", "--json"]
    return argv


def _setup_binary(args: argparse.Namespace, current: Dict[str, Any]) -> Optional[Path]:
    """--keys-path, else `keys` on PATH, else the path saved last time.

    Kept absolute but not symlink-resolved, so a Homebrew-style
    bin/keys -> Cellar/<version>/bin/keys link survives upgrades.
    """
    if args.keys_path:
        path = Path(args.keys_path).expanduser().absolute()
        return path if _executable(path) else None
    found = shutil.which("keys")
    if found:
        return Path(found).absolute()
    return resolve_keys_binary(current)


def cmd_setup(args: argparse.Namespace) -> int:
    cfg = _load_config()
    current = _section(cfg)

    key = (args.key or "").strip()
    label = (args.label or config_label(current)).strip()
    provider = (args.provider or config_provider(current)).strip().lower()
    if not valid_name(key):
        _err(f"--key {key!r}: use letters, digits, '.', '_' or '-'")
        return 64
    if not valid_name(label):
        _err(f"--label {label!r}: use letters, digits, '.', '_' or '-'")
        return 64
    if args.days is None or args.days < 1:
        _err("--days must be at least 1")
        return 64

    methods = [m.strip().upper() for m in (args.method or DEFAULT_METHODS) if m and m.strip()]
    if not methods or not all(m.isalpha() for m in methods):
        _err("--method must be an HTTP method name such as POST")
        return 64
    if args.any_path:
        path_prefix = None
    elif args.path_prefix is not None:
        path_prefix = args.path_prefix.strip().lstrip("/")
        if not path_prefix or path_prefix.startswith("-") or any(c.isspace() for c in path_prefix):
            _err("--path-prefix must be a plain path such as chat/completions")
            return 64
    elif provider in PROVIDERS:
        path_prefix = PROVIDERS[provider]["path_prefix"]
    else:
        _err("--provider custom needs --path-prefix <path> (or --any-path to allow every path)")
        return 64

    new_section: Dict[str, Any] = dict(current)
    new_section.update({"enabled": True, "label": label, "key": key, "provider": provider})
    same_provider = config_provider(current) == provider
    env_map = dict(current["env"]) if same_provider and isinstance(current.get("env"), dict) else {}
    if args.base_url_env is not None:
        env_map["base_url"] = args.base_url_env.strip()
    if args.api_key_env is not None:
        env_map["api_key"] = args.api_key_env.strip()
    if env_map:
        new_section["env"] = env_map
    else:
        new_section.pop("env", None)
    names, problem = resolve_env_names(new_section)
    if names is None:
        _err(problem)
        return 64

    binary = _setup_binary(args, current)
    if binary is None:
        _err("Keysrs CLI `keys` not found. Install Keysrs or pass --keys-path /path/to/keys.")
        return 1
    new_section["keys_path"] = str(binary)

    argv = build_issue_argv(binary, key, label, args.days, methods, path_prefix)
    scope = f"{', '.join(methods)} {('/' + path_prefix) if path_prefix else '(any path)'}"
    _out(f"Issuing a Keysrs client token for key '{key}' (label '{label}', {args.days} days, {scope}).")
    _out("Approve with Touch ID in the Keysrs app...")
    try:
        # Same allowlisted env and closed stdin as fetch(); Touch ID happens
        # in the Keysrs app, not on this terminal.
        proc = run_secret_cli(argv, allow_env=KEYS_ALLOW_ENV, timeout=ISSUE_TIMEOUT_SECONDS)
    except RuntimeError as exc:
        if isinstance(exc.__cause__, subprocess.TimeoutExpired):
            _err(f"keys client issue did not finish within {ISSUE_TIMEOUT_SECONDS:.0f}s; nothing was changed.")
        else:
            _err(f"could not run keys: {scrub(str(exc))}")
        return 1

    if proc.returncode != 0:
        _err(_issue_failure(proc.returncode, proc.stdout, proc.stderr, key))
        return proc.returncode

    issued = _parse_issue(proc.stdout)
    if issued is None:
        _err("keys client issue succeeded but printed no readable JSON; config not changed.")
        return 1
    if issued.get("held") is not True:
        _err("keys client issue did not report a held token (--hold); config not changed.")
        return 1

    if not isinstance(cfg.get("secrets"), dict):
        cfg["secrets"] = {}
    cfg["secrets"][SOURCE_NAME] = new_section
    _save_config(cfg)

    base_var, key_var = names
    _out("")
    _out("Keysrs source enabled (secrets.keysrs in config.yaml).")
    _out(f"  key        {issued.get('key', key)}")
    _out(f"  label      {issued.get('label', label)}")
    _out(f"  expires    {issued.get('expires_at', '?')}")
    _out(f"  scope      {scope}")
    _out(f"  fills      {', '.join(v for v in (base_var, key_var) if v)}")
    hermes_provider = PROVIDERS.get(provider, {}).get("hermes_provider")
    if hermes_provider:
        _out(f"  Hermes reads these when the model provider is '{hermes_provider}'.")
    old_label = config_label(current) if current else None
    if old_label and old_label != label:
        _out(f"  note       the held token for label '{old_label}' is still valid in Keysrs; "
             "revoke it there if you no longer need it.")

    check = KeysrsSource().fetch(new_section, Path("."))
    if check.ok:
        _out("  check      ok: Hermes can fetch the token without a prompt")
        return 0
    _out(f"  check      FAILED: {check.error}")
    hint = KeysrsSource().remediation(check.error_kind, new_section)
    if hint:
        _out(f"             {hint}")
    return 1


def _parse_issue(stdout: str) -> Optional[Dict[str, Any]]:
    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except ValueError:
            return None
        if not isinstance(payload, dict):
            return None
        payload.pop("token", None)  # contract says issue prints none; drop it if it ever does
        return payload
    return None


def _issue_failure(rc: int, stdout: str, stderr: str, key: str) -> str:
    detail = ""
    for line in (stdout or "").splitlines():
        try:
            payload = json.loads(line)
        except ValueError:
            continue
        if isinstance(payload, dict) and isinstance(payload.get("error"), str):
            detail = payload["error"]
            break
    detail = detail or (stderr or "").strip()
    if rc == 6:
        return "Keysrs app is not running and could not be launched. Open it and retry."
    if rc == 64:
        return "keys rejected the arguments (exit 64). Update Keysrs if `keys client issue --hold` is unknown."
    if rc == 2:
        return f"keys could not issue a token for '{key}'" + (f": {scrub(detail)}" if detail else "") + "."
    return f"keys client issue failed (exit {rc})" + (f": {scrub(detail)}" if detail else "") + "."


# ---------------------------------------------------------------------------
# status / disable
# ---------------------------------------------------------------------------


def cmd_status(args: argparse.Namespace) -> int:
    section = _section(_load_config())
    source = KeysrsSource()
    enabled = source.is_enabled(section)
    names, problem = resolve_env_names(section)
    binary = resolve_keys_binary(section)

    _out("Keysrs secret source")
    _out(f"  enabled    {'yes' if enabled else 'no'}")
    _out(f"  label      {config_label(section)}")
    _out(f"  key        {section.get('key') or '(not recorded)'}")
    _out(f"  provider   {config_provider(section)}")
    _out(f"  fills      {', '.join(v for v in names if v) if names else problem}")
    _out(f"  keys CLI   {binary or 'not found'}")

    lookup = lookup_token(section)
    if not lookup.ok:
        _out(f"  token      unavailable: {lookup.error}")
        hint = source.remediation(lookup.error_kind, section)
        if hint:
            _out(f"  fix        {hint}")
        return 1

    meta = lookup.meta
    _out("  token      held (value hidden)")
    _out(f"  client id  {meta.get('client_id', '?')}")
    _out(f"  gateway    {meta.get('base_url', '?')}")
    _out(f"  gateway_on {str(meta.get('gateway_on')).lower()}")
    expires = parse_expiry(meta.get("expires_at"))
    if expires is not None:
        left = expires - _now()
        _out(f"  expires    {meta.get('expires_at')} (in {max(0, int(left.total_seconds() // 3600))}h)")
    else:
        _out(f"  expires    {meta.get('expires_at', '?')}")
    methods = meta.get("methods")
    _out(f"  methods    {', '.join(str(m) for m in methods) if isinstance(methods, list) and methods else 'any'}")
    _out(f"  path       {meta.get('path_prefix') or 'any'}")
    for warning in lookup.warnings:
        _out(f"  warning    {warning}")
    return 0


def cmd_disable(args: argparse.Namespace) -> int:
    cfg = _load_config()
    secrets = cfg.get("secrets")
    if not isinstance(secrets, dict) or not isinstance(secrets.get(SOURCE_NAME), dict):
        _out("Keysrs source is not configured.")
        return 0
    secrets[SOURCE_NAME]["enabled"] = False
    _save_config(cfg)
    _out("Keysrs source disabled. The held token stays in Keysrs until it expires or you revoke it there.")
    return 0
