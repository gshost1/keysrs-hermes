"""``hermes keysrs`` subcommands: setup, status, disable.

Hermes hardcodes the ``hermes secrets <bundled-source>`` subparsers, so a
plugin source gets its own top-level command through
``ctx.register_cli_command`` instead.

``setup`` is the only interactive path: it runs
``keys client issue <key> --hold --json``, which asks for Touch ID in the
Keysrs app. It then writes non-secret settings to config.yaml:

* ``providers.<name>``: base_url = the gateway URL, key_env = KEYSRS_TOKEN,
  api_mode (a named custom provider, selected as ``custom:<name>``)
* ``secrets.keysrs``: label, vault key name, provider name, path to ``keys``

The token itself stays in Keysrs; nothing here prints or stores it.
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
    API_MODE_PATH_PREFIX,
    DEFAULT_API_MODE,
    DEFAULT_KEY_ENV,
    DEFAULT_LABEL,
    DEFAULT_PROVIDER_NAME,
    KEY_ENV_PREFIX,
    KEYS_ALLOW_ENV,
    SOURCE_NAME,
    KeysrsSource,
    _executable,
    _now,
    check_provider_entry,
    config_key_env,
    config_label,
    config_provider_name,
    is_loopback_http_url,
    lookup_token,
    normalize_url,
    parse_expiry,
    provider_entry_base_url,
    provider_entry_key_env,
    resolve_keys_binary,
    scrub,
    valid_key_env,
    valid_name,
    valid_provider_name,
)

# Long enough for the user to find the Keysrs window and touch the sensor.
ISSUE_TIMEOUT_SECONDS = 180.0
DEFAULT_DAYS = 7
DEFAULT_METHODS = ("POST",)
# Settings from the first version of this plugin, which filled vendor env
# vars directly. Dropped on the next setup.
_LEGACY_SECTION_KEYS = ("provider", "env")


def _load_config() -> Dict[str, Any]:
    from hermes_cli.config import load_config

    return load_config()


def _save_config(cfg: Dict[str, Any]) -> None:
    from hermes_cli.config import save_config

    save_config(cfg)


def _hermes_home() -> Path:
    from hermes_constants import get_hermes_home

    return Path(get_hermes_home())


def _section(cfg: Dict[str, Any]) -> Dict[str, Any]:
    secrets = cfg.get("secrets")
    if not isinstance(secrets, dict):
        return {}
    section = secrets.get(SOURCE_NAME)
    return section if isinstance(section, dict) else {}


def _providers(cfg: Dict[str, Any]) -> Dict[str, Any]:
    providers = cfg.get("providers")
    return providers if isinstance(providers, dict) else {}


def _model_provider(cfg: Dict[str, Any]) -> str:
    model = cfg.get("model")
    if isinstance(model, dict) and isinstance(model.get("provider"), str):
        return model["provider"].strip()
    return ""


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
        help="Issue a held Keysrs client token (one Touch ID) and add a gateway provider",
        description=(
            "Runs `keys client issue <key> --label <label> --days N --hold --json`. "
            "Keysrs asks for Touch ID once and keeps the token. Hermes stores only "
            "non-secret settings: providers.<name> (gateway base_url, key_env "
            f"{DEFAULT_KEY_ENV}) and secrets.keysrs."
        ),
    )
    s.add_argument("--key", required=True, help="Keysrs vault key name (e.g. openrouter)")
    s.add_argument("--label", default=None, help=f"Token label (default: {DEFAULT_LABEL})")
    s.add_argument("--days", type=int, default=DEFAULT_DAYS, help=f"Token lifetime in days (default: {DEFAULT_DAYS})")
    s.add_argument(
        "--provider-name",
        default=None,
        help=f"Name of the custom provider entry, used as custom:<name> (default: {DEFAULT_PROVIDER_NAME})",
    )
    s.add_argument(
        "--key-env",
        default=None,
        help=f"Env var for the token; must start with {KEY_ENV_PREFIX} (default: {DEFAULT_KEY_ENV})",
    )
    s.add_argument(
        "--api-mode",
        choices=sorted(API_MODE_PATH_PREFIX),
        default=None,
        help=f"Wire protocol Hermes speaks to the gateway (default: {DEFAULT_API_MODE})",
    )
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
        help="Path prefix the token may call (default: chat/completions for chat_completions)",
    )
    scope.add_argument("--any-path", action="store_true", help="Do not restrict the path")
    s.add_argument("--use", action="store_true", help="Also set model.provider to custom:<name>")
    s.add_argument("--model", default=None, help="Default model id for the provider (and model.default with --use)")
    s.add_argument("--keys-path", default=None, help="Absolute path to the keys CLI")

    sub.add_parser("status", help="Show the provider, token expiry and gateway state (never the token)")
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


def _owned_by_keysrs(entry: Any, key_env: str) -> bool:
    """An entry is ours when it reads our token variable."""
    return isinstance(entry, dict) and provider_entry_key_env(entry) == key_env


def cmd_setup(args: argparse.Namespace) -> int:
    cfg = _load_config()
    current = _section(cfg)

    key = (args.key or "").strip()
    label = (args.label or config_label(current)).strip()
    provider_name = (args.provider_name or config_provider_name(current)).strip().lower()
    key_env = (args.key_env or config_key_env(current)).strip()
    api_mode = args.api_mode or DEFAULT_API_MODE
    if not valid_name(key):
        _err(f"--key {key!r}: use letters, digits, '.', '_' or '-'")
        return 64
    if not valid_name(label):
        _err(f"--label {label!r}: use letters, digits, '.', '_' or '-'")
        return 64
    if not valid_provider_name(provider_name):
        _err(f"--provider-name {provider_name!r}: use lowercase letters, digits, '_' or '-'")
        return 64
    if not valid_key_env(key_env):
        _err(f"--key-env {key_env!r}: must be an env var name starting with {KEY_ENV_PREFIX} "
             "(Hermes never reads KEYSRS_* as a vendor key, so the token can only reach the gateway)")
        return 64
    if args.days is None or args.days < 1:
        _err("--days must be at least 1")
        return 64
    model_id = (args.model or "").strip() or None
    if model_id is not None and any(c.isspace() for c in model_id):
        _err("--model must not contain spaces")
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
    else:
        path_prefix = API_MODE_PATH_PREFIX[api_mode]

    # Refuse before spending a Touch ID: never take over someone else's entry.
    existing = _providers(cfg).get(provider_name)
    if existing is not None and not _owned_by_keysrs(existing, key_env):
        _err(f"providers.{provider_name} already exists and does not read {key_env}; "
             "not overwriting it. Pick another name with --provider-name.")
        return 1

    binary = _setup_binary(args, current)
    if binary is None:
        _err("Keysrs CLI `keys` not found. Install Keysrs or pass --keys-path /path/to/keys.")
        return 1

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
    base_url = normalize_url(issued.get("base_url"))
    if not base_url or not is_loopback_http_url(base_url):
        _err("keys client issue returned no loopback gateway base_url; config not changed.")
        return 1

    # providers.<name>: update our own entry in place (keeps any extra
    # fields the user added, e.g. context_length), or create it.
    entry: Dict[str, Any] = dict(existing) if isinstance(existing, dict) else {}
    for alias in ("api_key_env", "keyEnv", "apiKeyEnv", "url", "api", "baseUrl", "transport", "api_key"):
        entry.pop(alias, None)
    entry.update({"base_url": base_url, "key_env": key_env, "api_mode": api_mode})
    if model_id:
        entry["default_model"] = model_id

    section: Dict[str, Any] = {k: v for k, v in current.items() if k not in _LEGACY_SECTION_KEYS}
    section.update({
        "enabled": True,
        "label": label,
        "key": key,
        "provider_name": provider_name,
        "keys_path": str(binary),
    })
    if key_env != DEFAULT_KEY_ENV:
        section["key_env"] = key_env
    else:
        section.pop("key_env", None)

    if not isinstance(cfg.get("secrets"), dict):
        cfg["secrets"] = {}
    cfg["secrets"][SOURCE_NAME] = section
    if not isinstance(cfg.get("providers"), dict):
        cfg["providers"] = {}
    cfg["providers"][provider_name] = entry
    selector = f"custom:{provider_name}"
    if args.use:
        if not isinstance(cfg.get("model"), dict):
            cfg["model"] = {}
        cfg["model"]["provider"] = selector
        if model_id:
            cfg["model"]["default"] = model_id
    _save_config(cfg)

    _out("")
    _out(f"Keysrs provider '{provider_name}' written (providers.{provider_name}, secrets.keysrs).")
    _out(f"  key        {issued.get('key', key)}")
    _out(f"  label      {issued.get('label', label)}")
    _out(f"  expires    {issued.get('expires_at', '?')}")
    _out(f"  scope      {scope}")
    _out(f"  gateway    {base_url}")
    _out(f"  token in   {key_env} (read only by providers.{provider_name})")
    if args.use:
        _out(f"  model      model.provider = {selector}" + (f", model.default = {model_id}" if model_id else ""))
    elif _model_provider(cfg) != selector:
        _out(f"  to use it  set `model.provider: {selector}` in config.yaml (or rerun with --use)")
    old_label = config_label(current) if current else None
    if old_label and old_label != label:
        _out(f"  note       the held token for label '{old_label}' is still valid in Keysrs; "
             "revoke it there if you no longer need it.")

    check = KeysrsSource().fetch(section, _hermes_home())
    if check.ok:
        _out("  check      ok: Hermes can fetch the token without a prompt")
        return 0
    _out(f"  check      FAILED: {check.error}")
    hint = KeysrsSource().remediation(check.error_kind, section)
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
    cfg = _load_config()
    section = _section(cfg)
    source = KeysrsSource()
    provider_name = config_provider_name(section)
    key_env = config_key_env(section)
    entry = _providers(cfg).get(provider_name)
    selector = f"custom:{provider_name}"
    binary = resolve_keys_binary(section)

    _out("Keysrs secret source")
    _out(f"  enabled    {'yes' if source.is_enabled(section) else 'no'}")
    _out(f"  label      {config_label(section)}")
    _out(f"  key        {section.get('key') or '(not recorded)'}")
    _out(f"  provider   {selector}")
    _out(f"  base_url   {provider_entry_base_url(entry) or '(providers.' + provider_name + ' missing)'}")
    _out(f"  token in   {key_env}")
    current_model_provider = _model_provider(cfg)
    in_use = current_model_provider == selector
    _out(f"  in use     {'yes' if in_use else 'no'} (model.provider = {current_model_provider or 'unset'})")
    _out(f"  keys CLI   {binary or 'not found'}")

    rc = 0
    provider_url, problem = check_provider_entry(cfg, provider_name, key_env)
    if not provider_url:
        _out(f"  provider   problem: {problem}")
        rc = 1

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
    if provider_url and normalize_url(meta.get("base_url")) != provider_url:
        _out(f"  problem    the token's gateway URL differs from providers.{provider_name}.base_url; "
             "rerun hermes keysrs setup")
        rc = 1
    if not in_use and rc == 0:
        _out(f"  hint       set `model.provider: {selector}` to send chat through the gateway")
    return rc


def cmd_disable(args: argparse.Namespace) -> int:
    cfg = _load_config()
    secrets = cfg.get("secrets")
    if not isinstance(secrets, dict) or not isinstance(secrets.get(SOURCE_NAME), dict):
        _out("Keysrs source is not configured.")
        return 0
    secrets[SOURCE_NAME]["enabled"] = False
    _save_config(cfg)
    provider_name = config_provider_name(secrets[SOURCE_NAME])
    _out("Keysrs source disabled. The held token stays in Keysrs until it expires or you revoke it there.")
    if _model_provider(cfg) == f"custom:{provider_name}":
        _out(f"model.provider is still custom:{provider_name}; switch it with `hermes model`.")
    return 0
