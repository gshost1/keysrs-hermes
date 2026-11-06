"""Keysrs secret source for Hermes Agent.

Keysrs keeps provider API keys in the macOS Keychain behind Touch ID and
serves them through a local gateway (``http://127.0.0.1:12767/<key>``).
The gateway accepts a scoped, expiring *client token* (``ksfc_...``) and
swaps it for the real provider key on the way out.

How Hermes is pointed at the gateway:

* ``hermes keysrs setup`` writes a named custom provider,
  ``providers.<name>`` in config.yaml, whose ``base_url`` is the gateway
  URL and whose ``key_env`` is ``KEYSRS_TOKEN``. The user selects it as
  ``model.provider: custom:<name>``.
* At startup this source asks ``keys client token`` for the held token and
  fills only that ``key_env`` variable.

Why not ``OPENROUTER_API_KEY`` / ``OPENAI_API_KEY``: several Hermes paths
(side-task clients, pricing, doctor) read those variables and send them to
the vendor's real host regardless of any base-URL override. A
``KEYSRS_*`` variable is read by nothing in Hermes except the custom
provider entry that names it, and that entry always carries the gateway
URL, so the token can only travel to loopback.

Rules this module keeps (see ``agent.secret_sources.base``):

* ``fetch()`` never raises, never prompts and never writes ``os.environ``.
* The only way to a secret is the ``keys`` CLI, run through
  ``run_secret_cli()`` (argv list, closed stdin, allowlisted env).
* The token never appears in errors, warnings, log records or reprs.
"""

from __future__ import annotations

import datetime as _dt
import ipaddress
import json
import logging
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

from agent.secret_sources.base import (
    ErrorKind,
    FetchResult,
    SecretSource,
    is_valid_env_name,
    run_secret_cli,
)

logger = logging.getLogger(__name__)

SOURCE_NAME = "keysrs"
DEFAULT_LABEL = "hermes"
DEFAULT_PROVIDER_NAME = "keysrs"
DEFAULT_KEY_ENV = "KEYSRS_TOKEN"
# Every token variable must carry this prefix: no Hermes code reads a
# KEYSRS_* name as a provider credential, so the only consumer is the
# custom provider entry that names it.
KEY_ENV_PREFIX = "KEYSRS_"
DEFAULT_API_MODE = "chat_completions"
# Narrowest gateway path each Hermes transport needs (relative to the
# gateway base URL, which already ends in the provider's /v1 or /api/v1).
API_MODE_PATH_PREFIX: Dict[str, str] = {
    "chat_completions": "chat/completions",
    "codex_responses": "responses",
    "anthropic_messages": "messages",
}
# `keys` may have to launch the Keysrs app first (exit 6 if it cannot), so
# leave room for a cold app start.
DEFAULT_HELPER_TIMEOUT_SECONDS = 20.0
DEFAULT_FETCH_TIMEOUT_SECONDS = 30.0
EXPIRY_WARNING = _dt.timedelta(hours=24)

TOKEN_PREFIX = "ksfc_"
# Registered with Hermes's redaction engine so a token that ever lands in a
# log line or transcript is masked. Literal prefix, no alternation, no
# nested repeats (agent.redact rules).
TOKEN_REDACTION_PATTERN = r"ksfc_[A-Za-z0-9._~+/=-]{4,}"
# Keysrs task grants (keys grant): ksf_<8 hex id>_<base64url secret>.
GRANT_REDACTION_PATTERN = r"ksf_[0-9a-f]{8}_[A-Za-z0-9_-]{4,}"
REDACTED = "[Keysrs token hidden]"
_TOKEN_SCRUB_RE = re.compile(r"ksfc_\S*")

# Env vars the ``keys`` child gets on top of run_secret_cli()'s fixed base
# set (PATH, HOME, TMPDIR, locale, XDG dirs, NO_COLOR). ``keys`` needs
# nothing else: it reaches the Keysrs app through the user's HOME.
KEYS_ALLOW_ENV: Tuple[str, ...] = ()

# Vault key names and labels go on the ``keys`` command line. Keep them to
# a conservative charset so they can never parse as a flag.
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
# Hermes provider names: lowercase so `custom:<name>` matches exactly.
_PROVIDER_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")


def valid_name(value: str) -> bool:
    return bool(_NAME_RE.match(value or ""))


def valid_provider_name(value: str) -> bool:
    return bool(_PROVIDER_NAME_RE.match(value or ""))


def valid_key_env(value: str) -> bool:
    return (
        isinstance(value, str)
        and is_valid_env_name(value)
        and value.startswith(KEY_ENV_PREFIX)
        and len(value) > len(KEY_ENV_PREFIX)
    )


def scrub(text: str, *, limit: int = 160) -> str:
    """Make helper output safe to show: no tokens, one line, bounded."""
    text = _TOKEN_SCRUB_RE.sub("ksfc_***", text or "")
    text = " ".join(text.split())
    return text[:limit] + ("..." if len(text) > limit else "")


def normalize_url(url: Any) -> str:
    return str(url or "").strip().rstrip("/")


# ---------------------------------------------------------------------------
# Config helpers (pure)
# ---------------------------------------------------------------------------


def _as_dict(cfg: Any) -> dict:
    return cfg if isinstance(cfg, dict) else {}


_TRUE = {"1", "true", "yes", "on"}
_FALSE = {"0", "false", "no", "off", ""}


def config_flag(value: Any, default: bool) -> bool:
    """YAML booleans, plus the quoted spellings people write by hand."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        text = value.strip().lower()
        if text in _TRUE:
            return True
        if text in _FALSE:
            return False
    if isinstance(value, int):
        return value != 0
    return default


def _config_str(cfg: dict, key: str, default: str) -> str:
    raw = _as_dict(cfg).get(key)
    return raw.strip() if isinstance(raw, str) and raw.strip() else default


def config_label(cfg: dict) -> str:
    return _config_str(cfg, "label", DEFAULT_LABEL)


def config_provider_name(cfg: dict) -> str:
    return _config_str(cfg, "provider_name", DEFAULT_PROVIDER_NAME).lower()


def config_key_env(cfg: dict) -> str:
    return _config_str(cfg, "key_env", DEFAULT_KEY_ENV)


def resolve_keys_binary(cfg: dict) -> Optional[Path]:
    """Explicit ``keys_path`` wins; otherwise ``keys`` on PATH.

    No PATH fallback when ``keys_path`` is set: startup should run exactly
    the binary the user approved in setup, not whatever ``keys`` is first
    on PATH that day.
    """
    cfg = _as_dict(cfg)
    explicit = cfg.get("keys_path")
    if isinstance(explicit, str) and explicit.strip():
        path = Path(explicit.strip()).expanduser()
        return path if _executable(path) else None
    found = shutil.which("keys")
    return Path(found) if found else None


def _executable(path: Path) -> bool:
    return path.is_file() and os.access(path, os.X_OK)


def helper_timeout(cfg: dict) -> float:
    try:
        val = float(_as_dict(cfg).get("helper_timeout_seconds", DEFAULT_HELPER_TIMEOUT_SECONDS))
    except (TypeError, ValueError):
        return DEFAULT_HELPER_TIMEOUT_SECONDS
    return val if val > 0 else DEFAULT_HELPER_TIMEOUT_SECONDS


def is_loopback_http_url(url: str) -> bool:
    """The gateway is always local. Refuse to send a token anywhere else."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return False
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return False
    host = parts.hostname
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def parse_expiry(value: Any) -> Optional[_dt.datetime]:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = _dt.datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=_dt.timezone.utc)
    return parsed


def _now() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)


# Field precedence mirrors Hermes's own reader
# (hermes_cli/runtime_provider.py _get_named_custom_provider):
#   key_env or api_key_env;  api or url or base_url.
_KEY_ENV_FIELDS = ("key_env", "api_key_env")
_URL_FIELDS = ("api", "url", "base_url")


def provider_entry_key_env(entry: Any) -> str:
    entry = _as_dict(entry)
    for field_name in _KEY_ENV_FIELDS:
        raw = entry.get(field_name)
        if isinstance(raw, str) and raw.strip():
            return raw.strip()
    return ""


def provider_entry_base_url(entry: Any) -> str:
    """The URL Hermes will actually send to for this entry."""
    entry = _as_dict(entry)
    for field_name in _URL_FIELDS:
        raw = entry.get(field_name)
        if isinstance(raw, str) and raw.strip():
            return normalize_url(raw)
    return ""


def _entry_urls_all_loopback(entry: Any) -> bool:
    entry = _as_dict(entry)
    urls = [entry.get(f) for f in _URL_FIELDS if isinstance(entry.get(f), str) and entry.get(f).strip()]
    return bool(urls) and all(is_loopback_http_url(normalize_url(u)) for u in urls)


def _iter_provider_entries(hermes_cfg: Optional[dict]):
    """(label, entry) for every providers: dict entry and legacy custom_providers item."""
    cfg = _as_dict(hermes_cfg)
    for name, entry in _as_dict(cfg.get("providers")).items():
        if isinstance(entry, dict):
            yield f"providers.{name}", entry
    legacy = cfg.get("custom_providers")
    if isinstance(legacy, list):
        for i, entry in enumerate(legacy):
            if isinstance(entry, dict):
                yield f"custom_providers[{i}]", entry


def read_hermes_config(home_path: Path) -> Optional[dict]:
    """The profile's config.yaml (non-secret settings), or None if unreadable.

    Read from ``home_path`` -- not the process-global HERMES_HOME -- so a
    multiplexed profile checks its own provider entry.
    """
    try:
        text = (Path(home_path) / "config.yaml").read_text(encoding="utf-8")
        data = _safe_load_yaml(text)
    except Exception:  # noqa: BLE001 - missing/unreadable config is a state, not a crash
        return None
    return data if isinstance(data, dict) else None


def _safe_load_yaml(text: str) -> Any:
    # Hermes 0.20.x ships PyYAML; 0.22.x ships ruamel.yaml instead.
    try:
        import yaml
    except ImportError:
        from ruamel.yaml import YAML

        return YAML(typ="safe", pure=True).load(text)
    return yaml.safe_load(text)


def check_provider_entry(hermes_cfg: Optional[dict], provider_name: str, key_env: str) -> Tuple[str, str]:
    """Return ``(provider_base_url, "")`` or ``("", problem)``.

    Also refuses when ANY provider entry that reads ``key_env`` could send
    it off the machine -- filling the variable hands the token to every
    such entry, not just ours.
    """
    providers = _as_dict(_as_dict(hermes_cfg).get("providers"))
    entry = providers.get(provider_name)
    if not isinstance(entry, dict):
        return "", f"providers.{provider_name} is missing from config.yaml"
    if provider_entry_key_env(entry) != key_env:
        return "", f"providers.{provider_name}.key_env is not {key_env}"
    if not config_flag(entry.get("enabled"), True):
        return "", f"providers.{provider_name} is disabled (enabled: false)"
    base_url = provider_entry_base_url(entry)
    if not base_url:
        return "", f"providers.{provider_name} has no base_url"
    if not _entry_urls_all_loopback(entry):
        return "", f"providers.{provider_name} points somewhere other than the local Keysrs gateway"
    for where, other in _iter_provider_entries(hermes_cfg):
        if provider_entry_key_env(other) == key_env and not _entry_urls_all_loopback(other):
            return "", f"{where} also reads {key_env} but does not point at the local Keysrs gateway"
    return base_url, ""


# ---------------------------------------------------------------------------
# Talking to ``keys client token``
# ---------------------------------------------------------------------------


@dataclass
class TokenLookup:
    """Outcome of one ``keys client token`` call.

    ``meta`` is the CLI payload minus the token; it is safe to print.
    ``token`` is kept out of ``repr``.
    """

    meta: Dict[str, Any] = field(default_factory=dict)
    token: str = field(default="", repr=False)
    error: Optional[str] = None
    error_kind: Optional[ErrorKind] = None
    warnings: List[str] = field(default_factory=list)
    binary_path: Optional[Path] = None

    @property
    def ok(self) -> bool:
        return self.error is None

    def fail(self, kind: ErrorKind, message: str) -> "TokenLookup":
        self.error_kind = kind
        self.error = message
        self.token = ""
        return self


def lookup_token(cfg: dict) -> TokenLookup:
    """Run ``keys client token --label <label> --json`` (no prompt)."""
    cfg = _as_dict(cfg)
    out = TokenLookup()

    label = config_label(cfg)
    if not valid_name(label):
        return out.fail(
            ErrorKind.REF_INVALID,
            f"secrets.keysrs.label {scrub(label, limit=40)!r} has characters keys does not accept",
        )

    binary = resolve_keys_binary(cfg)
    if binary is None:
        where = cfg.get("keys_path") or "keys on PATH"
        return out.fail(ErrorKind.BINARY_MISSING, f"Keysrs CLI not found ({where})")
    out.binary_path = binary

    try:
        proc = run_secret_cli(
            [str(binary), "client", "token", "--label", label, "--json"],
            allow_env=KEYS_ALLOW_ENV,
            timeout=helper_timeout(cfg),
        )
    except RuntimeError as exc:
        if isinstance(exc.__cause__, subprocess.TimeoutExpired):
            return out.fail(ErrorKind.TIMEOUT, scrub(str(exc)))
        return out.fail(ErrorKind.BINARY_MISSING, scrub(str(exc)))

    rc = proc.returncode
    if rc == 0:
        return _parse_success(out, proc.stdout, label)
    if rc == 2:
        reason = _error_reason(proc.stdout)
        if reason == "expired":
            return out.fail(ErrorKind.AUTH_EXPIRED, f"Keysrs client token for label {label!r} has expired")
        if reason == "revoked":
            return out.fail(ErrorKind.AUTH_EXPIRED, f"Keysrs client token for label {label!r} was revoked")
        return out.fail(ErrorKind.NOT_CONFIGURED, f"no held Keysrs client token for label {label!r}")
    if rc == 6:
        return out.fail(ErrorKind.NETWORK, "Keysrs app is not running and could not be launched")
    if rc == 64:
        return out.fail(
            ErrorKind.INTERNAL,
            "keys rejected the arguments (exit 64); this Keysrs may predate "
            f"`keys client token`: {scrub(proc.stderr)}",
        )
    return out.fail(ErrorKind.INTERNAL, f"keys client token exited {rc}: {scrub(proc.stderr)}")


def _error_reason(stdout: str) -> str:
    try:
        payload = json.loads((stdout or "").strip().splitlines()[0])
    except (ValueError, IndexError):
        return ""
    if isinstance(payload, dict) and isinstance(payload.get("error"), str):
        return payload["error"]
    return ""


def _scrub_tree(value: Any) -> Any:
    if isinstance(value, str):
        return _TOKEN_SCRUB_RE.sub("ksfc_***", value)
    if isinstance(value, dict):
        return {k: _scrub_tree(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_scrub_tree(v) for v in value]
    return value


def _parse_success(out: TokenLookup, stdout: str, label: str) -> TokenLookup:
    lines = [ln for ln in (stdout or "").splitlines() if ln.strip()]
    if not lines:
        return out.fail(ErrorKind.EMPTY_VALUE, "keys client token printed nothing")
    try:
        payload = json.loads(lines[0])
    except ValueError:
        return out.fail(ErrorKind.EMPTY_VALUE, "keys client token printed malformed JSON")
    if not isinstance(payload, dict):
        return out.fail(ErrorKind.EMPTY_VALUE, "keys client token printed JSON that is not an object")

    token = payload.pop("token", None)
    # Metadata is printable; make sure nothing token-shaped rides along in it.
    out.meta = _scrub_tree(payload)
    if not isinstance(token, str) or not token.strip():
        return out.fail(ErrorKind.EMPTY_VALUE, "keys client token returned an empty token")
    token = token.strip()
    if not token.startswith(TOKEN_PREFIX) or any(c.isspace() for c in token):
        return out.fail(ErrorKind.EMPTY_VALUE, "keys client token returned a value that is not a Keysrs client token")

    base_url = payload.get("base_url")
    if not isinstance(base_url, str) or not base_url.strip():
        return out.fail(ErrorKind.EMPTY_VALUE, "keys client token returned no base_url")
    if not is_loopback_http_url(base_url.strip()):
        return out.fail(
            ErrorKind.INTERNAL,
            f"refusing gateway base_url {scrub(base_url, limit=80)!r}: not a loopback http URL",
        )

    key = payload.get("key") if isinstance(payload.get("key"), str) else ""
    if payload.get("gateway_on") is not True:
        hint = f"`keys gateway on {key}`" if key else "`keys gateway on <key>`"
        return out.fail(
            ErrorKind.AUTH_EXPIRED,
            f"Keysrs gateway has not loaded key {key or '?'!r} since the app restarted; run {hint}",
        )

    expires = parse_expiry(payload.get("expires_at"))
    if expires is None:
        out.warnings.append("Keysrs token has no readable expires_at")
    else:
        left = expires - _now()
        if left <= _dt.timedelta(0):
            return out.fail(ErrorKind.AUTH_EXPIRED, f"Keysrs client token for label {label!r} has expired")
        if left < EXPIRY_WARNING:
            hours = max(1, int(left.total_seconds() // 3600))
            out.warnings.append(
                f"Keysrs client token for label {label!r} expires in about {hours}h; "
                "run `hermes keysrs setup` to renew"
            )

    out.token = token
    return out


# ---------------------------------------------------------------------------
# The SecretSource
# ---------------------------------------------------------------------------


class KeysrsFetchResult(FetchResult):
    """FetchResult whose repr masks secret values."""

    def __repr__(self) -> str:
        masked = {name: "***" for name in self.secrets}
        return (
            f"KeysrsFetchResult(secrets={masked!r}, warnings={self.warnings!r}, "
            f"error={self.error!r}, error_kind={self.error_kind!r})"
        )

    __str__ = __repr__


class KeysrsSource(SecretSource):
    """Grant-mode credentials from Keysrs: a scoped client token for a
    custom provider whose base_url is the local gateway."""

    name = SOURCE_NAME
    label = "Keysrs"
    shape = "mapped"

    def config_schema(self) -> dict:
        return {
            "enabled": {"description": "Master switch", "default": False},
            "label": {
                "description": "Label of the held Keysrs client token",
                "default": DEFAULT_LABEL,
            },
            "key": {
                "description": "Keysrs vault key the token was issued for (shown in status and hints only)",
                "default": "",
            },
            "provider_name": {
                "description": "Name of the custom provider entry (providers.<name>, used as custom:<name>)",
                "default": DEFAULT_PROVIDER_NAME,
            },
            "key_env": {
                "description": f"Env var the token goes into; must start with {KEY_ENV_PREFIX}",
                "default": DEFAULT_KEY_ENV,
            },
            "keys_path": {
                "description": "Absolute path to the keys CLI (default: keys on PATH)",
                "default": "",
            },
            "helper_timeout_seconds": {
                "description": "Timeout for one `keys client token` call",
                "default": DEFAULT_HELPER_TIMEOUT_SECONDS,
            },
            "timeout_seconds": {
                "description": "Wall-clock budget Hermes enforces around fetch()",
                "default": DEFAULT_FETCH_TIMEOUT_SECONDS,
            },
            "override_existing": {
                "description": "Replace a stale token variable already set in the dotenv file or shell",
                "default": True,
            },
        }

    def is_enabled(self, cfg: dict) -> bool:
        return config_flag(_as_dict(cfg).get("enabled"), False)

    def override_existing(self, cfg: dict) -> bool:
        # Default on: a stale KEYSRS_TOKEN left in the dotenv file must not
        # win over the fresh one. Same default as the bundled sources.
        return config_flag(_as_dict(cfg).get("override_existing"), True)

    def fetch_timeout_seconds(self, cfg: dict) -> float:
        try:
            val = float(_as_dict(cfg).get("timeout_seconds", DEFAULT_FETCH_TIMEOUT_SECONDS))
        except (TypeError, ValueError):
            return DEFAULT_FETCH_TIMEOUT_SECONDS
        return val if val > 0 else DEFAULT_FETCH_TIMEOUT_SECONDS

    def fetch(self, cfg: dict, home_path: Path) -> FetchResult:
        try:
            result = self._fetch(_as_dict(cfg), home_path)
        except Exception as exc:  # noqa: BLE001 - contract: never raise
            result = KeysrsFetchResult()
            result.error = f"unexpected error in Keysrs source ({type(exc).__name__})"
            result.error_kind = ErrorKind.INTERNAL
        if result.error_kind is not None:
            logger.debug("keysrs fetch failed: %s", result.error_kind.value)
        return result

    def _fetch(self, cfg: dict, home_path: Path) -> KeysrsFetchResult:
        result = KeysrsFetchResult()

        def fail(kind: ErrorKind, message: str) -> KeysrsFetchResult:
            result.error, result.error_kind = message, kind
            result.secrets = {}
            return result

        provider_name = config_provider_name(cfg)
        key_env = config_key_env(cfg)
        if not valid_provider_name(provider_name):
            return fail(ErrorKind.REF_INVALID, f"secrets.keysrs.provider_name {scrub(provider_name, limit=40)!r} is not a valid provider name")
        if not valid_key_env(key_env):
            return fail(ErrorKind.REF_INVALID, f"secrets.keysrs.key_env must be an env var name starting with {KEY_ENV_PREFIX}")

        # The token may only go into a variable whose one reader is a
        # provider entry pointing at the local gateway.
        provider_url, problem = check_provider_entry(read_hermes_config(home_path), provider_name, key_env)
        if not provider_url:
            return fail(ErrorKind.NOT_CONFIGURED, problem)

        lookup = lookup_token(cfg)
        result.binary_path = lookup.binary_path
        result.warnings.extend(lookup.warnings)
        if not lookup.ok:
            return fail(lookup.error_kind or ErrorKind.INTERNAL, lookup.error or "keys client token failed")

        if normalize_url(lookup.meta.get("base_url")) != provider_url:
            return fail(
                ErrorKind.NOT_CONFIGURED,
                f"the held token is for a different gateway URL than providers.{provider_name}.base_url",
            )

        result.secrets = {key_env: lookup.token}
        return result

    def remediation(self, kind: Optional[ErrorKind], cfg: dict) -> str:
        cfg = _as_dict(cfg)
        key = cfg.get("key") if isinstance(cfg.get("key"), str) and cfg.get("key") else "<vault-key>"
        setup = f"hermes keysrs setup --key {key}"
        if kind == ErrorKind.NOT_CONFIGURED:
            return f"Rerun `{setup}` (one Touch ID) to issue a held token and write the provider entry."
        if kind == ErrorKind.BINARY_MISSING:
            return "Install Keysrs, or set secrets.keysrs.keys_path to the absolute path of `keys`."
        if kind == ErrorKind.AUTH_EXPIRED:
            return (
                f"If the Keysrs app restarted, run `keys gateway on {key}`; "
                f"if the token expired or was revoked, run `{setup}`."
            )
        if kind == ErrorKind.NETWORK:
            return "Open the Keysrs app, then restart Hermes."
        if kind == ErrorKind.REF_INVALID:
            return "Fix secrets.keysrs (provider_name / key_env / label) in config.yaml, or rerun setup."
        if kind == ErrorKind.EMPTY_VALUE:
            return f"Run `hermes keysrs status`; if it fails the same way, rerun `{setup}`."
        if kind == ErrorKind.INTERNAL:
            return "Run `hermes keysrs status` for details; update Keysrs if `keys client token` is unknown."
        if kind == ErrorKind.TIMEOUT:
            return "Keysrs was slow; raise secrets.keysrs.helper_timeout_seconds if this recurs."
        return super().remediation(kind, cfg)
