"""Keysrs secret source for Hermes Agent.

Keysrs keeps provider API keys in the macOS Keychain behind Touch ID and
serves them through a local gateway (``http://127.0.0.1:12767/<key>``).
The gateway accepts a scoped, expiring *client token* (``ksfc_...``) and
swaps it for the real provider key on the way out.

This source asks the ``keys`` CLI for the client token that was issued
earlier with ``keys client issue ... --hold`` (one Touch ID, done by the
user in ``hermes keysrs setup``) and hands Hermes two values:

* the gateway base URL, as the provider's base-URL env var
* the client token, as the provider's API-key env var

So Hermes talks to the local gateway and the real provider key never
enters the Hermes process.

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
DEFAULT_PROVIDER = "openrouter"
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
_TOKEN_SCRUB_RE = re.compile(r"ksfc_\S*")

# Env vars the ``keys`` child gets on top of run_secret_cli()'s fixed base
# set (PATH, HOME, TMPDIR, locale, XDG dirs, NO_COLOR). ``keys`` needs
# nothing else: it reaches the Keysrs app through the user's HOME.
KEYS_ALLOW_ENV: Tuple[str, ...] = ()

# Provider presets: which env vars Hermes reads for that provider, the
# Hermes provider id to select, and the narrowest gateway path prefix the
# provider's Hermes transport needs.
#   openrouter -> chat completions  (hermes_cli/providers.py: openai_chat)
#   openai     -> Responses API     (hermes_cli/providers.py: codex_responses)
PROVIDERS: Dict[str, Dict[str, str]] = {
    "openrouter": {
        "base_url": "OPENROUTER_BASE_URL",
        "api_key": "OPENROUTER_API_KEY",
        "hermes_provider": "openrouter",
        "path_prefix": "chat/completions",
    },
    "openai": {
        "base_url": "OPENAI_BASE_URL",
        "api_key": "OPENAI_API_KEY",
        "hermes_provider": "openai-api",
        "path_prefix": "responses",
    },
}
CUSTOM_PROVIDER = "custom"

# Vault key names and labels go on the ``keys`` command line. Keep them to
# a conservative charset so they can never parse as a flag.
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def valid_name(value: str) -> bool:
    return bool(_NAME_RE.match(value or ""))


def scrub(text: str, *, limit: int = 160) -> str:
    """Make helper output safe to show: no tokens, one line, bounded."""
    text = _TOKEN_SCRUB_RE.sub("ksfc_***", text or "")
    text = " ".join(text.split())
    return text[:limit] + ("..." if len(text) > limit else "")


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


def config_label(cfg: dict) -> str:
    raw = _as_dict(cfg).get("label")
    return str(raw).strip() if isinstance(raw, str) and raw.strip() else DEFAULT_LABEL


def config_provider(cfg: dict) -> str:
    raw = _as_dict(cfg).get("provider")
    return str(raw).strip().lower() if isinstance(raw, str) and raw.strip() else DEFAULT_PROVIDER


def resolve_env_names(cfg: dict) -> Tuple[Optional[Tuple[str, str]], str]:
    """Return ``((base_url_var, api_key_var), "")`` or ``(None, error)``.

    ``base_url_var`` may be ``""`` for a custom map that only fills the
    API key (the user then sets the gateway URL in config.yaml).
    """
    cfg = _as_dict(cfg)
    provider = config_provider(cfg)
    override = cfg.get("env")
    if provider in PROVIDERS:
        base_var = PROVIDERS[provider]["base_url"]
        key_var = PROVIDERS[provider]["api_key"]
    elif provider == CUSTOM_PROVIDER:
        base_var, key_var = "", ""
    else:
        known = ", ".join([*PROVIDERS, CUSTOM_PROVIDER])
        return None, f"secrets.keysrs.provider {provider!r} is not one of: {known}"

    if override is not None:
        if not isinstance(override, dict):
            return None, "secrets.keysrs.env must be a mapping with base_url / api_key"
        if "base_url" in override:
            base_var = str(override.get("base_url") or "").strip()
        if "api_key" in override:
            key_var = str(override.get("api_key") or "").strip()

    if not key_var:
        return None, "secrets.keysrs.env.api_key is not set (custom provider needs both names)"
    for var in (base_var, key_var):
        if var and not is_valid_env_name(var):
            return None, f"secrets.keysrs.env names an invalid env var: {var!r}"
    if base_var and base_var == key_var:
        return None, "secrets.keysrs.env.base_url and env.api_key must differ"
    return (base_var, key_var), ""


def _executable(path: Path) -> bool:
    return path.is_file() and os.access(path, os.X_OK)


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
    """Grant-mode credentials from Keysrs: gateway URL + scoped client token."""

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
            "provider": {
                "description": "Which provider env vars to fill: openrouter | openai | custom",
                "default": DEFAULT_PROVIDER,
            },
            "env": {
                "description": "Override the env var names: {base_url: VAR, api_key: VAR}",
                "default": {},
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
                "description": "Gateway values replace provider vars already set in .env/shell",
                "default": True,
            },
        }

    def is_enabled(self, cfg: dict) -> bool:
        return config_flag(_as_dict(cfg).get("enabled"), False)

    def override_existing(self, cfg: dict) -> bool:
        # Default on: a real key left in the dotenv file must not be paired
        # with the gateway URL (or win over the token). Same default as the
        # bundled sources, which need it for rotation.
        return config_flag(_as_dict(cfg).get("override_existing"), True)

    def fetch_timeout_seconds(self, cfg: dict) -> float:
        try:
            val = float(_as_dict(cfg).get("timeout_seconds", DEFAULT_FETCH_TIMEOUT_SECONDS))
        except (TypeError, ValueError):
            return DEFAULT_FETCH_TIMEOUT_SECONDS
        return val if val > 0 else DEFAULT_FETCH_TIMEOUT_SECONDS

    def fetch(self, cfg: dict, home_path: Path) -> FetchResult:
        try:
            result = self._fetch(_as_dict(cfg))
        except Exception as exc:  # noqa: BLE001 - contract: never raise
            result = KeysrsFetchResult()
            result.error = f"unexpected error in Keysrs source ({type(exc).__name__})"
            result.error_kind = ErrorKind.INTERNAL
        if result.error_kind is not None:
            logger.debug("keysrs fetch failed: %s", result.error_kind.value)
        return result

    def _fetch(self, cfg: dict) -> KeysrsFetchResult:
        result = KeysrsFetchResult()
        names, problem = resolve_env_names(cfg)
        if names is None:
            result.error = problem
            result.error_kind = ErrorKind.REF_INVALID
            return result
        base_var, key_var = names

        lookup = lookup_token(cfg)
        result.binary_path = lookup.binary_path
        result.warnings.extend(lookup.warnings)
        if not lookup.ok:
            result.error = lookup.error
            result.error_kind = lookup.error_kind
            return result

        secrets = {key_var: lookup.token}
        if base_var:
            secrets[base_var] = str(lookup.meta["base_url"]).strip().rstrip("/")
        result.secrets = secrets
        return result

    def remediation(self, kind: Optional[ErrorKind], cfg: dict) -> str:
        cfg = _as_dict(cfg)
        key = cfg.get("key") if isinstance(cfg.get("key"), str) and cfg.get("key") else "<vault-key>"
        setup = f"hermes keysrs setup --key {key}"
        if kind == ErrorKind.NOT_CONFIGURED:
            return f"Run `{setup}` to issue a held client token (one Touch ID)."
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
            return "Fix secrets.keysrs (provider / env / label) in config.yaml, or rerun setup."
        if kind == ErrorKind.EMPTY_VALUE:
            return f"Run `hermes keysrs status`; if it fails the same way, rerun `{setup}`."
        if kind == ErrorKind.INTERNAL:
            return "Run `hermes keysrs status` for details; update Keysrs if `keys client token` is unknown."
        if kind == ErrorKind.TIMEOUT:
            return "Keysrs was slow; raise secrets.keysrs.helper_timeout_seconds if this recurs."
        return super().remediation(kind, cfg)
