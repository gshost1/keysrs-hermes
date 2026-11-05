"""fetch() outcomes for every `keys client token` result."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from agent.secret_sources.base import ErrorKind, FetchResult

from conftest import BASE_URL, TOKEN, token_payload
from keysrs_hermes.keysrs_source import KeysrsSource, is_loopback_http_url

CFG = {"enabled": True}


def fetch(cfg=None):
    return KeysrsSource().fetch(dict(CFG, **(cfg or {})), Path("/nonexistent-hermes-home"))


def test_success_fills_openrouter_vars(fake_keys):
    fake_keys.token_ok()
    result = fetch()
    assert result.ok, result.error
    assert result.secrets == {"OPENROUTER_BASE_URL": BASE_URL, "OPENROUTER_API_KEY": TOKEN}
    assert result.binary_path == fake_keys.path
    assert result.warnings == []


def test_argv_is_client_token_with_label(fake_keys):
    fake_keys.token_ok()
    fetch({"label": "work"})
    (call,) = fake_keys.calls()
    assert call["argv"] == ["client", "token", "--label", "work", "--json"]


def test_openai_preset(fake_keys):
    fake_keys.token_ok(base_url="http://127.0.0.1:12767/openai")
    result = fetch({"provider": "openai"})
    assert result.secrets == {
        "OPENAI_BASE_URL": "http://127.0.0.1:12767/openai",
        "OPENAI_API_KEY": TOKEN,
    }


def test_env_override_map(fake_keys):
    fake_keys.token_ok()
    result = fetch({"provider": "custom", "env": {"base_url": "MY_URL", "api_key": "MY_KEY"}})
    assert result.secrets == {"MY_URL": BASE_URL, "MY_KEY": TOKEN}


def test_env_override_key_only(fake_keys):
    fake_keys.token_ok()
    result = fetch({"env": {"base_url": "", "api_key": "OPENROUTER_API_KEY"}})
    assert result.secrets == {"OPENROUTER_API_KEY": TOKEN}


@pytest.mark.parametrize(
    "cfg",
    [
        {"provider": "nope"},
        {"provider": "custom"},
        {"env": "not-a-dict"},
        {"env": {"api_key": "bad name"}},
        {"env": {"base_url": "SAME", "api_key": "SAME"}},
        {"label": "--evil"},
        {"label": "has space"},
    ],
)
def test_bad_config_is_ref_invalid_and_runs_nothing(fake_keys, cfg):
    result = fetch(cfg)
    assert result.error_kind == ErrorKind.REF_INVALID
    assert not result.secrets
    assert fake_keys.calls() == []


def test_trailing_slash_trimmed(fake_keys):
    fake_keys.token_ok(base_url=BASE_URL + "/")
    assert fetch().secrets["OPENROUTER_BASE_URL"] == BASE_URL


@pytest.mark.parametrize(
    "reason,kind",
    [
        ("not_found", ErrorKind.NOT_CONFIGURED),
        ("expired", ErrorKind.AUTH_EXPIRED),
        ("revoked", ErrorKind.AUTH_EXPIRED),
        ("something_new", ErrorKind.NOT_CONFIGURED),
    ],
)
def test_exit_2(fake_keys, reason, kind):
    fake_keys.set("token", exit=2, stdout=json.dumps({"error": reason, "label": "hermes"}) + "\n")
    result = fetch()
    assert result.error_kind == kind
    assert not result.secrets


def test_exit_2_without_json(fake_keys):
    fake_keys.set("token", exit=2, stdout="garbage")
    assert fetch().error_kind == ErrorKind.NOT_CONFIGURED


def test_exit_6_app_not_running(fake_keys):
    fake_keys.set("token", exit=6, stderr="Keysrs is not running\n")
    result = fetch()
    assert result.error_kind == ErrorKind.NETWORK
    assert "not running" in result.error


def test_exit_64_bad_args(fake_keys):
    fake_keys.set("token", exit=64, stderr="unknown subcommand: client\n")
    result = fetch()
    assert result.error_kind == ErrorKind.INTERNAL
    assert "exit 64" in result.error
    assert "unknown subcommand" in result.error


def test_exit_1_other(fake_keys):
    fake_keys.set("token", exit=1, stderr="\x1b[31mboom\x1b[0m\n")
    result = fetch()
    assert result.error_kind == ErrorKind.INTERNAL
    assert "boom" in result.error and "\x1b" not in result.error


def test_unexpected_exit_code(fake_keys):
    fake_keys.set("token", exit=3)
    assert fetch().error_kind == ErrorKind.INTERNAL


def test_gateway_off(fake_keys):
    fake_keys.token_ok(gateway_on=False)
    result = fetch()
    assert result.error_kind == ErrorKind.AUTH_EXPIRED
    assert "keys gateway on openrouter" in result.error
    assert not result.secrets


def test_gateway_on_missing_counts_as_off(fake_keys):
    payload = token_payload()
    del payload["gateway_on"]
    fake_keys.set("token", stdout=json.dumps(payload))
    assert fetch().error_kind == ErrorKind.AUTH_EXPIRED


@pytest.mark.parametrize(
    "stdout",
    [
        "",
        "\n\n",
        "not json",
        "[1, 2]",
        json.dumps(token_payload(token="")),
        json.dumps(token_payload(token=None)),
        json.dumps(token_payload(token="   ")),
        json.dumps(token_payload(token="sk-or-real-provider-key")),
        json.dumps(token_payload(token="ksfc_a b")),
        json.dumps(token_payload(base_url="")),
        json.dumps({k: v for k, v in token_payload().items() if k != "token"}),
    ],
)
def test_malformed_output_is_empty_value(fake_keys, stdout):
    fake_keys.set("token", stdout=stdout)
    result = fetch()
    assert result.error_kind == ErrorKind.EMPTY_VALUE, result.error
    assert not result.secrets


@pytest.mark.parametrize(
    "url", ["https://evil.example/openrouter", "http://10.0.0.5:12767/x", "file:///etc/passwd", "127.0.0.1:12767"]
)
def test_non_loopback_base_url_refused(fake_keys, url):
    fake_keys.token_ok(base_url=url)
    result = fetch()
    assert result.error_kind == ErrorKind.INTERNAL
    assert not result.secrets


def test_loopback_check():
    assert is_loopback_http_url("http://127.0.0.1:12767/x")
    assert is_loopback_http_url("http://localhost:12767/x")
    assert is_loopback_http_url("http://[::1]:12767/x")
    assert not is_loopback_http_url("http://127.0.0.1.evil.example/x")
    assert not is_loopback_http_url("http://localhost.evil.example/x")


def test_expired_by_timestamp(fake_keys):
    fake_keys.token_ok(expires_at="2000-01-01T00:00:00Z")
    assert fetch().error_kind == ErrorKind.AUTH_EXPIRED


def test_expiring_soon_warns(fake_keys):
    import datetime as dt

    soon = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=3)).strftime("%Y-%m-%dT%H:%M:%SZ")
    fake_keys.token_ok(expires_at=soon)
    result = fetch()
    assert result.ok
    assert any("expires in about" in w for w in result.warnings)


def test_unreadable_expiry_warns_but_works(fake_keys):
    fake_keys.token_ok(expires_at="whenever")
    result = fetch()
    assert result.ok
    assert any("expires_at" in w for w in result.warnings)


def test_timeout(fake_keys):
    fake_keys.set("token", sleep=5, stdout=json.dumps(token_payload()))
    result = fetch({"helper_timeout_seconds": 0.5})
    assert result.error_kind == ErrorKind.TIMEOUT
    assert not result.secrets


def test_binary_missing_explicit_path(fake_keys, tmp_path):
    result = fetch({"keys_path": str(tmp_path / "no-such-keys")})
    assert result.error_kind == ErrorKind.BINARY_MISSING


def test_binary_missing_on_path(fake_keys, monkeypatch, tmp_path):
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    assert fetch().error_kind == ErrorKind.BINARY_MISSING


def test_binary_not_executable(fake_keys):
    fake_keys.path.chmod(0o644)
    assert fetch({"keys_path": str(fake_keys.path)}).error_kind == ErrorKind.BINARY_MISSING


def test_explicit_keys_path_used(fake_keys, monkeypatch, tmp_path):
    fake_keys.token_ok()
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    result = fetch({"keys_path": str(fake_keys.path)})
    assert result.ok
    assert result.binary_path == fake_keys.path


def test_spawn_failure_is_binary_missing(fake_keys):
    fake_keys.path.write_text("#!/nonexistent/interpreter\n")
    fake_keys.path.chmod(0o755)
    assert fetch().error_kind == ErrorKind.BINARY_MISSING


def test_child_env_is_allowlisted(fake_keys, monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-real-should-not-leak")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "aws-should-not-leak")
    monkeypatch.setenv("HERMES_HOME", "/tmp/should-not-leak")
    monkeypatch.setenv("LANG", "en_US.UTF-8")
    fake_keys.token_ok()
    fetch()
    (call,) = fake_keys.calls()
    allowed = {"PATH", "HOME", "USERPROFILE", "SYSTEMROOT", "TMPDIR", "TEMP",
               "LANG", "LC_ALL", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "NO_COLOR"}
    # /bin/sh and the Python interpreter may add a few of their own
    # (PWD, SHLVL, _, __CF_USER_TEXT_ENCODING); none of them come from us.
    shell_added = {"PWD", "OLDPWD", "SHLVL", "_", "__CF_USER_TEXT_ENCODING"}
    child = set(call["env"]) - shell_added
    assert child <= allowed, child - allowed
    assert call["env"]["NO_COLOR"] == "1"
    assert call["env"]["HOME"] == str(fake_keys.home)
    blob = json.dumps(call["env"])
    assert "should-not-leak" not in blob


def test_fetch_never_writes_environ(fake_keys):
    fake_keys.token_ok()
    before = dict(os.environ)
    assert fetch().ok
    assert dict(os.environ) == before


def test_fetch_never_raises_on_internal_bug(fake_keys, monkeypatch):
    import keysrs_hermes.keysrs_source as mod

    def boom(cfg):
        raise ValueError(TOKEN)

    monkeypatch.setattr(mod, "lookup_token", boom)
    result = fetch()
    assert isinstance(result, FetchResult)
    assert result.error_kind == ErrorKind.INTERNAL
    assert TOKEN not in result.error


def test_stdin_is_closed(fake_keys, tmp_path):
    # A helper that tries to read a prompt answer gets EOF at once.
    script = tmp_path / "bin" / "keys"
    script.write_text('#!/bin/sh\nread answer || exit 1\necho "got $answer"\n')
    script.chmod(0o755)
    result = fetch({"helper_timeout_seconds": 3})
    assert result.error_kind == ErrorKind.INTERNAL


def test_override_existing_default_true():
    src = KeysrsSource()
    assert src.override_existing({}) is True
    assert src.override_existing({"override_existing": False}) is False


def test_timeouts():
    src = KeysrsSource()
    assert src.fetch_timeout_seconds({}) == 20.0
    assert src.fetch_timeout_seconds({"timeout_seconds": 5}) == 5.0
    assert src.fetch_timeout_seconds({"timeout_seconds": "junk"}) == 20.0
    assert src.fetch_timeout_seconds({"timeout_seconds": -1}) == 20.0


def test_remediation_points_at_setup():
    src = KeysrsSource()
    cfg = {"key": "openrouter"}
    assert "hermes keysrs setup --key openrouter" in src.remediation(ErrorKind.NOT_CONFIGURED, cfg)
    assert "keys gateway on openrouter" in src.remediation(ErrorKind.AUTH_EXPIRED, cfg)
    assert "<vault-key>" in src.remediation(ErrorKind.NOT_CONFIGURED, {})
    for kind in ErrorKind:
        hint = src.remediation(kind, cfg)
        assert isinstance(hint, str) and "\n" not in hint
    assert src.remediation(None, cfg) == ""
