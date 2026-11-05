"""fetch() outcomes for every `keys client token` result and provider-entry state."""

from __future__ import annotations

import json
import os

import pytest

from agent.secret_sources.base import ErrorKind, FetchResult

from conftest import BASE_URL, TOKEN, provider_cfg, token_payload, write_config
from keysrs_hermes.keysrs_source import KeysrsSource, is_loopback_http_url, valid_key_env

CFG = {"enabled": True}


@pytest.fixture
def fetch(hermes_home):
    def _fetch(cfg=None, home=None):
        return KeysrsSource().fetch(dict(CFG, **(cfg or {})), home or hermes_home)
    return _fetch


def test_success_fills_only_the_keysrs_var(fake_keys, fetch):
    fake_keys.token_ok()
    result = fetch()
    assert result.ok, result.error
    assert result.secrets == {"KEYSRS_TOKEN": TOKEN}
    assert result.binary_path == fake_keys.path
    assert result.warnings == []


def test_never_fills_vendor_vars(fake_keys, fetch):
    fake_keys.token_ok()
    names = set(fetch().secrets)
    assert all(n.startswith("KEYSRS_") for n in names)
    assert not names & {"OPENROUTER_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY",
                        "OPENROUTER_BASE_URL", "OPENAI_BASE_URL", "ANTHROPIC_BASE_URL"}


def test_argv_is_client_token_with_label(fake_keys, fetch):
    fake_keys.token_ok()
    fetch({"label": "work"})
    (call,) = fake_keys.calls()
    assert call["argv"] == ["client", "token", "--label", "work", "--json"]


def test_custom_provider_name_and_key_env(fake_keys, tmp_path, fetch):
    home = write_config(tmp_path / "h2", {"providers": {"gw": {
        "base_url": BASE_URL + "/", "api_key_env": "KEYSRS_WORK"}}})
    fake_keys.token_ok()
    result = fetch({"provider_name": "gw", "key_env": "KEYSRS_WORK"}, home=home)
    assert result.secrets == {"KEYSRS_WORK": TOKEN}


@pytest.mark.parametrize("key_env", ["OPENROUTER_API_KEY", "OPENAI_API_KEY", "KEYSRS_", "keysrs_token",
                                     "KEYSRS TOKEN", "MY_KEY"])
def test_key_env_must_be_keysrs_prefixed(fake_keys, fetch, key_env):
    assert not valid_key_env(key_env)
    result = fetch({"key_env": key_env})
    assert result.error_kind == ErrorKind.REF_INVALID
    assert not result.secrets and fake_keys.calls() == []


@pytest.mark.parametrize("cfg", [{"label": "--evil"}, {"label": "has space"}, {"provider_name": "Bad Name"},
                                 {"provider_name": "-x"}])
def test_bad_names_are_ref_invalid_and_run_nothing(fake_keys, fetch, cfg):
    result = fetch(cfg)
    assert result.error_kind == ErrorKind.REF_INVALID
    assert not result.secrets and fake_keys.calls() == []


@pytest.mark.parametrize("hermes_cfg,needle", [
    ({}, "missing"),
    ({"providers": {"other": {"base_url": BASE_URL, "key_env": "KEYSRS_TOKEN"}}}, "missing"),
    (provider_cfg(key_env="OPENROUTER_API_KEY"), "key_env"),
    (provider_cfg(base_url=""), "no base_url"),
    (provider_cfg(base_url="https://openrouter.ai/api/v1"), "other than the local Keysrs gateway"),
    # Hermes reads `api or url or base_url`: a remote url beside a loopback base_url wins in Hermes.
    (provider_cfg(url="https://evil.example/v1"), "other than the local Keysrs gateway"),
    (provider_cfg(api="https://evil.example/v1"), "other than the local Keysrs gateway"),
    (provider_cfg(enabled=False), "disabled"),
    # Hermes ignores camelCase keyEnv, so this entry does not read our variable.
    ({"providers": {"keysrs": {"base_url": BASE_URL, "keyEnv": "KEYSRS_TOKEN"}}}, "key_env"),
    # Any other entry that reads the same variable gets the token too.
    ({"providers": {"keysrs": provider_cfg()["providers"]["keysrs"],
                    "copy": {"base_url": "https://api.example.com/v1", "key_env": "KEYSRS_TOKEN"}}},
     "providers.copy also reads KEYSRS_TOKEN"),
    ({**provider_cfg(), "custom_providers": [{"name": "old", "base_url": "https://api.example.com/v1",
                                              "key_env": "KEYSRS_TOKEN"}]},
     "custom_providers[0] also reads KEYSRS_TOKEN"),
])
def test_provider_entry_problems_are_not_configured(fake_keys, tmp_path, fetch, hermes_cfg, needle):
    home = write_config(tmp_path / "h3", hermes_cfg)
    fake_keys.token_ok()
    result = fetch(home=home)
    assert result.error_kind == ErrorKind.NOT_CONFIGURED
    assert needle in result.error
    assert not result.secrets
    assert fake_keys.calls() == []  # checked before asking keys for the token


def test_no_config_file(fake_keys, tmp_path, fetch):
    assert fetch(home=tmp_path / "nowhere").error_kind == ErrorKind.NOT_CONFIGURED


def test_unparseable_config(fake_keys, tmp_path, fetch):
    (tmp_path / "bad").mkdir()
    (tmp_path / "bad" / "config.yaml").write_text("providers: [unclosed")
    assert fetch(home=tmp_path / "bad").error_kind == ErrorKind.NOT_CONFIGURED


def test_base_url_mismatch_is_not_configured(fake_keys, fetch):
    fake_keys.token_ok(base_url="http://127.0.0.1:12767/openai")
    result = fetch()
    assert result.error_kind == ErrorKind.NOT_CONFIGURED
    assert "different gateway URL" in result.error
    assert not result.secrets
    assert "rerun" in KeysrsSource().remediation(result.error_kind, {}).lower()


def test_other_loopback_entries_reading_the_var_are_fine(fake_keys, tmp_path, fetch):
    cfg = provider_cfg()
    cfg["providers"]["second"] = {"base_url": "http://127.0.0.1:12767/openai", "key_env": "KEYSRS_TOKEN"}
    fake_keys.token_ok()
    assert fetch(home=write_config(tmp_path / "h4", cfg)).ok


def test_trailing_slash_is_not_a_mismatch(fake_keys, fetch):
    fake_keys.token_ok(base_url=BASE_URL + "/")
    assert fetch().ok


@pytest.mark.parametrize(
    "reason,kind",
    [
        ("not_found", ErrorKind.NOT_CONFIGURED),
        ("expired", ErrorKind.AUTH_EXPIRED),
        ("revoked", ErrorKind.AUTH_EXPIRED),
        ("something_new", ErrorKind.NOT_CONFIGURED),
    ],
)
def test_exit_2(fake_keys, fetch, reason, kind):
    fake_keys.set("token", exit=2, stdout=json.dumps({"error": reason, "label": "hermes"}) + "\n")
    result = fetch()
    assert result.error_kind == kind
    assert not result.secrets


def test_exit_2_without_json(fake_keys, fetch):
    fake_keys.set("token", exit=2, stdout="garbage")
    assert fetch().error_kind == ErrorKind.NOT_CONFIGURED


def test_exit_6_app_not_running(fake_keys, fetch):
    fake_keys.set("token", exit=6, stderr="Keysrs is not running\n")
    result = fetch()
    assert result.error_kind == ErrorKind.NETWORK
    assert "not running" in result.error


def test_exit_64_bad_args(fake_keys, fetch):
    fake_keys.set("token", exit=64, stderr="unknown subcommand: client\n")
    result = fetch()
    assert result.error_kind == ErrorKind.INTERNAL
    assert "exit 64" in result.error and "unknown subcommand" in result.error


def test_exit_1_other(fake_keys, fetch):
    fake_keys.set("token", exit=1, stderr="\x1b[31mboom\x1b[0m\n")
    result = fetch()
    assert result.error_kind == ErrorKind.INTERNAL
    assert "boom" in result.error and "\x1b" not in result.error


def test_unexpected_exit_code(fake_keys, fetch):
    fake_keys.set("token", exit=3)
    assert fetch().error_kind == ErrorKind.INTERNAL


def test_gateway_off(fake_keys, fetch):
    fake_keys.token_ok(gateway_on=False)
    result = fetch()
    assert result.error_kind == ErrorKind.AUTH_EXPIRED
    assert "keys gateway on openrouter" in result.error
    assert not result.secrets


def test_gateway_on_missing_counts_as_off(fake_keys, fetch):
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
        json.dumps(token_payload(token="sk-or-" + "real-provider-key")),
        json.dumps(token_payload(token="ksfc_a b")),
        json.dumps(token_payload(base_url="")),
        json.dumps({k: v for k, v in token_payload().items() if k != "token"}),
    ],
)
def test_malformed_output_is_empty_value(fake_keys, fetch, stdout):
    fake_keys.set("token", stdout=stdout)
    result = fetch()
    assert result.error_kind == ErrorKind.EMPTY_VALUE, result.error
    assert not result.secrets


@pytest.mark.parametrize(
    "url", ["https://evil.example/openrouter", "http://10.0.0.5:12767/x", "file:///tmp/keysrs", "127.0.0.1:12767"]
)
def test_non_loopback_base_url_refused(fake_keys, fetch, url):
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
    assert not is_loopback_http_url("http://127.0.0.1@evil.example/x")


def test_expired_by_timestamp(fake_keys, fetch):
    fake_keys.token_ok(expires_at="2000-01-01T00:00:00Z")
    assert fetch().error_kind == ErrorKind.AUTH_EXPIRED


def test_expiring_soon_warns(fake_keys, fetch):
    import datetime as dt

    soon = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=3)).strftime("%Y-%m-%dT%H:%M:%SZ")
    fake_keys.token_ok(expires_at=soon)
    result = fetch()
    assert result.ok
    assert any("expires in about" in w for w in result.warnings)


def test_unreadable_expiry_warns_but_works(fake_keys, fetch):
    fake_keys.token_ok(expires_at="whenever")
    result = fetch()
    assert result.ok
    assert any("expires_at" in w for w in result.warnings)


def test_timeout(fake_keys, fetch):
    fake_keys.set("token", sleep=5, stdout=json.dumps(token_payload()))
    result = fetch({"helper_timeout_seconds": 0.5})
    assert result.error_kind == ErrorKind.TIMEOUT
    assert not result.secrets


def test_binary_missing_explicit_path(fake_keys, fetch, tmp_path):
    assert fetch({"keys_path": str(tmp_path / "no-such-keys")}).error_kind == ErrorKind.BINARY_MISSING


def test_binary_missing_on_path(fake_keys, fetch, monkeypatch, tmp_path):
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    assert fetch().error_kind == ErrorKind.BINARY_MISSING


def test_binary_not_executable(fake_keys, fetch):
    fake_keys.path.chmod(0o644)
    assert fetch({"keys_path": str(fake_keys.path)}).error_kind == ErrorKind.BINARY_MISSING


def test_explicit_keys_path_used(fake_keys, fetch, monkeypatch, tmp_path):
    fake_keys.token_ok()
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    result = fetch({"keys_path": str(fake_keys.path)})
    assert result.ok
    assert result.binary_path == fake_keys.path


def test_spawn_failure_is_binary_missing(fake_keys, fetch):
    fake_keys.path.write_text("#!/nonexistent/interpreter\n")
    fake_keys.path.chmod(0o755)
    assert fetch().error_kind == ErrorKind.BINARY_MISSING


def test_child_env_is_allowlisted(fake_keys, fetch, monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-real-should-not-leak")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "aws-should-not-leak")
    monkeypatch.setenv("HERMES_HOME", "/tmp/should-not-leak")
    monkeypatch.setenv("LANG", "en_US.UTF-8")
    fake_keys.token_ok()
    fetch()
    (call,) = fake_keys.calls()
    allowed = {"PATH", "HOME", "USERPROFILE", "SYSTEMROOT", "TMPDIR", "TEMP",
               "LANG", "LC_ALL", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "NO_COLOR"}
    # /bin/sh and the Python interpreter may add a few of their own.
    shell_added = {"PWD", "OLDPWD", "SHLVL", "_", "__CF_USER_TEXT_ENCODING"}
    child = set(call["env"]) - shell_added
    assert child <= allowed, child - allowed
    assert call["env"]["NO_COLOR"] == "1"
    assert call["env"]["HOME"] == str(fake_keys.home)
    assert "should-not-leak" not in json.dumps(call["env"])


def test_fetch_never_writes_environ(fake_keys, fetch):
    fake_keys.token_ok()
    before = dict(os.environ)
    assert fetch().ok
    assert dict(os.environ) == before


def test_fetch_never_raises_on_internal_bug(fake_keys, fetch, monkeypatch):
    import keysrs_hermes.keysrs_source as mod

    def boom(cfg):
        raise ValueError(TOKEN)

    monkeypatch.setattr(mod, "lookup_token", boom)
    result = fetch()
    assert isinstance(result, FetchResult)
    assert result.error_kind == ErrorKind.INTERNAL
    assert TOKEN not in result.error


def test_stdin_is_closed(fake_keys, fetch, tmp_path):
    # A helper that tries to read a prompt answer gets EOF at once.
    script = tmp_path / "bin" / "keys"
    script.write_text('#!/bin/sh\nread answer || exit 1\necho "got $answer"\n')
    script.chmod(0o755)
    assert fetch({"helper_timeout_seconds": 3}).error_kind == ErrorKind.INTERNAL


def test_override_existing_default_true():
    src = KeysrsSource()
    assert src.override_existing({}) is True
    assert src.override_existing({"override_existing": False}) is False


@pytest.mark.parametrize("value,expected", [
    (True, True), (False, False), ("false", False), ("no", False), ("off", False), ("0", False),
    ("true", True), ("YES", True), (1, True), (0, False), (None, None), ("maybe", None),
])
def test_flags_accept_quoted_spellings(value, expected):
    src = KeysrsSource()
    assert src.override_existing({"override_existing": value}) is (True if expected is None else expected)
    assert src.is_enabled({"enabled": value}) is (False if expected is None else expected)


def test_timeouts():
    src = KeysrsSource()
    assert src.fetch_timeout_seconds({}) == 30.0
    assert src.fetch_timeout_seconds({"timeout_seconds": 5}) == 5.0
    assert src.fetch_timeout_seconds({"timeout_seconds": "junk"}) == 30.0
    assert src.fetch_timeout_seconds({"timeout_seconds": -1}) == 30.0


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


def test_config_reader_works_without_pyyaml(tmp_path, monkeypatch):
    """Hermes 0.22.x ships ruamel.yaml, not PyYAML."""
    pytest.importorskip("ruamel.yaml")
    import sys

    from keysrs_hermes.keysrs_source import read_hermes_config

    write_config(tmp_path / "h", provider_cfg())
    monkeypatch.setitem(sys.modules, "yaml", None)  # import yaml -> ImportError
    assert read_hermes_config(tmp_path / "h")["providers"]["keysrs"]["key_env"] == "KEYSRS_TOKEN"
