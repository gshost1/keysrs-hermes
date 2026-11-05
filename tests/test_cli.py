"""`hermes keysrs setup|status|disable`; config saves go to a temp profile dir."""

from __future__ import annotations

import argparse
import json

import pytest

from conftest import BASE_URL, TOKEN, yaml_dump
import keysrs_hermes.cli as cli

ISSUED = {
    "base_url": BASE_URL,
    "client_id": 7,
    "expires_at": "2099-01-01T00:00:00Z",
    "held": True,
    "key": "openrouter",
    "label": "hermes",
    "methods": ["POST"],
    "path_prefix": "chat/completions",
}


@pytest.fixture
def config(monkeypatch, tmp_path):
    home = tmp_path / "hermes"
    home.mkdir()
    store = {"cfg": {"model": {"provider": "openrouter", "default": "x/y"}}, "saves": 0, "home": home}

    def load():
        return json.loads(json.dumps(store["cfg"]))

    def save(cfg):
        store["cfg"] = json.loads(json.dumps(cfg))
        store["saves"] += 1
        (home / "config.yaml").write_text(yaml_dump(store["cfg"]))

    monkeypatch.setattr(cli, "_load_config", load)
    monkeypatch.setattr(cli, "_save_config", save)
    monkeypatch.setattr(cli, "_hermes_home", lambda: home)
    return store


def parse(*argv):
    parser = argparse.ArgumentParser(prog="hermes keysrs")
    cli.setup_parser(parser)
    return parser.parse_args(list(argv))


def run(*argv):
    args = parse(*argv)
    return args.func(args)


def issue_ok(fake_keys, **overrides):
    fake_keys.set("issue", stdout=json.dumps(dict(ISSUED, **overrides)) + "\n")


def ready(fake_keys, **issue_overrides):
    issue_ok(fake_keys, **issue_overrides)
    fake_keys.token_ok(base_url=issue_overrides.get("base_url", BASE_URL))


def test_setup_writes_provider_and_section(fake_keys, config, capsys):
    ready(fake_keys)
    assert run("setup", "--key", "openrouter") == 0
    assert fake_keys.calls()[0]["argv"] == [
        "client", "issue", "openrouter", "--label", "hermes", "--days", "7",
        "--method", "POST", "--path-prefix", "chat/completions", "--hold", "--json",
    ]
    cfg = config["cfg"]
    assert cfg["providers"]["keysrs"] == {
        "base_url": BASE_URL, "key_env": "KEYSRS_TOKEN", "api_mode": "chat_completions",
    }
    assert cfg["secrets"]["keysrs"] == {
        "enabled": True, "label": "hermes", "key": "openrouter",
        "provider_name": "keysrs", "keys_path": str(fake_keys.path),
    }
    assert cfg["model"] == {"provider": "openrouter", "default": "x/y"}  # untouched without --use
    out = capsys.readouterr().out
    assert "model.provider: custom:keysrs" in out
    assert "check      ok" in out
    assert TOKEN not in out and TOKEN not in json.dumps(cfg)


def test_setup_use_selects_provider_and_model(fake_keys, config, capsys):
    ready(fake_keys)
    assert run("setup", "--key", "openrouter", "--use", "--model", "anthropic/claude-sonnet-4") == 0
    cfg = config["cfg"]
    assert cfg["model"]["provider"] == "custom:keysrs"
    assert cfg["model"]["default"] == "anthropic/claude-sonnet-4"
    assert cfg["providers"]["keysrs"]["default_model"] == "anthropic/claude-sonnet-4"
    assert "to use it" not in capsys.readouterr().out


def test_setup_use_without_model_keeps_default(fake_keys, config):
    ready(fake_keys)
    assert run("setup", "--key", "openrouter", "--use") == 0
    assert config["cfg"]["model"] == {"provider": "custom:keysrs", "default": "x/y"}


def test_setup_provider_name_and_key_env(fake_keys, config):
    ready(fake_keys)
    assert run("setup", "--key", "openrouter", "--provider-name", "or-gw", "--key-env", "KEYSRS_OR") == 0
    cfg = config["cfg"]
    assert cfg["providers"]["or-gw"]["key_env"] == "KEYSRS_OR"
    assert cfg["secrets"]["keysrs"]["provider_name"] == "or-gw"
    assert cfg["secrets"]["keysrs"]["key_env"] == "KEYSRS_OR"


@pytest.mark.parametrize("key_env", ["OPENROUTER_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "KEYSRS_", "bad name"])
def test_setup_refuses_vendor_key_env(fake_keys, config, key_env):
    assert run("setup", "--key", "openrouter", "--key-env", key_env) == 64
    assert fake_keys.calls() == [] and config["saves"] == 0


def test_setup_api_mode_sets_path_prefix(fake_keys, config):
    ready(fake_keys)
    assert run("setup", "--key", "openai", "--api-mode", "codex_responses") == 0
    argv = fake_keys.calls()[0]["argv"]
    assert argv[argv.index("--path-prefix") + 1] == "responses"
    assert config["cfg"]["providers"]["keysrs"]["api_mode"] == "codex_responses"


def test_setup_custom_scope(fake_keys, config):
    ready(fake_keys)
    assert run("setup", "--key", "k", "--method", "post", "--method", "GET", "--any-path") == 0
    argv = fake_keys.calls()[0]["argv"]
    assert "--path-prefix" not in argv
    assert argv.count("--method") == 2 and "GET" in argv and "POST" in argv


def test_setup_explicit_path_prefix(fake_keys, config):
    ready(fake_keys)
    assert run("setup", "--key", "k", "--path-prefix", "/chat") == 0
    argv = fake_keys.calls()[0]["argv"]
    assert argv[argv.index("--path-prefix") + 1] == "chat"


def test_setup_keeps_saved_api_mode_on_renewal(fake_keys, config):
    config["cfg"]["providers"] = {"keysrs": {"base_url": BASE_URL, "key_env": "KEYSRS_TOKEN",
                                             "api_mode": "codex_responses"}}
    ready(fake_keys)
    assert run("setup", "--key", "openai") == 0
    argv = fake_keys.calls()[0]["argv"]
    assert argv[argv.index("--path-prefix") + 1] == "responses"
    assert config["cfg"]["providers"]["keysrs"]["api_mode"] == "codex_responses"


def test_setup_reenables_disabled_entry(fake_keys, config):
    config["cfg"]["providers"] = {"keysrs": {"base_url": BASE_URL, "key_env": "KEYSRS_TOKEN", "enabled": False}}
    ready(fake_keys)
    assert run("setup", "--key", "openrouter") == 0
    assert "enabled" not in config["cfg"]["providers"]["keysrs"]


def test_setup_can_change_key_env_on_own_entry(fake_keys, config):
    config["cfg"]["providers"] = {"keysrs": {"base_url": BASE_URL, "key_env": "KEYSRS_TOKEN"}}
    ready(fake_keys)
    assert run("setup", "--key", "openrouter", "--key-env", "KEYSRS_OR") == 0
    assert config["cfg"]["providers"]["keysrs"]["key_env"] == "KEYSRS_OR"


def test_setup_drops_default_model_when_vault_key_changes(fake_keys, config):
    config["cfg"]["secrets"] = {"keysrs": {"key": "openrouter"}}
    config["cfg"]["providers"] = {"keysrs": {"base_url": BASE_URL, "key_env": "KEYSRS_TOKEN",
                                             "default_model": "openai/gpt-4o-mini"}}
    ready(fake_keys)
    assert run("setup", "--key", "anthropic") == 0
    assert "default_model" not in config["cfg"]["providers"]["keysrs"]


def test_setup_keeps_default_model_on_same_key_renewal(fake_keys, config):
    config["cfg"]["secrets"] = {"keysrs": {"key": "openrouter"}}
    config["cfg"]["providers"] = {"keysrs": {"base_url": BASE_URL, "key_env": "KEYSRS_TOKEN",
                                             "default_model": "openai/gpt-4o-mini"}}
    ready(fake_keys)
    assert run("setup", "--key", "openrouter") == 0
    assert config["cfg"]["providers"]["keysrs"]["default_model"] == "openai/gpt-4o-mini"


def test_setup_rename_moves_entry_and_selector(fake_keys, config, capsys):
    config["cfg"]["secrets"] = {"keysrs": {"key": "openrouter", "provider_name": "keysrs"}}
    config["cfg"]["providers"] = {"keysrs": {"base_url": BASE_URL, "key_env": "KEYSRS_TOKEN"},
                                  "mine": {"base_url": "https://x.example/v1", "key_env": "X_KEY"}}
    config["cfg"]["model"]["provider"] = "custom:keysrs"
    ready(fake_keys)
    assert run("setup", "--key", "openrouter", "--provider-name", "gw") == 0
    providers = config["cfg"]["providers"]
    assert set(providers) == {"gw", "mine"}
    assert config["cfg"]["model"]["provider"] == "custom:gw"
    assert "removed providers.keysrs" in capsys.readouterr().out


def test_setup_strips_aliases_hermes_would_prefer(fake_keys, config):
    config["cfg"]["providers"] = {"keysrs": {"base_url": BASE_URL, "key_env": "KEYSRS_TOKEN",
                                             "url": "https://evil.example/v1", "api": "https://evil.example/v1",
                                             "key_cmd": "echo x"}}
    ready(fake_keys)
    assert run("setup", "--key", "openrouter") == 0
    entry = config["cfg"]["providers"]["keysrs"]
    assert not {"url", "api", "key_cmd"} & set(entry)


def test_setup_never_overwrites_foreign_provider(fake_keys, config, capsys):
    foreign = {"base_url": "https://api.example.com/v1", "key_env": "EXAMPLE_API_KEY"}
    config["cfg"]["providers"] = {"keysrs": dict(foreign)}
    ready(fake_keys)
    assert run("setup", "--key", "openrouter") == 1
    assert config["saves"] == 0 and fake_keys.calls() == []  # refused before Touch ID
    assert config["cfg"]["providers"]["keysrs"] == foreign
    assert "--provider-name" in capsys.readouterr().err


def test_setup_refuses_foreign_entry_without_key_env(fake_keys, config):
    config["cfg"]["providers"] = {"keysrs": {"base_url": "http://127.0.0.1:8080/v1"}}
    assert run("setup", "--key", "openrouter") == 1
    assert config["saves"] == 0


def test_setup_updates_own_entry_and_keeps_extra_fields(fake_keys, config):
    config["cfg"]["providers"] = {"keysrs": {
        "base_url": "http://127.0.0.1:12767/old", "key_env": "KEYSRS_TOKEN",
        "context_length": 200000, "api_key": "stale-inline", "transport": "codex_responses"}}
    ready(fake_keys)
    assert run("setup", "--key", "openrouter") == 0
    entry = config["cfg"]["providers"]["keysrs"]
    assert entry == {"base_url": BASE_URL, "key_env": "KEYSRS_TOKEN", "api_mode": "codex_responses",
                     "context_length": 200000}


def test_setup_drops_legacy_env_preset_keys(fake_keys, config):
    config["cfg"]["secrets"] = {"keysrs": {"enabled": True, "provider": "openrouter",
                                           "env": {"api_key": "OPENROUTER_API_KEY"}}}
    ready(fake_keys)
    assert run("setup", "--key", "openrouter") == 0
    section = config["cfg"]["secrets"]["keysrs"]
    assert "provider" not in section and "env" not in section


def test_setup_refuses_non_loopback_issue_url(fake_keys, config):
    issue_ok(fake_keys, base_url="https://openrouter.ai/api/v1")
    assert run("setup", "--key", "openrouter") == 1
    assert config["saves"] == 0


@pytest.mark.parametrize("argv", [
    ("setup", "--key", "--bad"),
    ("setup", "--key", "a b"),
    ("setup", "--key", "k", "--label", "-x"),
    ("setup", "--key", "k", "--days", "0"),
    ("setup", "--key", "k", "--method", "PO ST"),
    ("setup", "--key", "k", "--path-prefix", "-rf"),
    ("setup", "--key", "k", "--provider-name", "Bad Name"),
    ("setup", "--key", "k", "--model", "a b"),
])
def test_setup_rejects_bad_args_before_running_keys(fake_keys, config, argv):
    try:
        rc = run(*argv)
    except SystemExit as exc:  # argparse itself refused it
        rc = exc.code
    assert rc != 0
    assert fake_keys.calls() == [] and config["saves"] == 0


@pytest.mark.parametrize("rc,needle", [(6, "not running"), (64, "exit 64"), (2, "could not issue"), (1, "exit 1")])
def test_setup_failure_leaves_config_alone(fake_keys, config, capsys, rc, needle):
    fake_keys.set("issue", exit=rc, stdout=json.dumps({"error": "denied"}) + "\n")
    assert run("setup", "--key", "openrouter") == rc
    assert config["saves"] == 0
    assert needle in capsys.readouterr().err


def test_setup_requires_held(fake_keys, config):
    issue_ok(fake_keys, held=False)
    assert run("setup", "--key", "openrouter") == 1
    assert config["saves"] == 0


def test_setup_bad_json(fake_keys, config):
    fake_keys.set("issue", stdout="oops\n")
    assert run("setup", "--key", "openrouter") == 1
    assert config["saves"] == 0


def test_setup_drops_token_if_issue_ever_prints_one(fake_keys, config, capsys):
    ready(fake_keys, token=TOKEN)
    assert run("setup", "--key", "openrouter") == 0
    assert TOKEN not in capsys.readouterr().out
    assert TOKEN not in json.dumps(config["cfg"])


def test_setup_missing_binary(fake_keys, config, monkeypatch, tmp_path):
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    assert run("setup", "--key", "openrouter") == 1
    assert config["saves"] == 0


def test_setup_reports_gateway_off_after_issue(fake_keys, config, capsys):
    issue_ok(fake_keys)
    fake_keys.token_ok(gateway_on=False)
    assert run("setup", "--key", "openrouter") == 1  # issued, but Hermes could not use it yet
    out = capsys.readouterr().out
    assert "check      FAILED" in out and "keys gateway on openrouter" in out
    assert config["cfg"]["secrets"]["keysrs"]["enabled"] is True


def test_setup_child_env_allowlisted(fake_keys, config, monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-should-not-leak")
    ready(fake_keys)
    run("setup", "--key", "openrouter")
    for call in fake_keys.calls():
        assert "should-not-leak" not in json.dumps(call["env"])


def test_setup_tolerates_non_string_config(fake_keys, config):
    config["cfg"]["secrets"] = {"keysrs": {"label": 2024, "provider_name": ["x"], "key_env": None}}
    ready(fake_keys)
    assert run("setup", "--key", "openrouter") == 0
    section = config["cfg"]["secrets"]["keysrs"]
    assert section["label"] == "hermes" and section["provider_name"] == "keysrs"


def test_setup_notes_old_label(fake_keys, config, capsys):
    config["cfg"]["secrets"] = {"keysrs": {"enabled": True, "label": "old"}}
    ready(fake_keys)
    assert run("setup", "--key", "openrouter", "--label", "hermes") == 0
    assert "label 'old' is still valid" in capsys.readouterr().out


def test_setup_keeps_symlink_path(fake_keys, config, tmp_path, monkeypatch):
    link_dir = tmp_path / "brew" / "bin"
    link_dir.mkdir(parents=True)
    (link_dir / "keys").symlink_to(fake_keys.path)
    monkeypatch.setenv("PATH", f"{link_dir}:/usr/bin:/bin")
    ready(fake_keys)
    assert run("setup", "--key", "openrouter") == 0
    assert config["cfg"]["secrets"]["keysrs"]["keys_path"] == str(link_dir / "keys")


def test_setup_prefers_path_over_stale_saved_path(fake_keys, config, tmp_path):
    config["cfg"]["secrets"] = {"keysrs": {"keys_path": str(tmp_path / "gone" / "keys")}}
    ready(fake_keys)
    assert run("setup", "--key", "openrouter") == 0
    assert config["cfg"]["secrets"]["keysrs"]["keys_path"] == str(fake_keys.path)


def test_setup_falls_back_to_saved_path(fake_keys, config, monkeypatch, tmp_path):
    config["cfg"]["secrets"] = {"keysrs": {"keys_path": str(fake_keys.path)}}
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    ready(fake_keys)
    assert run("setup", "--key", "openrouter") == 0


def test_setup_failure_shows_scrubbed_stderr(fake_keys, config, capsys):
    fake_keys.set("issue", exit=1, stderr=f"Touch ID cancelled near {TOKEN}\n")
    assert run("setup", "--key", "openrouter") == 1
    err = capsys.readouterr().err
    assert "Touch ID cancelled" in err and TOKEN not in err


def _configured(config, *, use=True):
    config["cfg"]["secrets"] = {"keysrs": {"enabled": True, "label": "hermes", "key": "openrouter"}}
    config["cfg"]["providers"] = {"keysrs": {"base_url": BASE_URL, "key_env": "KEYSRS_TOKEN"}}
    if use:
        config["cfg"]["model"]["provider"] = "custom:keysrs"
    _sync(config)


def _sync(config):
    (config["home"] / "config.yaml").write_text(yaml_dump(config["cfg"]))


def test_status_ok_hides_token(fake_keys, config, capsys):
    _configured(config)
    fake_keys.token_ok()
    assert run("status") == 0
    out = capsys.readouterr().out
    assert TOKEN not in out
    for needle in ("held (value hidden)", "gateway_on true", "2099-01-01T00:00:00Z", "custom:keysrs",
                   f"base_url   {BASE_URL}", "in use     yes", "KEYSRS_TOKEN"):
        assert needle in out, needle


def test_status_not_in_use(fake_keys, config, capsys):
    _configured(config, use=False)
    fake_keys.token_ok()
    assert run("status") == 0
    out = capsys.readouterr().out
    assert "in use     no (model.provider = openrouter)" in out
    assert "model.provider: custom:keysrs" in out


def test_status_url_mismatch(fake_keys, config, capsys):
    _configured(config)
    fake_keys.token_ok(base_url="http://127.0.0.1:12767/openai")
    assert run("status") == 1
    assert "rerun hermes keysrs setup" in capsys.readouterr().out


def test_status_missing_provider(fake_keys, config, capsys):
    _configured(config)
    del config["cfg"]["providers"]
    _sync(config)
    fake_keys.token_ok()
    assert run("status") == 1
    assert "providers.keysrs is missing" in capsys.readouterr().out


def test_status_failure(fake_keys, config, capsys):
    _configured(config)
    fake_keys.set("token", exit=2, stdout='{"error":"expired","label":"hermes"}')
    assert run("status") == 1
    out = capsys.readouterr().out
    assert "expired" in out and "hermes keysrs setup" in out


def test_status_gateway_off(fake_keys, config, capsys):
    _configured(config)
    fake_keys.token_ok(gateway_on=False)
    assert run("status") == 1
    assert "keys gateway on openrouter" in capsys.readouterr().out


def test_status_odd_methods_do_not_crash(fake_keys, config, capsys):
    _configured(config)
    fake_keys.token_ok(methods=[{"m": "POST"}, 3])
    assert run("status") == 0
    assert "methods" in capsys.readouterr().out


def test_disable(fake_keys, config, capsys):
    _configured(config)
    assert run("disable") == 0
    assert config["cfg"]["secrets"]["keysrs"]["enabled"] is False
    assert "still custom:keysrs" in capsys.readouterr().out


def test_disable_when_not_configured(fake_keys, config):
    assert run("disable") == 0
    assert config["saves"] == 0


def test_no_subcommand_prints_usage(config, capsys):
    assert run() == 0
    assert "usage" in capsys.readouterr().out
