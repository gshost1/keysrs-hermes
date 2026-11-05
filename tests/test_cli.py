"""`hermes keysrs setup|status|disable`, with config I/O kept in memory."""

from __future__ import annotations

import argparse
import json

import pytest

from conftest import TOKEN, token_payload
import keysrs_hermes.cli as cli

ISSUED = {
    "base_url": "http://127.0.0.1:12767/openrouter",
    "client_id": 7,
    "expires_at": "2099-01-01T00:00:00Z",
    "held": True,
    "key": "openrouter",
    "label": "hermes",
    "methods": ["POST"],
    "path_prefix": "chat/completions",
}


@pytest.fixture
def config(monkeypatch):
    store = {"cfg": {"model": {"provider": "openrouter"}}, "saves": 0}

    def load():
        return json.loads(json.dumps(store["cfg"]))

    def save(cfg):
        store["cfg"] = json.loads(json.dumps(cfg))
        store["saves"] += 1

    monkeypatch.setattr(cli, "_load_config", load)
    monkeypatch.setattr(cli, "_save_config", save)
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


def test_setup_issues_and_writes_only_non_secret_config(fake_keys, config, capsys):
    issue_ok(fake_keys)
    fake_keys.token_ok()
    assert run("setup", "--key", "openrouter") == 0
    issue_call = fake_keys.calls()[0]
    assert issue_call["argv"] == [
        "client", "issue", "openrouter", "--label", "hermes", "--days", "7",
        "--method", "POST", "--path-prefix", "chat/completions", "--hold", "--json",
    ]
    section = config["cfg"]["secrets"]["keysrs"]
    assert section == {
        "enabled": True,
        "label": "hermes",
        "key": "openrouter",
        "provider": "openrouter",
        "keys_path": str(fake_keys.path.resolve()),
    }
    assert config["cfg"]["model"] == {"provider": "openrouter"}  # untouched
    out = capsys.readouterr().out
    assert "check      ok" in out
    assert TOKEN not in out and TOKEN not in json.dumps(config["cfg"])


def test_setup_openai_defaults_to_responses_prefix(fake_keys, config):
    issue_ok(fake_keys)
    fake_keys.token_ok()
    assert run("setup", "--key", "openai", "--provider", "openai", "--days", "3", "--label", "work") == 0
    argv = fake_keys.calls()[0]["argv"]
    assert argv[argv.index("--path-prefix") + 1] == "responses"
    assert argv[argv.index("--days") + 1] == "3"
    assert config["cfg"]["secrets"]["keysrs"]["provider"] == "openai"
    assert config["cfg"]["secrets"]["keysrs"]["label"] == "work"


def test_setup_custom_scope(fake_keys, config):
    issue_ok(fake_keys)
    fake_keys.token_ok()
    assert run("setup", "--key", "k", "--method", "post", "--method", "GET", "--any-path") == 0
    argv = fake_keys.calls()[0]["argv"]
    assert "--path-prefix" not in argv
    assert argv.count("--method") == 2 and "GET" in argv and "POST" in argv


def test_setup_custom_env_names(fake_keys, config):
    issue_ok(fake_keys)
    fake_keys.token_ok()
    assert run("setup", "--key", "k", "--provider", "custom",
               "--base-url-env", "MY_URL", "--api-key-env", "MY_KEY") == 0
    assert config["cfg"]["secrets"]["keysrs"]["env"] == {"base_url": "MY_URL", "api_key": "MY_KEY"}


def test_setup_custom_without_env_names_refused(fake_keys, config):
    assert run("setup", "--key", "k", "--provider", "custom") == 64
    assert fake_keys.calls() == [] and config["saves"] == 0


@pytest.mark.parametrize("argv", [
    ("setup", "--key", "--bad"),
    ("setup", "--key", "a b"),
    ("setup", "--key", "k", "--label", "-x"),
    ("setup", "--key", "k", "--days", "0"),
    ("setup", "--key", "k", "--method", "PO ST"),
    ("setup", "--key", "k", "--path-prefix", "-rf"),
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
    issue_ok(fake_keys, token=TOKEN)
    fake_keys.token_ok()
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
    assert run("setup", "--key", "openrouter") == 0
    assert "keys gateway on openrouter" in capsys.readouterr().out


def test_setup_child_env_allowlisted(fake_keys, config, monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-should-not-leak")
    issue_ok(fake_keys)
    fake_keys.token_ok()
    run("setup", "--key", "openrouter")
    for call in fake_keys.calls():
        assert "should-not-leak" not in json.dumps(call["env"])


def test_status_ok_hides_token(fake_keys, config, capsys):
    config["cfg"]["secrets"] = {"keysrs": {"enabled": True, "label": "hermes", "key": "openrouter"}}
    fake_keys.token_ok()
    assert run("status") == 0
    out = capsys.readouterr().out
    assert TOKEN not in out
    assert "held (value hidden)" in out
    assert "gateway_on true" in out
    assert "2099-01-01T00:00:00Z" in out
    assert "OPENROUTER_BASE_URL, OPENROUTER_API_KEY" in out


def test_status_failure(fake_keys, config, capsys):
    fake_keys.set("token", exit=2, stdout='{"error":"expired","label":"hermes"}')
    assert run("status") == 1
    out = capsys.readouterr().out
    assert "expired" in out and "hermes keysrs setup" in out


def test_status_gateway_off(fake_keys, config, capsys):
    fake_keys.token_ok(gateway_on=False)
    assert run("status") == 1
    assert "keys gateway on openrouter" in capsys.readouterr().out


def test_disable(fake_keys, config):
    config["cfg"]["secrets"] = {"keysrs": {"enabled": True, "label": "hermes"}}
    assert run("disable") == 0
    assert config["cfg"]["secrets"]["keysrs"]["enabled"] is False


def test_disable_when_not_configured(fake_keys, config):
    assert run("disable") == 0
    assert config["saves"] == 0


def test_no_subcommand_prints_usage(config, capsys):
    assert run() == 0
    assert "usage" in capsys.readouterr().out
