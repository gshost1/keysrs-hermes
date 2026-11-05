"""The client token must never show up in errors, warnings, reprs, logs
or CLI output -- including when `keys` itself misbehaves and echoes it."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import logging
from pathlib import Path

import pytest

from agent.secret_sources.registry import _reset_registry_for_tests, apply_all, register_source

from conftest import BASE_URL, TOKEN, provider_cfg, token_payload, yaml_dump
import keysrs_hermes.cli as cli
from keysrs_hermes.keysrs_source import KeysrsSource, lookup_token

SOON = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")

SCENARIOS = {
    "ok": dict(stdout=json.dumps(token_payload())),
    "ok_expiring": dict(stdout=json.dumps(token_payload(expires_at=SOON))),
    "gateway_off": dict(stdout=json.dumps(token_payload(gateway_on=False))),
    "expired_ts": dict(stdout=json.dumps(token_payload(expires_at="2000-01-01T00:00:00Z"))),
    "evil_base_url": dict(stdout=json.dumps(token_payload(base_url=f"https://evil.example/{TOKEN}"))),
    "bad_token_with_space": dict(stdout=json.dumps(token_payload(token=TOKEN + " x"))),
    "exit2_echoes_token": dict(exit=2, stdout=json.dumps({"error": "expired", "token": TOKEN})),
    "exit1_stderr_token": dict(exit=1, stderr=f"panic: token={TOKEN}\n", stdout=TOKEN),
    "exit64_stderr_token": dict(exit=64, stderr=f"bad flag near {TOKEN}\n"),
    "exit6": dict(exit=6, stderr=TOKEN),
    "garbage_with_token": dict(stdout=f"not json {TOKEN}"),
}


def _strings(result, src, cfg):
    yield str(result.error)
    yield from result.warnings
    yield repr(result)
    yield str(result)
    yield src.remediation(result.error_kind, cfg)


@pytest.mark.parametrize("name", sorted(SCENARIOS))
def test_fetch_never_exposes_token(fake_keys, hermes_home, caplog, name):
    caplog.set_level(logging.DEBUG)
    fake_keys.set("token", **SCENARIOS[name])
    src = KeysrsSource()
    cfg = {"enabled": True, "key": "openrouter"}
    result = src.fetch(cfg, hermes_home)
    for text in _strings(result, src, cfg):
        assert TOKEN not in text, f"{name}: {text}"
    assert TOKEN not in caplog.text
    if result.ok:
        assert TOKEN in result.secrets.values()  # delivered, never shown
    else:
        assert not result.secrets
    lookup = lookup_token(cfg)
    assert TOKEN not in repr(lookup)
    assert TOKEN not in json.dumps(lookup.meta)


@pytest.mark.parametrize("name", sorted(SCENARIOS))
def test_status_never_prints_token(fake_keys, monkeypatch, capsys, caplog, name):
    caplog.set_level(logging.DEBUG)
    monkeypatch.setattr(
        cli, "_load_config",
        lambda: {"secrets": {"keysrs": {"enabled": True, "key": "openrouter"}}, **provider_cfg()},
    )
    fake_keys.set("token", **SCENARIOS[name])
    parser = argparse.ArgumentParser()
    cli.setup_parser(parser)
    args = parser.parse_args(["status"])
    args.func(args)
    captured = capsys.readouterr()
    assert TOKEN not in captured.out and TOKEN not in captured.err
    assert TOKEN not in caplog.text


def test_setup_never_prints_or_stores_token(fake_keys, tmp_path, monkeypatch, capsys, caplog):
    caplog.set_level(logging.DEBUG)
    saved = {}
    home = tmp_path / "h"
    home.mkdir()

    def save(cfg):
        saved.update(cfg)
        (home / "config.yaml").write_text(yaml_dump(cfg))

    monkeypatch.setattr(cli, "_load_config", lambda: {})
    monkeypatch.setattr(cli, "_save_config", save)
    monkeypatch.setattr(cli, "_hermes_home", lambda: home)
    fake_keys.set(
        "issue",
        stdout=json.dumps({"held": True, "key": "openrouter", "label": "hermes", "base_url": BASE_URL,
                           "expires_at": "2099-01-01T00:00:00Z", "token": TOKEN}),
    )
    fake_keys.token_ok()
    parser = argparse.ArgumentParser()
    cli.setup_parser(parser)
    args = parser.parse_args(["setup", "--key", "openrouter"])
    assert args.func(args) == 0
    captured = capsys.readouterr()
    assert TOKEN not in captured.out + captured.err + caplog.text
    assert TOKEN not in json.dumps(saved)
    assert TOKEN not in (home / "config.yaml").read_text()


@pytest.mark.parametrize("name", sorted(SCENARIOS))
def test_orchestrator_report_never_shows_token(fake_keys, hermes_home, monkeypatch, caplog, name):
    """A full Hermes apply_all() pass: the token lands in the env mapping only."""
    caplog.set_level(logging.DEBUG)
    fake_keys.set("token", **SCENARIOS[name])
    _reset_registry_for_tests()
    monkeypatch.setattr("agent.secret_sources.registry._ensure_builtin_sources", lambda: None)
    try:
        assert register_source(KeysrsSource())
        env = {"OPENROUTER_API_KEY": "sk-or-real-in-dotfile", "KEYSRS_TOKEN": "ksfc_stale"}
        report = apply_all({"keysrs": {"enabled": True}}, hermes_home, environ=env)
        (sr,) = report.sources
        assert TOKEN not in repr(sr.result)
        assert TOKEN not in str(report.conflicts) + str(sr.result.error) + str(sr.result.warnings)
        assert TOKEN not in caplog.text
        # The vendor key is never touched; only KEYSRS_TOKEN changes.
        assert env["OPENROUTER_API_KEY"] == "sk-or-real-in-dotfile"
        assert set(env) == {"OPENROUTER_API_KEY", "KEYSRS_TOKEN"}
        if sr.result.ok:
            assert env["KEYSRS_TOKEN"] == TOKEN  # override_existing default replaces a stale token
        else:
            assert env["KEYSRS_TOKEN"] == "ksfc_stale"
    finally:
        _reset_registry_for_tests()
