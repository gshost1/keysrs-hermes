"""/keysrs slash command: status without a token, revoke as a kill switch."""

from __future__ import annotations

import datetime as dt
import json

import pytest

import keysrs_hermes
from conftest import TOKEN, provider_cfg, write_config
from keysrs_hermes import commands, tripwire


@pytest.fixture
def home(tmp_path, monkeypatch, fake_keys):
    cfg = provider_cfg()
    cfg["secrets"] = {"keysrs": {"enabled": True, "key": "openrouter", "label": "hermes"}}
    h = write_config(tmp_path / "hermes", cfg)
    monkeypatch.setattr(commands, "_hermes_home", lambda: h)
    monkeypatch.setattr(tripwire, "_hermes_home", lambda: h)
    tripwire._reset_for_tests()
    return h


def today():
    return dt.date.today().isoformat()


def spend_payload(calls=12, usd=0.42):
    return {"by": "key", "daily": [
        {"day": today(), "model": "openrouter", "model_calls": calls, "usd": None, "usd_estimate": usd},
        {"day": today(), "model": "eval", "model_calls": 999, "usd": 9.0},
        {"day": "2000-01-01", "model": "openrouter", "model_calls": 5, "usd": 1.0},
    ]}


def log_lines():
    rows = [
        {"ts": f"{today()}T10:00:00Z", "key": "openrouter", "kind": "denial", "reason": "out_of_scope", "status": 401},
        {"ts": f"{today()}T10:01:00Z", "key": "openrouter", "kind": "denial", "reason": "out_of_scope", "status": 401},
        {"ts": f"{today()}T10:02:00Z", "key": "openrouter", "kind": "call", "reason": "upstream_status", "status": 500},
        {"ts": "2000-01-01T00:00:00Z", "key": "openrouter", "kind": "denial", "reason": "revoked", "status": 401},
    ]
    return "".join(json.dumps(r) + "\n" for r in rows)


def test_status(home, fake_keys):
    fake_keys.token_ok(expires_at=(dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=3, hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ"))
    fake_keys.set("spend", stdout=json.dumps(spend_payload()))
    fake_keys.set("log", stdout=log_lines())
    out = commands.handle("")
    assert "key openrouter" in out
    assert "expires in 3d" in out
    assert "POST chat/completions" in out
    assert "gateway: key loaded" in out
    assert "today: 12 calls, $0.42" in out
    assert "refusals: 2 today (2× out_of_scope)" in out
    assert "tripwire: on" in out
    assert TOKEN not in out


def test_status_warns_near_expiry(home, fake_keys):
    soon = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
    fake_keys.token_ok(expires_at=soon)
    out = commands.handle("status")
    assert "expires in 4h" in out or "expires in 5h" in out
    assert "renew soon" in out


def test_status_gateway_off(home, fake_keys):
    fake_keys.token_ok(gateway_on=False)
    out = commands.handle("")
    assert "keys gateway on openrouter" in out


def test_status_token_missing(home, fake_keys):
    fake_keys.set("token", exit=2, stdout=json.dumps({"error": "revoked", "label": "hermes"}) + "\n")
    out = commands.handle("")
    assert "unavailable" in out and "hermes keysrs setup --key openrouter" in out


def test_status_not_set_up(tmp_path, monkeypatch, fake_keys):
    h = write_config(tmp_path / "h", provider_cfg())
    monkeypatch.setattr(commands, "_hermes_home", lambda: h)
    assert "not set up" in commands.handle("")
    assert "nothing to revoke" in commands.handle("revoke")


def test_revoke(home, fake_keys):
    fake_keys.token_ok()
    fake_keys.set("revoke", stdout="revoked #7\n")
    out = commands.handle("revoke")
    assert "Revoked Keysrs client #7 for openrouter" in out
    revoke_calls = [c["argv"] for c in fake_keys.calls() if c["argv"][:2] == ["client", "revoke"]]
    assert revoke_calls == [["client", "revoke", "openrouter", "7"]]
    assert TOKEN not in out


def test_revoke_failure_is_reported(home, fake_keys):
    fake_keys.token_ok()
    fake_keys.set("revoke", exit=1, stderr="no such client\n")
    assert "Revoke failed" in commands.handle("REVOKE")


def test_revoke_with_no_live_token(home, fake_keys):
    fake_keys.set("token", exit=2, stdout=json.dumps({"error": "expired", "label": "hermes"}) + "\n")
    assert "already cut off" in commands.handle("revoke")
    assert not [c for c in fake_keys.calls() if c["argv"][:2] == ["client", "revoke"]]


def test_help_and_unknown(home):
    assert "/keysrs revoke" in commands.handle("help")
    assert "Unknown" in commands.handle("rm -rf")


def test_never_raises(home, monkeypatch):
    monkeypatch.setattr(commands, "status_text", lambda: 1 / 0)
    assert "failed" in commands.handle("")


def test_registered():
    got = {}

    class Ctx:
        def register_secret_source(self, s): pass
        def register_cli_command(self, **k): pass
        def register_command(self, name, handler, description="", args_hint=""):
            got[name] = (handler, args_hint)

    keysrs_hermes.register(Ctx())
    assert got["keysrs"][0] is commands.handle


def test_name_does_not_clash_with_builtin():
    from hermes_cli.commands import resolve_command

    assert resolve_command("keysrs") is None
