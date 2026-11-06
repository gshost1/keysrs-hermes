"""The error-classification hook: Keysrs gateway refusals become permanent
auth failures with the right fix, and nothing else is touched."""

from __future__ import annotations

import json

import pytest

import keysrs_hermes
from conftest import TOKEN, provider_cfg, write_config
from keysrs_hermes import hooks

GATEWAY_OFF_BODY = {
    "error": "not_found",
    "message": 'no key openrouter with the gateway on; run: keys grant openrouter --task "..."',
}
CLIENT_REFUSED_BODY = {
    "error": "client_required",
    "hint": 'issue one with: keys grant openrouter --task "..." (temporary) or keys client issue openrouter (long-lived)',
}


@pytest.fixture
def enabled_home(tmp_path, monkeypatch, fake_keys):
    cfg = provider_cfg()
    cfg["secrets"] = {"keysrs": {"enabled": True, "key": "openrouter", "label": "hermes"}}
    home = write_config(tmp_path / "hermes", cfg)
    monkeypatch.setattr(hooks, "_hermes_home", lambda: home)
    hooks._reset_for_tests()
    yield home
    hooks._reset_for_tests()


def classify(**kw):
    kw.setdefault("provider", "custom:keysrs")
    return hooks.classify_api_error(**kw)


def test_gateway_off_after_restart(enabled_home, fake_keys):
    fake_keys.token_ok(gateway_on=False)
    out = classify(status_code=404, error_message="Error code: 404", error_body=GATEWAY_OFF_BODY)
    assert out["reason"] == "auth_permanent"
    assert out["retryable"] is False and out["should_rotate_credential"] is False
    assert "keys gateway on openrouter" in out["message"]
    assert TOKEN not in json.dumps(out)


@pytest.mark.parametrize("reason", ["revoked", "expired", "not_found"])
def test_token_refused_names_setup(enabled_home, fake_keys, reason):
    fake_keys.set("token", exit=2, stdout=json.dumps({"error": reason, "label": "hermes"}) + "\n")
    out = classify(status_code=401, error_message="", error_body=CLIENT_REFUSED_BODY)
    assert out["reason"] == "auth_permanent"
    assert "hermes keysrs setup --key openrouter" in out["message"]


def test_token_fine_means_out_of_scope(enabled_home, fake_keys):
    fake_keys.token_ok()
    out = classify(status_code=401, error_body=CLIENT_REFUSED_BODY)
    assert "scope" in out["message"] and "POST chat/completions" in out["message"]
    assert TOKEN not in out["message"]


def test_plain_custom_provider_name_also_matches(enabled_home, fake_keys):
    fake_keys.token_ok(gateway_on=False)
    assert classify(provider="custom", status_code=404, error_body=GATEWAY_OFF_BODY) is not None


@pytest.mark.parametrize(
    "kw",
    [
        {"provider": "openrouter", "status_code": 404, "error_body": GATEWAY_OFF_BODY},
        {"provider": "custom:other", "status_code": 404, "error_body": GATEWAY_OFF_BODY},
        {"status_code": 404, "error_body": {"error": {"message": "model not found"}}},
        {"status_code": 401, "error_body": {"error": {"message": "invalid api key"}}},
        {"status_code": 500, "error_body": GATEWAY_OFF_BODY},
        {"provider": "custom", "status_code": 401, "error_body": {"error": "client_required"}},
        {"provider": "custom", "status_code": 404, "error_body": {"message": "nothing with the gateway on"}},
    ],
)
def test_declines_everything_else(enabled_home, fake_keys, kw):
    fake_keys.token_ok()
    assert classify(**kw) is None
    assert fake_keys.calls() == []


def test_declines_when_plugin_disabled(tmp_path, monkeypatch, fake_keys):
    home = write_config(tmp_path / "h", provider_cfg())
    monkeypatch.setattr(hooks, "_hermes_home", lambda: home)
    assert classify(status_code=404, error_body=GATEWAY_OFF_BODY) is None


def test_one_keys_call_per_burst(enabled_home, fake_keys):
    fake_keys.token_ok(gateway_on=False)
    for _ in range(5):
        classify(status_code=404, error_body=GATEWAY_OFF_BODY)
    assert len(fake_keys.calls()) == 1


def test_hook_never_raises(enabled_home, monkeypatch):
    monkeypatch.setattr(hooks, "read_hermes_config", lambda _h: 1 / 0)
    assert classify(status_code=404, error_body=GATEWAY_OFF_BODY) is None


def test_registered_with_hermes():
    calls = []

    class Ctx:
        def register_secret_source(self, s): pass
        def register_cli_command(self, **k): pass
        def register_hook(self, name, cb): calls.append((name, cb))

    keysrs_hermes.register(Ctx())
    assert ("transform_api_error_classification", hooks.classify_api_error) in calls


def _status_error(status: int, body: dict):
    httpx = pytest.importorskip("httpx")
    openai = pytest.importorskip("openai")

    request = httpx.Request("POST", "http://127.0.0.1:12767/openrouter/chat/completions")
    response = httpx.Response(status, json=body, request=request)
    cls = openai.NotFoundError if status == 404 else openai.AuthenticationError
    return cls(f"Error code: {status} - {body}", response=response, body=body)


def test_hermes_classifier_uses_the_hook(enabled_home, fake_keys, monkeypatch):
    """Through Hermes's real classify_api_error: no model switch, no retry."""
    from agent import error_classifier
    from hermes_cli import plugins

    def invoke_hook(name, **kwargs):
        if name != "transform_api_error_classification":
            return []
        out = hooks.classify_api_error(**kwargs)
        return [out] if out is not None else []

    monkeypatch.setattr(plugins, "invoke_hook", invoke_hook)
    fake_keys.token_ok(gateway_on=False)

    before = error_classifier.classify_api_error(
        _status_error(404, GATEWAY_OFF_BODY), provider="openrouter", model="m"
    )
    assert before.reason != error_classifier.FailoverReason.auth_permanent

    got = error_classifier.classify_api_error(
        _status_error(404, GATEWAY_OFF_BODY), provider="custom:keysrs", model="m"
    )
    assert got.reason == error_classifier.FailoverReason.auth_permanent
    assert got.retryable is False
    assert "keys gateway on openrouter" in got.message


def test_transient_lookup_failure_not_cached(enabled_home, fake_keys):
    fake_keys.set("token", exit=6)
    first = classify(status_code=404, error_body=GATEWAY_OFF_BODY)
    assert "Open the Keysrs app" in first["message"]
    fake_keys.token_ok(gateway_on=False)
    second = classify(status_code=404, error_body=GATEWAY_OFF_BODY)
    assert "keys gateway on openrouter" in second["message"]
    assert len(fake_keys.calls()) == 2
