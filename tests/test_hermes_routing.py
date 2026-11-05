"""End-to-end routing proof against Hermes's own resolvers, offline.

Under a temp HERMES_HOME with the config `hermes keysrs setup --use` writes,
the plugin's env is applied by Hermes's orchestrator, then every resolver
that picks an endpoint for a request is asked where it would send it:
main chat (runtime_provider), side tasks (auxiliary_client: titles,
compression, web extract, session search...), vision, and the credential
pool. The token must only ever sit next to the loopback gateway URL.

Sockets are blocked for the whole module: resolving builds clients, it must
never connect anywhere.
"""

from __future__ import annotations

import os
import re
import socket
from urllib.parse import urlsplit

import pytest

from agent.secret_sources.registry import _reset_registry_for_tests, apply_all, register_source

from conftest import BASE_URL, TOKEN, yaml_dump
from keysrs_hermes.keysrs_source import KeysrsSource, is_loopback_http_url

VENDOR_DECOYS = {
    "OPENROUTER_API_KEY": "sk-or-v1-decoy-real-openrouter-key",
    "OPENAI_API_KEY": "sk-decoy-real-openai-key",
    "ANTHROPIC_API_KEY": "sk-ant-decoy-real-anthropic-key",
}
TEXT_TASKS = ["", "compression", "title_generation", "web_extract", "session_search",
              "flush_memories", "approval", "mcp", "skills_hub"]
_CREDENTIAL_VAR = re.compile(r"(_API_KEY|_TOKEN|_KEY|_BASE_URL|_SECRET)$")


@pytest.fixture
def no_network(monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError(f"network access attempted: {args!r}")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket.socket, "connect_ex", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)


@pytest.fixture
def routed(fake_keys, tmp_path, monkeypatch, no_network):
    """Temp Hermes profile configured by setup --use, with the plugin's env applied."""
    # Start from a clean credential environment (whatever this machine has
    # must not influence or leak into the test), then plant vendor decoys:
    # the plugin must leave them alone and Hermes must never pair the token
    # with a vendor host.
    for var in list(os.environ):
        if _CREDENTIAL_VAR.search(var) or var.startswith(("HERMES_", "KEYSRS_")):
            monkeypatch.delenv(var, raising=False)
    for var, value in VENDOR_DECOYS.items():
        monkeypatch.setenv(var, value)

    home = tmp_path / "hermes"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    cfg = {
        "model": {"provider": "custom:keysrs", "default": "openai/gpt-4o-mini"},
        "providers": {"keysrs": {"base_url": BASE_URL, "key_env": "KEYSRS_TOKEN",
                                 "api_mode": "chat_completions", "default_model": "openai/gpt-4o-mini"}},
        "secrets": {"keysrs": {"enabled": True, "label": "hermes", "key": "openrouter",
                               "provider_name": "keysrs", "keys_path": str(fake_keys.path)}},
    }
    (home / "config.yaml").write_text(yaml_dump(cfg))
    fake_keys.token_ok()

    _reset_registry_for_tests()
    monkeypatch.setattr("agent.secret_sources.registry._ensure_builtin_sources", lambda: None)
    try:
        assert register_source(KeysrsSource())
        env = dict(os.environ)
        report = apply_all(cfg["secrets"], home, environ=env)
        (sr,) = report.sources
        assert sr.result.ok, sr.result.error
        assert sr.applied == ["KEYSRS_TOKEN"]
        for var in sr.applied:
            monkeypatch.setenv(var, env[var])
        yield home
    finally:
        _reset_registry_for_tests()


def _endpoint(client):
    """(base_url, api_key) from an OpenAI-style client or Hermes's wrappers."""
    seen = set()
    stack = [client]
    while stack:
        obj = stack.pop()
        if obj is None or id(obj) in seen:
            continue
        seen.add(id(obj))
        base = getattr(obj, "base_url", None)
        key = getattr(obj, "api_key", None)
        if base is not None and key is not None:
            return str(base), key if isinstance(key, str) else repr(key)
        for attr in ("_client", "client", "_real_client", "_inner", "_openai", "_sync_client"):
            stack.append(getattr(obj, attr, None))
    return None, None


def _assert_token_only_on_loopback(where, base_url, api_key):
    if api_key == TOKEN or (isinstance(api_key, str) and TOKEN in api_key):
        assert base_url and is_loopback_http_url(base_url), f"{where}: token paired with {base_url}"
    if base_url and is_loopback_http_url(base_url) and urlsplit(base_url).port == 12767:
        assert api_key == TOKEN, f"{where}: gateway got {'a vendor key' if api_key in VENDOR_DECOYS.values() else 'no token'}"


def test_only_keysrs_var_holds_the_token(routed):
    holders = [k for k, v in os.environ.items() if TOKEN in v]
    assert holders == ["KEYSRS_TOKEN"]
    for var, value in VENDOR_DECOYS.items():
        assert os.environ[var] == value


def test_named_custom_provider_entry(routed):
    from hermes_cli.runtime_provider import _get_named_custom_provider

    entry = _get_named_custom_provider("custom:keysrs")
    assert entry is not None
    assert entry["base_url"].rstrip("/") == BASE_URL
    assert entry["api_key"] == TOKEN
    assert entry.get("api_mode", "chat_completions") == "chat_completions"


@pytest.mark.parametrize("requested", [None, "custom:keysrs"])
def test_main_runtime_goes_to_gateway(routed, requested):
    from hermes_cli.runtime_provider import resolve_runtime_provider

    rt = resolve_runtime_provider(requested=requested)
    assert rt["base_url"].rstrip("/") == BASE_URL
    assert rt["api_key"] == TOKEN
    assert rt["api_mode"] == "chat_completions"
    assert is_loopback_http_url(rt["base_url"])


@pytest.mark.parametrize("task", TEXT_TASKS)
def test_side_tasks_go_to_gateway(routed, task):
    from agent.auxiliary_client import get_text_auxiliary_client
    from hermes_cli.runtime_provider import resolve_runtime_provider

    rt = resolve_runtime_provider()
    main_runtime = {**rt, "model": "openai/gpt-4o-mini"}
    for runtime in (main_runtime, None):
        client, _model = get_text_auxiliary_client(task, main_runtime=runtime)
        assert client is not None, f"no client for task {task!r}"
        base_url, api_key = _endpoint(client)
        assert base_url is not None, f"could not read endpoint of {type(client).__name__}"
        _assert_token_only_on_loopback(f"task {task!r}", base_url, api_key)
        assert is_loopback_http_url(base_url), f"task {task!r} resolved to {base_url}"


def test_vision_never_pairs_token_with_vendor(routed):
    from agent.auxiliary_client import resolve_vision_provider_client
    from hermes_cli.runtime_provider import resolve_runtime_provider

    rt = {**resolve_runtime_provider(), "model": "openai/gpt-4o-mini"}
    _provider, client, _model = resolve_vision_provider_client(main_runtime=rt)
    if client is not None:  # auto vision may decline a non-vision custom endpoint
        _assert_token_only_on_loopback("vision", *_endpoint(client))


@pytest.mark.parametrize("provider", ["auto", "custom:keysrs", "openrouter", "custom"])
def test_router_never_pairs_token_with_vendor(routed, provider):
    """Even when a side path asks for a vendor provider by name, it gets the
    decoy vendor key -- never the Keysrs token."""
    from agent.auxiliary_client import resolve_provider_client
    from hermes_cli.runtime_provider import resolve_runtime_provider

    rt = {**resolve_runtime_provider(), "model": "openai/gpt-4o-mini"}
    client, _model = resolve_provider_client(provider, model="openai/gpt-4o-mini", main_runtime=rt)
    if client is not None:
        _assert_token_only_on_loopback(f"provider {provider!r}", *_endpoint(client))


def test_credential_pools_pair_token_with_loopback_only(routed):
    from agent.credential_pool import load_pool

    for name in ("custom:keysrs", "openrouter", "openai-api", "anthropic"):
        try:
            pool = load_pool(name)
        except Exception:  # noqa: BLE001 - a provider with no pool support is fine
            continue
        for entry in pool.entries():
            key = getattr(entry, "access_token", None) or getattr(entry, "api_key", None) or ""
            base = getattr(entry, "base_url", None) or ""
            if TOKEN in str(key):
                assert is_loopback_http_url(base), f"pool {name}: token paired with {base}"
