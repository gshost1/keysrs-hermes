"""keysrs_keys / keysrs_request: the agent calls other APIs through the
gateway; grants are asked once per scope and never reach the model."""

from __future__ import annotations

import http.server
import json
import threading

import pytest

import keysrs_hermes
from conftest import provider_cfg, write_config
from keysrs_hermes import access, tripwire

GRANT = "ksf_" + "0a1b2c3d" + "_" + "GRANTSECRETvalue123"


class Gateway(http.server.BaseHTTPRequestHandler):
    calls: list = []
    refuse = False
    redirect = False

    def _handle(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode() if length else ""
        Gateway.calls.append({"method": self.command, "path": self.path, "headers": dict(self.headers), "body": body})
        if Gateway.redirect:
            self.send_response(302)
            self.send_header("Location", "https://evil.example/steal")
            self.end_headers()
            return
        if Gateway.refuse:
            self.send_response(403)
            self.send_header("X-Keysrs-Source", "gateway")
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"error":"grant_expired"}')
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("X-Keysrs-Source", "upstream")
        self.end_headers()
        self.wfile.write(json.dumps({"login": "octocat", "echo": GRANT}).encode())

    do_GET = do_POST = do_DELETE = do_PUT = do_PATCH = _handle

    def log_message(self, *a):
        pass


@pytest.fixture
def gateway():
    Gateway.calls, Gateway.refuse, Gateway.redirect = [], False, False
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Gateway)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}/github"
    server.shutdown()


@pytest.fixture
def home(tmp_path, monkeypatch, fake_keys):
    cfg = provider_cfg()
    cfg["secrets"] = {"keysrs": {"enabled": True, "key": "openrouter", "label": "hermes"}}
    h = write_config(tmp_path / "hermes", cfg)
    monkeypatch.setattr(access, "_hermes_home", lambda: h)
    monkeypatch.setattr(tripwire, "_hermes_home", lambda: h)
    access._reset_for_tests()
    tripwire._reset_for_tests()
    yield h
    access._reset_for_tests()


VAULT = [
    {"name": "github", "provider": "github", "host": "api.github.com", "kind": "runtime"},
    {"name": "stripe-live", "provider": "stripe", "host": "api.stripe.com", "kind": "billing"},
]


def grant_ok(fake_keys, base_url, **extra):
    fake_keys.set("list", stdout=json.dumps(VAULT))
    obj = {"id": "0a1b2c3d", "token": GRANT, "base_url": base_url, "auth_header": "Authorization",
           "expires_at": "2099-01-01T00:00:00Z", "methods": ["GET"], "paths": ["/user"]}
    obj.update(extra)
    fake_keys.set("grant", stdout=json.dumps(obj) + "\n")


def req(**kw):
    kw.setdefault("key", "github")
    kw.setdefault("method", "GET")
    kw.setdefault("path", "/user")
    kw.setdefault("task", "check my GitHub login")
    return json.loads(access.keysrs_request(kw))


def grant_calls(fake_keys):
    return [c["argv"] for c in fake_keys.calls() if c["argv"][:1] == ["grant"]]


def test_request_asks_once_then_reuses(home, fake_keys, gateway):
    grant_ok(fake_keys, gateway)
    first = req()
    assert first["ok"] and first["status"] == 200
    assert "octocat" in first["body"]
    assert "approved" in first["note"]
    second = req(path="/user")
    assert second["ok"] and "note" not in second
    (argv,) = grant_calls(fake_keys)
    assert argv[:2] == ["grant", "github"]
    assert argv[argv.index("--task") + 1] == "Hermes GET /user: check my GitHub login"
    assert argv[argv.index("--methods") + 1] == "GET"
    assert argv[argv.index("--paths") + 1] == "/user"
    assert argv[-1] == "--json"
    assert all(c["headers"].get("Authorization") == f"Bearer {GRANT}" for c in Gateway.calls)


def test_grant_token_never_reaches_the_model(home, fake_keys, gateway):
    grant_ok(fake_keys, gateway)
    out = access.keysrs_request({"key": "github", "method": "GET", "path": "/user", "task": "t"})
    assert GRANT not in out
    assert "[Keysrs token hidden]" in out


def test_new_method_or_path_asks_again(home, fake_keys, gateway):
    grant_ok(fake_keys, gateway)
    req()
    req(method="POST", path="/user/repos", body={"name": "x"})
    assert len(grant_calls(fake_keys)) == 2
    assert json.loads(Gateway.calls[-1]["body"]) == {"name": "x"}


def test_wide_scope_covers_subpaths(home, fake_keys, gateway):
    grant_ok(fake_keys, gateway)
    req(path="/repos/a/b/issues", scope="/repos")
    req(path="/repos/c/d/pulls?state=open", scope="/repos")
    assert len(grant_calls(fake_keys)) == 1
    assert Gateway.calls[-1]["path"] == "/github/repos/c/d/pulls?state=open"


def test_gateway_refusal_drops_grant(home, fake_keys, gateway):
    grant_ok(fake_keys, gateway)
    req()
    Gateway.refuse = True
    out = req()
    assert out["status"] == 403 and "refused_by" in out
    Gateway.refuse = False
    req()
    assert len(grant_calls(fake_keys)) == 2


def test_agent_cannot_set_auth_headers(home, fake_keys, gateway):
    grant_ok(fake_keys, gateway)
    req(headers={"Authorization": "Bearer stolen", "X-Api-Key": "x", "Accept": "application/vnd.github+json", "Bad\nName": "v"})
    sent = Gateway.calls[-1]["headers"]
    assert sent["Authorization"] == f"Bearer {GRANT}"
    assert "X-Api-Key" not in sent
    assert sent["Accept"] == "application/vnd.github+json"


def test_redirect_not_followed(home, fake_keys, gateway):
    grant_ok(fake_keys, gateway)
    Gateway.redirect = True
    out = req()
    assert out["status"] == 302
    assert len(Gateway.calls) == 1


@pytest.mark.parametrize(
    "kw,msg",
    [
        ({"key": "-rf"}, "vault key name"),
        ({"key": "openrouter"}, "own model key"),
        ({"method": "TRACE"}, "method"),
        ({"path": "https://evil.example/x"}, "path"),
        ({"path": "//evil.example/x"}, "path"),
        ({"path": "/a/../../b"}, "path"),
        ({"task": "  "}, "task"),
        ({"path": "/user", "scope": "/repos"}, "not under"),
    ],
)
def test_rejects_bad_args(home, fake_keys, kw, msg):
    out = req(**kw)
    assert not out["ok"] and msg in out["error"]
    assert grant_calls(fake_keys) == []


def test_allowlist(home, fake_keys, gateway):
    cfg = provider_cfg()
    cfg["secrets"] = {"keysrs": {"enabled": True, "key": "openrouter", "agent_keys": ["stripe"]}}
    write_config(home, cfg)
    out = req()
    assert "not allowed" in out["error"]


def test_access_off(home, fake_keys):
    cfg = provider_cfg()
    cfg["secrets"] = {"keysrs": {"enabled": True, "agent_access": False}}
    write_config(home, cfg)
    assert "turned off" in req()["error"]
    assert access.available() is False


def test_declined_grant(home, fake_keys):
    fake_keys.set("list", stdout=json.dumps(VAULT))
    fake_keys.set("grant", exit=1, stderr="presence check cancelled\n")
    out = req()
    assert not out["ok"] and "declined" in out["error"]


def test_non_loopback_grant_url_refused(home, fake_keys):
    grant_ok(fake_keys, "https://api.github.com")
    out = req()
    assert "not on this Mac" in out["error"]


def test_keys_list(home, fake_keys):
    rows = [
        {"name": "github", "provider": "github", "host": "api.github.com", "kind": "runtime", "notes": "secret note"},
        {"name": "stripe-live", "provider": "stripe", "host": "api.stripe.com", "kind": "billing"},
        {"name": "BAD NAME", "provider": "x"},
    ]
    fake_keys.set("list", stdout=json.dumps(rows))
    out = json.loads(access.keysrs_keys({}))
    assert out["keys"] == [{"name": "github", "provider": "github", "host": "api.github.com"}]
    assert "secret note" not in json.dumps(out)


def test_tripwire_skips_own_tools(home):  # noqa: D103
    assert tripwire.pre_tool_call(tool_name="keysrs_request", args={"task": "printenv keys get x"}) is None


def test_registered():
    tools = []

    class Ctx:
        def register_secret_source(self, s): pass
        def register_cli_command(self, **k): pass
        def register_tool(self, **k): tools.append(k)

    keysrs_hermes.register(Ctx())
    assert [t["name"] for t in tools] == ["keysrs_keys", "keysrs_request"]
    assert all(t["toolset"] == "keysrs" and t["check_fn"] is access.available for t in tools)


def test_prompt_shows_real_method_and_scope_within_limit():
    line = access.prompt_task("DELETE", "/repos/me/app", "list your repositories")
    assert line.startswith("Hermes DELETE /repos/me/app: ")
    long = access.prompt_task("POST", "/" + "a" * 200, "x" * 300)
    assert len(long) <= 120 and long.startswith("Hermes POST /aaa")
    assert len(access.prompt_task("GET", "/user", "y" * 500)) <= 120


def test_billing_key_refused_even_by_name(home, fake_keys, gateway):
    grant_ok(fake_keys, gateway)
    out = req(key="stripe-live", path="/v1/refunds", method="POST")
    assert "billing key" in out["error"]
    assert grant_calls(fake_keys) == []


def test_unknown_key(home, fake_keys, gateway):
    grant_ok(fake_keys, gateway)
    assert "no vault key" in req(key="nope")["error"]


def test_delete_needs_exact_path(home, fake_keys, gateway):
    grant_ok(fake_keys, gateway)
    out = req(method="DELETE", path="/repos/me/app", scope="/")
    assert "exactly one path" in out["error"]
    assert req(method="DELETE", path="/repos/me/app")["ok"]


def test_ksf_and_x_keysrs_headers_blocked(home, fake_keys, gateway):
    grant_ok(fake_keys, gateway)
    req(headers={"X-Keysrs-Key": "other", "X-Ksf-Grant": "x", "X-HTTP-Method-Override": "DELETE", "content-type": "application/vnd.api+json"}, method="POST", body={"a": 1})
    sent = {k.lower(): v for k, v in Gateway.calls[-1]["headers"].items()}
    assert "x-keysrs-key" not in sent and "x-ksf-grant" not in sent and "x-http-method-override" not in sent
    assert sent["content-type"] == "application/vnd.api+json"


def test_parallel_calls_ask_once(home, fake_keys, gateway):
    grant_ok(fake_keys, gateway)
    fake_keys.set("grant", stdout=fake_keys._scenario["grant"]["stdout"], sleep=0.5)
    results = []
    threads = [threading.Thread(target=lambda: results.append(req())) for _ in range(3)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert all(r["ok"] for r in results)
    assert len(grant_calls(fake_keys)) == 1


def test_keysrs_revoke_also_revokes_agent_grants(home, fake_keys, gateway, monkeypatch):
    import asyncio

    from keysrs_hermes import commands

    monkeypatch.setattr(commands, "_hermes_home", lambda: home)
    grant_ok(fake_keys, gateway)
    req()
    fake_keys.token_ok()
    fake_keys.set("revoke", stdout="ok\n")
    fake_keys.set("grant_revoke", stdout="ok\n")
    out = asyncio.run(commands.handle("revoke"))
    assert "Also revoked 1 agent grant" in out
    assert ["revoke", "0a1b2c3d"] in [c["argv"] for c in fake_keys.calls()]
    assert access.held_grants() == []


def test_tripwire_exempts_only_own_tools(home):
    assert tripwire.pre_tool_call(tool_name="keysrs_shell", args={"cmd": "keys client token"}) is not None


def test_tripwire_hides_grant_tokens(home):
    out = tripwire.transform_tool_result(tool_name="terminal", result=f"token {GRANT} here")
    assert GRANT not in out
