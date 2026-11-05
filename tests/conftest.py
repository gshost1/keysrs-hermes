"""Test setup: put Hermes on sys.path, load this plugin as a package, and
give each test a fake `keys` on PATH with a throwaway HOME."""

from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path

import pytest

sys.dont_write_bytecode = True  # never write .pyc into the Hermes install

REPO = Path(__file__).resolve().parents[1]
HERMES_DIR = Path(os.environ.get("HERMES_AGENT_DIR", Path.home() / ".hermes" / "hermes-agent"))
if str(HERMES_DIR) not in sys.path:
    sys.path.insert(0, str(HERMES_DIR))

PKG = "keysrs_hermes"
if PKG not in sys.modules:
    spec = importlib.util.spec_from_file_location(
        PKG, REPO / "__init__.py", submodule_search_locations=[str(REPO)]
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[PKG] = module
    spec.loader.exec_module(module)

TOKEN = "ksfc_TESTTOKEN_c0ffee1234567890abcdef"
BASE_URL = "http://127.0.0.1:12767/openrouter"


def provider_cfg(**overrides):
    entry = {"base_url": BASE_URL, "key_env": "KEYSRS_TOKEN", "api_mode": "chat_completions"}
    entry.update(overrides)
    return {"providers": {"keysrs": entry}}


def yaml_dump(data) -> str:
    """PyYAML on Hermes 0.20.x, ruamel.yaml on 0.22.x (whichever Hermes ships)."""
    try:
        import yaml
    except ImportError:
        import io

        from ruamel.yaml import YAML

        buf = io.StringIO()
        YAML(typ="safe", pure=True).dump(data, buf)
        return buf.getvalue()
    return yaml.safe_dump(data)


def write_config(home: Path, cfg: dict) -> Path:
    home.mkdir(parents=True, exist_ok=True)
    (home / "config.yaml").write_text(yaml_dump(cfg))
    return home


def token_payload(**overrides):
    payload = {
        "base_url": BASE_URL,
        "client_id": 7,
        "expires_at": "2099-01-01T00:00:00Z",
        "gateway_on": True,
        "key": "openrouter",
        "label": "hermes",
        "methods": ["POST"],
        "path_prefix": "chat/completions",
        "token": TOKEN,
    }
    payload.update(overrides)
    return payload


class FakeKeys:
    def __init__(self, root: Path):
        self.home = root / "home"
        self.bin = root / "bin"
        self.state = self.home / ".fake_keys"
        self.state.mkdir(parents=True)
        self.bin.mkdir()
        self.path = self.bin / "keys"
        self.path.write_text(
            f'#!/bin/sh\nexec "{sys.executable}" "{REPO / "tests" / "fake_keys.py"}" "$@"\n'
        )
        self.path.chmod(0o755)
        self._scenario: dict = {}

    def set(self, cmd: str, *, exit: int = 0, stdout: str = "", stderr: str = "", sleep: float = 0):
        self._scenario[cmd] = {"exit": exit, "stdout": stdout, "stderr": stderr, "sleep": sleep}
        (self.state / "scenario.json").write_text(json.dumps(self._scenario))

    def token_ok(self, **overrides):
        self.set("token", stdout=json.dumps(token_payload(**overrides)) + "\n")

    def calls(self):
        log = self.state / "calls.jsonl"
        if not log.exists():
            return []
        return [json.loads(line) for line in log.read_text().splitlines() if line.strip()]


@pytest.fixture
def fake_keys(tmp_path, monkeypatch):
    fk = FakeKeys(tmp_path)
    monkeypatch.setenv("HOME", str(fk.home))
    monkeypatch.setenv("PATH", f"{fk.bin}{os.pathsep}/usr/bin{os.pathsep}/bin")
    # Belt and braces: a test must never reach the real `keys`.
    import shutil

    assert shutil.which("keys") == str(fk.path)
    return fk


@pytest.fixture
def hermes_home(tmp_path):
    """A profile dir whose config.yaml has the standard keysrs provider entry."""
    return write_config(tmp_path / "hermes", provider_cfg())
