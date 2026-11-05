"""Hermes's own secret-source conformance kit, run against KeysrsSource."""

import importlib.util

import pytest

from conftest import HERMES_DIR
from keysrs_hermes.keysrs_source import KeysrsSource

# Loaded by path: our tests/ directory shadows Hermes's `tests` package name.
_spec = importlib.util.spec_from_file_location(
    "hermes_secret_source_conformance", HERMES_DIR / "tests" / "secret_sources" / "conformance.py"
)
_kit = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_kit)


class TestKeysrsConformance(_kit.SecretSourceConformance):
    @pytest.fixture
    def source(self, fake_keys):
        fake_keys.set("token", exit=2, stdout='{"error":"not_found","label":"hermes"}\n')
        return KeysrsSource()
