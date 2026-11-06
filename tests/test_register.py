"""register(ctx) wires the source, the CLI command and the redaction pattern."""

from __future__ import annotations

import argparse

import keysrs_hermes
from conftest import TOKEN
from keysrs_hermes.keysrs_source import GRANT_REDACTION_PATTERN, TOKEN_REDACTION_PATTERN, KeysrsSource


class FakeCtx:
    def __init__(self):
        self.sources, self.cli, self.patterns = [], [], []

    def register_secret_source(self, source):
        self.sources.append(source)

    def register_cli_command(self, **kwargs):
        self.cli.append(kwargs)

    def register_redaction_patterns(self, patterns):
        self.patterns.extend(patterns)
        return len(patterns)


def test_register():
    ctx = FakeCtx()
    keysrs_hermes.register(ctx)
    (source,) = ctx.sources
    assert isinstance(source, KeysrsSource)
    assert source.name == "keysrs" and source.shape == "mapped"
    (cmd,) = ctx.cli
    assert cmd["name"] == "keysrs"
    parser = argparse.ArgumentParser()
    cmd["setup_fn"](parser)
    assert parser.parse_args(["status"]).keysrs_command == "status"
    assert ctx.patterns == [TOKEN_REDACTION_PATTERN, GRANT_REDACTION_PATTERN]


def test_register_without_redaction_api():
    class Old(FakeCtx):
        register_redaction_patterns = None

    ctx = Old()
    keysrs_hermes.register(ctx)
    assert ctx.sources and ctx.cli


def test_redaction_pattern_accepted_and_masks_token():
    from agent import redact

    accepted = redact.register_redaction_patterns([TOKEN_REDACTION_PATTERN], source="plugin:keysrs-test")
    assert accepted in (0, 1)  # 0 only if an earlier test already registered it
    masked = redact.redact_sensitive_text(f"Authorization: Bearer {TOKEN} and more")
    assert TOKEN not in masked
