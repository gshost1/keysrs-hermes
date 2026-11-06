"""Keysrs for Hermes Agent: provider calls go through the local Keysrs
gateway with a scoped, expiring client token; the real key stays in Keysrs."""

from __future__ import annotations

from .cli import setup_parser
from .hooks import classify_api_error
from .keysrs_source import TOKEN_REDACTION_PATTERN, KeysrsSource


def register(ctx) -> None:
    ctx.register_secret_source(KeysrsSource())
    ctx.register_cli_command(
        name="keysrs",
        help="Keysrs secret source: setup, status, disable",
        setup_fn=setup_parser,
        description="Route provider calls through the local Keysrs gateway with a held client token.",
    )
    register_patterns = getattr(ctx, "register_redaction_patterns", None)
    if callable(register_patterns):
        register_patterns([TOKEN_REDACTION_PATTERN])
    register_hook = getattr(ctx, "register_hook", None)
    if callable(register_hook):
        register_hook("transform_api_error_classification", classify_api_error)
