"""Keysrs for Hermes Agent: provider calls go through the local Keysrs
gateway with a scoped, expiring client token; the real key stays in Keysrs."""

from __future__ import annotations

from . import access
from .cli import setup_parser
from .commands import handle as keysrs_command
from .hooks import classify_api_error
from .tripwire import pre_tool_call, transform_tool_result
from .keysrs_source import GRANT_REDACTION_PATTERN, TOKEN_REDACTION_PATTERN, KeysrsSource


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
        register_patterns([TOKEN_REDACTION_PATTERN, GRANT_REDACTION_PATTERN])
    register_hook = getattr(ctx, "register_hook", None)
    if callable(register_hook):
        register_hook("transform_api_error_classification", classify_api_error)
        register_hook("pre_tool_call", pre_tool_call)
        register_hook("transform_tool_result", transform_tool_result)
    register_command = getattr(ctx, "register_command", None)
    if callable(register_command):
        register_command(
            "keysrs",
            keysrs_command,
            description="Keysrs: token status and today's spend; `/keysrs revoke` cuts Hermes off",
            args_hint="[status|revoke|help]",
        )
    access.register(ctx)
