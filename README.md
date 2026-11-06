# Keysrs for Hermes Agent

Hermes calls your model provider through [Keysrs](https://github.com/gshost1/Keysreallysafe),
a local API-key vault on your Mac. Hermes never sees the real key: it gets
the loopback gateway URL and a **scoped, expiring, revocable client token**.
The Keysrs gateway swaps in the real key on the way out.

```
Hermes ──(ksfc_ token)──▶ Keysrs gateway 127.0.0.1:12767 ──(real key)──▶ provider
          POST chat/completions only        Keychain + Touch ID
          expires in N days
          revoke any time
```

- **The real key stays in the macOS Keychain.** It is never in `~/.hermes/.env`,
  `config.yaml`, process env, session logs or a crash dump. A prompt injection
  that dumps Hermes's environment gets a token that works only from this Mac,
  only on `POST chat/completions`, and only until it expires.
- **One Touch ID at setup, then unattended.** Hermes's startup, cron jobs and
  the messaging gateway fetch the token with no prompt.
- **Kill switch.** `keys client revoke` or `keys revoke --all` cuts Hermes off
  immediately. The next call is refused at the gateway, and `hermes keysrs status`
  says why and how to fix it.
- **Spend and audit in one place.** Every call Hermes makes shows up in
  `keys log` and the Keysrs spend chart, including out-of-scope attempts that
  the gateway refused.

## Requirements

- macOS with [Keysrs](https://keysrs.com) **0.16.0 or later** (held client tokens),
  with `keys` on your `PATH`
- Hermes Agent 0.20.4 or later
- A provider key in your Keysrs vault whose provider speaks the OpenAI chat
  completions API through the gateway (OpenRouter, OpenAI, DeepSeek,
  Moonshot, Inception, Vercel AI Gateway, …)

## Install

```sh
hermes plugins install keysrs
hermes keysrs setup --key <vault key name> --use --model <model id>
```

For example: `hermes keysrs setup --key openrouter --use --model mistralai/mistral-small-3.2-24b-instruct`.

`setup` runs `keys client issue <key> --label hermes --days 7 --hold --json`.
Keysrs shows one Touch ID prompt naming the key, the label and the lifetime,
keeps the token in its own Keychain item, and loads the key into its gateway.
Setup then writes two blocks to `config.yaml`. Neither contains a secret.

```yaml
providers:
  keysrs:
    base_url: http://127.0.0.1:12767/openrouter
    key_env: KEYSRS_TOKEN          # filled by this plugin at startup
    api_mode: chat_completions
    default_model: <model id>      # only with --model
secrets:
  keysrs:
    enabled: true
    label: hermes
    key: openrouter
    provider_name: keysrs
    keys_path: /Users/you/.local/bin/keys
model:
  provider: custom:keysrs          # only with --use
  default: <model id>              # only with --use --model
```

| Command | What it does |
|---|---|
| `hermes keysrs setup --key K [--days N] [--label L] [--path-prefix P \| --any-path] [--method M] [--use] [--model ID]` | Issue a held token (one Touch ID) and write the provider entry. Running it again replaces the old token. |
| `hermes keysrs status` | Label, key, gateway URL, scope, expiry, whether the gateway has the key loaded, and whether `model.provider` uses it. Never shows the token. |
| `hermes keysrs disable` | Stop fetching. The held token lives on in Keysrs until it expires or you revoke it. |

## How it works

The plugin registers a Hermes **secret source** (`ctx.register_secret_source`).
At startup and on every cron fire, Hermes calls its `fetch()`, which:

1. runs `keys client token --label hermes --json` through Hermes's
   `run_secret_cli()`: an argument list with no shell, stdin closed and a
   minimal allowlisted environment;
2. checks that the token is a Keysrs client token and that the gateway URL
   is loopback and matches `providers.keysrs`, and that no other provider
   entry would send `KEYSRS_TOKEN` anywhere else;
3. returns `{KEYSRS_TOKEN: <token>}`. Nothing else is set, and in particular
   no `OPENROUTER_*` / `OPENAI_*` variable, because several Hermes paths (title
   generation, model pricing, `hermes doctor`) send those to the vendor's own
   host whatever base URL you set.

Every failure comes back as a typed Hermes error with a one-line fix. The
token never appears in an error, log line or repr, and the plugin registers a
redaction pattern for `ksfc_` tokens with Hermes.

| Situation | Error kind | Fix shown |
|---|---|---|
| `keys` not installed | `BINARY_MISSING` | install Keysrs or set `secrets.keysrs.keys_path` |
| no held token for the label | `NOT_CONFIGURED` | `hermes keysrs setup --key K` |
| token expired or revoked | `AUTH_EXPIRED` | `hermes keysrs setup --key K` |
| Keysrs restarted and the key is not loaded | `AUTH_EXPIRED` | `keys gateway on K` (Touch ID) |
| Keysrs app unreachable | `NETWORK` | open Keysrs, restart Hermes |
| `keys` too slow | `TIMEOUT` | raise `secrets.keysrs.helper_timeout_seconds` |
| unexpected output, URL mismatch | `EMPTY_VALUE` / `REF_INVALID` / `INTERNAL` | `hermes keysrs status` |

None of these prompt or hang, so cron and the messaging gateway fail fast
and say why.

The same goes for a refusal in the middle of a session. If Keysrs restarts
while Hermes is running, its gateway answers `404`, which Hermes would read as
"model not found"; a revoked or expired token answers `401`, which Hermes
would retry and try to refresh. The plugin registers a
`transform_api_error_classification` hook that claims those two refusals
(matched on the Keysrs gateway's own error bodies) as permanent auth
failures, so Hermes stops retrying, moves to your fallback chain if you set
one, and logs the fix (`keys gateway on <key>` or `hermes keysrs setup`).

## What this plugin does that you should know about (disclosures)

- **Shell commands.** It runs the Keysrs CLI `keys`: `keys client token …`
  at every Hermes startup and cron fire, at most once per 30 seconds when the
  gateway refuses a call (to name the fix), and `keys client issue … --hold`
  during `hermes keysrs setup`. If the Keysrs app is not running, `keys`
  opens it (it runs headless).
- **User presence.** `setup` shows one Touch ID prompt from the Keysrs app.
  Nothing else ever prompts.
- **Network.** The plugin itself makes no network calls. Hermes's own provider
  calls go to `http://127.0.0.1:12767/<key>` (the Keysrs gateway), which
  forwards them to the provider the key belongs to.
- **Files.** `setup` and `disable` write `providers.<name>` and
  `secrets.keysrs` in Hermes's `config.yaml`, with no secrets. The plugin reads
  no other files: no `.env`, no `auth.json`, no Keychain.
- **Stored credentials.** None in Hermes. The token lives in Keysrs's own
  Keychain item (service `keysreallysafe.held`) and in Hermes's process
  environment while it runs. While a held token is live, any process running
  as your user can ask `keys` for it without Touch ID. That is the price of
  unattended startup, so keep `--days` short and the scope narrow (the
  defaults are 7 days, `POST`, `chat/completions`).
- **Telemetry.** None.
- **Background processes.** None.

## Limitations

- macOS only (Keysrs is a Mac app).
- After the Keysrs app restarts (a reboot, or an update), the gateway needs
  `keys gateway on <key>` (one Touch ID) before calls work again. The token
  stays valid in the meantime.
- Anthropic's native Messages API through the gateway isn't covered yet. Use
  an OpenAI-compatible route such as OpenRouter.
- With the default `chat/completions` scope, Hermes's `GET /models` metadata
  lookups are refused at the gateway (`out_of_scope` in `keys log`). Chat is
  unaffected. Use `--any-path --method GET --method POST` if you want them.

## Development

```sh
pip install pytest
HERMES_AGENT_DIR=~/.hermes/hermes-agent python -m pytest -q tests
```

The tests are offline and use a fake `keys` (`tests/fake_keys.py`): no Touch
ID, Keychain or provider calls. They include a routing test that runs
Hermes's own provider resolution (main chat, side tasks, vision, credential
pools) with network calls blocked, and asserts that the token is only ever
paired with the loopback gateway.

## License

MIT
