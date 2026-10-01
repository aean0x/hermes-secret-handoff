# secret-handoff — paste a password into a login form without it touching disk

A Hermes Agent plugin that gives the agent one tool: `request_secret`. It asks
the human for a credential, types the answer into a live browser over CDP, and
returns **status only**.

Use it when the agent has to log into something and no password manager is in
reach: the value flows human → CDP → page, and never reaches the tool result,
a file, or the transcript the agent reads back.

The question itself is an ordinary free-text `clarify` prompt, so it is only as
private as the surface showing it: in the CLI the answer appears in scrollback,
and on a messaging platform it is a normal chat message that stays in that
platform's history. Hermes offers no masked prompt to plugins here, so prefer a
password manager, or answer on a surface you accept will hold the value.

```
request_secret(service, target_id?, frame_id?)
  ├── CDP: resolve the target page and read its origin
  │        → refuse unless the page host is `service` or a subdomain of it
  ├── stock clarify prompt      → "Password for <service> — it will be typed
  │                                into <origin>"; human types the value
  ├── classify reply            → "inject" | "cancel"  (cancel/n/no = cancel)
  ├── CDP: re-check the live origin and that focus is on a password /
  │        one-time-code input, then insert the value (no submit)
  └── return {"status": "ok", "service": "…", "detail": "…"}   ← never the value
```

## Install

```bash
hermes plugins install <owner>/hermes-secret-handoff
hermes plugins enable secret-handoff
```

Manual install: copy this directory into `~/.hermes/plugins/secret-handoff`,
add `secret-handoff` to `plugins.enabled` in `config.yaml`, and restart.

## Requirements

- A browser already running with a CDP endpoint (the same one the agent's
  browser tools use), reachable from the Hermes process.
- The `websockets` package, which Hermes' browser tooling already installs.

## Configuration

All optional; the endpoint falls back to the host's configured browser.

| Variable | Default | Meaning |
| --- | --- | --- |
| `BROWSER_CDP_URL` | – | CDP endpoint. The standard Hermes variable; checked first. |
| `SECRET_HANDOFF_CDP_URL` | loopback `:9222` | Fallback endpoint for this plugin only, used when neither an explicit `browser.cdp_url` nor `BROWSER_CDP_URL` is set. |
| `SECRET_HANDOFF_CDP_TIMEOUT_S` | `8` | Per-websocket open/timeout budget for one injection. |
| `SECRET_HANDOFF_PROMPT_TIMEOUT_S` | `90` | How long one clarify prompt may take before the tool gives up and reports `no_response`. `0` disables the cap. |
| `SECRET_HANDOFF_FALLBACK_HINT` | – | Host-supplied pointer carried by a bounded failure, so the caller knows which surface to switch to. |
| `HERMES_SESSION_KEY` | – | Session the pending request belongs to; set by Hermes. |

Resolution order for the endpoint: `BROWSER_CDP_URL` → `browser.cdp_url` in
`config.yaml` → `SECRET_HANDOFF_CDP_URL` → loopback `:9222`. The model cannot
choose the endpoint, and the websocket the endpoint returns must stay on the
same host (or loopback).

## When the prompt is not answered

The prompt budget exists because the host owns its own, longer, wait: on a
surface where the prompt is raised but never rendered or answered, stock
clarify returns nothing at all and the *host's* tool ceiling ends the call —
420 s in the observed WebUI case, with a generic error and no usable result.

Past the budget the tool returns immediately:

```json
{"status": "failed", "service": "check24.de", "detail": "no_response", "fallback": "…"}
```

`no_response` is a statement about the surface, not about the human: the reply
never arrived, so nothing was injected and the value was discarded. The caller
must not re-raise the same prompt in the same session — it switches surface
instead, to the browser cast UI or whatever `SECRET_HANDOFF_FALLBACK_HINT`
names, so the human can type into the page himself.

A prompt abandoned this way may stay visible in the session's UI for a while;
answering it later is harmless (the reply is discarded, and the platform clears
it on its own timeout).

## Security model

- The value is held in memory, keyed by session, and **deleted** on success,
  cancel, timeout and injection failure (`clear_all`).
- The tool result carries a status and the target description. There is no
  code path that puts the value in the result, the log, or an exception
  message — the test suite asserts this for all four outcomes.
- The clarifying prompt tells the human that their reply is not echoed back.
- Injection is a websocket write to the page whose origin the prompt showed;
  it is refused if the page's host does not match `service`, if the page
  navigated to another origin before the reply, or if focus is not on a
  password / one-time-code input. The plugin does not store the value, and
  does not read it back out of the DOM.
- It is a plugin tool, so it has no default approval gate of its own. The gate
  is the prompt: nothing is typed unless a human answers it, and disabling the
  plugin removes the tool.

## Tests

```bash
python3 -m unittest discover -s tests
```

Pure unit tests — stock CPython, no Hermes runtime, no CDP, no network. They
cover reply classification, endpoint resolution, the clarify round-trip, the
never-return-the-secret invariant for inject/cancel/timeout/failure, the
bounded prompt wait (a prompt that is raised and never answered must fail the
tool in seconds, with `no_response` and a fallback), and the
`request_secret` schema.

## License

MIT — see [LICENSE](LICENSE).
