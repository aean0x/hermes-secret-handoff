# secret-handoff — paste a password into a login form without it touching disk

A Hermes Agent plugin that gives the agent one tool: `request_secret`. It asks
the human for a credential, types the answer into a live browser over CDP, and
returns **status only**.

Use it when the agent has to log into something and no password manager is in
reach: the value flows human → CDP → page, and never lands in the session
transcript, a log line, a tool result, or a file.

```
request_secret(reason, url)
  ├── stock clarify prompt      → human types the value
  ├── classify reply            → "inject" | "cancel"  (cancel/n/no = cancel)
  ├── close the clarifying turn → reply is not echoed back into the session
  ├── CDP: pick the tab matching `url`, attach, fill the focused field,
  │        submit on request, wait for the page's own result
  └── return {"status": "injected", "target": "…"}   ← never the value
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
| `SECRET_HANDOFF_TOOL_TIMEOUT_S` | `300` | Overall tool timeout; the human may take a while to paste. |
| `HERMES_SESSION_KEY` | – | Session the pending request belongs to; set by Hermes. |

Resolution order for the endpoint: explicit tool argument → `BROWSER_CDP_URL` →
`browser.cdp_url` in `config.yaml` → `SECRET_HANDOFF_CDP_URL` → loopback `:9222`.

## Security model

- The value is held in memory, keyed by session, and **deleted** on success,
  cancel, timeout and injection failure (`clear_all`).
- The tool result carries a status and the target description. There is no
  code path that puts the value in the result, the log, or an exception
  message — the test suite asserts this for all four outcomes.
- The clarifying prompt tells the human that their reply is not echoed back.
- Injection is a websocket write to the page the human pointed at; the plugin
  does not store the value, and does not read it back out of the DOM.
- Because it is a plugin tool, it is subject to the host's normal tool
  approval surface: disable the plugin and the tool disappears.

## Tests

```bash
python -m pytest tests/ -q
```

Pure unit tests — stock CPython, no Hermes runtime, no CDP, no network. They
cover reply classification, endpoint resolution, the clarify round-trip, the
never-return-the-secret invariant for inject/cancel/timeout/failure, and the
`request_secret` schema.

## License

MIT — see [LICENSE](LICENSE).
