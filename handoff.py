"""Ephemeral login paste: clarify, inject via CDP, return status only.

Same-process gateway, WebUI, and CLI. Pending metadata lives in module-level
RAM only. The tool asks via stock clarify, extracts the reply, injects it
over a direct CDP websocket, and returns {status, service, detail} — never
the secret.
"""

from __future__ import annotations

import inspect
import json
import logging
import os
import threading
import time
from typing import Any, Callable, Optional
from urllib.error import URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

logger = logging.getLogger("hermes.plugins.secret_handoff")

DEFAULT_CDP_URL = "http://127.0.0.1:9222"
TOOL_TIMEOUT_S = 300.0
PROMPT_TIMEOUT_S = 90.0
_PROMPT_SLACK_S = 30.0
_CDP_TIMEOUT_S = 8.0

# Carried by a bounded failure so the caller changes surface instead of
# re-raising the same prompt that produced nothing. Overridable per host.
FALLBACK_HINT = (
    "No reply arrived inside the prompt budget. Do not retry request_secret in "
    "this session — its prompt may not be visible there. Switch to the browser "
    "cast UI, or any surface where the human can type into the page himself."
)


def _fallback_hint() -> str:
    """Host-supplied pointer for the bounded-failure path."""
    return os.environ.get("SECRET_HANDOFF_FALLBACK_HINT", "").strip() or FALLBACK_HINT


def _env_float(name: str, default: float) -> float:
    """Read a numeric knob from the environment; junk falls back to default."""
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        logger.warning("%s=%r is not a number; using %s", name, raw, default)
        return default

_CANCEL_REPLIES = frozenset({"cancel", "n", "no"})

# session_key → metadata (never the secret)
_pending: dict[str, dict[str, Any]] = {}
_lock = threading.RLock()


# ---------------------------------------------------------------------------
# Pure helpers (unit-tested without Hermes)
# ---------------------------------------------------------------------------


def classify_reply(text: Optional[str]) -> str:
    """Classify inbound clarify text: inject | cancel | ignore."""
    stripped = "" if text is None else str(text).strip()
    if stripped.startswith("/"):
        return "ignore"
    if not stripped or stripped.casefold() in _CANCEL_REPLIES:
        return "cancel"
    return "inject"


# ---------------------------------------------------------------------------
# RAM state
# ---------------------------------------------------------------------------


def set_pending(session_key: str, meta: dict[str, Any]) -> None:
    with _lock:
        _pending[session_key] = dict(meta)


def peek_pending(session_key: str) -> Optional[dict[str, Any]]:
    with _lock:
        meta = _pending.get(session_key)
        return dict(meta) if meta else None


def clear_pending(session_key: str) -> None:
    with _lock:
        _pending.pop(session_key, None)


def clear_all(session_key: str) -> None:
    clear_pending(session_key)


def reset_state() -> None:
    """Test helper: drop all RAM slots."""
    with _lock:
        _pending.clear()


# ---------------------------------------------------------------------------
# Session key — same format the gateway uses for pending clarify
# ---------------------------------------------------------------------------


def resolve_session_key_for_tool(**kwargs: Any) -> str:
    """Same key the gateway bound for this agent turn (clarify / approval)."""
    try:
        from tools.approval import get_current_session_key

        key = get_current_session_key("")
        if key and key != "default":
            return str(key)
    except Exception:
        pass
    try:
        from gateway.session_context import get_session_env

        key = get_session_env("HERMES_SESSION_KEY", "")
        if key:
            return str(key)
    except Exception:
        pass
    env = os.environ.get("HERMES_SESSION_KEY", "").strip()
    if env:
        return env
    for name in ("session_id", "task_id"):
        val = kwargs.get(name)
        if val:
            return str(val)
    return "default"


def _callback_from_agent(obj: Any) -> Optional[Callable]:
    cb = getattr(obj, "clarify_callback", None)
    return cb if callable(cb) else None


def _find_clarify_callback_from_stack() -> Optional[Callable]:
    """Live ``agent`` / ``self`` on the executor stack — not a stale heap object."""
    frame = inspect.currentframe()
    try:
        while frame is not None:
            loc = frame.f_locals
            for name in ("agent", "self"):
                cb = _callback_from_agent(loc.get(name))
                if cb is not None:
                    return cb
            frame = frame.f_back
    finally:
        del frame
    return None


def _find_clarify_callback_on_heap(session_key: str) -> Optional[Callable]:
    """Exact session-key match only. Never the first callable on the heap."""
    if not session_key or session_key == "default":
        return None
    try:
        import gc

        for obj in gc.get_objects():
            cb = _callback_from_agent(obj)
            if cb is None:
                continue
            gsk = getattr(obj, "_gateway_session_key", None) or getattr(
                obj, "gateway_session_key", None
            )
            sid = getattr(obj, "session_id", None)
            if str(gsk or "") == session_key or str(sid or "") == session_key:
                return cb
    except Exception:
        return None
    return None


def _find_clarify_callback(session_key: str) -> Optional[Callable]:
    """Resolve the current turn's clarify callback.

    Core ``clarify`` is special-cased in tool_executor.py with
    ``callback=agent.clarify_callback``. Plugin tools are not, so recover the
    same live agent from the call stack. A gc heap scan is last-resort and
    only when it matches ``session_key`` exactly — never the first callable
    on the heap (stale WebUI AIAgent objects return empty instantly).
    """
    return _find_clarify_callback_from_stack() or _find_clarify_callback_on_heap(
        session_key
    )


# ---------------------------------------------------------------------------
# Direct CDP (never via browser_type / browser_cdp / dispatch_tool)
# ---------------------------------------------------------------------------


def _as_http_base(url: str) -> str:
    raw = (url or "").strip()
    if raw.startswith("ws://"):
        raw = "http://" + raw[5:]
    elif raw.startswith("wss://"):
        raw = "https://" + raw[6:]
    for suffix in ("/json/version", "/json/list", "/json"):
        if raw.endswith(suffix):
            raw = raw[: -len(suffix)]
            break
    if "/devtools/" in raw:
        raw = raw.split("/devtools/", 1)[0]
    return raw.rstrip("/")


def resolve_cdp_http_base(explicit: Optional[str] = None) -> str:
    """explicit arg > BROWSER_CDP_URL > browser.cdp_url > SECRET_HANDOFF_CDP_URL
    > loopback :9222."""
    if explicit and str(explicit).strip():
        return _as_http_base(str(explicit))
    env = os.environ.get("BROWSER_CDP_URL", "").strip()
    if env:
        return _as_http_base(env)
    try:
        from hermes_cli.config import read_raw_config

        cfg = read_raw_config() or {}
        browser = cfg.get("browser") if isinstance(cfg, dict) else None
        if isinstance(browser, dict):
            configured = str(browser.get("cdp_url") or "").strip()
            if configured:
                return _as_http_base(configured)
    except Exception:
        pass
    return os.environ.get("SECRET_HANDOFF_CDP_URL", "").strip() or DEFAULT_CDP_URL


def _host(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def _is_loopback(url: str) -> bool:
    host = _host(url)
    return host in {"localhost", "::1"} or host.startswith("127.")


def page_origin(url: str) -> str:
    """``scheme://host[:port]`` of a target URL, or ``""`` when it has none."""
    try:
        parts = urlsplit(url or "")
    except ValueError:
        return ""
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return ""
    return f"{parts.scheme}://{parts.netloc.rsplit('@', 1)[-1]}"


def origin_matches_service(origin: str, service: str) -> bool:
    """True when the page host is ``service``'s domain or a subdomain of it."""
    host = _host(origin)
    raw = (service or "").strip().lower()
    want = _host(raw if "://" in raw else "https://" + raw)
    if not host or not want:
        return False
    return host == want or host.endswith("." + want)


def _http_json(url: str, timeout: float = 3.0) -> Any:
    req = Request(url, headers={"Accept": "application/json"})
    with urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", errors="replace"))


def pick_target(
    targets: list,
    target_id: Optional[str] = None,
    frame_id: Optional[str] = None,
) -> Optional[dict]:
    pages = [t for t in targets if isinstance(t, dict)]
    if frame_id:
        for item in pages:
            if item.get("id") == frame_id:
                return item
    if target_id:
        for item in pages:
            if item.get("id") == target_id:
                return item
    for item in pages:
        if item.get("type") == "page" and item.get("attached"):
            return item
    for item in pages:
        if item.get("type") == "page":
            return item
    return pages[0] if pages else None


def _run_async(coro):
    import asyncio

    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None
    if loop and loop.is_running():
        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(asyncio.run, coro).result()
    return asyncio.run(coro)


async def _cdp_session_call(
    ws_url: str,
    calls: list[tuple[str, dict]],
    *,
    attach_target_id: Optional[str] = None,
    timeout: Optional[float] = None,
    guard: Optional[Callable[[Any], bool]] = None,
) -> list[Any]:
    """Open one CDP websocket, optionally attach, run methods, return results.

    When *guard* is given it sees the first call's result; ``False`` aborts
    before any later call (the text insertion) is sent.
    """
    import websockets

    if timeout is None:
        timeout = _env_float("SECRET_HANDOFF_CDP_TIMEOUT_S", _CDP_TIMEOUT_S)

    results: list[Any] = []
    async with websockets.connect(
        ws_url,
        max_size=None,
        open_timeout=timeout,
        close_timeout=3,
        ping_interval=None,
    ) as ws:
        next_id = 1
        session_id: Optional[str] = None

        async def _rpc(method: str, params: dict) -> Any:
            nonlocal next_id
            call_id = next_id
            next_id += 1
            req: dict[str, Any] = {"id": call_id, "method": method, "params": params or {}}
            if session_id:
                req["sessionId"] = session_id
            await ws.send(json.dumps(req))
            deadline = time.monotonic() + timeout
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError(method)
                raw = await _wait_recv(ws, remaining)
                msg = json.loads(raw)
                if msg.get("id") != call_id:
                    continue
                if "error" in msg:
                    raise RuntimeError(str(msg.get("error")))
                return msg.get("result", {})

        if attach_target_id:
            attached = await _rpc(
                "Target.attachToTarget",
                {"targetId": attach_target_id, "flatten": True},
            )
            session_id = (attached or {}).get("sessionId")
            if not session_id:
                raise RuntimeError("attachToTarget returned no sessionId")

        for method, params in calls:
            results.append(await _rpc(method, params))
            if guard is not None and len(results) == 1 and not guard(results[0]):
                raise _GuardRefused()
    return results


async def _wait_recv(ws: Any, remaining: float) -> str:
    import asyncio

    raw = await asyncio.wait_for(ws.recv(), timeout=remaining)
    return raw if isinstance(raw, str) else raw.decode("utf-8", errors="replace")


def _eval_length_expr() -> str:
    return (
        "(function(){var el=document.activeElement;"
        "if(!el||typeof el.value!=='string')return 0;"
        "return el.value.length;})()"
    )


def _eval_focus_expr() -> str:
    """Report the live origin and whether focus is on a password-type input."""
    return (
        "(function(){var el=document.activeElement,ok=false;"
        "if(el&&el.tagName==='INPUT'){var t=(el.type||'').toLowerCase(),"
        "ac=(el.getAttribute('autocomplete')||'').toLowerCase();"
        "ok=t==='password'||/password|one-time-code/.test(ac);}"
        "if(ok&&typeof el.focus==='function')el.focus();"
        "return {origin:location.origin,field:ok};})()"
    )


def _length_from_eval(result: Any) -> int:
    if not isinstance(result, dict):
        return 0
    inner = result.get("result")
    if not isinstance(inner, dict):
        return 0
    value = inner.get("value")
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _plan_target(
    cdp_url: Optional[str] = None,
    target_id: Optional[str] = None,
    frame_id: Optional[str] = None,
) -> tuple[Optional[dict[str, Any]], str]:
    """Resolve the CDP target: ``({ws_url, attach_id, origin}, "")`` or ``(None, detail)``.

    The endpoint must be loopback unless it is the operator-configured one, and
    the websocket the endpoint hands back must stay on the same host.
    """
    base = resolve_cdp_http_base(cdp_url)
    if not _is_loopback(base) and base != resolve_cdp_http_base(None):
        return None, "cdp endpoint not allowed"
    try:
        targets = _http_json(base + "/json")
    except (URLError, OSError, TimeoutError, json.JSONDecodeError, ValueError):
        logger.warning("secret-handoff: CDP target list failed")
        return None, "cdp unavailable"
    if not isinstance(targets, list):
        return None, "cdp unavailable"

    target = pick_target(targets, target_id=target_id, frame_id=frame_id)
    if target is None:
        return None, "no target"
    ws_url = str(target.get("webSocketDebuggerUrl") or "").strip()
    attach_id: Optional[str] = None
    if not ws_url:
        # Browser-level endpoint + attach to the chosen target / OOPIF.
        try:
            version = _http_json(base + "/json/version")
            ws_url = str((version or {}).get("webSocketDebuggerUrl") or "").strip()
        except (URLError, OSError, TimeoutError, json.JSONDecodeError, ValueError):
            ws_url = ""
        attach_id = str(target.get("id") or frame_id or target_id or "") or None
    elif frame_id and target.get("id") != frame_id:
        attach_id = frame_id

    if not ws_url:
        return None, "cdp unavailable"
    if not (_is_loopback(ws_url) or _host(ws_url) == _host(base)):
        return None, "cdp endpoint not allowed"
    origin = page_origin(str(target.get("url") or ""))
    return {"ws_url": ws_url, "attach_id": attach_id, "origin": origin}, ""


def describe_target(
    target_id: Optional[str] = None, frame_id: Optional[str] = None
) -> tuple[bool, str]:
    """``(True, origin)`` of the page the secret would be typed into, else ``(False, detail)``."""
    plan, detail = _plan_target(None, target_id=target_id, frame_id=frame_id)
    if plan is None:
        return False, detail
    if not plan["origin"]:
        return False, "target has no web origin"
    return True, plan["origin"]


class _GuardRefused(Exception):
    """The page changed origin, or focus is not on a password field."""


def inject_secret(
    secret: str,
    *,
    cdp_url: Optional[str] = None,
    target_id: Optional[str] = None,
    frame_id: Optional[str] = None,
    expected_origin: Optional[str] = None,
) -> tuple[bool, str]:
    """Type *secret* into the focused password field over a direct CDP websocket.

    Nothing is typed unless the page's live ``location.origin`` equals
    *expected_origin* (when given) and focus is on a password / one-time-code input.
    """
    if not secret:
        return False, "empty secret"
    plan, detail = _plan_target(cdp_url, target_id=target_id, frame_id=frame_id)
    if plan is None:
        return False, detail
    ws_url, attach_id = plan["ws_url"], plan["attach_id"]
    expected = expected_origin or plan["origin"]

    def _guard(result: Any) -> bool:
        value = (result or {}).get("result", {}).get("value") if isinstance(result, dict) else None
        return (
            isinstance(value, dict)
            and bool(expected)
            and value.get("origin") == expected
            and value.get("field") is True
        )

    focus_call = ("Runtime.evaluate", {"expression": _eval_focus_expr(), "returnByValue": True})
    insert_call = ("Input.insertText", {"text": secret})
    len_call = ("Runtime.evaluate", {"expression": _eval_length_expr(), "returnByValue": True})
    char_calls = [("Input.dispatchKeyEvent", {"type": "char", "text": ch}) for ch in secret]

    try:
        results = _run_async(
            _cdp_session_call(
                ws_url,
                [focus_call, insert_call, len_call],
                attach_target_id=attach_id,
                guard=_guard,
            )
        )
        length = _length_from_eval(results[-1] if results else None)
        if length > 0:
            return True, "injected"
        results = _run_async(
            _cdp_session_call(
                ws_url,
                [focus_call, *char_calls, len_call],
                attach_target_id=attach_id,
                guard=_guard,
            )
        )
        length = _length_from_eval(results[-1] if results else None)
        if length > 0:
            return True, "injected"
        return False, "field still empty"
    except _GuardRefused:
        logger.warning("secret-handoff: page origin changed or focus is not a password field")
        return False, "not a password field on the expected origin"
    except Exception:
        logger.warning("secret-handoff: CDP inject failed")
        return False, "inject failed"


# ---------------------------------------------------------------------------
# Tool
# ---------------------------------------------------------------------------

_QUESTION = (
    "Type the password here; it will not be saved to the transcript; "
    "reply `cancel` to abort."
)

REQUEST_SECRET_SCHEMA: dict[str, Any] = {
    "name": "request_secret",
    "description": (
        "Ask the user for a site password without persisting it. Focus the "
        "password field in the browser first, then call this. Stock clarify "
        "collects the reply; the plugin injects it via a direct CDP websocket "
        "and returns only a status JSON — the secret never enters the "
        "transcript or model context. Do not ask the user to paste a password "
        "in chat. A result of {\"status\": \"failed\", \"detail\": "
        "\"no_response\"} means the prompt went unanswered in this session — "
        "do not retry it; switch to the cast UI so the human can type into "
        "the page himself."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "service": {
                "type": "string",
                "description": (
                    "Domain of the site (e.g. example.com). The secret is only "
                    "typed into a page whose host is this domain or a subdomain."
                ),
            },
            "target_id": {
                "type": "string",
                "description": "CDP target/tab id. Omit to use the focused/attached page.",
            },
            "frame_id": {
                "type": "string",
                "description": "OOPIF frame id (same constraint as browser_cdp).",
            },
        },
        "required": ["service"],
    },
}


def _opt_str(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _from_responses(data: dict) -> str:
    """Current clarify shape: ``{"responses": [{"user_response"}], "outcome"}``."""
    outcome = str(data.get("outcome") or "")
    if outcome == "timed_out":
        return "[user did not respond in time]"
    if outcome == "cancelled":
        return "cancel"
    if outcome == "undelivered":
        return "[clarify undelivered]"
    first = data["responses"][0] if data["responses"] else None
    value = first.get("user_response") if isinstance(first, dict) else None
    return value if isinstance(value, str) else ""


def _extract_clarify_response(raw: Any) -> str:
    if raw is None:
        return ""
    if isinstance(raw, dict):
        data: Any = raw
    else:
        text = str(raw)
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return text.strip()
    if isinstance(data, dict):
        if isinstance(data.get("responses"), list):
            return _from_responses(data)
        return str(data.get("user_response") or "")
    return str(raw).strip()


def _clarify_looks_failed(response: str) -> Optional[dict[str, str]]:
    low = response.strip()
    flat = low.lower()
    if not low:
        return {"status": "failed", "detail": "empty"}
    if flat.startswith("[user did not respond") or flat.startswith(
        "the user did not provide a response"
    ):
        return {"status": "failed", "detail": "timed out"}
    if low.startswith("[clarify") or "not available" in flat:
        return {"status": "failed", "detail": "clarify unavailable"}
    return None


def _prompt_timeout_s() -> float:
    """Budget for one clarify round-trip. ``<= 0`` means wait without a cap."""
    return _env_float("SECRET_HANDOFF_PROMPT_TIMEOUT_S", PROMPT_TIMEOUT_S)


def _takes_questions(fn: Callable) -> bool:
    """Current Hermes clarify takes ``questions=[...]``; older releases ``question=``."""
    try:
        return "questions" in inspect.signature(fn).parameters
    except (TypeError, ValueError):
        return False


def _clarify_with_deadline(
    question: str, callback: Optional[Callable], timeout_s: float
) -> tuple[Any, bool]:
    """Ask through stock clarify, but never block past ``timeout_s``.

    The platform callback owns its own wait, which can outlive the host's tool
    ceiling: on a surface where the prompt is raised but never answered, the
    callback returns nothing at all and the *host* ends the call with a generic
    timeout, long after the turn was useful. This bound keeps the decision in
    the plugin. Returns ``(raw, timed_out)``; ``timed_out`` True means no reply
    arrived inside the budget and the caller must fail fast.
    """
    from tools.clarify_tool import clarify_tool

    result: dict[str, Any] = {}

    def _ask() -> None:
        try:
            if _takes_questions(clarify_tool):
                result["raw"] = clarify_tool(questions=[{"question": question}], callback=callback)
            else:  # older Hermes: clarify_tool(question, choices, callback)
                result["raw"] = clarify_tool(question=question, choices=None, callback=callback)
        except BaseException as exc:  # re-raised on the caller's thread
            result["error"] = exc

    worker = threading.Thread(target=_ask, name="secret-handoff-prompt", daemon=True)
    worker.start()
    worker.join(None if timeout_s <= 0 else timeout_s)
    if worker.is_alive():
        return None, True
    if "error" in result:
        raise result["error"]
    return result.get("raw"), False


def handle_request_secret(args: dict, **kwargs: Any) -> str:
    service = str((args or {}).get("service") or "").strip()
    if not service:
        return json.dumps(
            {"status": "failed", "service": "", "detail": "service is required"}
        )

    session_key = resolve_session_key_for_tool(**kwargs)
    target_id = _opt_str((args or {}).get("target_id"))
    frame_id = _opt_str((args or {}).get("frame_id"))

    # Bind the prompt to the real page before asking: the human sees where the
    # value will be typed, and a page on another site is refused outright.
    found, origin = describe_target(target_id=target_id, frame_id=frame_id)
    if not found:
        return json.dumps({"status": "failed", "service": service, "detail": origin})
    if not origin_matches_service(origin, service):
        return json.dumps(
            {
                "status": "failed",
                "service": service,
                "detail": "page origin does not match service",
                "origin": origin,
            }
        )

    set_pending(
        session_key,
        {
            "service": service,
            "target_id": target_id,
            "frame_id": frame_id,
            "origin": origin,
            "created_at": time.time(),
        },
    )

    question = f"Password for {service} — it will be typed into {origin}. {_QUESTION}"
    callback = kwargs.get("callback")
    if callback is None:
        callback = _find_clarify_callback_from_stack()
        source = "stack"
        if callback is None:
            callback = _find_clarify_callback_on_heap(session_key)
            source = "heap" if callback is not None else "none"
        logger.info(
            "secret-handoff: clarify callback resolved via %s (session=%s)", source, session_key
        )

    raw: Any = ""
    response = ""
    try:
        try:
            raw, prompt_timed_out = _clarify_with_deadline(
                question, callback, _prompt_timeout_s()
            )
        except Exception:
            logger.warning("secret-handoff: clarify_tool failed")
            return json.dumps(
                {"status": "failed", "service": service, "detail": "clarify unavailable"}
            )

        if prompt_timed_out:
            logger.warning(
                "secret-handoff: no reply inside %.0fs for %s (session=%s); "
                "the prompt is raised but this session's surface never answered it",
                _prompt_timeout_s(),
                service,
                session_key,
            )
            return json.dumps(
                {
                    "status": "failed",
                    "service": service,
                    "detail": "no_response",
                    "fallback": _fallback_hint(),
                }
            )

        response = _extract_clarify_response(raw)
        raw = ""
        mapped = _clarify_looks_failed(response)
        if mapped:
            return json.dumps(
                {
                    "status": mapped["status"],
                    "service": service,
                    "detail": mapped["detail"],
                }
            )

        kind = classify_reply(response)
        if kind in {"cancel", "ignore"}:
            return json.dumps(
                {"status": "cancelled", "service": service, "detail": "user cancelled"}
            )

        pending = peek_pending(session_key) or {}
        try:
            ok, detail = inject_secret(
                response,
                target_id=target_id or pending.get("target_id"),
                frame_id=frame_id or pending.get("frame_id"),
                expected_origin=origin,
            )
        except Exception:
            ok, detail = False, "inject failed"

        return json.dumps(
            {
                "status": "ok" if ok else "failed",
                "service": service,
                "detail": detail,
            }
        )
    except Exception:
        logger.warning("secret-handoff: request_secret failed")
        return json.dumps(
            {"status": "failed", "service": service, "detail": "inject failed"}
        )
    finally:
        raw = ""
        response = ""
        clear_all(session_key)


def _register_tool(ctx: Any) -> None:
    kwargs: dict[str, Any] = {
        "name": "request_secret",
        "handler": handle_request_secret,
        "schema": REQUEST_SECRET_SCHEMA,
        "toolset": "plugin",
        "timeout_s": max(
            _env_float("SECRET_HANDOFF_TOOL_TIMEOUT_S", TOOL_TIMEOUT_S),
            _prompt_timeout_s() + _PROMPT_SLACK_S,
        ),
        "description": REQUEST_SECRET_SCHEMA["description"],
        "emoji": "🔐",
    }
    try:
        sig = inspect.signature(ctx.register_tool)
        params = sig.parameters
        if any(p.kind == inspect.Parameter.VAR_KEYWORD for p in params.values()):
            ctx.register_tool(**kwargs)
            return
        accepted = {
            name
            for name, p in params.items()
            if p.kind
            in (inspect.Parameter.POSITIONAL_OR_KEYWORD, inspect.Parameter.KEYWORD_ONLY)
        }
        ctx.register_tool(**{k: v for k, v in kwargs.items() if k in accepted})
    except TypeError:
        ctx.register_tool(
            name="request_secret",
            toolset="plugin",
            schema=REQUEST_SECRET_SCHEMA,
            handler=handle_request_secret,
            description=REQUEST_SECRET_SCHEMA["description"],
            emoji="🔐",
        )


def register(ctx: Any) -> None:
    _register_tool(ctx)
    logger.info("secret-handoff: registered request_secret")
