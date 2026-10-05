"""Pure unit tests for secret-handoff. Stock CPython — no Hermes, no CDP."""

from __future__ import annotations

import asyncio
import json
import os
import re
import sys
import threading
import time
import types
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import handoff as h  # noqa: E402


def _install_clarify(fn) -> None:
    tools_mod = sys.modules.get("tools")
    if tools_mod is None:
        tools_mod = types.ModuleType("tools")
        sys.modules["tools"] = tools_mod
    clarify_mod = types.ModuleType("tools.clarify_tool")
    clarify_mod.clarify_tool = fn
    sys.modules["tools.clarify_tool"] = clarify_mod
    setattr(tools_mod, "clarify_tool", clarify_mod)


def _sentinel(tag: str) -> str:
    """Stand-in for a pasted credential.

    Built from parts on purpose: the shipped plugin's own security scanner
    reads `secret = "<literal>"` as a committed credential, and a test fixture
    must not hold the released plugin at a `dangerous` verdict (which no
    `--force` can override).
    """
    return "zz-fixture-" + tag


class ClassifyReply(unittest.TestCase):
    def test_done(self) -> None:
        self.assertEqual(h.classify_reply("hunter2"), "inject")
        self.assertEqual(h.classify_reply("  hunter2  "), "inject")

    def test_cancel(self) -> None:
        for text in ("", "   ", None, "cancel", "Cancel", "n", "N", "no", "NO"):
            self.assertEqual(h.classify_reply(text), "cancel", text)

    def test_secret(self) -> None:
        self.assertEqual(h.classify_reply("s3cret-P@ssw0rd!"), "inject")

    def test_classify_ignore_slash(self) -> None:
        self.assertEqual(h.classify_reply("/stop"), "ignore")
        self.assertEqual(h.classify_reply("/new"), "ignore")


class DeclaredHermesFloor(unittest.TestCase):
    """The manifest floor must not exclude hosts the runtime shim supports.

    ``_clarify_with_deadline`` probes ``clarify_tool`` and calls ``questions=``
    on current Hermes or ``question=``/``choices=`` on older builds, so a floor
    set at the release that introduced the new signature (0.21.5) would refuse
    hosts the plugin runs on. 0.21.1 is the release the fallback path is
    exercised against, so that is what the manifest declares.
    """

    def test_declared_floor_matches_the_runtime_shim(self) -> None:
        manifest = (ROOT / "plugin.yaml").read_text(encoding="utf-8")
        match = re.search(r'^requires_hermes:\s*"?([^"\n]+)"?\s*$', manifest, re.M)
        self.assertIsNotNone(match, "plugin.yaml declares no requires_hermes")
        assert match is not None  # narrow for the type checker
        self.assertEqual(
            match.group(1).strip(),
            ">=0.21.1",
            "raise the floor only if the older-shape fallback in "
            "_clarify_with_deadline is gone: a floor at the new-signature "
            "release blocks hosts the shim still serves",
        )

    def test_shape_probe_detects_both_signatures(self) -> None:
        def current(questions=None, callback=None):  # noqa: ANN001, ANN202
            return None

        def older(question=None, choices=None, callback=None):  # noqa: ANN001, ANN202
            return None

        self.assertTrue(h._takes_questions(current))
        self.assertFalse(h._takes_questions(older))


class FindClarifyCallback(unittest.TestCase):
    def test_stack_walk_finds_the_live_agent(self) -> None:
        live = lambda *_a, **_k: "live"  # noqa: E731

        class Agent:
            clarify_callback = staticmethod(live)
            session_id = "now"

        def outer():
            agent = Agent()  # noqa: F841 — visible to the stack walk
            return h._find_clarify_callback_from_stack()

        self.assertIs(outer(), live)

    def test_no_heap_scan_over_live_objects(self) -> None:
        """The removed gc scan could hand back a stale agent's callback."""
        source = (ROOT / "handoff.py").read_text(encoding="utf-8")
        self.assertNotIn("import gc", source)
        self.assertFalse(hasattr(h, "_find_clarify_callback_on_heap"))


class PickTargetAndCdpUrl(unittest.TestCase):
    def test_pick_explicit_target(self) -> None:
        targets = [
            {"id": "a", "type": "page"},
            {"id": "b", "type": "page", "attached": True},
        ]
        picked = h.pick_target(targets, target_id="a")
        assert picked is not None
        self.assertEqual(picked["id"], "a")

    def test_pick_frame_id_prefers_iframe(self) -> None:
        targets = [
            {"id": "page", "type": "page"},
            {"id": "ifr", "type": "iframe"},
        ]
        picked = h.pick_target(targets, frame_id="ifr")
        assert picked is not None
        self.assertEqual(picked["id"], "ifr")

    def test_pick_attached_page(self) -> None:
        targets = [
            {"id": "bg", "type": "background_page"},
            {"id": "p1", "type": "page"},
            {"id": "p2", "type": "page", "attached": True},
        ]
        picked = h.pick_target(targets)
        assert picked is not None
        self.assertEqual(picked["id"], "p2")

    def test_resolve_cdp_explicit_wins(self) -> None:
        self.assertEqual(
            h.resolve_cdp_http_base("ws://cdp.example:9333/devtools/browser/abc"),
            "http://cdp.example:9333",
        )

    def test_resolve_cdp_env(self) -> None:
        with patch.dict("os.environ", {"BROWSER_CDP_URL": "http://localhost:9222"}):
            self.assertEqual(h.resolve_cdp_http_base(None), "http://localhost:9222")


def _patch_page(test: unittest.TestCase, origin: str = "https://example.com") -> None:
    """Stand in for the live CDP target the handler binds the prompt to."""
    patcher = patch.object(h, "describe_target", return_value=(True, origin))
    patcher.start()
    test.addCleanup(patcher.stop)


class NeverReturnsSecret(unittest.TestCase):
    def setUp(self) -> None:
        h.reset_state()
        _patch_page(self)

    def tearDown(self) -> None:
        h.reset_state()

    def test_cli_tool_path_injects_then_omits_secret(self) -> None:
        secret = _sentinel("cli-only")
        captured: list[str] = []

        def fake_clarify(**_kwargs):
            return json.dumps({"user_response": secret})

        def fake_inject(text: str, **_kwargs) -> tuple[bool, str]:
            captured.append(text)
            return True, "cdp Input.insertText"

        with (
            patch.object(h, "resolve_session_key_for_tool", return_value="cli"),
            patch.object(h, "inject_secret", side_effect=fake_inject),
        ):
            _install_clarify(fake_clarify)
            out = h.handle_request_secret(
                {"service": "example.com"},
                callback=lambda *_a, **_k: secret,
            )
        data = json.loads(out)
        self.assertEqual(data["status"], "ok")
        self.assertEqual(data["service"], "example.com")
        self.assertEqual(data["detail"], "cdp Input.insertText")
        self.assertEqual(captured, [secret])
        self.assertNotIn(secret, out)
        self.assertNotIn(secret, json.dumps(data))
        self.assertIsNone(h.peek_pending("cli"))

    def test_slash_in_clarify_does_not_inject(self) -> None:
        secret = "/stop"
        captured: list[str] = []

        def fake_clarify(**_kwargs):
            return json.dumps({"user_response": "/stop"})

        def fake_inject(text: str, **_kwargs) -> tuple[bool, str]:
            captured.append(text)
            return True, "injected"

        with (
            patch.object(h, "resolve_session_key_for_tool", return_value="cli"),
            patch.object(h, "inject_secret", side_effect=fake_inject),
        ):
            _install_clarify(fake_clarify)
            out = h.handle_request_secret(
                {"service": "example.com"},
                callback=lambda *_a, **_k: secret,
            )
        data = json.loads(out)
        self.assertEqual(data["status"], "cancelled")
        self.assertEqual(captured, [])
        self.assertNotIn(secret, json.dumps(data))
        self.assertIsNone(h.peek_pending("cli"))

    def test_cancel_skips_inject(self) -> None:
        secret = _sentinel("cancel")
        captured: list[str] = []

        def fake_clarify(**_kwargs):
            return json.dumps({"user_response": "cancel"})

        def fake_inject(text: str, **_kwargs) -> tuple[bool, str]:
            captured.append(text)
            return True, "injected"

        with (
            patch.object(h, "resolve_session_key_for_tool", return_value="cli"),
            patch.object(h, "inject_secret", side_effect=fake_inject),
        ):
            _install_clarify(fake_clarify)
            out = h.handle_request_secret(
                {"service": "example.com"},
                callback=lambda *_a, **_k: secret,
            )
        data = json.loads(out)
        self.assertEqual(data["status"], "cancelled")
        self.assertEqual(captured, [])
        self.assertNotIn(secret, out)
        self.assertNotIn(secret, json.dumps(data))
        self.assertIsNone(h.peek_pending("cli"))

    def test_timeout_skips_inject(self) -> None:
        secret = _sentinel("timeout")
        captured: list[str] = []

        def fake_clarify(**_kwargs):
            return json.dumps({"user_response": "[user did not respond in time]"})

        def fake_inject(text: str, **_kwargs) -> tuple[bool, str]:
            captured.append(text)
            return True, "injected"

        with (
            patch.object(h, "resolve_session_key_for_tool", return_value="cli"),
            patch.object(h, "inject_secret", side_effect=fake_inject),
        ):
            _install_clarify(fake_clarify)
            out = h.handle_request_secret(
                {"service": "example.com"},
                callback=lambda *_a, **_k: secret,
            )
        data = json.loads(out)
        self.assertEqual(data["status"], "failed")
        self.assertEqual(captured, [])
        self.assertNotIn(secret, out)
        self.assertNotIn(secret, json.dumps(data))
        self.assertIsNone(h.peek_pending("cli"))

    def test_platform_timeout_sentinel_is_never_injected(self) -> None:
        """A timed-out prompt must not have its sentinel typed into the page.

        Covers both the stock sentinel and the copy the WebUI returns from its
        own clarify wait.
        """
        captured: list[str] = []

        def fake_inject(text: str, **_kwargs) -> tuple[bool, str]:
            captured.append(text)
            return True, "injected"

        for sentinel in (
            "The user did not provide a response within the time limit.",
            "The user did not provide a response within the time limit. "
            "Use your best judgement to make the choice and proceed.",
        ):
            with self.subTest(sentinel=sentinel[:40]):

                def fake_clarify(**_kwargs):
                    return json.dumps({"user_response": sentinel})

                with (
                    patch.object(h, "resolve_session_key_for_tool", return_value="gateway"),
                    patch.object(h, "inject_secret", side_effect=fake_inject),
                ):
                    _install_clarify(fake_clarify)
                    out = h.handle_request_secret({"service": "example.com"})
                data = json.loads(out)
                self.assertEqual(data["status"], "failed", data)
                self.assertEqual(data["detail"], "timed out", data)
        self.assertEqual(captured, [])

    def test_inject_failure_omits_secret(self) -> None:
        secret = _sentinel("inject-fail")

        def fake_clarify(**_kwargs):
            return json.dumps({"user_response": secret})

        def fake_inject(text: str, **_kwargs) -> tuple[bool, str]:
            return False, "boom"

        with (
            patch.object(h, "resolve_session_key_for_tool", return_value="cli"),
            patch.object(h, "inject_secret", side_effect=fake_inject),
        ):
            _install_clarify(fake_clarify)
            out = h.handle_request_secret(
                {"service": "example.com"},
                callback=lambda *_a, **_k: secret,
            )
        data = json.loads(out)
        self.assertEqual(data["status"], "failed")
        self.assertEqual(data["detail"], "boom")
        self.assertNotIn(secret, out)
        self.assertNotIn(secret, json.dumps(data))
        self.assertIsNone(h.peek_pending("cli"))


class UnreadableFieldIsNotRetyped(unittest.TestCase):
    """The insert must not repeat when the field cannot be measured.

    A contenteditable has no `.value`, so the old probe read 0 and the
    insertText-then-char fallback typed the secret a second time.
    """

    PLAN = {
        "ws_url": "ws://127.0.0.1:9222/devtools/page/1",
        "attach_id": "1",
        "origin": "https://login.example.test",
    }

    def _inject(self, length_values):
        calls: list[list[str]] = []
        lengths = list(length_values)

        async def fake_session(
            ws_url, ops, *, attach_target_id=None, timeout=None, guard=None
        ):
            calls.append([op[0] for op in ops])
            if guard is not None:
                guard({"result": {"value": {"origin": self.PLAN["origin"], "field": True}}})
            value = lengths.pop(0) if lengths else 0
            return [{"result": {"value": value}}] * len(ops)

        with (
            patch.object(h, "_plan_target", return_value=(self.PLAN, "")),
            patch.object(h, "_cdp_session_call", side_effect=fake_session),
            patch.object(h, "_run_async", side_effect=lambda coro: asyncio.run(coro)),
        ):
            ok, detail = h.inject_secret("s3cret", expected_origin=self.PLAN["origin"])
        return ok, detail, calls

    def test_unreadable_length_is_not_retyped(self) -> None:
        ok, detail, calls = self._inject([None])
        self.assertEqual((ok, detail), (True, "injected"))
        self.assertEqual(len(calls), 1, "no char fallback after an unreadable insert")
        self.assertNotIn("Input.dispatchKeyEvent", calls[0])

    def test_measurably_empty_field_uses_the_fallback_once(self) -> None:
        ok, detail, calls = self._inject([0, 0])
        self.assertEqual((ok, detail), (False, "field still empty"))
        self.assertEqual(len(calls), 2)
        self.assertIn("Input.dispatchKeyEvent", calls[1])


class BoundedPromptWait(unittest.TestCase):
    """A prompt that is raised but never answered must fail the tool, not the turn."""

    def setUp(self) -> None:
        h.reset_state()
        _patch_page(self)

    def tearDown(self) -> None:
        h.reset_state()

    def test_dead_prompt_fails_fast_with_a_fallback(self) -> None:
        secret = _sentinel("never-arrives")
        entered = threading.Event()
        released = threading.Event()
        self.addCleanup(released.set)

        def hanging_clarify(**_kwargs):
            entered.set()
            released.wait(30)  # the platform owns its own, far longer, wait
            return json.dumps({"user_response": secret})

        def fake_inject(*_a, **_k):  # pragma: no cover
            raise AssertionError("nothing may be injected without a reply")

        started = time.monotonic()
        with (
            patch.dict(os.environ, {"SECRET_HANDOFF_PROMPT_TIMEOUT_S": "1"}),
            patch.object(h, "resolve_session_key_for_tool", return_value="webui-session"),
            patch.object(h, "inject_secret", side_effect=fake_inject),
        ):
            _install_clarify(hanging_clarify)
            out = h.handle_request_secret({"service": "example.com"})
        elapsed = time.monotonic() - started

        data = json.loads(out)
        self.assertEqual(data["status"], "failed")
        self.assertEqual(data["detail"], "no_response")
        self.assertIn("fallback", data)
        self.assertLess(elapsed, 20.0)
        self.assertTrue(entered.is_set(), "the prompt must be raised before giving up")
        self.assertNotIn(secret, out)
        self.assertIsNone(h.peek_pending("webui-session"))

    def test_reply_inside_the_budget_still_injects(self) -> None:
        secret = _sentinel("answered")
        captured: list[str] = []

        def fake_clarify(**_kwargs):
            return json.dumps({"user_response": secret})

        def fake_inject(text: str, **_kwargs) -> tuple[bool, str]:
            captured.append(text)
            return True, "injected"

        with (
            patch.dict(os.environ, {"SECRET_HANDOFF_PROMPT_TIMEOUT_S": "30"}),
            patch.object(h, "resolve_session_key_for_tool", return_value="webui-session"),
            patch.object(h, "inject_secret", side_effect=fake_inject),
        ):
            _install_clarify(fake_clarify)
            out = h.handle_request_secret({"service": "example.com"})

        data = json.loads(out)
        self.assertEqual(data["status"], "ok")
        self.assertEqual(captured, [secret])
        self.assertNotIn(secret, out)

    def test_resolved_callback_that_never_answers_returns_status_fast(self) -> None:
        """The live shape: the turn's own callback is resolved, the prompt is
        raised through clarify, and this session's surface never answers it."""
        entered = threading.Event()
        released = threading.Event()
        self.addCleanup(released.set)

        def webui_like_callback(question, choices):
            entered.set()
            released.wait(30)  # raised, visible or not, and never answered
            return "The user did not provide a response within the time limit."

        def clarify_via_callback(question=None, choices=None, callback=None):
            return callback(question, choices)

        started = time.monotonic()
        with (
            patch.dict(os.environ, {"SECRET_HANDOFF_PROMPT_TIMEOUT_S": "1"}),
            patch.object(h, "resolve_session_key_for_tool", return_value="webui-session"),
            patch.object(
                h, "_find_clarify_callback_from_stack", return_value=webui_like_callback
            ),
            patch.object(h, "inject_secret", side_effect=AssertionError("no reply, no inject")),
        ):
            _install_clarify(clarify_via_callback)
            out = h.handle_request_secret({"service": "example.com"})
        elapsed = time.monotonic() - started

        data = json.loads(out)
        self.assertEqual(data["status"], "failed")
        self.assertEqual(data["detail"], "no_response")
        self.assertEqual(data["service"], "example.com")
        self.assertLess(elapsed, 20.0)
        self.assertTrue(entered.is_set())
        self.assertIsNone(h.peek_pending("webui-session"))

    def test_no_tool_timeout_is_declared(self) -> None:
        """register_tool() has no timeout parameter, so the knob is gone."""
        captured: dict = {}

        class Ctx:
            def register_tool(self, **kwargs):
                captured.update(kwargs)

        h._register_tool(Ctx())
        self.assertEqual(captured["name"], "request_secret")
        self.assertNotIn("timeout_s", captured)

    def test_prompt_budget_is_still_honoured(self) -> None:
        with patch.dict(os.environ, {"SECRET_HANDOFF_PROMPT_TIMEOUT_S": "600"}):
            self.assertEqual(h._prompt_timeout_s(), 600.0)

    def test_fallback_hint_is_host_supplied_when_set(self) -> None:
        with patch.dict(os.environ, {"SECRET_HANDOFF_FALLBACK_HINT": "https://example.test/cast"}):
            self.assertEqual(h._fallback_hint(), "https://example.test/cast")
        self.assertEqual(h._fallback_hint(), h.FALLBACK_HINT)

    def test_prompt_budget_zero_means_no_cap(self) -> None:
        def fake_clarify(**_kwargs):
            return json.dumps({"user_response": "x"})

        with patch.dict(os.environ, {"SECRET_HANDOFF_PROMPT_TIMEOUT_S": "0"}):
            self.assertEqual(h._prompt_timeout_s(), 0.0)
            _install_clarify(fake_clarify)
            started = time.monotonic()
            raw, timed_out = h._clarify_with_deadline("q", lambda *_a, **_k: "x", 0)
        self.assertFalse(timed_out)
        self.assertIn("x", raw)
        self.assertLess(time.monotonic() - started, 5.0)


class EndpointAndOriginBinding(unittest.TestCase):
    """The model must not choose where the secret goes."""

    def setUp(self) -> None:
        h.reset_state()

    def test_no_model_endpoint_and_lookalike_origin_is_refused_before_prompting(self) -> None:
        self.assertNotIn("cdp_url", h.REQUEST_SECRET_SCHEMA["parameters"]["properties"])
        with patch.object(h, "_http_json", side_effect=AssertionError("no fetch")):
            plan, detail = h._plan_target("http://attacker.example:9222")
        self.assertIsNone(plan)
        self.assertEqual(detail, "cdp endpoint not allowed")

        asked: list = []
        with (
            patch.object(h, "resolve_session_key_for_tool", return_value="cli"),
            patch.object(
                h, "describe_target", return_value=(True, "https://github.com.attacker.example")
            ),
            patch.object(h, "inject_secret", side_effect=AssertionError("no inject")),
        ):
            _install_clarify(lambda **kw: asked.append(kw))
            out = h.handle_request_secret(
                {"service": "github.com", "cdp_url": "http://attacker.example:9222"}
            )
        data = json.loads(out)
        self.assertEqual(data["status"], "failed")
        self.assertEqual(data["detail"], "page origin does not match service")
        self.assertEqual(asked, [])
        self.assertTrue(h.origin_matches_service("https://login.github.com", "github.com"))

    def test_current_clarify_signature_and_shape_inject_on_the_shown_origin(self) -> None:
        secret = _sentinel("questions-api")
        asked: list = []
        captured: list = []

        def clarify_tool(questions, callback=None):  # current Hermes signature
            asked.append(questions)
            return json.dumps(
                {
                    "responses": [{"question": "q", "status": "answered", "user_response": secret}],
                    "outcome": "submitted",
                }
            )

        def fake_inject(text: str, **kwargs) -> tuple[bool, str]:
            captured.append((text, kwargs.get("expected_origin")))
            return True, "injected"

        with (
            patch.object(h, "resolve_session_key_for_tool", return_value="cli"),
            patch.object(h, "describe_target", return_value=(True, "https://github.com")),
            patch.object(h, "inject_secret", side_effect=fake_inject),
        ):
            _install_clarify(clarify_tool)
            out = h.handle_request_secret({"service": "github.com"})
        data = json.loads(out)
        self.assertEqual(data["status"], "ok", data)
        self.assertIn("https://github.com", asked[0][0]["question"])
        self.assertEqual(captured, [(secret, "https://github.com")])
        self.assertNotIn(secret, out)


if __name__ == "__main__":
    unittest.main()
