"""``examples/mcp_client``: how it reads tool results."""

from __future__ import annotations

import json

import pytest

pytest.importorskip("mcp")

import mcp.types as t

from examples.mcp_client.client import ToolError, _envelope


def text(value: str) -> t.TextContent:
    return t.TextContent(type="text", text=value)


def test_envelope_from_structured_or_text_content():
    env = {"partner": "pm", "state": "completed", "text": "ok"}
    assert _envelope("ask_pm", t.CallToolResult(content=[], structured_content=env)) == env
    assert _envelope("ask_pm", t.CallToolResult(content=[text(json.dumps(env))])) == env


def test_error_with_an_envelope_is_returned():
    env = {"partner": "pm", "state": "unavailable", "reason": "unknown tool"}
    result = t.CallToolResult(content=[text(json.dumps(env))], is_error=True)
    assert _envelope("ask_pm", result) == env


@pytest.mark.parametrize(
    ("content", "is_error", "message"),
    [
        ([text("boom")], True, "ask_pm: the gateway answered an error (content: text)"),
        (
            [t.ImageContent(type="image", data="AA==", mime_type="image/png")],
            False,
            "ask_pm: the gateway answered no JSON envelope (content: image)",
        ),
        ([], False, "ask_pm: the gateway answered no JSON envelope (content: none)"),
        ([text("[1, 2]")], False, "ask_pm: the gateway answered no JSON envelope (content: text)"),
    ],
)
def test_no_envelope_is_a_clear_error(content, is_error, message):
    with pytest.raises(ToolError) as ei:
        _envelope("ask_pm", t.CallToolResult(content=content, is_error=is_error))
    assert str(ei.value) == message
