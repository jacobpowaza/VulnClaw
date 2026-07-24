"""OpenCode provider — uses ``opencode run`` subprocess for LLM inference.

No API key needed. Relies on the user's local OpenCode installation which
already has authentication configured via ``/connect`` or ``opencode auth
login``.

How it works
------------
``opencode run --format json`` accepts a single prompt string and returns
newline-delimited JSON (NDJSON) events on stdout.  It does **not** natively
support custom tool schemas or structured message history.

This adapter serialises VulnClaw's ``messages`` + ``tools`` into the prompt
and instructs the model to emit ``{"tool_call": …}`` JSON when it wants to
use a tool.  The JSON is parsed from the text response and mapped back into
standard OpenAI-format tool-call objects so the agent loop works unchanged.

Limitation
----------
Tool calling relies on the model following an instruction to emit structured
JSON rather than native tool-call protocol support.  The ``opencode`` free
models do reliably output ``{"tool_call": …}`` JSON when the instruction is
placed directly in the system prompt (as demonstrated in testing), but the
mechanism is inherently less robust than native tool calling.
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
from types import SimpleNamespace
from typing import Any, Iterator

logger = logging.getLogger(__name__)

DEFAULT_OPENCODE_MODEL = "opencode/deepseek-v4-flash-free"


# ── Prompt building ───────────────────────────────────────────────


def _serialise_tool_call(name: str, arguments: dict | str) -> str:
    """Render a single tool call in the format the model understands."""
    if isinstance(arguments, str):
        arguments = json.loads(arguments)
    return json.dumps({"tool_call": {"name": name, "arguments": arguments}})


def build_prompt(
    messages: list[dict[str, Any]],
    tools: list[dict[str, Any]] | None = None,
) -> str:
    """Serialize messages + tool schemas into a single prompt string.

    Tool descriptions are injected into the system message with an
    instruction to call them via ``{"tool_call": …}`` JSON.
    """
    parts: list[str] = []
    for msg in messages:
        role = msg.get("role", "")
        content = msg.get("content") or ""
        if role == "system":
            sys_text = content
            if tools:
                sys_text += "\n\n## Available tools\n"
                for t in tools:
                    fn = t.get("function", t)
                    sys_text += "\n### %s: %s\n" % (
                        fn["name"], fn.get("description", "")
                    )
                    params = fn.get("parameters", {}).get("properties", {})
                    for pname, pinfo in params.items():
                        desc = pinfo.get("description", "")
                        sys_text += "  - %s: %s\n" % (pname, desc)
                sys_text += (
                    "\nWhen you need to call a tool, respond with exactly:\n"
                    '{"tool_call": {"name": "<tool_name>", "arguments": {…}}}\n'
                    "No other text before or after the JSON. "
                    "Wait for the tool result before continuing.\n"
                )
            parts.append("[System]\n" + sys_text)
        elif role == "user":
            parts.append("[User]\n" + content)
        elif role == "assistant":
            tc = msg.get("tool_calls")
            if tc:
                tc_lines = []
                for c in tc:
                    tc_lines.append(
                        _serialise_tool_call(c.function.name, c.function.arguments)
                    )
                parts.append("[Assistant]\n" + "\n".join(tc_lines))
            else:
                parts.append("[Assistant]\n" + content)
        elif role == "tool":
            parts.append("[Tool result]\n" + content)
    return "\n\n".join(parts)


# ── Subprocess execution ──────────────────────────────────────────


def run_opencode(
    model: str,
    prompt: str,
    *,
    timeout: float = 300.0,
) -> str:
    """Run ``opencode run --format json`` and return stdout."""
    cmd = [
        "opencode",
        "run",
        "--format",
        "json",
        "--model",
        model,
        "--dangerously-skip-permissions",
        prompt,
    ]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
        )
        if result.returncode != 0:
            logger.warning(
                "opencode run failed (exit %d): %s",
                result.returncode, result.stderr.strip(),
            )
        return result.stdout
    except subprocess.TimeoutExpired:
        logger.error("opencode run timed out after %ss", timeout)
        return ""
    except FileNotFoundError:
        logger.error("opencode not found on PATH")
        return ""


# ── Response parsing ──────────────────────────────────────────────


def _balanced_brace_regions(text: str, start: int = 0) -> list[tuple[int, int]]:
    """Find outermost ``{…}`` regions spanning ``tool_call`` at position *start*.

    Yields ``(brace_open, brace_close)`` for each top-level object where
    the ``"tool_call"`` key appears immediately inside the opening brace.
    Nested braces are handled correctly via depth counting.
    """
    regions: list[tuple[int, int]] = []
    i = start
    while i < len(text):
        # Scan for '{' followed by "tool_call"
        if text[i] == "{":
            depth = 1
            j = i + 1
            # peek ahead for key
            while j < len(text) and text[j] in " \t\n\r":
                j += 1
            if j < len(text) and text[j] == '"':
                # extract the key name
                key_end = text.index('"', j + 1) if '"' in text[j + 1:] else -1
                if key_end > j:
                    key = text[j + 1:key_end]
                    if key == "tool_call":
                        # walk to matching close brace
                        k = key_end + 1
                        while k < len(text) and depth > 0:
                            if text[k] == "{":
                                depth += 1
                            elif text[k] == "}":
                                depth -= 1
                            k += 1
                        # k is now past the closing '}'
                        regions.append((i, k - 1))
                        i = k
                        continue
            # Not a tool_call region — walk past this brace group
            k = j
            while k < len(text) and depth > 0:
                if text[k] == "{":
                    depth += 1
                elif text[k] == "}":
                    depth -= 1
                k += 1
            i = k
        else:
            i += 1
    return regions


def _extract_tool_calls(text: str) -> list[dict[str, Any]]:
    """Extract ``{"tool_call": …}`` JSON blocks from model output."""
    results: list[dict[str, Any]] = []
    for start, end in _balanced_brace_regions(text):
        block = text[start:end + 1]
        try:
            obj = json.loads(block)
            tc = obj.get("tool_call")
            if tc and "name" in tc:
                results.append(tc)
        except (json.JSONDecodeError, TypeError):
            continue
    return results


def _strip_tool_call_json(text: str) -> str:
    """Remove ``{"tool_call": …}`` JSON blocks, returning clean text."""
    regions = _balanced_brace_regions(text)
    if not regions:
        return text.strip()
    # Build output skipping the regions (reverse order to avoid index shifts)
    result = list(text)
    for start, end in sorted(regions, reverse=True):
        del result[start:end + 1]
    return "".join(result).strip()


def _clean_stripped_text(text: str) -> str:
    """Remove empty markdown code fences left after stripping tool-call JSON."""
    # Remove ```json followed by optional whitespace then ```
    text = re.sub(
        r'```(?:json)?\s*\n?\s*```\s*',
        "",
        text,
        flags=re.MULTILINE,
    )
    # Remove single remaining backtick fences
    text = re.sub(r'^```.*\n?', "", text, flags=re.MULTILINE)
    return text.strip()


def parse_opencode_output(stdout: str) -> tuple[str, list[dict[str, Any]]]:
    """Parse NDJSON events into (text, tool_calls).

    *text* is the concatenated ``text`` event content with ``{"tool_call":…}``
    blocks removed.  *tool_calls* is a list of ``{"name": …, "arguments": {…}}``.
    """
    text_parts: list[str] = []
    for line in stdout.strip().split("\n"):
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("type") == "text":
            text_parts.append(event.get("part", {}).get("text", ""))

    full_text = "".join(text_parts)
    tool_calls = _extract_tool_calls(full_text)
    clean_text = _strip_tool_call_json(full_text)
    clean_text = _clean_stripped_text(clean_text)
    return clean_text, tool_calls


# ── OpenAI-compatible response types (duck-typed) ─────────────────


def _build_tool_call(tc_id: str, name: str, arguments: str) -> Any:
    """Create a tool-call object matching OpenAI's structure."""
    try:
        from openai.types.chat.chat_completion_message_tool_call import (
            ChatCompletionMessageToolCall,
            Function,
        )
        return ChatCompletionMessageToolCall(
            id=tc_id,
            type="function",
            function=Function(name=name, arguments=arguments),
        )
    except (TypeError, ValueError, AttributeError, ImportError):
        func = SimpleNamespace(name=name, arguments=arguments)
        return SimpleNamespace(id=tc_id, type="function", function=func)


def _build_tool_call_delta(index: int, tc_id: str, name: str, arguments: str) -> Any:
    """Create a streaming tool-call delta matching OpenAI's structure."""
    try:
        from openai.types.chat.chat_completion_chunk import ChoiceDeltaToolCall
        return ChoiceDeltaToolCall(
            index=index,
            id=tc_id,
            function={"name": name, "arguments": arguments},
        )
    except (TypeError, ValueError, AttributeError, ImportError):
        func = SimpleNamespace(name=name, arguments=arguments)
        return SimpleNamespace(index=index, id=tc_id, function=func)


class OpenCodeChatCompletion:
    """Duck-typed non-streaming response matching ``ChatCompletion``."""

    def __init__(
        self,
        content: str,
        tool_calls: list[dict[str, Any]] | None = None,
        model: str = "",
    ):
        tcs = None
        finish_reason = "stop"
        if tool_calls:
            tcs = [
                _build_tool_call(
                    f"call_opencode_{i}",
                    tc["name"],
                    json.dumps(tc.get("arguments", {})),
                )
                for i, tc in enumerate(tool_calls)
            ]
            finish_reason = "tool_calls"
        self.choices = [
            SimpleNamespace(
                index=0,
                message=SimpleNamespace(
                    content=content or "",
                    role="assistant",
                    tool_calls=tcs,
                ),
                finish_reason=finish_reason,
            )
        ]
        self.model = model or "opencode"
        self.id = f"chatcmpl-opencode-{id(self)}"


# ── Streaming ─────────────────────────────────────────────────────


class OpenCodeStream:
    """Iterator yielding OpenAI-format streaming chunks.

    Reads ``opencode run --format json`` line-by-line.  Text events are
    forwarded immediately; ``{"tool_call": …}`` JSON blocks detected in
    the full response are emitted as final delta chunks.
    """

    def __init__(self, model: str, prompt: str, timeout: float = 300.0):
        self._model = model
        self._prompt = prompt
        self._timeout = timeout
        self._buffer: list[str] = []

    def __iter__(self) -> Iterator[Any]:
        return self._stream()

    def _stream(self) -> Any:
        cmd = [
            "opencode", "run", "--format", "json",
            "--model", self._model,
            "--dangerously-skip-permissions",
            self._prompt,
        ]
        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
        except FileNotFoundError:
            logger.error("opencode not found on PATH")
            return

        chunk_id = f"chatcmpl-opencode-{id(self)}"

        for raw_line in proc.stdout or []:
            line = raw_line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if event.get("type") == "text":
                text = event.get("part", {}).get("text", "")
                if text:
                    self._buffer.append(text)
                    yield self._make_chunk(chunk_id, delta_content=text)

        proc.wait()
        full_text = "".join(self._buffer)
        _, tool_calls = parse_opencode_output(full_text)

        if tool_calls:
            for i, tc in enumerate(tool_calls):
                yield self._make_chunk(
                    chunk_id,
                    tool_call_delta=_build_tool_call_delta(
                        i,
                        f"call_opencode_{i}",
                        tc["name"],
                        json.dumps(tc.get("arguments", {})),
                    ),
                )
            yield self._make_chunk(chunk_id, finish_reason="tool_calls")
        else:
            yield self._make_chunk(chunk_id, finish_reason="stop")

    @staticmethod
    def _make_chunk(
        chunk_id: str,
        *,
        delta_content: str | None = None,
        tool_call_delta: Any | None = None,
        finish_reason: str | None = None,
    ) -> Any:
        tool_calls_list = [tool_call_delta] if tool_call_delta else None
        try:
            from openai.types.chat.chat_completion_chunk import (
                Choice, ChoiceDelta,
            )
            delta = ChoiceDelta(
                content=delta_content,
                tool_calls=tool_calls_list,
                role="assistant" if delta_content else None,
            )
            return SimpleNamespace(
                id=chunk_id, model="opencode",
                choices=[Choice(index=0, delta=delta, finish_reason=finish_reason)],
            )
        except (TypeError, ValueError, AttributeError, ImportError):
            delta = SimpleNamespace(
                content=delta_content,
                tool_calls=tool_calls_list,
                role="assistant" if delta_content else None,
            )
            return SimpleNamespace(
                id=chunk_id, model="opencode",
                choices=[SimpleNamespace(
                    index=0, delta=delta, finish_reason=finish_reason,
                )],
            )


# ── Duck-typed client ─────────────────────────────────────────────


class OpenCodeClient:
    """Drop-in replacement for ``openai.OpenAI`` using ``opencode run``."""

    def __init__(self, model: str | None = None):
        self._model = model or DEFAULT_OPENCODE_MODEL
        self._completions = _OpenCodeCompletions(self._model)
        self.api_key = "opencode-local"
        self.base_url = "opencode://local"

    @property
    def chat(self) -> _OpenCodeChat:
        return _OpenCodeChat(self._completions)


class _OpenCodeChat:
    def __init__(self, completions: _OpenCodeCompletions):
        self._completions = completions

    @property
    def completions(self) -> _OpenCodeCompletions:
        return self._completions


class _OpenCodeCompletions:
    def __init__(self, model: str):
        self._model = model

    def create(
        self,
        *,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        stream: bool = False,
        **kwargs: Any,
    ) -> OpenCodeChatCompletion | OpenCodeStream:
        prompt = build_prompt(messages, tools)
        if stream:
            return OpenCodeStream(self._model, prompt)
        stdout = run_opencode(self._model, prompt)
        text, tool_calls = parse_opencode_output(stdout)
        return OpenCodeChatCompletion(text, tool_calls, model=self._model)


# ── Model discovery ───────────────────────────────────────────────


def discover_models(extra_models: list[str] | None = None) -> list[str]:
    """Return available model names from the local OpenCode installation.

    *extra_models* are merged into the returned list (deduplicated) so
    that users can advertise custom or locally-connected models that
    ``opencode models`` does not report.
    """
    discovered: list[str] = []
    try:
        result = subprocess.run(
            ["opencode", "models"],
            capture_output=True, text=True, timeout=15.0,
        )
        if result.returncode == 0:
            discovered = [
                line.strip()
                for line in result.stdout.strip().split("\n")
                if line.strip() and "/" in line
            ]
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    if not discovered:
        logger.warning("opencode models failed; falling back to static list")
        discovered = [
            "opencode/big-pickle",
            "opencode/deepseek-v4-flash-free",
            "opencode/laguna-s-2.1-free",
            "opencode/ling-3.0-flash-free",
            "opencode/mimo-v2.5-free",
            "opencode/nemotron-3-ultra-free",
            "opencode/north-mini-code-free",
        ]

    if extra_models:
        seen = set(discovered)
        for m in extra_models:
            if m not in seen:
                discovered.append(m)
                seen.add(m)
    return discovered


def is_opencode_available() -> bool:
    """Return True if the ``opencode`` CLI is installed."""
    try:
        result = subprocess.run(
            ["opencode", "--version"],
            capture_output=True, text=True, timeout=10.0,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False
