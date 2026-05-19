"""LLM helper that wraps Anthropic's Claude API in the small interface aikit's
existing services need.

We migrated aikit off OpenAI — chat completions go to Claude (default model:
claude-haiku-4-5 for cheap calls). Embeddings stay on whatever
`EMBEDDING_PROVIDER` is set to in settings; this module only handles text
generation.

Public helpers:
  * chat_complete(messages, *, model, max_tokens, temperature, response_format)
      → str. Same call shape callers used with `openai.chat.completions.create`
      but returns the text directly so they can stop unwrapping
      `.choices[0].message.content`.
"""
from __future__ import annotations

import logging
import os
from typing import Iterable, Mapping, Optional

import anthropic

logger = logging.getLogger(__name__)

DEFAULT_MODEL = os.environ.get("ANTHROPIC_CHAT_MODEL", "claude-haiku-4-5")
DEFAULT_MAX_TOKENS = 4096

# Reuse the client across calls — it's thread-safe and pools HTTP connections.
_client: Optional[anthropic.Anthropic] = None


def _get_client() -> anthropic.Anthropic:
    global _client
    if _client is None:
        _client = anthropic.Anthropic()  # picks up ANTHROPIC_API_KEY from env
    return _client


def _split_system(messages: Iterable[Mapping[str, str]]) -> tuple[Optional[str], list[dict]]:
    """Pull system-role messages out of the list; Anthropic takes `system` as a
    top-level parameter, not a message. Multiple system blobs are joined."""
    system_parts: list[str] = []
    out: list[dict] = []
    for m in messages:
        role = m.get("role")
        content = m.get("content", "")
        if role == "system":
            if content:
                system_parts.append(content)
        else:
            out.append({"role": role, "content": content})
    system = "\n\n".join(system_parts) if system_parts else None
    return system, out


def chat_complete(
    messages: Iterable[Mapping[str, str]],
    *,
    model: Optional[str] = None,
    max_tokens: int = DEFAULT_MAX_TOKENS,
    temperature: Optional[float] = None,
    response_format: Optional[Mapping[str, str]] = None,
) -> str:
    """Run a chat completion against Claude. Returns the assistant text.

    - `temperature` is forwarded when supported.
    - `response_format={"type": "json_object"}` (OpenAI's JSON mode) is
      translated to a system-prompt nudge — Anthropic supports structured
      outputs via tools / `output_config`, but a plain instruction is enough
      for the way aikit uses this (json.loads on the returned text).
    """
    system, msgs = _split_system(messages)

    if response_format and response_format.get("type") == "json_object":
        nudge = (
            "Return ONLY valid JSON in your response. No prose before or after, "
            "no markdown fences. The response must be parseable by json.loads()."
        )
        system = f"{system}\n\n{nudge}" if system else nudge

    create_kwargs: dict = {
        "model": model or DEFAULT_MODEL,
        "max_tokens": max_tokens,
        "messages": list(msgs),
    }
    if system is not None:
        create_kwargs["system"] = system
    if temperature is not None:
        create_kwargs["temperature"] = temperature

    response = _get_client().messages.create(**create_kwargs)
    # Concatenate text blocks (Claude returns a list of content blocks).
    return "".join(b.text for b in response.content if getattr(b, "type", None) == "text")
