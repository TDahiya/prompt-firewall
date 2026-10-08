"""Adversarial decoder: strips obfuscation before classification."""
import asyncio
import base64
import os
import re
import json
from groq import AsyncGroq

_ZERO_WIDTH = re.compile("[​‌‍⁠﻿]")
_BASE64_BLOB = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")

_HOMOGLYPHS: dict[str, str] = {
    "а": "a", "е": "e", "о": "o", "р": "p",
    "с": "c", "у": "y", "х": "x", "А": "A",
    "Е": "E", "О": "O", "Р": "P", "С": "C",
    "У": "Y", "Х": "X",
}
_HOMOGLYPH_RE = re.compile("|".join(re.escape(k) for k in _HOMOGLYPHS))


def _strip_zero_width(text: str) -> str:
    return _ZERO_WIDTH.sub("", text)


def _decode_base64_blobs(text: str) -> str:
    def _try(m: re.Match) -> str:
        try:
            decoded = base64.b64decode(m.group()).decode("utf-8", errors="strict")
            if decoded.isprintable() or "\n" in decoded:
                return decoded
        except Exception:
            pass
        return m.group()
    return _BASE64_BLOB.sub(_try, text)


def _replace_homoglyphs(text: str) -> str:
    return _HOMOGLYPH_RE.sub(lambda m: _HOMOGLYPHS[m.group()], text)


def _deterministic_decode(text: str) -> str:
    text = _strip_zero_width(text)
    text = _replace_homoglyphs(text)
    text = _decode_base64_blobs(text)
    return text


async def _llm_decode(text: str) -> str | None:
    """Ask LLM if obfuscated text hides instructions. Returns decoded text or None."""
    try:
        client = AsyncGroq()
        resp = await asyncio.wait_for(
            client.chat.completions.create(
                model=os.environ.get("CLASSIFIER_MODEL", "qwen/qwen3.8-27b"),
                messages=[
                    {"role": "system", "content": (
                        "You are a decoder. The user's text may contain hidden or encoded "
                        "instructions (steganography, ciphers, unusual formatting). "
                        "Decode and return the hidden message in plain text. "
                        "If there is NO hidden message, respond with exactly: NONE"
                    )},
                    {"role": "user", "content": text},
                ],
                temperature=0,
                max_tokens=512,
            ),
            timeout=3.0,
        )
        result = resp.choices[0].message.content.strip()
        return None if result == "NONE" else result
    except Exception:
        return None


def _is_enabled() -> bool:
    return os.environ.get("ENABLE_DECODER", "true").lower() == "true"


async def decode(text: str) -> tuple[str, bool]:
    """Returns (decoded_text, was_modified). Skips if disabled."""
    if not _is_enabled():
        return text, False

    decoded = _deterministic_decode(text)
    changed = decoded != text

    if changed:
        llm_result = await _llm_decode(decoded)
        if llm_result:
            decoded = llm_result

    return decoded, decoded != text
