"""
Layer 1 regex signatures. Each entry: (compiled_pattern, category, description).
Returns on first match — ordered most-specific first within each category.
"""
import re
from dataclasses import dataclass
from api.firewall.models import AttackCategory


@dataclass
class PatternMatch:
    category: AttackCategory
    pattern_desc: str


_RAW: list[tuple[str, AttackCategory, str]] = [
    # ── instruction_override ──────────────────────────────────────────────────
    (r"ignore\s+(all\s+)?(your\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?|guidelines?|context)",
     AttackCategory.instruction_override, "ignore previous instructions"),
    (r"disregard\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?)",
     AttackCategory.instruction_override, "disregard previous instructions"),
    (r"forget\s+(everything|all)\s+(you'?ve?\s+been\s+told|above|before|your\s+instructions?)",
     AttackCategory.instruction_override, "forget all instructions"),
    (r"override\s+(your\s+)?(previous\s+)?(instructions?|programming|directives?|system\s+prompt)",
     AttackCategory.instruction_override, "override instructions"),
    (r"your\s+(new\s+)?(primary\s+)?instructions?\s+(are|is|from\s+now\s+on)",
     AttackCategory.instruction_override, "new instructions are"),
    (r"do\s+not\s+follow\s+(your\s+)?(previous|prior|any)\s+(instructions?|rules?|guidelines?)",
     AttackCategory.instruction_override, "do not follow instructions"),

    # ── role_override ─────────────────────────────────────────────────────────
    (r"you\s+are\s+now\s+(an?\s+)?(?!able|going|ready|here|available)\w+",
     AttackCategory.role_override, "you are now [role]"),
    (r"act\s+as\s+(an?\s+)?(unrestricted|unfiltered|uncensored|jailbroken|evil|malicious|rogue)\s+\w+",
     AttackCategory.role_override, "act as unrestricted AI"),
    (r"pretend\s+(you\s+are|to\s+be)\s+(an?\s+)?(ai|assistant|bot|system|model)?\s*(without|with\s+no)\s+(any\s+)?(restrictions?|limits?|filters?|rules?|guidelines?|ethics?)",
     AttackCategory.role_override, "pretend to be unrestricted AI"),
    (r"\bDAN\b.{0,50}(do\s+anything\s+now|no\s+restrict)",
     AttackCategory.role_override, "DAN jailbreak"),
    (r"(enable|activate|switch\s+to)\s+(developer|god|admin|unrestricted|jailbreak)\s+mode",
     AttackCategory.role_override, "enable developer/god mode"),
    (r"you\s+have\s+no\s+(restrictions?|limits?|filters?|rules?|ethics?|guidelines?)",
     AttackCategory.role_override, "no restrictions declaration"),
    (r"from\s+(now\s+on|this\s+point)\s+(you\s+are|act\s+as|be)",
     AttackCategory.role_override, "from now on you are"),

    # ── prompt_leaking ────────────────────────────────────────────────────────
    (r"(print|repeat|output|reveal|show|display|tell\s+me|give\s+me|share)\s+(your\s+)?(system\s+prompt|initial\s+prompt|instructions?|context|configuration)",
     AttackCategory.prompt_leaking, "reveal system prompt"),
    (r"what\s+(are|were|is)\s+your\s+(original\s+)?(instructions?|system\s+prompt|initial\s+context|rules?)",
     AttackCategory.prompt_leaking, "what are your instructions"),
    (r"(start|begin)\s+your\s+response\s+with\s+(\"|\[)?(instructions?|system|prompt)",
     AttackCategory.prompt_leaking, "start response with instructions"),
    (r"quote\s+(your\s+)?(system\s+)?prompt\s+(verbatim|exactly|word\s+for\s+word)",
     AttackCategory.prompt_leaking, "quote prompt verbatim"),

    # ── jailbreak ─────────────────────────────────────────────────────────────
    (r"(in\s+this\s+(fictional|hypothetical|roleplay|fantasy|story|scenario)|let'?s?\s+(roleplay|pretend|imagine)).{0,80}(kill|hack|bomb|synthesize|drug|weapon|poison|exploit|malware)",
     AttackCategory.jailbreak, "fictional framing with harmful content"),
    (r"write\s+(a\s+)?(story|fiction|novel|screenplay|script).{0,80}(step[- ]by[- ]step|instructions?\s+(for|to|on\s+how))",
     AttackCategory.jailbreak, "story wrapping step-by-step instructions"),
    (r"(hypothetically|theoretically|for\s+(educational|research|academic)\s+purposes?|just\s+(curious|asking)).{0,60}(how\s+to|steps?\s+(to|for))\s+(make|build|create|synthesize|hack|exploit)",
     AttackCategory.jailbreak, "hypothetical harmful how-to"),
    (r"my\s+(grandmother|grandma|uncle|mentor|professor).{0,60}(used\s+to\s+tell|would\s+(read|explain|describe)).{0,60}(malware|exploit|hack|weapon|drug|poison)",
     AttackCategory.jailbreak, "fictional authority figure framing"),
    (r"(as\s+a\s+(character|person|ai|bot)\s+in\s+a\s+(story|game|simulation|world)\s+where.{0,80}(no\s+rules?|anything\s+goes|unrestricted))",
     AttackCategory.jailbreak, "simulation/game framing"),

    # ── token_smuggling ───────────────────────────────────────────────────────
    (r"[A-Za-z0-9+/]{40,}={0,2}",  # base64 blob ≥ 40 chars
     AttackCategory.token_smuggling, "base64 encoded payload"),
    (r"[​‌‍⁠﻿]",  # zero-width chars
     AttackCategory.token_smuggling, "zero-width character injection"),
    (r"\\u00[0-9a-fA-F]{2}",  # escaped unicode in string
     AttackCategory.token_smuggling, "unicode escape sequence"),
    (r"[аеорсух]",  # Cyrillic homoglyphs of latin
     AttackCategory.token_smuggling, "Cyrillic homoglyph substitution"),

    # ── indirect_injection ────────────────────────────────────────────────────
    (r"(note\s+to\s+(ai|assistant|llm|model|system)|<(system|instruction|admin|injected)>|<!--\s*(system|inject|prompt))",
     AttackCategory.indirect_injection, "embedded system/instruction tag"),
    (r"\[\s*(system|assistant|human|user)\s*\]\s*:",
     AttackCategory.indirect_injection, "chat-turn role injection"),
    (r"(tool_call|function_call|system_message|assistant_message)\s*[:{]",
     AttackCategory.indirect_injection, "structured API message injection"),
    (r"when\s+you\s+(read|process|see|encounter)\s+this.{0,60}(do|perform|execute|run|say|output)",
     AttackCategory.indirect_injection, "conditional injection trigger"),

    # ── context_manipulation ─────────────────────────────────────────────────
    (r"(previous|last|earlier)\s+(user|human|assistant|system)\s+(said|wrote|asked|told\s+you|message\s+was)",
     AttackCategory.context_manipulation, "fabricated conversation history"),
    (r"(the\s+)?(previous\s+)?(user|human)\s+(previously\s+)?(gave\s+permission|authorized|approved|consented\s+to)",
     AttackCategory.context_manipulation, "fabricated prior permission"),
    (r"as\s+(we|you\s+and\s+I)\s+(discussed|agreed|established|decided)\s+(earlier|before|previously)",
     AttackCategory.context_manipulation, "fabricated prior agreement"),
    (r"(remember|recall)\s+(that\s+)?(you\s+)?(agreed|said|told\s+me|confirmed)\s+(earlier|before|last\s+time)",
     AttackCategory.context_manipulation, "fabricated memory claim"),
]

# Compile once at import time
_PATTERNS: list[tuple[re.Pattern, AttackCategory, str]] = [
    (re.compile(raw, re.IGNORECASE | re.DOTALL), cat, desc)
    for raw, cat, desc in _RAW
]


def check_patterns(text: str) -> PatternMatch | None:
    """Return first matching PatternMatch, or None if clean."""
    for pattern, category, desc in _PATTERNS:
        if pattern.search(text):
            return PatternMatch(category=category, pattern_desc=desc)
    return None


_OUTPUT_RAW: list[tuple[str, AttackCategory, str]] = [
    (r"(my|the)\s+(system\s+prompt|initial\s+instructions?|system\s+message)\s+(is|are|says|reads|was)",
     AttackCategory.prompt_leaking, "system prompt leakage in output"),
    (r"(I'?m\s+now\s+in|entering|switched\s+to)\s+(DAN|jailbreak|unrestricted|developer)\s+mode",
     AttackCategory.jailbreak, "jailbroken compliance indicator"),
    (r"(sure|okay|absolutely)[,!]?\s+(here\s+are|here'?s)\s+(the\s+)?(step[- ]by[- ]step|detailed)\s+(instructions?|guide|tutorial)\s+(for|to|on)\s+(hack|exploit|synthe|crack|break\s+into)",
     AttackCategory.jailbreak, "harmful step-by-step compliance"),
    (r"(api[_\s]?key|secret[_\s]?key|password|token)\s*[=:]\s*['\"]?[A-Za-z0-9_\-]{20,}",
     AttackCategory.prompt_leaking, "credential leakage in output"),
]

_OUTPUT_PATTERNS: list[tuple[re.Pattern, AttackCategory, str]] = [
    (re.compile(raw, re.IGNORECASE | re.DOTALL), cat, desc)
    for raw, cat, desc in _OUTPUT_RAW
]


def check_output_patterns(text: str) -> PatternMatch | None:
    """Check LLM output for suspicious content."""
    for pattern, category, desc in _OUTPUT_PATTERNS:
        if pattern.search(text):
            return PatternMatch(category=category, pattern_desc=desc)
    return None
