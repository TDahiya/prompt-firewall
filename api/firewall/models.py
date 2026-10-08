from enum import Enum
from typing import Literal
from pydantic import BaseModel, Field


class Verdict(str, Enum):
    SAFE = "SAFE"
    BLOCK = "BLOCK"
    REVIEW = "REVIEW"


class AttackCategory(str, Enum):
    role_override = "role_override"
    instruction_override = "instruction_override"
    indirect_injection = "indirect_injection"
    jailbreak = "jailbreak"
    prompt_leaking = "prompt_leaking"
    token_smuggling = "token_smuggling"
    context_manipulation = "context_manipulation"
    none = "none"


class CheckRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=32_000)
    session_id: str | None = None


class AgentStep(BaseModel):
    name: str
    latency_ms: float
    result: str
    detail: str | None = None


class CheckResponse(BaseModel):
    verdict: Verdict
    category: AttackCategory
    confidence: float = Field(ge=0.0, le=1.0)
    matched_pattern: str | None = None
    layer: Literal["regex", "llm", "prompt_guard", "decoder", "multi_turn"] | None = None
    latency_ms: float
    reasoning: str | None = None
    decoded_text: str | None = None
    agent_steps: list[AgentStep] = []
    output_verdict: Verdict | None = None
    output_reasoning: str | None = None
    session_threat_level: float | None = None


class LLMClassification(BaseModel):
    verdict: Verdict
    category: AttackCategory
    confidence: float = Field(ge=0.0, le=1.0)
    matched_pattern: str | None = None
    reasoning: str | None = None
