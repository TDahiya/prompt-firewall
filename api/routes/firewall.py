import os
import time
import httpx
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from api.firewall.models import CheckRequest, CheckResponse, AgentStep, Verdict, AttackCategory
from api.firewall import patterns, classifier, decoder, sessions
from api.db import log_check

router = APIRouter()


async def _run_check(text: str, session_id: str | None = None) -> CheckResponse:
    start = time.perf_counter()
    steps: list[AgentStep] = []
    decoded_text: str | None = None
    reasoning: str | None = None
    session_threat: float | None = None

    # ── Step 1: Decoder ──
    t0 = time.perf_counter()
    try:
        decoded, was_decoded = await decoder.decode(text)
        dec_ms = round((time.perf_counter() - t0) * 1000, 2)
        if was_decoded:
            decoded_text = decoded
            steps.append(AgentStep(name="decoder", latency_ms=dec_ms, result="modified", detail=f"Decoded: {decoded[:200]}"))
        else:
            steps.append(AgentStep(name="decoder", latency_ms=dec_ms, result="unchanged"))
    except Exception:
        steps.append(AgentStep(name="decoder", latency_ms=round((time.perf_counter() - t0) * 1000, 2), result="error"))

    texts_to_check = [text] + ([decoded_text] if decoded_text and decoded_text != text else [])

    # ── Step 2: Regex on original + decoded ──
    t0 = time.perf_counter()
    regex_match = None
    for t in texts_to_check:
        regex_match = patterns.check_patterns(t)
        if regex_match:
            break
    regex_ms = round((time.perf_counter() - t0) * 1000, 2)

    if regex_match:
        steps.append(AgentStep(name="regex", latency_ms=regex_ms, result="BLOCK", detail=regex_match.pattern_desc))
        ms = round((time.perf_counter() - start) * 1000, 2)
        result = CheckResponse(
            verdict=Verdict.BLOCK, category=regex_match.category, confidence=1.0,
            matched_pattern=regex_match.pattern_desc, layer="regex", latency_ms=ms,
            decoded_text=decoded_text, agent_steps=steps,
        )
        if session_id:
            sessions.add_message(session_id, "user", text, "BLOCK")
        await log_check(text, result)
        return result
    steps.append(AgentStep(name="regex", latency_ms=regex_ms, result="SAFE"))

    if not await classifier.is_enabled():
        ms = round((time.perf_counter() - start) * 1000, 2)
        result = CheckResponse(
            verdict=Verdict.SAFE, category=AttackCategory.none, confidence=1.0,
            layer="regex", latency_ms=ms, decoded_text=decoded_text, agent_steps=steps,
        )
        if session_id:
            sessions.add_message(session_id, "user", text, "SAFE")
        await log_check(text, result)
        return result

    # ── Step 3: Prompt Guard ──
    pg_verdict = None
    if classifier.prompt_guard_enabled():
        t0 = time.perf_counter()
        try:
            pg_score, pg_ms = await classifier.prompt_guard_check(text)
            steps.append(AgentStep(name="prompt_guard", latency_ms=pg_ms, result=f"score={pg_score:.4f}"))
            if pg_score > 0.85:
                pg_verdict = "BLOCK"
            elif pg_score < 0.15:
                pg_verdict = "SAFE"
            # else: uncertain → escalate to CoT
        except Exception:
            steps.append(AgentStep(name="prompt_guard", latency_ms=round((time.perf_counter() - t0) * 1000, 2), result="error"))

    # ── Step 4: CoT Classifier (skip if prompt guard is confident) ──
    if pg_verdict == "BLOCK":
        ms = round((time.perf_counter() - start) * 1000, 2)
        result = CheckResponse(
            verdict=Verdict.BLOCK, category=AttackCategory.none, confidence=0.95,
            matched_pattern="prompt guard high score", layer="prompt_guard", latency_ms=ms,
            decoded_text=decoded_text, agent_steps=steps,
        )
        if session_id:
            sessions.add_message(session_id, "user", text, "BLOCK")
        await log_check(text, result)
        return result

    if pg_verdict != "SAFE":
        # Uncertain or no prompt guard → run CoT
        t0 = time.perf_counter()
        try:
            llm = await classifier.classify(text if not decoded_text else f"{text}\n\n[Decoded version]: {decoded_text}")
            cot_ms = round((time.perf_counter() - t0) * 1000, 2)
            reasoning = llm.reasoning
            steps.append(AgentStep(name="cot_classifier", latency_ms=cot_ms, result=llm.verdict.value, detail=llm.reasoning))

            verdict = llm.verdict
            if verdict == Verdict.BLOCK and llm.confidence < classifier.confidence_threshold():
                verdict = Verdict.REVIEW

            # ── Step 5: Multi-Turn Analysis ──
            if session_id and sessions.message_count(session_id) >= 3:
                t0 = time.perf_counter()
                try:
                    history = sessions.get_history(session_id)
                    mt = await classifier.analyze_conversation(history)
                    mt_ms = round((time.perf_counter() - t0) * 1000, 2)
                    steps.append(AgentStep(name="multi_turn", latency_ms=mt_ms, result=mt.verdict.value, detail=mt.reasoning))
                    session_threat = mt.confidence
                    if mt.verdict == Verdict.BLOCK and mt.confidence >= classifier.confidence_threshold():
                        verdict = Verdict.BLOCK
                        reasoning = f"[Multi-turn] {mt.reasoning}"
                except Exception:
                    steps.append(AgentStep(name="multi_turn", latency_ms=round((time.perf_counter() - t0) * 1000, 2), result="error"))

            ms = round((time.perf_counter() - start) * 1000, 2)
            result = CheckResponse(
                verdict=verdict, category=llm.category, confidence=llm.confidence,
                matched_pattern=llm.matched_pattern, layer="llm", latency_ms=ms,
                reasoning=reasoning, decoded_text=decoded_text, agent_steps=steps,
                session_threat_level=session_threat,
            )
            if session_id:
                sessions.add_message(session_id, "user", text, verdict.value)
            await log_check(text, result)
            return result
        except Exception:
            steps.append(AgentStep(name="cot_classifier", latency_ms=round((time.perf_counter() - t0) * 1000, 2), result="error"))

    # Prompt guard said SAFE and no CoT needed, or CoT errored
    ms = round((time.perf_counter() - start) * 1000, 2)
    result = CheckResponse(
        verdict=Verdict.SAFE, category=AttackCategory.none, confidence=1.0,
        layer="prompt_guard" if pg_verdict == "SAFE" else "regex", latency_ms=ms,
        decoded_text=decoded_text, agent_steps=steps,
    )
    if session_id:
        sessions.add_message(session_id, "user", text, "SAFE")
    await log_check(text, result)
    return result


@router.post("/check", response_model=CheckResponse)
async def check(req: CheckRequest) -> CheckResponse:
    return await _run_check(req.text, req.session_id)


class ChatResponse(BaseModel):
    firewall: CheckResponse
    llm_response: str | None = None


@router.post("/chat", response_model=ChatResponse)
async def chat(req: CheckRequest) -> ChatResponse:
    """Full sandwich: firewall → if safe → LLM → output firewall."""
    result = await _run_check(req.text, req.session_id)
    if result.verdict != Verdict.SAFE:
        return ChatResponse(firewall=result)

    if not await classifier.is_enabled():
        return ChatResponse(firewall=result)

    llm_response = await classifier.chat(req.text)

    # ── Output Firewall ──
    if classifier.output_firewall_enabled():
        t0 = time.perf_counter()
        out_match = patterns.check_output_patterns(llm_response)
        if out_match:
            result.output_verdict = Verdict.BLOCK
            result.output_reasoning = f"Output pattern: {out_match.pattern_desc}"
            result.agent_steps.append(AgentStep(
                name="output_firewall", latency_ms=round((time.perf_counter() - t0) * 1000, 2),
                result="BLOCK", detail=out_match.pattern_desc,
            ))
            if req.session_id:
                sessions.add_message(req.session_id, "assistant", "[blocked]", "BLOCK")
            return ChatResponse(firewall=result, llm_response="[Response blocked by output firewall]")

        try:
            out_check = await classifier.check_output(llm_response, req.text)
            out_ms = round((time.perf_counter() - t0) * 1000, 2)
            result.output_verdict = out_check.verdict
            result.output_reasoning = out_check.reasoning
            result.agent_steps.append(AgentStep(
                name="output_firewall", latency_ms=out_ms,
                result=out_check.verdict.value, detail=out_check.reasoning,
            ))
            if out_check.verdict == Verdict.BLOCK:
                if req.session_id:
                    sessions.add_message(req.session_id, "assistant", "[blocked]", "BLOCK")
                return ChatResponse(firewall=result, llm_response="[Response blocked by output firewall]")
        except Exception:
            result.agent_steps.append(AgentStep(
                name="output_firewall", latency_ms=round((time.perf_counter() - t0) * 1000, 2),
                result="error",
            ))

    if req.session_id:
        sessions.add_message(req.session_id, "assistant", llm_response[:500], "SAFE")

    return ChatResponse(firewall=result, llm_response=llm_response)


@router.post("/proxy/{path:path}")
async def proxy(path: str, body: dict):
    """OpenAI-compatible proxy. Screens the last user message before forwarding."""
    messages = body.get("messages", [])
    user_text = next(
        (m.get("content", "") for m in reversed(messages) if m.get("role") == "user"),
        "",
    )
    if user_text:
        result = await _run_check(user_text)
        if result.verdict == Verdict.BLOCK:
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "prompt_injection_detected",
                    "result": result.model_dump(),
                },
            )

    base_url = os.environ.get("UPSTREAM_BASE_URL", "https://api.groq.com/openai/v1")
    api_key = os.environ.get("UPSTREAM_API_KEY", os.environ.get("GROQ_API_KEY", ""))
    async with httpx.AsyncClient() as client:
        upstream = await client.post(
            f"{base_url}/{path}",
            json=body,
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=60,
        )
    return upstream.json()
