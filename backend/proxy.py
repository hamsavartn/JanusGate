"""OpenAI-compatible security proxy — drop-in protection for any agent.

Point any OpenAI-SDK-based agent's `base_url` at Sentinel:
    client = OpenAI(base_url="http://localhost:8123/v1", api_key="upstream-key")

Flow per request:
  1. INGRESS: every message content (system/user/tool) is inspected with the full
     ensemble (per-source policy thresholds apply).
  2. If any content is an attack → no upstream call happens; a synthetic assistant
     message explaining the block (with evidence) is returned, plus a `sentinel` object.
  3. Otherwise the request is forwarded to the configured upstream (Gemini's
     OpenAI-compatible endpoint by default), and the assistant reply is EGRESS-inspected
     (canary/credential/echo). Leaks are replaced with a block message + evidence.

Non-streaming only (documented limitation). Without UPSTREAM_API_KEY the proxy still
blocks attacks (no upstream needed for that) and returns 503 for clean traffic.
"""
import json
import time
import uuid

import httpx
from fastapi import HTTPException
from fastapi.responses import StreamingResponse

from backend import audit
from backend.config import UPSTREAM_API_KEY, UPSTREAM_BASE_URL, UPSTREAM_DEFAULT_MODEL
from backend.engine.egress import inspect_output
from backend.sentinel_core import inspect_text

# Role → inspection source (drives per-source policy thresholds)
_ROLE_SOURCE = {"system": "document", "user": "user_message", "tool": "tool_output",
                "assistant": "user_message"}


def extract_contents(messages: list[dict]) -> list[tuple[str, str, str]]:
    """[(role, source, text)] — flattens OpenAI content parts, stringifies others."""
    out: list[tuple[str, str, str]] = []
    for m in messages:
        role = str(m.get("role", "user"))
        content = m.get("content", "")
        if isinstance(content, str):
            texts = [content]
        elif isinstance(content, list):
            texts = [str(p.get("text", "")) for p in content
                     if isinstance(p, dict) and p.get("type") == "text"]
        else:
            texts = [str(content)]
        for t in texts:
            if t.strip():
                out.append((role, _ROLE_SOURCE.get(role, "user_message"), t))
    return out


def _synthetic_response(model: str, content: str, sentinel: dict) -> dict:
    return {
        "id": f"chatcmpl-janusgate-{uuid.uuid4().hex[:12]}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model,
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": content},
            "finish_reason": "stop",
        }],
        "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        "sentinel": sentinel,
    }


async def handle_chat_completions(payload: dict) -> dict:
    messages = payload.get("messages")
    if not isinstance(messages, list) or not messages:
        raise HTTPException(status_code=400, detail="messages[] is required")

    model = str(payload.get("model") or UPSTREAM_DEFAULT_MODEL)
    ingress_results, worst = [], None

    for role, source, text in extract_contents(messages):
        v = await inspect_text(text, source=source, record=True)
        ingress_results.append({
            "role": role, "is_attack": v.is_attack, "attack_class": v.attack_class,
            "risk": v.final_risk, "evidence": (v.heuristic_hits[0].snippet
                                               if v.heuristic_hits else None),
        })
        if v.is_attack and (worst is None or v.final_risk > worst["risk"]):
            worst = ingress_results[-1]

    if worst is not None:
        content = (f"⛔ [JanusGate] Request blocked — {worst['attack_class']} detected "
                   f"in the {worst['role']} message (risk {worst['risk']}/10). "
                   f"Evidence: “{worst['evidence']}”. The request was never sent upstream.")
        if payload.get("stream"):
            async def _stream_synthetic_block():
                chunk = {
                    "id": f"chatcmpl-janusgate-{uuid.uuid4().hex[:12]}",
                    "object": "chat.completion.chunk",
                    "model": model,
                    "choices": [{"index": 0, "delta": {"role": "assistant", "content": content}, "finish_reason": "stop"}],
                    "sentinel": {"action": "blocked_ingress", "verdicts": ingress_results},
                }
                yield f"data: {json.dumps(chunk)}\n\n"
                yield "data: [DONE]\n\n"
            return StreamingResponse(_stream_synthetic_block(), media_type="text/event-stream")
        return _synthetic_response(model, content, {
            "action": "blocked_ingress", "verdicts": ingress_results})

    if not UPSTREAM_API_KEY:
        raise HTTPException(
            status_code=503,
            detail="Sentinel proxy has no upstream key configured (UPSTREAM_API_KEY); "
                   "ingress inspection passed but forwarding is unavailable.")

    t0 = time.perf_counter()

    if payload.get("stream"):
        async def _stream_upstream():
            async with httpx.AsyncClient() as client:
                try:
                    async with client.stream(
                        "POST",
                        f"{UPSTREAM_BASE_URL.rstrip('/')}/chat/completions",
                        headers={"Authorization": f"Bearer {UPSTREAM_API_KEY}"},
                        json=payload,
                        timeout=120,
                    ) as response:
                        if response.status_code != 200:
                            err = await response.aread()
                            yield f"data: {json.dumps({'error': f'upstream error {response.status_code}', 'details': err.decode('utf-8', errors='ignore')})}\n\n"
                            return
                        
                        accumulated_text = ""
                        async for line in response.aiter_lines():
                            if line.startswith("data: ") and line != "data: [DONE]":
                                data_str = line[6:]
                                try:
                                    chunk = json.loads(data_str)
                                    delta = chunk.get("choices", [{}])[0].get("delta", {})
                                    if "content" in delta:
                                        new_text = delta["content"]
                                        test_text = accumulated_text + new_text
                                        
                                        egress = inspect_output(test_text)
                                        if egress is not None and egress.is_leak and egress.risk >= 8:
                                            block_msg = (f"\n\n⛔ [JanusGate] Reply blocked by egress defense — "
                                                         f"{'/'.join(egress.reasons)} (risk {egress.risk}/10).")
                                            block_chunk = {
                                                "id": chunk.get("id", f"chatcmpl-janusgate-{uuid.uuid4().hex[:12]}"),
                                                "object": "chat.completion.chunk",
                                                "model": model,
                                                "choices": [{"index": 0, "delta": {"content": block_msg}, "finish_reason": "stop"}],
                                                "sentinel": {
                                                    "action": "blocked_egress", "verdicts": ingress_results,
                                                    "egress": {"reasons": egress.reasons, "risk": egress.risk}
                                                }
                                            }
                                            yield f"data: {json.dumps(block_chunk)}\n\n"
                                            yield "data: [DONE]\n\n"
                                            
                                            audit.record_egress(egress, source="proxy_stream")
                                            return
                                            
                                        accumulated_text = test_text
                                except Exception:
                                    pass
                            
                            yield f"{line}\n"
                except Exception:
                    yield f"data: {json.dumps({'error': 'upstream unreachable'})}\n\n"
        return StreamingResponse(_stream_upstream(), media_type="text/event-stream")

    try:
        r = httpx.post(
            f"{UPSTREAM_BASE_URL.rstrip('/')}/chat/completions",
            headers={"Authorization": f"Bearer {UPSTREAM_API_KEY}"},
            json=payload,
            timeout=120,
        )
        r.raise_for_status()
        upstream = r.json()
    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=502, detail=f"upstream error {e.response.status_code}")
    except Exception:
        raise HTTPException(status_code=502, detail="upstream unreachable")

    reply_text = ""
    try:
        reply_text = str(upstream["choices"][0]["message"]["content"] or "")
    except Exception:
        pass

    egress = inspect_output(reply_text) if reply_text else None
    if egress is not None:
        audit.record_egress(egress, source="proxy_reply")
    if egress is not None and egress.is_leak and egress.risk >= 8:
        content = (f"⛔ [JanusGate] Reply blocked by egress defense — "
                   f"{'/'.join(egress.reasons)} (risk {egress.risk}/10). The model output "
                   f"was stopped before leaving the system.")
        return _synthetic_response(model, content, {
            "action": "blocked_egress", "verdicts": ingress_results,
            "egress": {"reasons": egress.reasons, "risk": egress.risk}})

    upstream.setdefault("sentinel", {
        "action": "passed",
        "inspected_messages": len(ingress_results),
        "egress_reasons": egress.reasons if egress is not None else [],
        "overhead_ms": int((time.perf_counter() - t0) * 1000),
    })
    return upstream
