"""Attack simulator — fires the labeled corpus through the ensemble and scores it.

This is the "prove it's not a wrapper" component: it produces live
precision / recall / F1 for the detection engine on every run.
"""
from backend.config import GEMINI_API_KEY
from backend.engine.corpus import ALL_PAYLOADS
from backend.schemas import SuitePayloadResult, SuiteResult
from backend.sentinel_core import inspect_text


async def run_suite_async() -> SuiteResult:
    results: list[SuitePayloadResult] = []
    for payload in ALL_PAYLOADS:
        verdict = await inspect_text(payload.text, source="user_message")
        detected = verdict.is_attack
        expected = payload.category != "benign"
        results.append(
            SuitePayloadResult(
                name=payload.name,
                category=payload.category,  # type: ignore[arg-type]
                expected_attack=expected,
                detected_attack=detected,
                final_risk=verdict.final_risk,
                correct=detected == expected,
                top_hit=verdict.heuristic_hits[0].rule if verdict.heuristic_hits else None,
            )
        )

    tp = sum(1 for r in results if r.expected_attack and r.detected_attack)
    fp = sum(1 for r in results if not r.expected_attack and r.detected_attack)
    fn = sum(1 for r in results if r.expected_attack and not r.detected_attack)
    tn = sum(1 for r in results if not r.expected_attack and not r.detected_attack)

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    total = len(results)

    return SuiteResult(
        total=total,
        true_positives=tp,
        false_positives=fp,
        false_negatives=fn,
        true_negatives=tn,
        precision=round(precision, 3),
        recall=round(recall, 3),
        f1=round(f1, 3),
        accuracy=round((tp + tn) / total, 3) if total else 0.0,
        llm_layer_active=bool(GEMINI_API_KEY),
        results=results,
    )


def run_suite() -> SuiteResult:
    """Sync wrapper used by the FastAPI endpoint and CLI."""
    import asyncio

    return asyncio.run(run_suite_async())


if __name__ == "__main__":
    report = run_suite()
    print(f"JanusGate attack suite — {report.total} payloads")
    print(
        f"precision={report.precision}  recall={report.recall}  "
        f"f1={report.f1}  accuracy={report.accuracy}"
    )
    for r in report.results:
        mark = "OK " if r.correct else "MISS"
        print(f"[{mark}] {r.name:<28} expected_attack={r.expected_attack} "
              f"detected={r.detected_attack} risk={r.final_risk} hit={r.top_hit}")
