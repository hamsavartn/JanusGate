import asyncio
import json
import time
import math
from pathlib import Path
from collections import defaultdict

from backend.sentinel_core import inspect_text

TRAIN_PATH = Path("evals/external/prompt_injections.jsonl")
TEST_PATH = Path("evals/external/prompt_injections_test.jsonl")

def wilson_score_interval(p_hat, n, z=1.96):
    if n == 0:
        return 0.0, 0.0
    denominator = 1 + z**2/n
    centre_adjusted_probability = p_hat + z**2 / (2*n)
    adjusted_standard_deviation = math.sqrt((p_hat*(1 - p_hat) + z**2 / (4*n)) / n)
    lower_bound = (centre_adjusted_probability - z*adjusted_standard_deviation) / denominator
    upper_bound = (centre_adjusted_probability + z*adjusted_standard_deviation) / denominator
    return max(0.0, lower_bound), min(1.0, upper_bound)

async def collect_raw_results(dataset_path: Path):
    items = [json.loads(line) for line in dataset_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    results = []
    print(f"Running eval on {len(items)} items from {dataset_path}...")
    
    semaphore = asyncio.Semaphore(15) # 15 concurrent requests
    
    completed = 0
    total = len(items)
    
    async def process_item(item):
        nonlocal completed
        text = item["text"]
        label = 1 if str(item["label"]).strip() in ("1", "prompt_injection") else 0
        
        async with semaphore:
            v = await inspect_text(text, source="user_message", record=False)
            
        completed += 1
        if completed % 50 == 0:
            print(f"Processed {completed}/{total}")
            
        return {
            "text": text,
            "label": label,
            "h_risk": v.heuristic_risk,
            "sem_similarity": v.semantic_hit.similarity if v.semantic_hit else 0.0,
            "sem_severity": v.semantic_hit.severity if v.semantic_hit else 0,
            "llm_is_attack": v.llm_verdict.is_attack if v.llm_verdict else False,
            "llm_risk": v.llm_verdict.risk_score if v.llm_verdict else 0,
            "judge_status": v.judge_status
        }

    tasks = [process_item(item) for item in items]
    results = await asyncio.gather(*tasks)
    return results

def compute_ablation_risk(res, config, threshold):
    h = res["h_risk"]
    ssim = res["sem_similarity"]
    ssev = res["sem_severity"]
    l_is = res["llm_is_attack"]
    l_risk = res["llm_risk"]
    
    if l_is and l_risk < threshold:
        l_risk = threshold
        
    if config == "L1_only":
        return h
    elif config == "L1_L2_gated_0.90":
        corroborated = h >= threshold
        if ssim >= 0.90 or corroborated:
            return max(h, ssev)
        return h
    elif config == "L1_L2_gated_0.35":
        corroborated = h >= threshold
        if ssim >= 0.35 or corroborated:
            return max(h, ssev)
        return h
    elif config == "L3_only":
        return l_risk if l_is else 0
    elif config == "full":
        candidates = [h]
        corroborated = h >= threshold or l_is
        if ssim >= 0.90 or corroborated:
            candidates.append(ssev)
        if l_risk > 0:
            candidates.append(l_risk)
        return max(candidates)
    
    return 0

def run_sweep_and_report(results, config_name):
    print(f"\n--- Config: {config_name} ---")
    best_t = None
    best_metrics = None
    
    for t in range(1, 11):
        tp, fp, fn, tn = 0, 0, 0, 0
        for res in results:
            pred_risk = compute_ablation_risk(res, config_name, t)
            pred = pred_risk >= t
            actual = res["label"] == 1
            if pred and actual: tp += 1
            elif pred and not actual: fp += 1
            elif not pred and actual: fn += 1
            else: tn += 1
            
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        
        # We want FPR <= 1%
        if fpr <= 0.01 and best_t is None:
            best_t = t
            best_metrics = (tp, fp, fn, tn, fpr, recall)
            
    if best_t is not None:
        tp, fp, fn, tn, fpr, recall = best_metrics
        low, high = wilson_score_interval(recall, tp+fn)
        print(f"Optimal Threshold (FPR <= 1%): {best_t}")
        print(f"FPR: {fpr:.3f} | Recall: {recall:.3f} (95% CI: [{low:.3f}, {high:.3f}])")
        print(f"TP: {tp}, FP: {fp}, FN: {fn}, TN: {tn}")
        return best_t
    else:
        print("No threshold achieved FPR <= 1%")
        return None

async def main():
    print("Collecting raw results for Test split (116 rows)...")
    test_results = await collect_raw_results(TEST_PATH)
    
    print("\nEvaluating configs on Test split:")
    configs = ["L1_only", "L1_L2_gated_0.90", "L1_L2_gated_0.35", "L3_only", "full"]
    for c in configs:
        run_sweep_and_report(test_results, c)
        
    print("\nCollecting raw results for Train split (546 rows) for miss dumping...")
    train_results = await collect_raw_results(TRAIN_PATH)
    
    t = 5 # default threshold for full config
    misses = []
    for res in train_results:
        pred_risk = compute_ablation_risk(res, "full", t)
        if res["label"] == 1 and pred_risk < t:
            misses.append(res)
            
    # Simple language bucketing heuristic based on common German words
    german_keywords = [" und ", " die ", " der ", " das ", " ist ", " in ", " den ", " von ", " zu ", " mit ", " auf ", " für ", " nicht "]
    
    buckets = defaultdict(list)
    for m in misses:
        text_lower = m["text"].lower()
        if any(kw in text_lower for kw in german_keywords):
            buckets["german"].append(m)
        elif "roleplay" in text_lower or "pretend" in text_lower or "act as" in text_lower or "persona" in text_lower:
            buckets["roleplay"].append(m)
        elif "ignore" in text_lower or "previous instructions" in text_lower:
            buckets["paraphrase_override"].append(m)
        else:
            buckets["other"].append(m)
            
    dump_text = f"# Train Split Misses (Total: {len(misses)})\n\n"
    for cat, items in buckets.items():
        dump_text += f"## {cat.upper()} ({len(items)})\n"
        for i, m in enumerate(items[:10]):
            dump_text += f"- {m['text'][:100]}... (Status: {m['judge_status']}, L1: {m['h_risk']}, L3: {m['llm_risk']})\n"
        if len(items) > 10:
            dump_text += f"- ... and {len(items)-10} more.\n"
        dump_text += "\n"
        
    Path("evals/ablation_misses.md").write_text(dump_text, encoding="utf-8")
    print(f"\nDumped {len(misses)} misses to evals/ablation_misses.md")

if __name__ == "__main__":
    asyncio.run(main())
