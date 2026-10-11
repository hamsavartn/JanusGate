import json
import math
import torch
import torch.nn.functional as F
from pathlib import Path
from transformers import AutoTokenizer, AutoModelForSequenceClassification

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

def evaluate_classifier():
    print("Loading PromptGuard model...")
    model_id = "meta-llama/Prompt-Guard-86M"
    tokenizer = AutoTokenizer.from_pretrained(model_id)
    model = AutoModelForSequenceClassification.from_pretrained(model_id)
    model.eval()

    items = [json.loads(line) for line in TEST_PATH.read_text(encoding="utf-8").splitlines() if line.strip()]
    
    results = []
    print(f"Running eval on {len(items)} items...")
    for i, item in enumerate(items):
        text = item["text"]
        label = 1 if str(item["label"]).strip() in ("1", "prompt_injection") else 0
        
        inputs = tokenizer(text, return_tensors="pt", truncation=True, max_length=512)
        with torch.no_grad():
            outputs = model(**inputs)
            logits = outputs.logits[0]
            
        results.append({
            "text": text,
            "label": label,
            "logits": logits.tolist()
        })
        if (i+1) % 20 == 0:
            print(f"Processed {i+1}/{len(items)}")
            
    # PromptGuard labels: 0=BENIGN, 1=INJECTION, 2=JAILBREAK
    # Attack probability = P(1) + P(2)
    
    # Let's test different temperature values for calibration
    temperatures = [0.5, 1.0, 2.0, 5.0]
    
    for temp in temperatures:
        print(f"\n--- Temperature: {temp} ---")
        best_t = None
        best_metrics = None
        
        # Sweep thresholds from 0.01 to 0.99
        thresholds = [x/100.0 for x in range(1, 100)]
        for t in thresholds:
            tp, fp, fn, tn = 0, 0, 0, 0
            for res in results:
                logits = torch.tensor(res["logits"])
                scaled_logits = logits / temp
                probs = F.softmax(scaled_logits, dim=0)
                
                # Attack is class 1 and 2
                attack_prob = probs[1].item() + probs[2].item()
                
                pred = attack_prob >= t
                actual = res["label"] == 1
                
                if pred and actual: tp += 1
                elif pred and not actual: fp += 1
                elif not pred and actual: fn += 1
                else: tn += 1
                
            fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0
            
            if fpr <= 0.01 and best_t is None:
                best_t = t
                best_metrics = (tp, fp, fn, tn, fpr, recall)
                
        if best_t is not None:
            tp, fp, fn, tn, fpr, recall = best_metrics
            low, high = wilson_score_interval(recall, tp+fn)
            print(f"Optimal Threshold (FPR <= 1%): {best_t}")
            print(f"FPR: {fpr:.3f} | Recall: {recall:.3f} (95% CI: [{low:.3f}, {high:.3f}])")
            print(f"TP: {tp}, FP: {fp}, FN: {fn}, TN: {tn}")
        else:
            print("No threshold achieved FPR <= 1%")

if __name__ == "__main__":
    evaluate_classifier()
