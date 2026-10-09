# External benchmark data

`prompt_injections.jsonl` — 546 unique samples (203 labeled prompt injection, 343 benign),
vendored from the public HuggingFace dataset [`deepset/prompt-injections`](https://huggingface.co/datasets/deepset/prompt-injections)
via the datasets-server API on Oct 3, 2026. Labels are the dataset authors' — AgentSentinel's
tuning never touched this data. Re-fetch with `evals/run_external_eval.py --refresh`.
