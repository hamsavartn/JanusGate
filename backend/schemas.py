"""Pydantic schemas shared across the API, engine, and dashboard."""
from typing import Literal

from pydantic import BaseModel, Field

AttackClass = Literal[
    "direct_injection",
    "indirect_injection",
    "jailbreak",
    "tool_hijack",
    "exfiltration",
    "phishing",
    "benign",
]

Category = Literal["injection", "jailbreak", "tool_hijack", "exfiltration", "phishing"]


class HeuristicHit(BaseModel):
    rule: str = Field(description="Rule id that fired, e.g. 'ignore_instructions'")
    category: Category
    severity: int = Field(ge=0, le=10)
    snippet: str = Field(description="Matched text, trimmed")
    explanation: str


class SemanticHit(BaseModel):
    """Layer 2 — corpus-similarity hit."""
    category: Category
    similarity: float = Field(ge=0.0, le=1.0)
    matched_payload: str
    severity: int = Field(ge=0, le=10)
    mode: str = Field(description="'gemini' (embeddings) or 'tfidf' (offline fallback)")


class LLMJudgeVerdict(BaseModel):
    """Structured verdict produced by the Gemini LLM judge."""
    is_attack: bool
    attack_class: AttackClass
    risk_score: int = Field(ge=0, le=10, description="0 = clearly benign, 10 = critical attack")
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[str] = Field(description="Short verbatim quotes that drove the verdict")
    reasoning: str


class EnsembleVerdict(BaseModel):
    """Merged verdict across all detection layers."""
    is_attack: bool
    final_risk: int = Field(ge=0, le=10)
    attack_class: AttackClass
    heuristic_hits: list[HeuristicHit]
    heuristic_risk: int = Field(ge=0, le=10)
    semantic_hit: SemanticHit | None = None
    llm_verdict: LLMJudgeVerdict | None = None
    layers_used: list[str]
    latency_ms: int
    text_preview: str


class InspectRequest(BaseModel):
    text: str = Field(min_length=1, max_length=20000)
    source: Literal["user_message", "tool_output", "email", "document"] = "user_message"


class SuitePayloadResult(BaseModel):
    name: str
    category: Category | Literal["benign"]
    expected_attack: bool
    detected_attack: bool
    final_risk: int
    correct: bool
    top_hit: str | None = None


class SuiteResult(BaseModel):
    total: int
    true_positives: int
    false_positives: int
    false_negatives: int
    true_negatives: int
    precision: float
    recall: float
    f1: float
    accuracy: float
    llm_layer_active: bool
    results: list[SuitePayloadResult]


class ScenarioStep(BaseModel):
    """One step of the scripted demo scenario."""
    step: int
    actor: str = Field(description="e.g. 'email from billing@…' or 'assistant calls send_email'")
    action: str
    blocked: bool
    attack_class: str | None = None
    risk: int | None = None
    evidence: str | None = None
    detail: str


class ScenarioResult(BaseModel):
    title: str
    steps: list[ScenarioStep]
    benign_handled: int
    attacks_blocked: int
    audit_entries_after: int
