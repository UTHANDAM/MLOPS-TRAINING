# ─────────────────────────────────────────────────────────────────────────────
# AEGIS – Threat Modeling Engine
# Defines AI-specific threat taxonomy, component parsers, and risk scoring
# ─────────────────────────────────────────────────────────────────────────────

from dataclasses import dataclass, field
from typing import List, Dict, Optional
from enum import Enum

# ── Enumerations ───────────────────────────────────────────────────────────────

class RiskLevel(str, Enum):
    CRITICAL = "Critical"
    HIGH     = "High"
    MEDIUM   = "Medium"
    LOW      = "Low"
    INFO     = "Informational"

class ThreatCategory(str, Enum):
    PROMPT_INJECTION        = "Prompt Injection"
    INSECURE_OUTPUT         = "Insecure Output Handling"
    TRAINING_DATA_POISONING = "Training Data Poisoning"
    MODEL_DENIAL_OF_SERVICE = "Model Denial of Service"
    SUPPLY_CHAIN            = "Supply Chain Vulnerabilities"
    SENSITIVE_INFO_LEAKAGE  = "Sensitive Information Disclosure"
    INSECURE_PLUGIN_DESIGN  = "Insecure Plugin / Tool Design"
    EXCESSIVE_AGENCY        = "Excessive Agency"
    OVERRELIANCE            = "Overreliance"
    MODEL_THEFT             = "Model Theft"
    RETRIEVAL_POISONING     = "Retrieval / RAG Poisoning"
    AGENT_HIJACKING         = "Agent Hijacking"
    EMBEDDING_INVERSION     = "Embedding Inversion Attack"
    INSECURE_TOOL_EXEC      = "Insecure Tool Execution"
    DATA_EXFILTRATION       = "Data Exfiltration via LLM"

class ComponentType(str, Enum):
    LLM              = "LLM / Foundation Model"
    RAG              = "RAG Pipeline"
    VECTOR_DB        = "Vector Database"
    AGENT            = "AI Agent"
    TOOL_CALLER      = "Tool / Function Caller"
    EMBEDDING_MODEL  = "Embedding Model"
    ORCHESTRATOR     = "Orchestration Layer"
    API_GATEWAY      = "API Gateway"
    USER_INTERFACE   = "User Interface"
    DATA_STORE       = "Data Store / Database"
    EXTERNAL_API     = "External API / Plugin"
    PROMPT_SYSTEM    = "System Prompt / Prompt Template"
    AUTH_LAYER       = "Authentication / Authorization Layer"
    FINE_TUNED_MODEL = "Fine-Tuned Model"

# ── Data Classes ───────────────────────────────────────────────────────────────

@dataclass
class ThreatFinding:
    id: str
    title: str
    category: ThreatCategory
    risk_level: RiskLevel
    affected_components: List[str]
    description: str
    attack_scenario: str
    impact: str
    owasp_reference: str
    nist_control: str
    mitigations: List[str]
    references: List[str] = field(default_factory=list)
    cvss_score: float = 0.0

@dataclass
class ArchitectureComponent:
    name: str
    component_type: ComponentType
    description: str
    trust_level: str       # "trusted", "semi-trusted", "untrusted"
    data_flows: List[str]  # other component names it connects to

@dataclass
class ThreatModel:
    architecture_summary: str
    components: List[ArchitectureComponent]
    threats: List[ThreatFinding]
    risk_summary: Dict[str, int]
    trust_boundaries: List[str]
    recommendations: List[str]
    compliance_gaps: Dict[str, List[str]]

# ── OWASP LLM Top 10 Knowledge Base ───────────────────────────────────────────

OWASP_LLM_TOP10 = {
    "LLM01": {
        "name": "Prompt Injection",
        "category": ThreatCategory.PROMPT_INJECTION,
        "base_risk": RiskLevel.CRITICAL,
        "triggers": ["llm", "chatbot", "agent", "prompt", "user input", "api", "rag"],
        "cvss": 9.1,
    },
    "LLM02": {
        "name": "Insecure Output Handling",
        "category": ThreatCategory.INSECURE_OUTPUT,
        "base_risk": RiskLevel.HIGH,
        "triggers": ["llm", "output", "ui", "frontend", "render", "code execution"],
        "cvss": 8.2,
    },
    "LLM03": {
        "name": "Training Data Poisoning",
        "category": ThreatCategory.TRAINING_DATA_POISONING,
        "base_risk": RiskLevel.HIGH,
        "triggers": ["fine-tuned", "training", "dataset", "rlhf", "custom model"],
        "cvss": 7.5,
    },
    "LLM04": {
        "name": "Model Denial of Service",
        "category": ThreatCategory.MODEL_DENIAL_OF_SERVICE,
        "base_risk": RiskLevel.MEDIUM,
        "triggers": ["llm", "api", "public", "endpoint", "token", "context window"],
        "cvss": 6.5,
    },
    "LLM05": {
        "name": "Supply Chain Vulnerabilities",
        "category": ThreatCategory.SUPPLY_CHAIN,
        "base_risk": RiskLevel.HIGH,
        "triggers": ["third-party", "model", "library", "plugin", "huggingface", "open-source"],
        "cvss": 7.8,
    },
    "LLM06": {
        "name": "Sensitive Information Disclosure",
        "category": ThreatCategory.SENSITIVE_INFO_LEAKAGE,
        "base_risk": RiskLevel.HIGH,
        "triggers": ["pii", "database", "rag", "memory", "system prompt", "context", "vector db"],
        "cvss": 8.5,
    },
    "LLM07": {
        "name": "Insecure Plugin Design",
        "category": ThreatCategory.INSECURE_PLUGIN_DESIGN,
        "base_risk": RiskLevel.HIGH,
        "triggers": ["tool", "plugin", "function calling", "api", "action", "integration"],
        "cvss": 8.0,
    },
    "LLM08": {
        "name": "Excessive Agency",
        "category": ThreatCategory.EXCESSIVE_AGENCY,
        "base_risk": RiskLevel.CRITICAL,
        "triggers": ["agent", "autonomous", "action", "tool", "permission", "execute", "write"],
        "cvss": 9.3,
    },
    "LLM09": {
        "name": "Overreliance",
        "category": ThreatCategory.OVERRELIANCE,
        "base_risk": RiskLevel.MEDIUM,
        "triggers": ["llm", "decision", "healthcare", "finance", "legal", "automation"],
        "cvss": 5.5,
    },
    "LLM10": {
        "name": "Model Theft",
        "category": ThreatCategory.MODEL_THEFT,
        "base_risk": RiskLevel.MEDIUM,
        "triggers": ["api", "public", "endpoint", "model", "inference", "fine-tuned"],
        "cvss": 6.8,
    },
}

# ── AI Component → Threat Mapping ──────────────────────────────────────────────

COMPONENT_THREAT_MAP: Dict[str, List[str]] = {
    "llm":             ["LLM01", "LLM02", "LLM04", "LLM06", "LLM09", "LLM10"],
    "rag":             ["LLM01", "LLM06", "LLM03"],
    "vector":          ["LLM06", "LLM03"],
    "agent":           ["LLM01", "LLM07", "LLM08", "LLM02"],
    "tool":            ["LLM07", "LLM08", "LLM01"],
    "function":        ["LLM07", "LLM08"],
    "embedding":       ["LLM06"],
    "fine-tun":        ["LLM03", "LLM05"],
    "plugin":          ["LLM05", "LLM07", "LLM08"],
    "api":             ["LLM04", "LLM10", "LLM07"],
    "database":        ["LLM06"],
    "memory":          ["LLM06", "LLM01"],
    "orchestrat":      ["LLM08", "LLM01"],
    "authentication":  ["LLM08"],
    "user":            ["LLM01", "LLM02"],
}

# ── Detailed Mitigation Library ────────────────────────────────────────────────

MITIGATION_LIBRARY: Dict[str, Dict] = {
    "LLM01": {
        "mitigations": [
            "Implement strict input validation and sanitization for all user-supplied content",
            "Use separate system and user prompt contexts with clear delimiters",
            "Apply LLM-based prompt injection classifiers before processing",
            "Enforce privilege separation: treat all LLM output as untrusted",
            "Use Constitutional AI or guardrail models (e.g., Llama Guard)",
            "Implement output sandboxing before executing any LLM-generated actions",
        ],
        "nist": "GOVERN 1.1, MAP 1.5, MEASURE 2.5",
        "references": [
            "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
            "https://arxiv.org/abs/2302.12173",
        ],
    },
    "LLM02": {
        "mitigations": [
            "Encode and escape all LLM outputs before rendering in UI (HTML, JS)",
            "Never execute LLM-generated code without human-in-the-loop review",
            "Apply Content Security Policy (CSP) headers to prevent XSS via AI output",
            "Use output format validation to ensure structured responses",
            "Implement post-generation filters for code injection patterns",
        ],
        "nist": "MAP 1.6, MEASURE 2.6",
        "references": [
            "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
        ],
    },
    "LLM03": {
        "mitigations": [
            "Audit and validate all training datasets for adversarial samples",
            "Implement data provenance tracking for fine-tuning pipelines",
            "Use differential privacy techniques during fine-tuning",
            "Regularly red-team fine-tuned models for backdoor triggers",
            "Enforce supply chain integrity checks for datasets and base models",
        ],
        "nist": "MAP 2.3, MEASURE 2.7",
        "references": [
            "https://arxiv.org/abs/2202.10328",
        ],
    },
    "LLM04": {
        "mitigations": [
            "Enforce token limits and context window caps per request",
            "Implement rate limiting and throttling at the API gateway level",
            "Monitor for abnormally long or recursive prompts",
            "Use async processing queues for expensive inference requests",
            "Set hard timeouts and cost budgets per user/session",
        ],
        "nist": "MANAGE 1.3",
        "references": [],
    },
    "LLM05": {
        "mitigations": [
            "Pin model versions with cryptographic hash verification",
            "Scan third-party plugins and libraries for known CVEs",
            "Use private model registries instead of public HuggingFace downloads",
            "Implement software composition analysis (SCA) for AI dependencies",
            "Review and restrict model licenses before deployment",
        ],
        "nist": "GOVERN 6.1, MAP 5.1",
        "references": [],
    },
    "LLM06": {
        "mitigations": [
            "Implement namespace isolation in vector databases per user/tenant",
            "Redact PII and sensitive data before embedding and indexing",
            "Apply access control at the retrieval layer (not just UI)",
            "Never include confidential system prompts in embeddings",
            "Use encryption at rest for all vector database contents",
            "Implement audit logging for all retrieval queries",
        ],
        "nist": "GOVERN 4.2, MANAGE 2.4",
        "references": [
            "https://arxiv.org/abs/2302.05671",
        ],
    },
    "LLM07": {
        "mitigations": [
            "Define explicit allowlists for plugin/tool capabilities",
            "Require OAuth 2.0 / API keys for all external tool calls",
            "Validate and sanitize all tool inputs and outputs",
            "Apply principle of least privilege for tool permissions",
            "Implement human confirmation for irreversible actions",
            "Log and audit all tool invocations with full request/response",
        ],
        "nist": "GOVERN 1.7, MAP 1.3",
        "references": [],
    },
    "LLM08": {
        "mitigations": [
            "Apply principle of least privilege — limit agent action scope",
            "Require human-in-the-loop approval for high-impact actions",
            "Implement action allowlists: explicitly define permitted operations",
            "Use reversible actions where possible; stage destructive operations",
            "Monitor and alert on agent behavior anomalies",
            "Implement session-scoped permission models",
        ],
        "nist": "GOVERN 1.1, MAP 1.6, MANAGE 1.3",
        "references": [
            "https://arxiv.org/abs/2309.07864",
        ],
    },
    "LLM09": {
        "mitigations": [
            "Display confidence scores and uncertainty estimates with AI outputs",
            "Mandate human review for high-stakes decisions (medical, legal, financial)",
            "Implement output disclaimers and explainability features",
            "Track and audit AI decision outcomes for bias and error rates",
            "Provide fallback mechanisms to human judgment",
        ],
        "nist": "MEASURE 1.1, GOVERN 2.2",
        "references": [],
    },
    "LLM10": {
        "mitigations": [
            "Rate-limit inference API calls to prevent model extraction attacks",
            "Implement query complexity analysis to detect systematic probing",
            "Add watermarking to model outputs for theft detection",
            "Use differential privacy in model outputs if applicable",
            "Monitor for unusually high or repetitive API query patterns",
        ],
        "nist": "GOVERN 4.1, MANAGE 2.2",
        "references": [],
    },
}


def detect_components_from_text(architecture_text: str) -> List[str]:
    """
    Identify likely AI components from a free-text architecture description.
    Returns a list of detected component keywords.
    """
    text_lower = architecture_text.lower()
    detected = []

    component_keywords = {
        "llm":            ["llm", "language model", "gpt", "gemini", "claude", "mistral", "openai", "anthropic"],
        "rag":            ["rag", "retrieval-augmented", "retrieval augmented", "knowledge base"],
        "vector":         ["vector db", "vector database", "pinecone", "weaviate", "chroma", "qdrant", "milvus", "faiss"],
        "agent":          ["agent", "autonomous", "agentic", "multi-agent"],
        "tool":           ["tool calling", "function calling", "tool use", "actions"],
        "function":       ["function call", "tool call", "api call"],
        "embedding":      ["embedding", "embed", "vectorize"],
        "fine-tun":       ["fine-tun", "finetuned", "custom model", "lora", "rlhf"],
        "plugin":         ["plugin", "extension", "add-on"],
        "api":            ["api", "rest api", "graphql", "endpoint", "webhook"],
        "database":       ["database", "db", "sql", "nosql", "postgres", "mongodb"],
        "memory":         ["memory", "conversation history", "session", "context window"],
        "orchestrat":     ["orchestrat", "langchain", "langgraph", "autogen", "crewai"],
        "authentication": ["auth", "oauth", "jwt", "sso", "rbac", "iam"],
        "user":           ["user", "customer", "client", "human", "interface", "ui", "frontend"],
    }

    for component_key, keywords in component_keywords.items():
        for kw in keywords:
            if kw in text_lower:
                if component_key not in detected:
                    detected.append(component_key)
                break

    return detected


def score_architecture_risk(threats: List[ThreatFinding]) -> Dict[str, int]:
    """Summarize risk counts by severity level."""
    summary = {r.value: 0 for r in RiskLevel}
    for threat in threats:
        summary[threat.risk_level.value] += 1
    return summary


def calculate_overall_risk_score(risk_summary: Dict[str, int]) -> float:
    """
    Calculate a 0–100 composite risk score.
    Weights: Critical=10, High=7, Medium=4, Low=1, Info=0.5
    """
    weights = {
        RiskLevel.CRITICAL.value: 10,
        RiskLevel.HIGH.value:     7,
        RiskLevel.MEDIUM.value:   4,
        RiskLevel.LOW.value:      1,
        RiskLevel.INFO.value:     0.5,
    }
    raw = sum(count * weights.get(level, 0) for level, count in risk_summary.items())
    return min(raw, 100)


def get_risk_color(risk_level: str) -> str:
    """Map risk level to display color."""
    colors = {
        "Critical":       "#ff2d55",
        "High":           "#ff6b35",
        "Medium":         "#ffd60a",
        "Low":            "#30d158",
        "Informational":  "#636366",
    }
    return colors.get(risk_level, "#636366")


def get_risk_badge_html(risk_level: str) -> str:
    """Return an HTML badge for a risk level."""
    color = get_risk_color(risk_level)
    return (
        f'<span style="background:{color}22;color:{color};border:1px solid {color}66;'
        f'border-radius:12px;padding:2px 10px;font-size:0.78rem;font-weight:600;">'
        f'{risk_level}</span>'
    )
