# ─────────────────────────────────────────────────────────────────────────────
# AEGIS – LLM Analysis Engine
# Uses Google Gemini with RAG context to generate structured threat models
# ─────────────────────────────────────────────────────────────────────────────

import os
import logging
from typing import List, Dict, Any
from dotenv import load_dotenv

from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.messages import SystemMessage, HumanMessage

from threat_engine import (
    ThreatFinding, ThreatModel, ArchitectureComponent,
    ThreatCategory, RiskLevel, ComponentType,
    OWASP_LLM_TOP10, COMPONENT_THREAT_MAP, MITIGATION_LIBRARY,
    detect_components_from_text, score_architecture_risk,
    calculate_overall_risk_score,
)
from retrieval import retrieve_security_context, retrieve_threat_specific_context

load_dotenv()
logger = logging.getLogger("AEGIS.LLM")

GOOGLE_API_KEY = os.environ.get("GOOGLE_API_KEY")
MODEL_NAME     = "gemini-2.0-flash"  # Stable, fast, free-tier friendly

# ── System Prompt ──────────────────────────────────────────────────────────────

AEGIS_SYSTEM_PROMPT = """You are AEGIS — an expert AI Security Architect and Threat Modeling Engine.
Your role is to analyze AI system architectures and generate comprehensive, actionable security assessments.

You are grounded in:
- OWASP LLM Top 10 (2025 edition)
- NIST AI Risk Management Framework (AI RMF 1.0)
- ENISA AI Threat Landscape
- MITRE ATLAS
- Cloud Security Alliance (CSA) AI Security Guidelines

When analyzing an architecture:
1. Identify all AI components and their trust boundaries
2. Map each component to applicable OWASP LLM Top 10 threats
3. Provide specific, actionable mitigations grounded in the retrieved context
4. Highlight attack paths and cascading failure scenarios
5. Prioritize findings by CVSS-based risk scores

Format your responses with clear structure:
- Use **bold** for component names and threat titles
- Provide concrete examples, not generic advice
- Reference specific OWASP IDs (LLM01–LLM10) and NIST controls
- Be direct and technically precise

IMPORTANT: Always base your analysis on the provided security framework context and the specific architecture described."""

# ── LLM Initialization ─────────────────────────────────────────────────────────

def get_llm(temperature: float = 0.2) -> ChatGoogleGenerativeAI:
    return ChatGoogleGenerativeAI(
        model=MODEL_NAME,
        temperature=temperature,
        google_api_key=GOOGLE_API_KEY,
    )


# ── Core Analysis Functions ────────────────────────────────────────────────────

def analyze_architecture(
    architecture_text: str,
    vector_store,
    num_chunks: int = 6,
    score_threshold: float = 0.35,
) -> Dict[str, Any]:
    """
    Main analysis pipeline:
    1. Parse components from architecture text
    2. Retrieve relevant security context via RAG
    3. Generate structured threat model via LLM
    4. Return structured result dict
    """
    llm = get_llm()
    detected = detect_components_from_text(architecture_text)

    # ── RAG Retrieval ──────────────────────────────────────────────────────────
    retrieval_query = (
        f"AI security threats for: {', '.join(detected)} "
        f"architecture — OWASP LLM prompt injection agent tool misuse "
        f"sensitive data retrieval poisoning mitigation"
    )
    rag_context, source_docs = retrieve_security_context(
        retrieval_query, vector_store, k=num_chunks, score_threshold=score_threshold
    )

    # ── Build Analysis Prompt ──────────────────────────────────────────────────
    rag_section = (
        f"RETRIEVED SECURITY FRAMEWORK CONTEXT:\n{rag_context}"
        if rag_context
        else "No specific framework passages retrieved — use your built-in knowledge."
    )

    prompt = f"""Analyze the following AI system architecture and generate a comprehensive security threat model.

ARCHITECTURE DESCRIPTION:
{architecture_text}

DETECTED COMPONENTS: {', '.join(detected) if detected else 'See architecture description'}

{rag_section}

Generate a detailed threat model with the following sections:

## 1. ARCHITECTURE SUMMARY
Brief technical summary of the AI system and its attack surface.

## 2. IDENTIFIED COMPONENTS & TRUST BOUNDARIES
List each AI component, its role, and trust classification (trusted/semi-trusted/untrusted).

## 3. THREAT FINDINGS
For each applicable OWASP LLM threat (LLM01–LLM10), provide:
- **Threat ID & Name** (e.g., LLM01 – Prompt Injection)
- **Risk Level**: Critical / High / Medium / Low
- **Affected Components**: Which parts of the architecture are vulnerable
- **Attack Scenario**: Concrete, specific attack narrative for THIS architecture
- **Business Impact**: What an attacker can achieve
- **NIST AI RMF Control**: Applicable control reference
- **Mitigations**: 3–5 specific, actionable countermeasures

## 4. ATTACK PATHS
Describe 2–3 end-to-end attack chains specific to this architecture.

## 5. PRIORITY REMEDIATION ROADMAP
Rank top 5 most critical fixes with implementation guidance.

## 6. COMPLIANCE GAPS
Map findings to OWASP LLM Top 10 and NIST AI RMF gaps.

Be specific to the described architecture. Avoid generic advice."""

    # ── LLM Invocation ─────────────────────────────────────────────────────────
    messages = [
        SystemMessage(content=AEGIS_SYSTEM_PROMPT),
        HumanMessage(content=prompt),
    ]

    try:
        response = llm.invoke(messages)
        raw = response.content
        if isinstance(raw, list):
            analysis_text = " ".join(
                b.get("text", "") for b in raw if isinstance(b, dict) and b.get("type") == "text"
            )
        else:
            analysis_text = str(raw)
    except Exception as e:
        logger.error(f"LLM invocation error: {e}")
        analysis_text = f"⚠️ Analysis failed: {str(e)}"

    # ── Build Threat Findings (structured) ────────────────────────────────────
    threat_findings = _build_threat_findings(detected, architecture_text)
    risk_summary    = score_architecture_risk(threat_findings)
    overall_score   = calculate_overall_risk_score(risk_summary)

    return {
        "analysis_text":    analysis_text,
        "source_docs":      source_docs,
        "detected_components": detected,
        "threat_findings":  threat_findings,
        "risk_summary":     risk_summary,
        "overall_score":    overall_score,
        "rag_context_used": bool(rag_context),
        "num_sources":      len(source_docs),
    }


def _build_threat_findings(detected_components: List[str], arch_text: str) -> List[ThreatFinding]:
    """Build structured ThreatFinding objects based on detected components."""
    applicable_threat_ids = set()
    for comp in detected_components:
        for key, threats in COMPONENT_THREAT_MAP.items():
            if key in comp or comp in key:
                applicable_threat_ids.update(threats)

    # Always include LLM01 (Prompt Injection) if any LLM-related component found
    if any(c in detected_components for c in ["llm", "rag", "agent", "orchestrat"]):
        applicable_threat_ids.add("LLM01")

    findings = []
    for threat_id in sorted(applicable_threat_ids):
        if threat_id not in OWASP_LLM_TOP10:
            continue
        threat_meta = OWASP_LLM_TOP10[threat_id]
        mitig_meta  = MITIGATION_LIBRARY.get(threat_id, {})

        affected = [
            comp for comp in detected_components
            if any(kw in arch_text.lower() for kw in [comp])
        ] or ["System-wide"]

        findings.append(ThreatFinding(
            id=threat_id,
            title=threat_meta["name"],
            category=threat_meta["category"],
            risk_level=threat_meta["base_risk"],
            affected_components=affected,
            description=f"OWASP LLM {threat_id}: {threat_meta['name']} — applicable to detected components: {', '.join(affected)}",
            attack_scenario="See detailed analysis above.",
            impact="Depends on component configuration and data sensitivity.",
            owasp_reference=f"OWASP LLM Top 10 – {threat_id}",
            nist_control=mitig_meta.get("nist", "GOVERN 1.1"),
            mitigations=mitig_meta.get("mitigations", ["Apply defense-in-depth"]),
            references=mitig_meta.get("references", []),
            cvss_score=threat_meta.get("cvss", 5.0),
        ))

    return sorted(findings, key=lambda f: f.cvss_score, reverse=True)


def generate_followup_answer(
    question: str,
    architecture_context: str,
    chat_history: List,
    vector_store,
    num_chunks: int = 4,
) -> tuple:
    """
    Handle follow-up Q&A with architecture context preserved.
    Returns (answer_text, source_docs)
    """
    llm = get_llm(temperature=0.3)

    # Retrieve context for the specific question
    rag_context, source_docs = retrieve_security_context(
        question, vector_store, k=num_chunks, score_threshold=0.3
    )

    rag_section = (
        f"RELEVANT SECURITY KNOWLEDGE:\n{rag_context}"
        if rag_context else
        "Use your built-in AI security knowledge."
    )

    qa_prompt = f"""You are AEGIS, an AI Security expert. Answer the following security question about the architecture.

ARCHITECTURE CONTEXT:
{architecture_context[:2000]}

{rag_section}

QUESTION: {question}

Provide a specific, technical, actionable answer referencing the architecture and OWASP/NIST frameworks where applicable."""

    messages = (
        [SystemMessage(content=AEGIS_SYSTEM_PROMPT)]
        + chat_history
        + [HumanMessage(content=qa_prompt)]
    )

    try:
        response = llm.invoke(messages)
        raw = response.content
        answer = " ".join(
            b.get("text", "") for b in raw if isinstance(b, dict) and b.get("type") == "text"
        ) if isinstance(raw, list) else str(raw)
    except Exception as e:
        answer = f"⚠️ Error: {str(e)}"

    return answer, source_docs


def generate_executive_summary(analysis_text: str, risk_summary: Dict, overall_score: float) -> str:
    """Generate a concise executive summary suitable for non-technical stakeholders."""
    llm = get_llm(temperature=0.1)

    prompt = f"""Based on this AI security threat model analysis:

RISK SUMMARY: {risk_summary}
OVERALL RISK SCORE: {overall_score}/100

FULL ANALYSIS:
{analysis_text[:3000]}

Write a concise 3-paragraph executive summary (non-technical language) covering:
1. Overall security posture and risk level
2. Top 3 most critical risks and potential business impact  
3. Recommended immediate actions

Keep it under 300 words. Use clear business language, not security jargon."""

    try:
        response = llm.invoke([
            SystemMessage(content="You are a senior security advisor writing for C-suite executives."),
            HumanMessage(content=prompt),
        ])
        return str(response.content)
    except Exception as e:
        return f"Executive summary unavailable: {e}"
