# ─────────────────────────────────────────────────────────────────────────────
# AEGIS – AI Architecture Threat Modeling & Security Review Engine
# Main Streamlit Application
# ─────────────────────────────────────────────────────────────────────────────

import os
import sys
import time
import streamlit as st
from dotenv import load_dotenv

# Fix Unicode on Windows
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

load_dotenv()

# ── Page Config (MUST be first Streamlit call) ─────────────────────────────────
st.set_page_config(
    page_title="AEGIS – AI Security Review Engine",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Imports (after page config) ────────────────────────────────────────────────
from langchain_core.messages import HumanMessage, AIMessage, SystemMessage
from retrieval import get_vector_store, check_index_health
from llm_engine import analyze_architecture, generate_followup_answer, generate_executive_summary
from threat_engine import (
    OWASP_LLM_TOP10, RiskLevel,
    get_risk_badge_html, get_risk_color, calculate_overall_risk_score,
)

try:
    from report_generator import generate_pdf_report
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False

import plotly.graph_objects as go
import plotly.express as px

# ═══════════════════════════════════════════════════════════════════════════════
# CUSTOM CSS
# ═══════════════════════════════════════════════════════════════════════════════
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;900&family=JetBrains+Mono:wght@400;600&display=swap');

/* ── Global Reset ── */
html, body, [class*="css"] {
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
}

.stApp {
    background: #060b14;
    color: #e2e8f0;
}

/* ── Scrollbar ── */
::-webkit-scrollbar { width: 6px; }
::-webkit-scrollbar-track { background: #0d1526; }
::-webkit-scrollbar-thumb { background: #1e3a5f; border-radius: 3px; }

/* ── Hero Banner ── */
.aegis-hero {
    background: linear-gradient(135deg, #060b14 0%, #0a1628 40%, #0d2347 100%);
    border: 1px solid rgba(0,212,255,0.15);
    border-radius: 20px;
    padding: 3rem 2.5rem;
    margin-bottom: 2rem;
    position: relative;
    overflow: hidden;
}
.aegis-hero::before {
    content: '';
    position: absolute;
    top: -50%;
    left: -50%;
    width: 200%;
    height: 200%;
    background: radial-gradient(ellipse at 30% 50%, rgba(0,212,255,0.06) 0%, transparent 60%),
                radial-gradient(ellipse at 70% 20%, rgba(124,58,237,0.06) 0%, transparent 50%);
    pointer-events: none;
}
.aegis-title {
    font-size: 3.2rem;
    font-weight: 900;
    letter-spacing: -2px;
    background: linear-gradient(135deg, #00d4ff 0%, #7c3aed 50%, #ff2d55 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
    margin: 0;
    line-height: 1.1;
}
.aegis-tagline {
    font-size: 1.05rem;
    color: #64748b;
    margin-top: 0.5rem;
    font-weight: 400;
    letter-spacing: 0.3px;
}
.aegis-sub {
    font-size: 0.85rem;
    color: #475569;
    margin-top: 1rem;
    padding-top: 1rem;
    border-top: 1px solid rgba(255,255,255,0.06);
}

/* ── Framework Badges ── */
.framework-badge {
    display: inline-block;
    background: rgba(0,212,255,0.08);
    color: #00d4ff;
    border: 1px solid rgba(0,212,255,0.25);
    border-radius: 20px;
    padding: 3px 12px;
    font-size: 0.72rem;
    font-weight: 600;
    margin: 3px;
    letter-spacing: 0.5px;
}

/* ── Risk Score Gauge ── */
.risk-score-card {
    background: linear-gradient(135deg, #0a1628, #111827);
    border: 1px solid rgba(255,255,255,0.08);
    border-radius: 16px;
    padding: 1.5rem;
    text-align: center;
}
.risk-score-number {
    font-size: 3.5rem;
    font-weight: 900;
    font-family: 'JetBrains Mono', monospace;
    line-height: 1;
}

/* ── Metric Cards ── */
.metric-card {
    background: linear-gradient(135deg, #0a1628, #111827);
    border: 1px solid rgba(255,255,255,0.08);
    border-radius: 12px;
    padding: 1.2rem 1.5rem;
    text-align: center;
}
.metric-value {
    font-size: 2rem;
    font-weight: 800;
    font-family: 'JetBrains Mono', monospace;
}
.metric-label {
    font-size: 0.78rem;
    color: #64748b;
    font-weight: 500;
    text-transform: uppercase;
    letter-spacing: 1px;
    margin-top: 4px;
}

/* ── Threat Cards ── */
.threat-card {
    background: linear-gradient(135deg, #0a1628, #0f1f3d);
    border: 1px solid rgba(255,255,255,0.07);
    border-radius: 14px;
    padding: 1.4rem 1.8rem;
    margin: 0.8rem 0;
    position: relative;
    transition: border-color 0.2s;
}
.threat-card:hover {
    border-color: rgba(0,212,255,0.25);
}
.threat-card-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 0.8rem;
}
.threat-id {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.8rem;
    font-weight: 600;
    color: #00d4ff;
    background: rgba(0,212,255,0.1);
    padding: 2px 10px;
    border-radius: 8px;
    border: 1px solid rgba(0,212,255,0.2);
}
.threat-title {
    font-size: 1rem;
    font-weight: 700;
    color: #f1f5f9;
    flex: 1;
    margin-left: 10px;
}
.cvss-badge {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.75rem;
    font-weight: 700;
    color: #94a3b8;
    background: rgba(255,255,255,0.06);
    padding: 2px 8px;
    border-radius: 6px;
}
.threat-detail-label {
    font-size: 0.72rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: #475569;
    margin-bottom: 3px;
}
.mitigation-item {
    background: rgba(0,212,255,0.04);
    border-left: 2px solid rgba(0,212,255,0.4);
    border-radius: 0 6px 6px 0;
    padding: 5px 10px;
    margin: 4px 0;
    font-size: 0.85rem;
    color: #cbd5e1;
}

/* ── Source Docs ── */
.source-doc {
    background: rgba(0,0,0,0.3);
    border: 1px solid rgba(255,255,255,0.06);
    border-left: 3px solid #7c3aed;
    border-radius: 0 8px 8px 0;
    padding: 0.7rem 1rem;
    margin: 0.5rem 0;
    font-size: 0.82rem;
    color: #94a3b8;
}
.source-framework-tag {
    display: inline-block;
    background: rgba(124,58,237,0.15);
    color: #a78bfa;
    border: 1px solid rgba(124,58,237,0.3);
    border-radius: 10px;
    padding: 1px 8px;
    font-size: 0.70rem;
    font-weight: 600;
    margin-right: 6px;
}

/* ── Chat UI ── */
.chat-message-user {
    background: rgba(124,58,237,0.12);
    border: 1px solid rgba(124,58,237,0.25);
    border-radius: 12px 12px 4px 12px;
    padding: 0.8rem 1.2rem;
    margin: 0.5rem 0;
    font-size: 0.9rem;
    color: #e2e8f0;
}
.chat-message-ai {
    background: rgba(0,212,255,0.06);
    border: 1px solid rgba(0,212,255,0.15);
    border-radius: 4px 12px 12px 12px;
    padding: 0.8rem 1.2rem;
    margin: 0.5rem 0;
    font-size: 0.9rem;
    color: #e2e8f0;
}

/* ── Input Area ── */
.stTextArea textarea {
    background: #0a1628 !important;
    border: 1px solid rgba(0,212,255,0.2) !important;
    border-radius: 12px !important;
    color: #e2e8f0 !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 0.88rem !important;
}
.stTextArea textarea:focus {
    border-color: rgba(0,212,255,0.5) !important;
    box-shadow: 0 0 0 2px rgba(0,212,255,0.12) !important;
}

/* ── Buttons ── */
.stButton > button {
    background: linear-gradient(135deg, #0d2347, #1a3a6e) !important;
    color: #00d4ff !important;
    border: 1px solid rgba(0,212,255,0.3) !important;
    border-radius: 10px !important;
    font-weight: 600 !important;
    font-family: 'Inter', sans-serif !important;
    letter-spacing: 0.3px !important;
    transition: all 0.2s !important;
}
.stButton > button:hover {
    background: linear-gradient(135deg, #1a3a6e, #2455a0) !important;
    border-color: rgba(0,212,255,0.6) !important;
    transform: translateY(-1px) !important;
    box-shadow: 0 4px 20px rgba(0,212,255,0.15) !important;
}

/* Primary CTA */
.stButton > button[kind="primary"] {
    background: linear-gradient(135deg, #00d4ff, #7c3aed) !important;
    color: white !important;
    border: none !important;
    font-size: 0.95rem !important;
}
.stButton > button[kind="primary"]:hover {
    filter: brightness(1.1) !important;
    box-shadow: 0 6px 24px rgba(0,212,255,0.3) !important;
}

/* ── Sidebar ── */
section[data-testid="stSidebar"] {
    background: #070d1a !important;
    border-right: 1px solid rgba(255,255,255,0.06) !important;
}
.sidebar-section-title {
    font-size: 0.72rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 2px;
    color: #475569;
    padding: 0.5rem 0;
    border-bottom: 1px solid rgba(255,255,255,0.06);
    margin-bottom: 0.5rem;
}

/* ── Status/Alert Pills ── */
.status-ok   { color: #30d158; }
.status-warn { color: #ffd60a; }
.status-err  { color: #ff2d55; }

/* ── Dividers ── */
.aegis-divider {
    height: 1px;
    background: linear-gradient(90deg, transparent, rgba(0,212,255,0.2), transparent);
    margin: 1.5rem 0;
}

/* ── Tab styling ── */
.stTabs [data-baseweb="tab-list"] {
    background: rgba(10,22,40,0.8);
    border-radius: 12px;
    padding: 4px;
    gap: 4px;
}
.stTabs [data-baseweb="tab"] {
    background: transparent;
    border-radius: 8px;
    color: #64748b;
    font-weight: 600;
    font-size: 0.88rem;
}
.stTabs [aria-selected="true"] {
    background: rgba(0,212,255,0.12) !important;
    color: #00d4ff !important;
}

/* ── Expander ── */
.streamlit-expanderHeader {
    background: rgba(10,22,40,0.8) !important;
    border-radius: 8px !important;
    color: #94a3b8 !important;
}

/* ── Hide Streamlit branding ── */
#MainMenu { visibility: hidden; }
footer { visibility: hidden; }
header { visibility: hidden; }
</style>
""", unsafe_allow_html=True)

# ═══════════════════════════════════════════════════════════════════════════════
# SESSION STATE INITIALIZATION
# ═══════════════════════════════════════════════════════════════════════════════
def init_session_state():
    defaults = {
        "analysis_result":    None,
        "architecture_text":  "",
        "executive_summary":  "",
        "chat_history":       [],
        "analysis_done":      False,
        "pdf_bytes":          None,
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value

init_session_state()

# ═══════════════════════════════════════════════════════════════════════════════
# CACHED RESOURCES
# ═══════════════════════════════════════════════════════════════════════════════
@st.cache_resource(show_spinner="🔗 Connecting to AEGIS Knowledge Base...")
def load_vector_store():
    return get_vector_store()

# ═══════════════════════════════════════════════════════════════════════════════
# SIDEBAR
# ═══════════════════════════════════════════════════════════════════════════════
with st.sidebar:
    st.markdown("""
    <div style="text-align:center;padding:1rem 0;">
        <div style="font-size:2rem;">🛡️</div>
        <div style="font-size:1.1rem;font-weight:800;background:linear-gradient(135deg,#00d4ff,#7c3aed);
                    -webkit-background-clip:text;-webkit-text-fill-color:transparent;">AEGIS</div>
        <div style="font-size:0.7rem;color:#475569;letter-spacing:1px;">v1.0 · AI SECURITY ENGINE</div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown('<div class="sidebar-section-title">⚙️ Analysis Settings</div>', unsafe_allow_html=True)

    num_chunks = st.slider("RAG Context Chunks", 3, 10, 6,
                           help="More chunks = richer context but slower analysis")
    score_threshold = st.slider("Relevance Threshold", 0.2, 0.8, 0.35, 0.05,
                                help="Minimum similarity score for retrieved security passages")
    show_sources = st.toggle("Show Retrieved Sources", value=True)
    show_raw_analysis = st.toggle("Show Full LLM Analysis", value=True)

    st.markdown('<div class="sidebar-section-title" style="margin-top:1rem;">📚 Knowledge Base</div>', unsafe_allow_html=True)

    # Check KB health
    try:
        vs = load_vector_store()
        health = check_index_health(vs)
        if health["healthy"] and health["has_documents"]:
            st.markdown('<span class="status-ok">● KB Connected & Populated</span>', unsafe_allow_html=True)
        elif health["healthy"]:
            st.markdown('<span class="status-warn">● KB Connected — Empty</span>', unsafe_allow_html=True)
            st.caption("Run `ingestion.py` to load security frameworks")
        else:
            st.markdown('<span class="status-err">● KB Offline</span>', unsafe_allow_html=True)
            st.caption(health["message"])
    except Exception as e:
        st.markdown('<span class="status-err">● Connection Error</span>', unsafe_allow_html=True)
        st.caption(str(e)[:80])

    st.markdown('<div class="sidebar-section-title" style="margin-top:1rem;">🔖 Frameworks</div>', unsafe_allow_html=True)
    frameworks = ["OWASP LLM Top 10", "NIST AI RMF", "ENISA AI Threat Landscape", "MITRE ATLAS", "CSA AI Security"]
    for fw in frameworks:
        st.markdown(f'<span class="framework-badge">{fw}</span>', unsafe_allow_html=True)

    st.markdown("---")
    if st.button("🗑️ Clear Session", use_container_width=True):
        for key in ["analysis_result", "architecture_text", "executive_summary",
                    "chat_history", "analysis_done", "pdf_bytes"]:
            st.session_state[key] = None if key != "chat_history" else []
        st.session_state.analysis_done = False
        st.rerun()

    # Example architectures
    st.markdown('<div class="sidebar-section-title" style="margin-top:0.5rem;">💡 Quick Examples</div>', unsafe_allow_html=True)

    examples = {
        "RAG Chatbot": (
            "A customer support chatbot using GPT-4 with a RAG pipeline backed by Pinecone vector database. "
            "Users submit queries via a public web interface. The system retrieves internal company documents "
            "and product manuals. It calls external tools including a CRM API and an email sending service. "
            "System prompts contain confidential business rules. No authentication is required for the chatbot."
        ),
        "AI Agent": (
            "An autonomous AI agent built with LangChain that accepts natural language task instructions "
            "from employees. The agent can: read/write to a PostgreSQL database, execute Python code via "
            "a code interpreter tool, send Slack messages, create JIRA tickets, and query external APIs. "
            "The agent uses GPT-4 as its backbone with a system prompt defining its persona and permissions. "
            "Multiple employees with different privilege levels can interact with the agent."
        ),
        "Fine-Tuned LLM API": (
            "A SaaS platform offering a fine-tuned medical diagnostic LLM via REST API. The model was "
            "fine-tuned on proprietary hospital records and clinical notes. The API is publicly accessible "
            "with API key authentication. Responses include confidence scores used by clinicians to make "
            "treatment decisions. The platform uses HuggingFace for model hosting and updates."
        ),
    }

    for name, text in examples.items():
        if st.button(f"📋 {name}", use_container_width=True, key=f"example_{name}"):
            st.session_state.architecture_text = text
            st.rerun()

# ═══════════════════════════════════════════════════════════════════════════════
# HERO HEADER
# ═══════════════════════════════════════════════════════════════════════════════
st.markdown("""
<div class="aegis-hero">
    <h1 class="aegis-title">AEGIS</h1>
    <p style="font-size:1.1rem;color:#94a3b8;margin:0.4rem 0 0.8rem;">
        AI Architecture Threat Modeling & Security Review Engine
    </p>
    <p class="aegis-tagline">
        Transform your AI system architecture into a comprehensive security intelligence report.<br>
        Grounded in OWASP LLM Top 10 · NIST AI RMF · ENISA · MITRE ATLAS
    </p>
    <div style="margin-top:1.2rem;">
        <span class="framework-badge">🔴 OWASP LLM Top 10</span>
        <span class="framework-badge">🔵 NIST AI RMF</span>
        <span class="framework-badge">🟡 ENISA</span>
        <span class="framework-badge">⚫ MITRE ATLAS</span>
        <span class="framework-badge">🟣 CSA AI Guidelines</span>
    </div>
</div>
""", unsafe_allow_html=True)

# ═══════════════════════════════════════════════════════════════════════════════
# MAIN TABS
# ═══════════════════════════════════════════════════════════════════════════════
tab_analyze, tab_results, tab_chat, tab_owasp = st.tabs([
    "🔍 Analyze Architecture",
    "📊 Threat Report",
    "💬 Security Q&A",
    "📖 OWASP Reference"
])

# ═══════════════════════════════════════════════════════════════════════════════
# TAB 1: ANALYZE ARCHITECTURE
# ═══════════════════════════════════════════════════════════════════════════════
with tab_analyze:
    st.markdown("### Describe Your AI Architecture")
    st.markdown(
        "<p style='color:#64748b;font-size:0.9rem;'>Provide a detailed description of your AI system. "
        "Include: components (LLMs, vector DBs, agents, tools), data flows, authentication mechanisms, "
        "deployment environment, and user access patterns.</p>",
        unsafe_allow_html=True
    )

    architecture_input = st.text_area(
        label="Architecture Description",
        value=st.session_state.architecture_text,
        placeholder=(
            "Example:\n"
            "Our AI system uses GPT-4 as the backbone LLM, connected to a Pinecone vector database "
            "for RAG-based document retrieval. Users interact via a public web UI without authentication. "
            "The system has tool-calling capabilities including: web search, code execution sandbox, "
            "and a CRM API integration. System prompts contain proprietary business logic. "
            "We also use LangChain for orchestration and have a fine-tuned model for classification tasks..."
        ),
        height=220,
        label_visibility="collapsed",
        key="arch_input"
    )

    col1, col2, col3 = st.columns([3, 1, 1])
    with col1:
        analyze_btn = st.button(
            "🛡️  Run AEGIS Security Analysis",
            type="primary",
            use_container_width=True,
            disabled=(len(architecture_input.strip()) < 30),
        )
    with col2:
        if st.session_state.analysis_done and PDF_AVAILABLE and st.session_state.pdf_bytes:
            st.download_button(
                "📄 Export PDF",
                data=st.session_state.pdf_bytes,
                file_name=f"AEGIS_Report_{int(time.time())}.pdf",
                mime="application/pdf",
                use_container_width=True,
            )
    with col3:
        char_count = len(architecture_input)
        if char_count < 50:
            st.markdown(f"<small style='color:#ff6b35;'>⚠️ {char_count} chars (need more detail)</small>", unsafe_allow_html=True)
        else:
            st.markdown(f"<small style='color:#30d158;'>✓ {char_count} chars</small>", unsafe_allow_html=True)

    # ── Analysis Execution ─────────────────────────────────────────────────────
    if analyze_btn and len(architecture_input.strip()) >= 30:
        st.session_state.architecture_text = architecture_input
        st.session_state.analysis_done = False
        st.session_state.chat_history   = []

        with st.status("🔒 AEGIS Security Analysis in Progress...", expanded=True) as status:
            st.write("📡 Connecting to knowledge base...")
            try:
                vs = load_vector_store()
                st.write("✅ Knowledge base connected")

                st.write("🔍 Identifying AI components...")
                from threat_engine import detect_components_from_text
                detected = detect_components_from_text(architecture_input)
                if detected:
                    st.write(f"   Found: **{', '.join(detected)}**")

                st.write("🧠 Retrieving security framework context (RAG)...")
                time.sleep(0.3)

                st.write("🤖 Generating threat model with Gemini...")
                result = analyze_architecture(
                    architecture_input, vs,
                    num_chunks=num_chunks,
                    score_threshold=score_threshold,
                )
                st.session_state.analysis_result = result

                st.write("📝 Generating executive summary...")
                exec_summary = generate_executive_summary(
                    result["analysis_text"],
                    result["risk_summary"],
                    result["overall_score"],
                )
                st.session_state.executive_summary = exec_summary

                if PDF_AVAILABLE:
                    st.write("📄 Generating PDF report...")
                    try:
                        pdf_bytes = generate_pdf_report(
                            architecture_input, result, exec_summary
                        )
                        st.session_state.pdf_bytes = pdf_bytes
                    except Exception as e:
                        st.warning(f"PDF generation skipped: {e}")

                st.session_state.analysis_done = True
                status.update(label="✅ Analysis Complete!", state="complete")

            except Exception as e:
                status.update(label=f"❌ Analysis Failed", state="error")
                st.error(f"Error: {str(e)}")

        if st.session_state.analysis_done:
            st.success("🎯 Threat model generated! Navigate to the **📊 Threat Report** tab to view results.")
            st.balloons()

    # ── Quick Tips ─────────────────────────────────────────────────────────────
    if not st.session_state.analysis_done:
        st.markdown("<div class='aegis-divider'></div>", unsafe_allow_html=True)
        st.markdown("#### 💡 What to Include in Your Description")
        tips_col1, tips_col2 = st.columns(2)
        with tips_col1:
            st.markdown("""
            **AI Components**
            - Foundation model (GPT-4, Gemini, Llama, etc.)
            - RAG pipeline and vector database
            - Agent frameworks (LangChain, AutoGen, CrewAI)
            - Fine-tuned models

            **Integrations**
            - Tool/function calling capabilities
            - External API integrations
            - Plugin systems
            """)
        with tips_col2:
            st.markdown("""
            **Security Context**
            - Authentication / authorization model
            - User types and access levels
            - Data sensitivity (PII, confidential)
            - Deployment environment (cloud, on-prem)

            **Data Flows**
            - Input sources (public/internal users)
            - Data processed by the AI
            - Output destinations
            """)

# ═══════════════════════════════════════════════════════════════════════════════
# TAB 2: THREAT REPORT
# ═══════════════════════════════════════════════════════════════════════════════
with tab_results:
    if not st.session_state.analysis_done:
        st.markdown("""
        <div style="text-align:center;padding:4rem 2rem;">
            <div style="font-size:4rem;margin-bottom:1rem;">🛡️</div>
            <h3 style="color:#475569;">No Analysis Yet</h3>
            <p style="color:#334155;">Describe your AI architecture in the <strong>Analyze Architecture</strong> tab and run AEGIS.</p>
        </div>
        """, unsafe_allow_html=True)
    else:
        result = st.session_state.analysis_result
        score  = result["overall_score"]
        risk_summary = result["risk_summary"]

        # Determine color based on score
        if score >= 80:
            score_color = "#ff2d55"
            risk_label  = "CRITICAL RISK"
        elif score >= 60:
            score_color = "#ff6b35"
            risk_label  = "HIGH RISK"
        elif score >= 40:
            score_color = "#ffd60a"
            risk_label  = "MEDIUM RISK"
        else:
            score_color = "#30d158"
            risk_label  = "LOW RISK"

        # ── Overall Risk Banner ────────────────────────────────────────────────
        st.markdown(f"""
        <div style="background:linear-gradient(135deg,#0a1628,#0f1f3d);border:1px solid {score_color}33;
                    border-radius:16px;padding:1.5rem 2rem;margin-bottom:1.5rem;
                    border-left:4px solid {score_color};">
            <div style="display:flex;align-items:center;justify-content:space-between;">
                <div>
                    <div style="font-size:0.72rem;font-weight:700;text-transform:uppercase;
                                letter-spacing:2px;color:{score_color};margin-bottom:4px;">
                        Security Assessment Complete
                    </div>
                    <div style="font-size:1.6rem;font-weight:800;color:#f1f5f9;">
                        {risk_label}
                    </div>
                    <div style="color:#64748b;font-size:0.88rem;margin-top:4px;">
                        {len(result['threat_findings'])} threats identified · {len(result['detected_components'])} components analyzed
                        {'· ' + str(result['num_sources']) + ' framework sources retrieved' if result.get('num_sources') else ''}
                    </div>
                </div>
                <div style="text-align:center;">
                    <div style="font-size:3.5rem;font-weight:900;font-family:'JetBrains Mono',monospace;
                                color:{score_color};">{score:.0f}</div>
                    <div style="font-size:0.72rem;color:#64748b;font-weight:600;letter-spacing:1px;">/ 100 RISK SCORE</div>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        # ── Metrics Row ────────────────────────────────────────────────────────
        m1, m2, m3, m4, m5 = st.columns(5)
        metric_data = [
            (m1, risk_summary.get("Critical", 0),  "#ff2d55", "Critical"),
            (m2, risk_summary.get("High", 0),       "#ff6b35", "High"),
            (m3, risk_summary.get("Medium", 0),     "#ffd60a", "Medium"),
            (m4, risk_summary.get("Low", 0),        "#30d158", "Low"),
            (m5, len(result["detected_components"]), "#00d4ff","Components"),
        ]
        for col, val, color, label in metric_data:
            with col:
                st.markdown(f"""
                <div class="metric-card">
                    <div class="metric-value" style="color:{color};">{val}</div>
                    <div class="metric-label">{label}</div>
                </div>
                """, unsafe_allow_html=True)

        st.markdown("<div class='aegis-divider'></div>", unsafe_allow_html=True)

        # ── Risk Visualization ─────────────────────────────────────────────────
        viz_col, summary_col = st.columns([1, 1])

        with viz_col:
            st.markdown("##### 📊 Risk Distribution")
            labels = list(risk_summary.keys())
            values = list(risk_summary.values())
            colors_map = {
                "Critical": "#ff2d55", "High": "#ff6b35",
                "Medium": "#ffd60a", "Low": "#30d158", "Informational": "#636366"
            }
            chart_colors = [colors_map.get(l, "#636366") for l in labels]
            fig = go.Figure(data=[go.Pie(
                labels=labels, values=values,
                marker=dict(colors=chart_colors, line=dict(color="#060b14", width=2)),
                hole=0.55,
                textinfo="label+value",
                textfont=dict(color="white", size=12),
            )])
            fig.update_layout(
                showlegend=False,
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                margin=dict(l=10, r=10, t=10, b=10),
                height=220,
                annotations=[dict(
                    text=f"<b>{score:.0f}</b>",
                    x=0.5, y=0.5, font_size=28, showarrow=False,
                    font_color=score_color,
                )]
            )
            st.plotly_chart(fig, use_container_width=True)

        with summary_col:
            st.markdown("##### 📝 Executive Summary")
            if st.session_state.executive_summary:
                st.markdown(
                    f"<div style='background:rgba(0,0,0,0.3);border-radius:10px;padding:1rem;"
                    f"color:#cbd5e1;font-size:0.88rem;line-height:1.6;'>"
                    f"{st.session_state.executive_summary.replace(chr(10), '<br>')}</div>",
                    unsafe_allow_html=True
                )

        st.markdown("<div class='aegis-divider'></div>", unsafe_allow_html=True)

        # ── Threat Findings ────────────────────────────────────────────────────
        st.markdown("##### 🎯 Identified Threats")
        threats = result["threat_findings"]
        if not threats:
            st.info("No specific threat findings mapped. Check the detailed analysis below.")
        else:
            for threat in threats:
                risk_color = get_risk_color(threat.risk_level.value)
                with st.expander(
                    f"{threat.id} — {threat.title}  |  {threat.risk_level.value}  |  CVSS {threat.cvss_score}",
                    expanded=(threat.cvss_score >= 9.0)
                ):
                    tc1, tc2 = st.columns([1, 1])
                    with tc1:
                        st.markdown(f"**Category:** {threat.category.value}")
                        st.markdown(f"**OWASP Ref:** `{threat.owasp_reference}`")
                        st.markdown(f"**NIST Control:** `{threat.nist_control}`")
                        st.markdown(f"**Affected Components:** {', '.join(threat.affected_components)}")
                        st.markdown(
                            f"**Risk Level:** {get_risk_badge_html(threat.risk_level.value)}",
                            unsafe_allow_html=True
                        )
                    with tc2:
                        st.markdown("**🔧 Key Mitigations:**")
                        for m in threat.mitigations[:4]:
                            st.markdown(f"""
                            <div class="mitigation-item">✓ {m}</div>
                            """, unsafe_allow_html=True)

                    if threat.references:
                        st.markdown("**📎 References:**")
                        for ref in threat.references:
                            st.markdown(f"- [{ref}]({ref})")

        # ── Full Analysis ──────────────────────────────────────────────────────
        if show_raw_analysis:
            st.markdown("<div class='aegis-divider'></div>", unsafe_allow_html=True)
            st.markdown("##### 📋 Full LLM Security Analysis")
            with st.expander("View Complete AEGIS Analysis Report", expanded=True):
                st.markdown(result["analysis_text"])

        # ── Sources ────────────────────────────────────────────────────────────
        if show_sources and result.get("source_docs"):
            st.markdown("<div class='aegis-divider'></div>", unsafe_allow_html=True)
            st.markdown(f"##### 📚 Retrieved Framework Sources ({result['num_sources']} chunks)")
            with st.expander("Security Framework Passages Used"):
                for i, doc in enumerate(result["source_docs"], 1):
                    framework = doc.metadata.get("framework", "General")
                    source    = os.path.basename(str(doc.metadata.get("source", "Unknown")))
                    page      = doc.metadata.get("page", "?")
                    st.markdown(f"""
                    <div class="source-doc">
                        <span class="source-framework-tag">{framework}</span>
                        <strong>{source}</strong> · Page {page}
                        <br><span style="font-size:0.80rem;color:#64748b;">{doc.page_content[:300]}{'...' if len(doc.page_content) > 300 else ''}</span>
                    </div>
                    """, unsafe_allow_html=True)

        # ── Download Buttons ───────────────────────────────────────────────────
        st.markdown("<div class='aegis-divider'></div>", unsafe_allow_html=True)
        dl1, dl2, dl3 = st.columns(3)
        with dl1:
            if st.session_state.pdf_bytes and PDF_AVAILABLE:
                st.download_button(
                    "📄 Download PDF Report",
                    data=st.session_state.pdf_bytes,
                    file_name=f"AEGIS_Security_Report_{int(time.time())}.pdf",
                    mime="application/pdf",
                    use_container_width=True,
                )
        with dl2:
            report_md = f"# AEGIS Security Report\n\n{result['analysis_text']}"
            st.download_button(
                "📝 Download Markdown",
                data=report_md.encode("utf-8"),
                file_name=f"AEGIS_Report_{int(time.time())}.md",
                mime="text/markdown",
                use_container_width=True,
            )
        with dl3:
            import json
            export_data = {
                "overall_score":    result["overall_score"],
                "risk_summary":     result["risk_summary"],
                "detected":         result["detected_components"],
                "num_threats":      len(result["threat_findings"]),
            }
            st.download_button(
                "📊 Download JSON Summary",
                data=json.dumps(export_data, indent=2).encode("utf-8"),
                file_name=f"AEGIS_Summary_{int(time.time())}.json",
                mime="application/json",
                use_container_width=True,
            )

# ═══════════════════════════════════════════════════════════════════════════════
# TAB 3: SECURITY Q&A CHAT
# ═══════════════════════════════════════════════════════════════════════════════
with tab_chat:
    st.markdown("### 💬 Security Q&A — Ask AEGIS")
    st.markdown(
        "<p style='color:#64748b;font-size:0.9rem;'>Ask follow-up questions about your architecture's security. "
        "AEGIS will answer using your architecture context and retrieved security framework knowledge.</p>",
        unsafe_allow_html=True
    )

    if not st.session_state.analysis_done:
        st.info("🔍 Run an architecture analysis first to enable the security Q&A chat.")
    else:
        # Display chat history
        for msg in st.session_state.chat_history:
            if isinstance(msg, HumanMessage):
                with st.chat_message("user", avatar="🔐"):
                    st.markdown(msg.content)
            elif isinstance(msg, AIMessage):
                with st.chat_message("assistant", avatar="🛡️"):
                    st.markdown(msg.content)

        # Suggested questions
        if not st.session_state.chat_history:
            st.markdown("**💡 Suggested Questions:**")
            suggestions = [
                "What is the most critical attack path in this architecture?",
                "How should I implement prompt injection defense for this system?",
                "What NIST AI RMF controls apply to my RAG pipeline?",
                "How can an attacker exploit the agent's tool-calling capabilities?",
                "What data should I redact before embedding into the vector database?",
            ]
            q_cols = st.columns(2)
            for i, suggestion in enumerate(suggestions):
                with q_cols[i % 2]:
                    if st.button(suggestion, key=f"sugg_{i}", use_container_width=True):
                        st.session_state._pending_question = suggestion
                        st.rerun()

        # Handle pending suggestion clicks
        if hasattr(st.session_state, '_pending_question') and st.session_state._pending_question:
            user_input = st.session_state._pending_question
            st.session_state._pending_question = None
        else:
            user_input = None

        # Chat input
        chat_input = st.chat_input("Ask about threats, mitigations, compliance, attack paths...")

        if chat_input:
            user_input = chat_input

        if user_input:
            st.session_state.chat_history.append(HumanMessage(content=user_input))
            with st.chat_message("user", avatar="🔐"):
                st.markdown(user_input)

            with st.chat_message("assistant", avatar="🛡️"):
                with st.spinner("🔍 Retrieving security knowledge..."):
                    try:
                        vs = load_vector_store()
                        answer, src_docs = generate_followup_answer(
                            question=user_input,
                            architecture_context=st.session_state.architecture_text,
                            chat_history=st.session_state.chat_history[:-1],
                            vector_store=vs,
                            num_chunks=num_chunks,
                        )
                        st.markdown(answer)

                        if show_sources and src_docs:
                            with st.expander(f"📚 {len(src_docs)} source(s) retrieved"):
                                for doc in src_docs:
                                    fw = doc.metadata.get("framework", "General")
                                    st.markdown(f"""
                                    <div class="source-doc">
                                        <span class="source-framework-tag">{fw}</span>
                                        {doc.page_content[:250]}...
                                    </div>
                                    """, unsafe_allow_html=True)
                    except Exception as e:
                        answer = f"⚠️ Error: {str(e)}"
                        st.error(answer)

            st.session_state.chat_history.append(AIMessage(content=answer))

# ═══════════════════════════════════════════════════════════════════════════════
# TAB 4: OWASP REFERENCE
# ═══════════════════════════════════════════════════════════════════════════════
with tab_owasp:
    st.markdown("### 📖 OWASP LLM Top 10 — Quick Reference")
    st.markdown(
        "<p style='color:#64748b;font-size:0.9rem;'>Built-in reference guide to the OWASP Top 10 for "
        "Large Language Model Applications. Grounded in the 2025 edition.</p>",
        unsafe_allow_html=True
    )

    for threat_id, meta in OWASP_LLM_TOP10.items():
        risk_color = get_risk_color(meta["base_risk"].value)
        from threat_engine import MITIGATION_LIBRARY
        mitig = MITIGATION_LIBRARY.get(threat_id, {})

        with st.expander(
            f"**{threat_id}** — {meta['name']}  ·  {meta['base_risk'].value}  ·  CVSS {meta.get('cvss', '?')}",
            expanded=False
        ):
            oc1, oc2 = st.columns([1, 1])
            with oc1:
                st.markdown(f"**Risk Level:** {get_risk_badge_html(meta['base_risk'].value)}", unsafe_allow_html=True)
                st.markdown(f"**CVSS Score:** `{meta.get('cvss', 'N/A')}`")
                st.markdown(f"**NIST Controls:** `{mitig.get('nist', 'N/A')}`")
                st.markdown("**Common Triggers:**")
                for kw in meta.get("triggers", []):
                    st.markdown(f"`{kw}` ", unsafe_allow_html=True)
            with oc2:
                st.markdown("**Mitigations:**")
                for m in mitig.get("mitigations", []):
                    st.markdown(f"""<div class="mitigation-item">✓ {m}</div>""", unsafe_allow_html=True)
                if mitig.get("references"):
                    st.markdown("**References:**")
                    for ref in mitig["references"]:
                        st.markdown(f"- [{ref}]({ref})")
