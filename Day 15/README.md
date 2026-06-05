# 🛡️ AEGIS — AI Architecture Threat Modeling & Security Review Engine

> **Transform AI system architectures into security intelligence before deployment.**

AEGIS is a RAG-powered AI Security Review Engine that analyzes your AI architecture description and generates a comprehensive threat model grounded in authoritative security frameworks: **OWASP LLM Top 10**, **NIST AI RMF**, **ENISA**, **MITRE ATLAS**, and **CSA AI Security Guidelines**.

---

## 📁 Project Structure

```
AEGIS/
├── aegis_app.py              # Main Streamlit application (run this)
├── seed_knowledge_base.py    # Seeds Pinecone with built-in security knowledge (run first!)
├── ingestion.py              # Optional: ingest your own PDF security frameworks
├── retrieval.py              # RAG retrieval engine module
├── llm_engine.py             # Gemini LLM analysis orchestrator
├── threat_engine.py          # OWASP threat taxonomy and scoring engine
├── report_generator.py       # PDF report generator
├── requirements.txt          # Python dependencies
├── .env                      # API keys (Pinecone + Google Gemini)
└── documents/
    └── security_frameworks/  # (Optional) Drop PDF security frameworks here
```

---

## 🚀 Quick Start (5 Steps)

### Step 1: Activate Virtual Environment
```powershell
# Windows
.\venv\Scripts\Activate

# Mac/Linux
source venv/bin/activate
```

### Step 2: Verify API Keys in `.env`
```env
PINECONE_API_KEY=your_pinecone_api_key
PINECONE_INDEX_NAME=aegis-security-kb
GOOGLE_API_KEY=your_google_gemini_api_key
```

### Step 3: Seed the Knowledge Base (Run Once)
```powershell
python seed_knowledge_base.py
```
This populates Pinecone with **built-in OWASP LLM Top 10, NIST AI RMF, ENISA, and MITRE ATLAS content** — no PDF files required!

### Step 4: Launch AEGIS
```powershell
streamlit run aegis_app.py
```

### Step 5: Open in Browser
Navigate to **http://localhost:8501**

---

## 🔑 API Keys Setup

### Pinecone (Free tier available)
1. Go to [pinecone.io](https://www.pinecone.io/) → Sign up → Create API Key
2. The index `aegis-security-kb` is created automatically

### Google Gemini API
1. Go to [aistudio.google.com](https://aistudio.google.com/) → Get API Key
2. Free tier: 15 RPM, 1M tokens/day

---

## 🧠 How AEGIS Works

```
User describes AI Architecture
         │
         ▼
┌─────────────────────┐
│  Component Parser   │  ← Detects: LLM, RAG, Vector DB, Agents, Tools...
└─────────────────────┘
         │
         ▼
┌─────────────────────┐
│   RAG Retrieval     │  ← Fetches relevant OWASP/NIST/ENISA passages from Pinecone
│   (Pinecone)        │
└─────────────────────┘
         │
         ▼
┌─────────────────────┐
│  Gemini LLM Engine  │  ← Generates structured threat model with context
└─────────────────────┘
         │
         ▼
┌─────────────────────┐
│  Threat Report      │  ← Risk scores, attack paths, mitigations, PDF export
└─────────────────────┘
```

---

## 📊 Features

| Feature | Description |
|---------|-------------|
| 🔍 **Architecture Analysis** | Paste any AI system description — AEGIS detects components automatically |
| 🎯 **OWASP LLM Top 10 Mapping** | Maps LLM01–LLM10 threats to your specific architecture |
| 📈 **Risk Scoring** | CVSS-based composite risk score (0–100) |
| 📄 **PDF Reports** | Professional security assessment reports for stakeholders |
| 💬 **Security Q&A** | RAG-powered chat — ask follow-up questions about your architecture |
| 📚 **Framework Reference** | Built-in OWASP LLM Top 10 quick reference guide |
| 🔒 **Framework Coverage** | OWASP · NIST AI RMF · ENISA · MITRE ATLAS · CSA |

---

## 💡 Example Architectures to Test

**RAG Chatbot:**
```
Customer support chatbot using GPT-4 with Pinecone RAG. Users submit 
queries via public web UI without authentication. System retrieves from 
internal knowledge base and calls CRM API and email tools.
```

**AI Agent:**
```
Autonomous LangChain agent accepting natural language tasks from employees.
Can read/write to PostgreSQL, execute Python code, send Slack messages,
and create JIRA tickets. Uses GPT-4 with no human approval for actions.
```

---

## 🔧 Optional: Add Your Own PDFs

Drop PDF security frameworks into `documents/security_frameworks/` then run:
```powershell
python ingestion.py
```
Supported frameworks: OWASP LLM Top 10 PDF, NIST AI RMF, ENISA reports, custom security policies.

---

## 🏗️ Architecture: LangChain + Pinecone + Gemini

This project follows the same pattern as the `LangChain-Pinecone-RAG` reference:
- **LangChain** for orchestration and document processing
- **Pinecone** as the vector database for security knowledge retrieval
- **Google Gemini** (gemini-2.0-flash) for LLM reasoning
- **Google Gemini Embeddings** (gemini-embedding-2) for vector representation
- **Streamlit** for the interactive web interface

---

## ⚠️ Security Notice

The `.env` file contains sensitive API keys. Never commit it to version control.
The `.gitignore` is pre-configured to exclude `.env`.
