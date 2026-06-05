# ─────────────────────────────────────────────────────────────────────────────
# AEGIS – AI Architecture Threat Modeling & Security Review Engine
# Knowledge Base Ingestion Script
# ─────────────────────────────────────────────────────────────────────────────
#
# This script ingests security framework PDFs into Pinecone for RAG retrieval.
# Place PDFs in: documents/security_frameworks/
#
# Supported frameworks:
#   - OWASP LLM Top 10
#   - NIST AI RMF
#   - ENISA AI Threat Landscape
#   - Cloud Security Alliance AI Guidelines
#   - MITRE ATLAS
# ─────────────────────────────────────────────────────────────────────────────

import os
import sys
import time
import logging
from pathlib import Path
from dotenv import load_dotenv

# Fix Unicode encoding on Windows
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

# ── Imports ────────────────────────────────────────────────────────────────────
from pinecone import Pinecone, ServerlessSpec
from langchain_pinecone import PineconeVectorStore
from langchain_google_genai import GoogleGenerativeAIEmbeddings
from langchain_community.document_loaders import PyPDFDirectoryLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_core.documents import Document

# ── Logging ────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger("AEGIS.Ingestion")

# ── Load Environment ───────────────────────────────────────────────────────────
load_dotenv()

PINECONE_API_KEY    = os.environ.get("PINECONE_API_KEY")
GOOGLE_API_KEY      = os.environ.get("GOOGLE_API_KEY")
PINECONE_INDEX_NAME = os.environ.get("PINECONE_INDEX_NAME", "aegis-security-kb")
DOCS_DIR            = Path("documents/security_frameworks")

def main():
    logger.info("=" * 60)
    logger.info("  AEGIS Knowledge Base Ingestion Pipeline")
    logger.info("=" * 60)

    # ── Validate Keys ──────────────────────────────────────────────────────────
    if not PINECONE_API_KEY or not GOOGLE_API_KEY:
        logger.error("Missing API keys. Check your .env file.")
        sys.exit(1)

    if not DOCS_DIR.exists() or not any(DOCS_DIR.glob("*.pdf")):
        logger.error(f"No PDF files found in {DOCS_DIR}")
        logger.info("Please add security framework PDFs to: documents/security_frameworks/")
        logger.info("Suggested sources:")
        logger.info("  - OWASP LLM Top 10: https://owasp.org/www-project-top-10-for-large-language-model-applications/")
        logger.info("  - NIST AI RMF: https://airc.nist.gov/RMF/riskManagementFramework")
        logger.info("  - ENISA AI Threat Landscape: https://www.enisa.europa.eu/publications/enisa-threat-landscape-for-ai")
        sys.exit(1)

    # ── Initialize Pinecone ────────────────────────────────────────────────────
    logger.info(f"Connecting to Pinecone...")
    pc = Pinecone(api_key=PINECONE_API_KEY)

    existing_indexes = [idx["name"] for idx in pc.list_indexes()]
    if PINECONE_INDEX_NAME not in existing_indexes:
        logger.info(f"Creating new index: {PINECONE_INDEX_NAME}")
        pc.create_index(
            name=PINECONE_INDEX_NAME,
            dimension=3072,          # gemini-embedding-2 dimension
            metric="cosine",
            spec=ServerlessSpec(cloud="aws", region="us-east-1"),
        )
        logger.info("Waiting for index to be ready...")
        while not pc.describe_index(PINECONE_INDEX_NAME).status["ready"]:
            time.sleep(1)
    else:
        logger.info(f"Using existing index: {PINECONE_INDEX_NAME}")

    index = pc.Index(PINECONE_INDEX_NAME)

    # ── Initialize Embeddings ──────────────────────────────────────────────────
    logger.info("Initializing Google Gemini Embeddings...")
    embeddings = GoogleGenerativeAIEmbeddings(
        model="models/gemini-embedding-2",
        google_api_key=GOOGLE_API_KEY
    )
    vector_store = PineconeVectorStore(index=index, embedding=embeddings)

    # ── Load PDF Documents ─────────────────────────────────────────────────────
    logger.info(f"Loading PDFs from: {DOCS_DIR}")
    pdf_files = list(DOCS_DIR.glob("*.pdf"))
    logger.info(f"Found {len(pdf_files)} PDF file(s):")
    for pdf in pdf_files:
        logger.info(f"  - {pdf.name}")

    loader = PyPDFDirectoryLoader(str(DOCS_DIR))
    raw_documents = loader.load()
    logger.info(f"Loaded {len(raw_documents)} raw document pages")

    # ── Split Documents ────────────────────────────────────────────────────────
    logger.info("Splitting documents into chunks...")
    text_splitter = RecursiveCharacterTextSplitter(
        chunk_size=800,
        chunk_overlap=200,
        length_function=len,
        is_separator_regex=False,
        separators=["\n\n", "\n", ". ", " ", ""],
    )
    documents = text_splitter.split_documents(raw_documents)
    logger.info(f"Created {len(documents)} text chunks")

    # ── Enrich Metadata ────────────────────────────────────────────────────────
    # Tag each chunk with its source framework for better retrieval filtering
    framework_tags = {
        "owasp":    "OWASP LLM Top 10",
        "nist":     "NIST AI RMF",
        "enisa":    "ENISA AI Threat Landscape",
        "mitre":    "MITRE ATLAS",
        "csa":      "Cloud Security Alliance",
        "atlas":    "MITRE ATLAS",
    }
    for doc in documents:
        source = doc.metadata.get("source", "").lower()
        doc.metadata["framework"] = "General AI Security"
        for key, value in framework_tags.items():
            if key in source:
                doc.metadata["framework"] = value
                break
        doc.metadata["ingested_by"] = "AEGIS"

    # ── Ingest into Pinecone ────────────────────────────────────────────────────
    logger.info(f"Ingesting {len(documents)} chunks into Pinecone...")
    uuids = [f"aegis-chunk-{i+1}" for i in range(len(documents))]

    # Batch in groups of 100 to respect API limits
    BATCH_SIZE = 100
    for i in range(0, len(documents), BATCH_SIZE):
        batch_docs = documents[i:i + BATCH_SIZE]
        batch_ids  = uuids[i:i + BATCH_SIZE]
        vector_store.add_documents(documents=batch_docs, ids=batch_ids)
        logger.info(f"  Ingested batch {i//BATCH_SIZE + 1}/{(len(documents)-1)//BATCH_SIZE + 1}")
        time.sleep(0.5)  # Rate limiting

    # ── Summary ────────────────────────────────────────────────────────────────
    stats = index.describe_index_stats()
    logger.info("=" * 60)
    logger.info("  Ingestion Complete!")
    logger.info(f"  Total vectors in index: {stats.total_vector_count}")
    logger.info("=" * 60)
    logger.info("Next step: Run 'streamlit run aegis_app.py' to launch AEGIS")

if __name__ == "__main__":
    main()
