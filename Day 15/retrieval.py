# ─────────────────────────────────────────────────────────────────────────────
# AEGIS – RAG Retrieval Engine
# Handles vector similarity search against the security knowledge base
# ─────────────────────────────────────────────────────────────────────────────

import os
import logging
from typing import List, Tuple
from dotenv import load_dotenv

from pinecone import Pinecone
from langchain_pinecone import PineconeVectorStore
from langchain_google_genai import GoogleGenerativeAIEmbeddings
from langchain_core.documents import Document

load_dotenv()
logger = logging.getLogger("AEGIS.Retrieval")

PINECONE_API_KEY    = os.environ.get("PINECONE_API_KEY")
GOOGLE_API_KEY      = os.environ.get("GOOGLE_API_KEY")
PINECONE_INDEX_NAME = os.environ.get("PINECONE_INDEX_NAME", "aegis-security-kb")


def get_vector_store() -> PineconeVectorStore:
    """Initialize and return the Pinecone vector store."""
    pc = Pinecone(api_key=PINECONE_API_KEY)
    index = pc.Index(PINECONE_INDEX_NAME)
    embeddings = GoogleGenerativeAIEmbeddings(
        model="models/gemini-embedding-2",
        google_api_key=GOOGLE_API_KEY
    )
    return PineconeVectorStore(index=index, embedding=embeddings)


def retrieve_security_context(
    query: str,
    vector_store: PineconeVectorStore,
    k: int = 5,
    score_threshold: float = 0.35,
) -> Tuple[str, List[Document]]:
    """
    Retrieve relevant security framework passages for a given query.

    Returns:
        (formatted_context_string, list_of_source_documents)
    """
    try:
        retriever = vector_store.as_retriever(
            search_type="similarity_score_threshold",
            search_kwargs={"k": k, "score_threshold": score_threshold},
        )
        docs = retriever.invoke(query)
    except Exception as e:
        logger.warning(f"Retrieval error: {e}")
        docs = []

    if not docs:
        return "", []

    context = "\n\n---\n\n".join(
        f"[Source: {doc.metadata.get('source', 'Unknown')} | "
        f"Framework: {doc.metadata.get('framework', 'General')} | "
        f"Page: {doc.metadata.get('page', '?')}]\n{doc.page_content}"
        for doc in docs
    )
    return context, docs


def retrieve_threat_specific_context(
    threat_name: str,
    component: str,
    vector_store: PineconeVectorStore,
    k: int = 3,
) -> str:
    """Build a targeted retrieval query combining threat type + component."""
    query = (
        f"AI security threat {threat_name} mitigation for {component} "
        f"OWASP LLM NIST countermeasure attack vector"
    )
    context, _ = retrieve_security_context(query, vector_store, k=k, score_threshold=0.3)
    return context


def check_index_health(vector_store: PineconeVectorStore) -> dict:
    """Check if the knowledge base index is populated."""
    try:
        # Quick retrieval test
        docs = vector_store.similarity_search("AI security threat", k=1)
        return {
            "healthy": True,
            "has_documents": len(docs) > 0,
            "message": "Knowledge base connected and populated."
            if docs else "Knowledge base connected but empty. Run ingestion.py first.",
        }
    except Exception as e:
        return {
            "healthy": False,
            "has_documents": False,
            "message": f"Knowledge base error: {e}",
        }
