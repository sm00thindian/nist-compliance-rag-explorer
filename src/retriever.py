import os
import logging
from typing import List, Optional, Any
from vector_store import build_vector_store as _build_vector_store, retrieve_documents
from embedding_manager import EmbeddingManager

logger = logging.getLogger(__name__)

# Global variables to store model state
_embedding_manager = None
_index = None
_doc_list = None

def build_vector_store(documents: List[str], embedding_manager: EmbeddingManager) -> Any:
    """
    Build vector store and return the index.
    Stores embedding manager, index and doc_list globally for retrieval.
    """
    global _embedding_manager, _index, _doc_list

    knowledge_dir = "knowledge"
    os.makedirs(knowledge_dir, exist_ok=True)

    _embedding_manager, _index, _doc_list = _build_vector_store(documents, embedding_manager, knowledge_dir)
    return _index

def retrieve_relevant_docs(query: str, index: Any, embedding_manager: EmbeddingManager, top_k: int = 100) -> List[str]:
    """
    Retrieve relevant documents for the query using the embedding manager.
    """
    global _embedding_manager, _index, _doc_list

    # Ensure we have the stored data
    if _embedding_manager is None or _index is None or _doc_list is None:
        raise RuntimeError("Vector store not built. Call build_vector_store first.")

    # Use the embedding manager's search method
    query_embedding = embedding_manager.encode([query])
    return embedding_manager.search(query_embedding, _index, _doc_list, top_k)

def get_embedding_manager() -> Optional[EmbeddingManager]:
    """Get the current embedding manager instance."""
    return _embedding_manager
