import os
from .vector_store import build_vector_store as _build_vector_store, retrieve_documents

# Global variables to store model state
_model = None
_index = None
_doc_list = None

def build_vector_store(documents, embedder):
    """
    Build vector store and return the index.
    Stores model and doc_list globally for retrieval.
    """
    global _model, _index, _doc_list

    # Use the model name from embedder if available, otherwise default
    model_name = getattr(embedder, 'model_name', 'all-MiniLM-L12-v2')
    knowledge_dir = "knowledge"

    _model, _index, _doc_list = _build_vector_store(documents, model_name, knowledge_dir)
    return _index

def retrieve_relevant_docs(query, index, embedder, top_k=100):
    """
    Retrieve relevant documents for the query.
    """
    global _model, _index, _doc_list

    # Ensure we have the stored data
    if _model is None or _index is None or _doc_list is None:
        raise RuntimeError("Vector store not built. Call build_vector_store first.")

    return retrieve_documents(query, _model, _index, _doc_list, top_k)