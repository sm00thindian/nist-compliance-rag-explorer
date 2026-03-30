import os
import hashlib
import pickle
import logging
from typing import List, Tuple, Any
import faiss
import numpy as np
import re
from parsers import normalize_control_id
from embedding_manager import EmbeddingManager

def build_vector_store(documents: List[str], embedding_manager: EmbeddingManager, knowledge_dir: str) -> Tuple[Any, Any, List[str]]:
    """
    Build or load a FAISS vector store from a list of documents using the embedding manager.

    Args:
        documents (List[str]): List of strings representing the documents.
        embedding_manager (EmbeddingManager): Configured embedding manager.
        knowledge_dir (str): Directory to save or load the FAISS index.

    Returns:
        tuple: (embedding_manager, index, doc_list)
            - embedding_manager: The embedding manager instance.
            - index: The FAISS index.
            - doc_list: The list of documents.

    Example:
        >>> manager, index, doc_list = build_vector_store(['doc1', 'doc2'], embedding_manager, 'knowledge')
    """
    # Create unique index filename based on model and similarity metric
    model_name = embedding_manager.model_name
    similarity = embedding_manager.similarity_metric
    index_hash = hashlib.md5(f"{model_name}_{similarity}".encode()).hexdigest()
    index_file = os.path.join(knowledge_dir, f"faiss_index_{index_hash}.pkl")

    logging.info(f"Building vector store with model: {model_name}, similarity: {similarity}")

    if os.path.exists(index_file):
        with open(index_file, 'rb') as f:
            index, doc_list = pickle.load(f)
        logging.info(f"Loaded existing FAISS index from {index_file}")
    else:
        logging.info(f"Building new FAISS index for {len(documents)} documents...")
        embeddings = embedding_manager.encode(documents, show_progress=True)

        # Create appropriate index based on similarity metric
        index = embedding_manager.get_similarity_search_index(embeddings)

        # Add embeddings to index (only if we have embeddings)
        if embeddings.size > 0:
            if embedding_manager.similarity_metric == 'cosine':
                # Embeddings already normalized in get_similarity_search_index
                index.add(embeddings)
            else:
                index.add(embeddings)

        doc_list = documents

        # Save index
        with open(index_file, 'wb') as f:
            pickle.dump((index, doc_list), f)
        logging.info(f"Built new FAISS index and saved to {index_file}")

    return embedding_manager, index, doc_list

def retrieve_documents(query, model, index, doc_list, top_k=100):
    """
    Retrieve the top-k most relevant documents for a given query.

    Args:
        query (str): The query string.
        model (SentenceTransformer): The SentenceTransformer model.
        index (faiss.Index): The FAISS index.
        doc_list (list): The list of documents.
        top_k (int, optional): Number of documents to retrieve. Defaults to 100.

    Returns:
        list: The top-k relevant documents.

    Example:
        >>> retrieved = retrieve_documents('How to implement AC-1?', model, index, doc_list)
        >>> print(len(retrieved))
        100
    """
    query_embedding = model.encode([query])
    distances, indices = index.search(query_embedding, top_k)
    retrieved_docs = [doc_list[idx] for idx in indices[0]]
    # Filter for exact control ID match if present in query
    control_match = re.search(r'(\w{2}-\d+(?:\([a-z0-9]+\))?)', query, re.IGNORECASE)
    if control_match:
        control_id = normalize_control_id(control_match.group(1).upper())
        retrieved_docs = [doc for doc in retrieved_docs if control_id in doc] or retrieved_docs[:5]  # Fallback to top 5 if no exact match
    logging.info(f"Retrieved {len(retrieved_docs)} documents for query")
    return retrieved_docs
