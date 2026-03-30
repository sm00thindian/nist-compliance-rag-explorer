"""
Hybrid search implementation combining semantic and keyword-based retrieval.
"""
import re
import logging
from typing import List, Dict, Any, Set, Tuple
from collections import Counter
import numpy as np

logger = logging.getLogger(__name__)

class HybridSearch:
    """Combines semantic and keyword-based search for better retrieval."""

    def __init__(self, semantic_weight: float = 0.7, keyword_weight: float = 0.3):
        self.semantic_weight = semantic_weight
        self.keyword_weight = keyword_weight

    def search(self, query: str, semantic_results: List[str], all_docs: List[str],
               top_k: int = 100) -> List[str]:
        """
        Perform hybrid search combining semantic and keyword results.

        Args:
            query: Search query
            semantic_results: Results from semantic search
            all_docs: All available documents
            top_k: Number of results to return

        Returns:
            Combined and ranked results
        """
        # Get keyword-based results
        keyword_results = self._keyword_search(query, all_docs, len(semantic_results))

        # Combine results with weights
        combined_scores = self._combine_results(
            semantic_results, keyword_results, self.semantic_weight, self.keyword_weight
        )

        # Sort by combined score and return top results
        sorted_results = sorted(combined_scores.items(), key=lambda x: x[1], reverse=True)
        return [doc for doc, score in sorted_results[:top_k]]

    def _keyword_search(self, query: str, documents: List[str], num_results: int) -> List[str]:
        """Perform keyword-based search using TF-IDF style scoring."""
        # Tokenize query
        query_terms = self._tokenize_and_normalize(query)

        if not query_terms:
            return documents[:num_results]

        # Score documents
        doc_scores = []
        for doc in documents:
            doc_terms = self._tokenize_and_normalize(doc)
            score = self._calculate_keyword_score(query_terms, doc_terms)
            doc_scores.append((doc, score))

        # Sort by score and return top results
        doc_scores.sort(key=lambda x: x[1], reverse=True)
        return [doc for doc, score in doc_scores[:num_results]]

    def _tokenize_and_normalize(self, text: str) -> Set[str]:
        """Tokenize and normalize text for keyword search."""
        # Simple tokenization: split on whitespace and punctuation
        tokens = re.findall(r'\b\w+\b', text.lower())

        # Remove common stop words
        stop_words = {'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of', 'with', 'by', 'is', 'are', 'was', 'were', 'be', 'been', 'being', 'have', 'has', 'had', 'do', 'does', 'did', 'will', 'would', 'could', 'should', 'may', 'might', 'must', 'can', 'shall'}
        tokens = [token for token in tokens if token not in stop_words and len(token) > 2]

        return set(tokens)

    def _calculate_keyword_score(self, query_terms: Set[str], doc_terms: Set[str]) -> float:
        """Calculate keyword matching score."""
        if not query_terms:
            return 0.0

        # Jaccard similarity
        intersection = len(query_terms & doc_terms)
        union = len(query_terms | doc_terms)

        if union == 0:
            return 0.0

        return intersection / union

    def _combine_results(self, semantic_results: List[str], keyword_results: List[str],
                        semantic_weight: float, keyword_weight: float) -> Dict[str, float]:
        """Combine semantic and keyword results with weights."""
        combined_scores = {}

        # Score semantic results
        for i, doc in enumerate(semantic_results):
            score = semantic_weight * (len(semantic_results) - i) / len(semantic_results)
            combined_scores[doc] = combined_scores.get(doc, 0) + score

        # Score keyword results
        for i, doc in enumerate(keyword_results):
            score = keyword_weight * (len(keyword_results) - i) / len(keyword_results)
            combined_scores[doc] = combined_scores.get(doc, 0) + score

        return combined_scores

def rerank_with_cross_encoder(query: str, documents: List[str], top_k: int = 10) -> List[str]:
    """
    Rerank documents using a cross-encoder for better relevance.
    Note: This requires a cross-encoder model, placeholder for future implementation.
    """
    # Placeholder - would implement cross-encoder reranking
    # from sentence_transformers import CrossEncoder
    # model = CrossEncoder('cross-encoder/ms-marco-MiniLM-L-6-v2')
    # scores = model.predict([(query, doc) for doc in documents])
    # return [doc for _, doc in sorted(zip(scores, documents), reverse=True)][:top_k]

    logger.warning("Cross-encoder reranking not implemented yet, returning original order")
    return documents[:top_k]

def expand_query(query: str, expansion_terms: Dict[str, List[str]] = None) -> str:
    """
    Expand query with synonyms and related terms for better retrieval.
    """
    if expansion_terms is None:
        # Default expansion terms for compliance domain
        expansion_terms = {
            'assess': ['evaluate', 'test', 'check', 'verify', 'validate'],
            'implement': ['deploy', 'configure', 'setup', 'establish'],
            'control': ['requirement', 'measure', ' safeguard'],
            'audit': ['review', 'examine', 'inspect', 'monitor'],
            'access': ['entry', 'admission', 'permission', 'authorization'],
            'security': ['protection', 'safeguard', 'defense'],
            'compliance': ['conformance', 'adherence', 'observance']
        }

    expanded_terms = []
    query_lower = query.lower()

    for term in query.split():
        term_lower = term.lower().strip('.,!?')
        if term_lower in expansion_terms:
            # Add original term and expansions
            expanded_terms.extend([term] + expansion_terms[term_lower])
        else:
            expanded_terms.append(term)

    return ' '.join(expanded_terms)