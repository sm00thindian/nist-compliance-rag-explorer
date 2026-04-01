"""
Enhanced embedding manager with model validation, fallbacks, and performance optimizations.
"""
import os
import sys
import logging
import tempfile
import time
import re
from typing import List, Dict, Any, Optional, Tuple
from sentence_transformers import SentenceTransformer
from transformers.utils import logging as transformers_logging
import faiss
import numpy as np
from contextlib import contextmanager

logger = logging.getLogger(__name__)

@contextmanager
def _capture_console_output():
    """Capture direct stdout/stderr writes around a block of code."""
    stdout_fd = sys.stdout.fileno()
    stderr_fd = sys.stderr.fileno()
    saved_stdout_fd = os.dup(stdout_fd)
    saved_stderr_fd = os.dup(stderr_fd)

    with tempfile.TemporaryFile(mode='w+b') as tmp:
        try:
            sys.stdout.flush()
            sys.stderr.flush()
            os.dup2(tmp.fileno(), stdout_fd)
            os.dup2(tmp.fileno(), stderr_fd)
            yield tmp
        finally:
            sys.stdout.flush()
            sys.stderr.flush()
            os.dup2(saved_stdout_fd, stdout_fd)
            os.dup2(saved_stderr_fd, stderr_fd)
            os.close(saved_stdout_fd)
            os.close(saved_stderr_fd)


def _normalize_transformer_output(raw: str) -> str:
    raw = raw.replace('\r', '\n')
    lines = [line for line in raw.splitlines() if line.strip()]
    filtered = [line for line in lines if not line.startswith('Loading weights:')]
    return '\n'.join(filtered).strip()

class EmbeddingManager:
    """Enhanced embedding manager with validation and fallbacks."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.model = None
        self.model_name = config.get('model_name', 'all-mpnet-base-v2')
        self.dimensions = config.get('dimensions', 768)
        self.similarity_metric = config.get('similarity_metric', 'cosine')
        self.cache_dir = config.get('cache_dir', './models')
        self.enable_gpu = config.get('enable_gpu', False)
        self.fallbacks = config.get('fallbacks', ['all-MiniLM-L12-v2'])

        # Ensure cache directory exists
        os.makedirs(self.cache_dir, exist_ok=True)

        # Initialize model
        self._load_model()

    def _load_model(self) -> bool:
        """Load the embedding model with fallbacks."""
        model_candidates = [self.model_name] + self.fallbacks

        # Configure transformer logging once to prevent direct stdout/stderr output.
        try:
            transformers_logging.disable_default_handler()
        except Exception:
            pass
        transformers_logging.set_verbosity_info()

        for candidate in model_candidates:
            try:
                logger.info(f"Attempting to load embedding model: {candidate}")

                # Set device
                device = 'cuda' if self.enable_gpu else 'cpu'

                # Capture direct console output from model loading and log it instead of printing it.
                with _capture_console_output() as capture:
                    start_time = time.time()
                    self.model = SentenceTransformer(candidate, device=device, cache_folder=self.cache_dir)
                    capture.seek(0)
                    console_output = capture.read().decode('utf-8', errors='replace')
                    if console_output.strip():
                        normalized = _normalize_transformer_output(console_output)
                        logger.info("Suppressing direct transformer load output; captured details in logs.")
                        logger.debug("Transformer load output:\n%s", normalized)
                load_time = time.time() - start_time

                # Validate model
                if self._validate_model():
                    logger.info(f"Successfully loaded {candidate} in {load_time:.2f}s")
                    self.model_name = candidate
                    return True
                else:
                    logger.warning(f"Model {candidate} failed validation, trying next fallback")

            except Exception as e:
                logger.warning(f"Failed to load model {candidate}: {e}")
                continue

        logger.error("All embedding models failed to load")
        return False

    def _validate_model(self) -> bool:
        """Validate that the model works correctly."""
        try:
            # Test encoding
            test_texts = ["This is a test document", "Another test document"]
            embeddings = self.model.encode(test_texts, show_progress_bar=False)

            # Check dimensions
            if embeddings.shape[1] != self.dimensions:
                logger.warning(f"Model dimensions {embeddings.shape[1]} don't match expected {self.dimensions}")

            # Check for NaN/inf values
            if not np.isfinite(embeddings).all():
                logger.error("Model produced non-finite embeddings")
                return False

            return True

        except Exception as e:
            logger.error(f"Model validation failed: {e}")
            return False

    def encode(self, texts: List[str], batch_size: int = 32, show_progress: bool = False) -> np.ndarray:
        """Encode texts to embeddings with batching."""
        if self.model is None:
            raise RuntimeError("No embedding model loaded")

        if not texts:
            return np.array([])

        # Process in batches to manage memory
        all_embeddings = []

        for i in range(0, len(texts), batch_size):
            batch = texts[i:i + batch_size]
            try:
                embeddings = self.model.encode(
                    batch,
                    show_progress_bar=show_progress and len(batch) > 10,
                    batch_size=min(batch_size, 16)  # Smaller internal batch for memory
                )
                all_embeddings.append(embeddings)
            except Exception as e:
                logger.error(f"Failed to encode batch {i//batch_size}: {e}")
                # Return zero embeddings for failed batch
                all_embeddings.append(np.zeros((len(batch), self.dimensions)))

        return np.vstack(all_embeddings) if all_embeddings else np.array([])

    def get_similarity_search_index(self, embeddings: np.ndarray) -> faiss.Index:
        """Create appropriate FAISS index based on configuration."""
        if embeddings.size == 0:
            # Handle empty embeddings case
            dimension = self.dimensions
        else:
            dimension = embeddings.shape[1]

        if self.similarity_metric == 'cosine':
            # Normalize embeddings for cosine similarity (only if we have embeddings)
            if embeddings.size > 0:
                faiss.normalize_L2(embeddings)
            index = faiss.IndexFlatIP(dimension)  # Inner product for cosine
        elif self.similarity_metric == 'l2':
            index = faiss.IndexFlatL2(dimension)  # L2 distance
        else:
            logger.warning(f"Unknown similarity metric {self.similarity_metric}, using cosine")
            if embeddings.size > 0:
                faiss.normalize_L2(embeddings)
            index = faiss.IndexFlatIP(dimension)

        return index

    def search(self, query_embedding: np.ndarray, index: faiss.Index,
               doc_list: List[str], top_k: int = 100) -> List[str]:
        """Search for similar documents."""
        if len(doc_list) == 0:
            return []

        if self.similarity_metric == 'cosine':
            # Normalize query for cosine similarity
            faiss.normalize_L2(query_embedding)

        # Search
        distances, indices = index.search(query_embedding, min(top_k, len(doc_list)))

        # Return documents in order of relevance
        results = []
        for idx in indices[0]:
            if idx < len(doc_list):
                results.append(doc_list[idx])

        return results

    def get_model_info(self) -> Dict[str, Any]:
        """Get information about the current model."""
        if self.model is None:
            return {"status": "no_model_loaded"}

        return {
            "model_name": self.model_name,
            "dimensions": self.dimensions,
            "similarity_metric": self.similarity_metric,
            "device": "cuda" if self.enable_gpu else "cpu",
            "max_seq_length": getattr(self.model, 'max_seq_length', 'unknown'),
            "status": "loaded"
        }

@contextmanager
def timer(description: str):
    """Context manager for timing operations."""
    start = time.time()
    try:
        yield
    finally:
        elapsed = time.time() - start
        logger.info(f"{description}: {elapsed:.2f}s")

def benchmark_embedding_models(model_names: List[str], test_texts: List[str],
                              cache_dir: str = "./models") -> Dict[str, Dict[str, Any]]:
    """Benchmark different embedding models."""
    results = {}

    for model_name in model_names:
        try:
            logger.info(f"Benchmarking {model_name}...")

            config = {
                'model_name': model_name,
                'dimensions': 768,  # Will be updated after loading
                'similarity_metric': 'cosine',
                'cache_dir': cache_dir,
                'enable_gpu': False,
                'fallbacks': []
            }

            manager = EmbeddingManager(config)

            with timer(f"Encoding {len(test_texts)} texts with {model_name}"):
                embeddings = manager.encode(test_texts, show_progress=False)

            results[model_name] = {
                "success": True,
                "dimensions": embeddings.shape[1],
                "encoding_time": 0,  # Would need to modify timer to capture this
                "model_info": manager.get_model_info()
            }

        except Exception as e:
            results[model_name] = {
                "success": False,
                "error": str(e)
            }

    return results