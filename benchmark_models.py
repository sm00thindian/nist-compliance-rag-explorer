#!/usr/bin/env python3
"""
Benchmark different embedding models for the NIST Compliance RAG Explorer.
This script tests various models and provides performance comparisons.
"""
import os
import sys
import time
import json
from typing import List, Dict, Any
import numpy as np

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from embedding_manager import benchmark_embedding_models
from config_loader import get_config

def load_test_data() -> List[str]:
    """Load test documents for benchmarking."""
    knowledge_dir = "knowledge"

    # Try to load real NIST data if available
    test_docs = []

    # Load control descriptions
    catalog_file = os.path.join(knowledge_dir, "nist_800_53-rev5_catalog_json.json")
    if os.path.exists(catalog_file):
        try:
            with open(catalog_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            # Extract control descriptions
            for control in data[:50]:  # Use first 50 controls for testing
                if 'description' in control:
                    test_docs.append(f"Control {control.get('control_id', 'Unknown')}: {control['description'][:200]}")
        except Exception as e:
            print(f"Could not load catalog data: {e}")

    # Fallback to synthetic test data
    if len(test_docs) < 10:
        test_docs = [
            "Access control mechanisms must be implemented to prevent unauthorized access to systems and data.",
            "Audit logs should capture all security-relevant events for monitoring and analysis.",
            "Configuration management ensures systems are configured securely and consistently.",
            "Encryption must be used to protect sensitive data both at rest and in transit.",
            "Identity management systems should implement multi-factor authentication.",
            "Incident response procedures must be established and tested regularly.",
            "Network security controls should segment and protect network traffic.",
            "Password policies must enforce complexity and regular changes.",
            "Physical security measures protect facilities and equipment from unauthorized access.",
            "Risk assessments should be conducted regularly to identify and mitigate threats.",
            "Security awareness training is essential for all personnel.",
            "System hardening reduces attack surface by removing unnecessary services.",
            "Third-party vendor assessments ensure supply chain security.",
            "Vulnerability scanning identifies and remediates security weaknesses.",
            "Zero trust architecture assumes no implicit trust in any user or system."
        ]

    return test_docs[:20]  # Use 20 test documents

def create_test_queries() -> List[str]:
    """Create test queries for benchmarking."""
    return [
        "How do I implement access controls?",
        "What are the requirements for audit logging?",
        "How to configure encryption for sensitive data?",
        "What is multi-factor authentication?",
        "How to conduct security risk assessments?",
        "What are incident response procedures?",
        "How to secure network communications?",
        "What are password policy requirements?",
        "How to assess physical security?",
        "What is zero trust architecture?"
    ]

def run_benchmark():
    """Run comprehensive embedding model benchmark."""
    print("🔬 NIST Compliance RAG Explorer - Embedding Model Benchmark")
    print("=" * 60)

    # Load configuration
    try:
        config = get_config()
        embedding_config = config.get_embedding_config()
        cache_dir = embedding_config.get('cache_dir', './models')
    except Exception as e:
        print(f"Could not load config: {e}, using defaults")
        cache_dir = './models'

    # Load test data
    print("\n📚 Loading test data...")
    test_docs = load_test_data()
    test_queries = create_test_queries()
    print(f"Loaded {len(test_docs)} test documents and {len(test_queries)} test queries")

    # Define models to benchmark
    models_to_test = [
        'all-MiniLM-L12-v2',      # Fast baseline
        'all-mpnet-base-v2',      # Recommended default
        'multi-qa-MiniLM-L6-cos-v1',  # QA specialized
        'paraphrase-MiniLM-L6-v2',    # Paraphrase focused
        'all-distilroberta-v1',       # Good performance
    ]

    # Optional models (may require additional setup)
    optional_models = [
        'text-embedding-3-small',     # OpenAI (requires API key)
        'bge-large-en-v1.5',          # BGE high performance
    ]

    print(f"\n🤖 Benchmarking {len(models_to_test)} core models...")
    print("This may take several minutes depending on your hardware...")

    # Run benchmark
    start_time = time.time()
    results = benchmark_embedding_models(models_to_test, test_docs, cache_dir)
    benchmark_time = time.time() - start_time

    # Display results
    print(f"\n📊 Benchmark Results (completed in {benchmark_time:.1f}s)")
    print("=" * 60)

    successful_models = []
    failed_models = []

    for model_name, result in results.items():
        if result.get('success', False):
            successful_models.append((model_name, result))
        else:
            failed_models.append((model_name, result.get('error', 'Unknown error')))

    # Show successful models
    if successful_models:
        print("\n✅ Successful Models:")
        print("-" * 40)

        # Sort by dimensions (rough performance indicator)
        successful_models.sort(key=lambda x: x[1].get('dimensions', 0), reverse=True)

        for model_name, result in successful_models:
            dims = result.get('dimensions', 'unknown')
            print("25")

    # Show failed models
    if failed_models:
        print("\n❌ Failed Models:")
        print("-" * 40)
        for model_name, error in failed_models:
            print("25")

    # Recommendations
    print("\n🎯 Recommendations:")
    print("-" * 40)

    if successful_models:
        # Recommend based on dimensions and success
        best_model = max(successful_models, key=lambda x: x[1].get('dimensions', 0))
        print(f"🏆 Best Overall: {best_model[0]} ({best_model[1].get('dimensions', 'unknown')}D)")

        # Fast option
        fast_models = [m for m in successful_models if m[1].get('dimensions', 1000) < 500]
        if fast_models:
            fast_model = min(fast_models, key=lambda x: x[1].get('dimensions', 0))
            print(f"⚡ Fast Option: {fast_model[0]} ({fast_model[1].get('dimensions', 'unknown')}D)")

        # Balanced option (default)
        balanced = next((m for m in successful_models if 'mpnet' in m[0]), successful_models[0])
        print(f"⚖️  Balanced: {balanced[0]} ({balanced[1].get('dimensions', 'unknown')}D) - Recommended for most use cases")

    print("\n💡 Tips:")
    print("   • Higher dimensions generally mean better semantic understanding")
    print("   • Consider your hardware constraints and use case")
    print("   • Models with 'mpnet' or 'large' in the name are typically best")
    print("   • Test with your specific compliance queries for best results")

    # Save results
    output_file = "model_benchmark_results.json"
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\n💾 Detailed results saved to {output_file}")

if __name__ == "__main__":
    try:
        run_benchmark()
    except KeyboardInterrupt:
        print("\n⏹️  Benchmark interrupted by user")
    except Exception as e:
        print(f"\n❌ Benchmark failed: {e}")
        import traceback
        traceback.print_exc()