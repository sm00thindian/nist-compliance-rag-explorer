#!/usr/bin/env python3
"""
Proof of Concept script for the Evidence Evaluation API
This script demonstrates how to use the API to evaluate evidence against NIST controls.
"""
import base64
import json
import requests
import time
from typing import Dict, Any

# API configuration
API_BASE_URL = "http://localhost:8000"

def encode_evidence(text: str) -> str:
    """Encode evidence text as base64"""
    return base64.b64encode(text.encode('utf-8')).decode('utf-8')

def test_health_check():
    """Test the health check endpoint"""
    print("🔍 Testing health check...")
    try:
        response = requests.get(f"{API_BASE_URL}/health")
        if response.status_code == 200:
            print("✅ Health check passed")
            return True
        else:
            print(f"❌ Health check failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Health check error: {e}")
        return False

def test_get_controls():
    """Test getting control information"""
    print("\n📋 Testing control listing...")
    try:
        response = requests.get(f"{API_BASE_URL}/controls?limit=5")
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Found {data.get('total', 0)} controls")
            if data.get('controls'):
                print(f"   Sample control: {data['controls'][0]['control_id']} - {data['controls'][0]['title'][:50]}...")
            return True
        else:
            print(f"❌ Control listing failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Control listing error: {e}")
        return False

def test_get_specific_control():
    """Test getting a specific control"""
    print("\n🎯 Testing specific control lookup...")
    try:
        response = requests.get(f"{API_BASE_URL}/controls/AC-2")
        if response.status_code == 200:
            control = response.json()
            print(f"✅ Found control: {control['control_id']} - {control['title']}")
            return True
        else:
            print(f"❌ Control lookup failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Control lookup error: {e}")
        return False

def test_evidence_evaluation():
    """Test evidence evaluation"""
    print("\n🧠 Testing evidence evaluation...")

    # Sample evidence for AC-2 (Account Management)
    sample_evidence = """
    Account Management Policy:

    1. All user accounts must be approved by management before creation
    2. Accounts are disabled after 90 days of inactivity
    3. Password complexity requirements are enforced
    4. Multi-factor authentication is required for privileged accounts
    5. Account reviews are conducted quarterly
    6. Automated account lockout after 5 failed login attempts

    Last updated: 2024-01-15
    Approved by: Security Team
    """

    evidence_submission = {
        "control_id": "AC-2",
        "evidence_type": "document",
        "evidence_data": encode_evidence(sample_evidence),
        "metadata": {
            "system": "test-policy-server",
            "document_version": "1.2",
            "last_reviewed": "2024-01-15"
        },
        "assessor_id": "test-assessor"
    }

    try:
        print("   Submitting evidence for evaluation...")
        response = requests.post(
            f"{API_BASE_URL}/evidence/evaluate",
            json=evidence_submission,
            headers={"Content-Type": "application/json"}
        )

        if response.status_code == 200:
            result = response.json()
            if result.get("success"):
                evaluation = result["data"]
                print("✅ Evidence evaluation completed!")
                print(f"   Control: {evaluation['control_id']}")
                print(f"   Compliance: {evaluation['overall_compliance']}")
                print(f"   Compliance Score: {evaluation['compliance_score']:.2f}")
                print(f"   Confidence: {evaluation['confidence_level']:.2f}")
                print(f"   Processing time: {evaluation['processing_time_seconds']:.2f}s")
                print(f"   Findings: {len(evaluation['findings'])}")
                if evaluation['findings']:
                    print(f"   Sample finding: {evaluation['findings'][0]['explanation'][:100]}...")
                return True
            else:
                print(f"❌ Evaluation failed: {result.get('message')}")
                return False
        else:
            print(f"❌ Evaluation request failed: {response.status_code}")
            print(f"   Response: {response.text}")
            return False

    except Exception as e:
        print(f"❌ Evaluation error: {e}")
        return False

def test_api_stats():
    """Test getting API statistics"""
    print("\n📊 Testing API statistics...")
    try:
        response = requests.get(f"{API_BASE_URL}/stats")
        if response.status_code == 200:
            stats = response.json()
            print("✅ API stats retrieved:")
            print(f"   Controls loaded: {stats.get('controls_loaded', 0)}")
            print(f"   RAG initialized: {stats.get('rag_initialized', False)}")
            print(f"   LLM provider: {stats.get('llm_provider', 'none')}")
            print(f"   Service status: {stats.get('service_status', 'unknown')}")
            return True
        else:
            print(f"❌ Stats request failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Stats error: {e}")
        return False

def run_poc_tests():
    """Run all POC tests"""
    print("🚀 NIST Compliance Evidence Evaluation API - Proof of Concept")
    print("=" * 60)

    # Check if API is running
    if not test_health_check():
        print("\n❌ API is not running. Please start the API server first:")
        print("   cd /path/to/project")
        print("   export OPENAI_API_KEY='your-key-here'")
        print("   python -m src.api.main")
        return

    # Run tests
    tests = [
        test_get_controls,
        test_get_specific_control,
        test_evidence_evaluation,
        test_api_stats
    ]

    passed = 0
    total = len(tests)

    for test in tests:
        if test():
            passed += 1
        time.sleep(0.5)  # Brief pause between tests

    print("\n" + "=" * 60)
    print(f"📋 Test Results: {passed}/{total} tests passed")

    if passed == total:
        print("🎉 All POC tests passed! The evidence evaluation API is working.")
        print("\nNext steps:")
        print("1. Try different types of evidence (logs, configurations, screenshots)")
        print("2. Test with various NIST controls")
        print("3. Integrate with your CI/CD pipeline")
        print("4. Add evidence storage and history tracking")
    else:
        print("⚠️  Some tests failed. Check the API configuration and logs.")

if __name__ == "__main__":
    run_poc_tests()