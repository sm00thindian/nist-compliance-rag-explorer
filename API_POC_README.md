# NIST Compliance Evidence Evaluation API - Proof of Concept

This proof of concept demonstrates an AI-powered evidence evaluation service that transforms the NIST Compliance RAG Explorer into an active compliance assessment platform.

## 🎯 What This POC Does

Instead of just providing information about NIST controls, this API:
- **Accepts evidence submissions** from developers/assessors
- **Uses AI (LLMs) to evaluate** evidence against control requirements
- **Provides structured compliance assessments** with confidence scores
- **Generates actionable recommendations** for remediation

## 🚀 Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Set API Keys
```bash
export OPENAI_API_KEY="your-openai-api-key-here"
# OR for Anthropic Claude:
export ANTHROPIC_API_KEY="your-anthropic-api-key-here"
export LLM_PROVIDER="anthropic"
```

### 3. Start the API Server
```bash
python -m src.api.main
```

The API will be available at `http://localhost:8000`

### 4. Run POC Tests
```bash
python test_api_poc.py
```

## 📡 API Endpoints

### Core Endpoints

- `GET /health` - Health check
- `GET /controls` - List available NIST controls
- `GET /controls/{control_id}` - Get specific control details
- `POST /evidence/evaluate` - Submit evidence for AI evaluation
- `GET /stats` - API usage statistics

### Example API Usage

#### Submit Evidence for Evaluation
```python
import requests
import base64

# Encode your evidence
evidence_text = """
Account Management Policy:
1. All accounts require manager approval
2. 90-day inactivity timeout
3. Complex passwords enforced
4. MFA for privileged accounts
"""

evidence_b64 = base64.b64encode(evidence_text.encode()).decode()

# Submit for evaluation
response = requests.post("http://localhost:8000/evidence/evaluate", json={
    "control_id": "AC-2",
    "evidence_type": "document",
    "evidence_data": evidence_b64,
    "metadata": {"system": "hr-server", "version": "1.0"},
    "assessor_id": "security-team"
})

result = response.json()
print(f"Compliance: {result['data']['overall_compliance']}")
print(f"Score: {result['data']['compliance_score']}")
```

## 🧠 AI Evaluation Process

1. **Evidence Preprocessing**: Decode and categorize evidence (config, log, document, etc.)
2. **Requirement Retrieval**: Use RAG to get relevant control requirements
3. **AI Analysis**: LLM evaluates evidence against requirements
4. **Structured Output**: Returns compliance level, findings, and recommendations

### Sample Evaluation Output
```json
{
  "evaluation_id": "eval_12345",
  "control_id": "AC-2",
  "overall_compliance": "compliant",
  "compliance_score": 0.85,
  "confidence_level": 0.92,
  "findings": [
    {
      "requirement": "Account approval process",
      "status": "compliant",
      "explanation": "Evidence shows manager approval required for account creation",
      "evidence_references": ["Section 1"]
    }
  ],
  "recommendations": [
    {
      "priority": "medium",
      "action": "Document approval workflow",
      "rationale": "While approval exists, process could be better documented"
    }
  ],
  "processing_time_seconds": 2.34
}
```

## 🏗️ Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Developer     │    │   Evidence API   │    │      AI LLM     │
│   Submits       │───▶│   Evaluation     │───▶│   Evaluation    │
│   Evidence      │    │   Service        │    │   Engine        │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                │                        │
                                ▼                        ▼
                       ┌──────────────────┐    ┌─────────────────┐
                       │   RAG System     │    │  Compliance     │
                       │   (Requirements) │    │  Assessment     │
                       └──────────────────┘    └─────────────────┘
```

## 🔧 Configuration Options

### Environment Variables
- `OPENAI_API_KEY` - OpenAI API key
- `ANTHROPIC_API_KEY` - Anthropic API key
- `LLM_PROVIDER` - "openai" or "anthropic" (default: "openai")
- `PORT` - API server port (default: 8000)

### Supported Evidence Types
- `configuration` - System configurations, policies
- `log` - System logs, audit trails
- `screenshot` - GUI screenshots, console outputs
- `document` - Policies, procedures, documentation

## 🧪 Testing the POC

The `test_api_poc.py` script provides comprehensive testing:

1. **Health Check** - Verifies API availability
2. **Control Lookup** - Tests NIST control data access
3. **Evidence Evaluation** - Demonstrates AI-powered assessment
4. **Statistics** - Shows system status and metrics

## 🚀 Production Considerations

### Scalability
- Containerize with Docker for easy deployment
- Use serverless functions (AWS Lambda, Cloud Functions) for on-demand scaling
- Implement caching for frequently accessed controls

### Security
- Add authentication and authorization
- Implement rate limiting
- Use HTTPS in production
- Validate and sanitize all inputs

### Monitoring
- Add structured logging
- Implement metrics collection
- Set up health checks and alerts

## 🔄 Next Steps

1. **Enhanced Evidence Processing**
   - OCR for image processing
   - Log parsing and analysis
   - Configuration file validation

2. **Batch Processing**
   - Evaluate multiple controls simultaneously
   - Bulk evidence submission

3. **Integration Features**
   - Webhook notifications
   - CI/CD pipeline integration
   - SIEM system integration

4. **Advanced Analytics**
   - Compliance trend analysis
   - Risk scoring
   - Executive dashboards

## 🤝 Contributing

This is a proof of concept demonstrating the potential of AI-powered compliance automation. The architecture can be extended to support:

- Custom control frameworks
- Multi-cloud assessments
- Real-time monitoring
- Automated remediation

---

**Ready to revolutionize compliance assessment?** This POC shows how AI can transform manual compliance reviews into automated, intelligent evaluations.