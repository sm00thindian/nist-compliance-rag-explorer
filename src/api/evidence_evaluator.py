import os
import uuid
import time
import base64
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime

import openai
from anthropic import Anthropic

from .models import (
    EvidenceSubmission, EvaluationResult, Finding, Recommendation,
    ComplianceLevel, EvidenceType
)
from parsers import extract_controls_from_json, normalize_control_id
from retriever import build_vector_store, retrieve_relevant_docs
from embedding_manager import EmbeddingManager
from config_loader import get_config

logger = logging.getLogger(__name__)

class EvidenceEvaluator:
    """AI-powered evidence evaluation service"""

    def __init__(self):
        self.config = get_config()
        self.llm_provider = os.getenv('LLM_PROVIDER', 'openai')  # 'openai' or 'anthropic'

        # Initialize LLM clients
        if self.llm_provider == 'openai':
            self.openai_client = openai.OpenAI(api_key=os.getenv('OPENAI_API_KEY'))
            self.model = os.getenv('OPENAI_MODEL', 'gpt-4-turbo-preview')
        elif self.llm_provider == 'anthropic':
            self.anthropic_client = Anthropic(api_key=os.getenv('ANTHROPIC_API_KEY'))
            self.model = os.getenv('ANTHROPIC_MODEL', 'claude-3-sonnet-20240229')

        # Load control data
        self._load_control_data()

        # Initialize RAG system
        self._initialize_rag()

    def _load_control_data(self):
        """Load NIST control data for evaluation"""
        try:
            knowledge_dir = "knowledge"
            catalog_file = os.path.join(knowledge_dir, "nist_800_53-rev5_catalog_json.json")

            with open(catalog_file, 'r', encoding='utf-8') as f:
                catalog_data = __import__('json').load(f)

            self.control_details = {c['control_id']: c for c in extract_controls_from_json(catalog_data)}
            logger.info(f"Loaded {len(self.control_details)} NIST controls")

        except Exception as e:
            logger.error(f"Failed to load control data: {e}")
            self.control_details = {}

    def _initialize_rag(self):
        """Initialize the RAG system for requirement retrieval"""
        try:
            # Create documents for vector store
            all_docs = []
            for ctrl in self.control_details.values():
                all_docs.append(f"Control {ctrl['control_id']}: {ctrl['title']}")
                all_docs.append(f"Description {ctrl['control_id']}: {ctrl['description'][:500]}")

            # Initialize embedding manager
            embedding_config = self.config.get_embedding_config()
            self.embedding_manager = EmbeddingManager(embedding_config)

            # Build vector store
            self.index = build_vector_store(all_docs, self.embedding_manager)

            logger.info("RAG system initialized successfully")

        except Exception as e:
            logger.error(f"Failed to initialize RAG system: {e}")
            self.embedding_manager = None
            self.index = None

    def _decode_evidence(self, evidence_data: str, evidence_type: EvidenceType) -> str:
        """Decode and preprocess evidence based on type"""
        try:
            # Decode base64
            decoded_bytes = base64.b64decode(evidence_data)
            content = decoded_bytes.decode('utf-8')

            # Basic preprocessing based on type
            if evidence_type == EvidenceType.CONFIGURATION:
                # For config files, try to identify key settings
                return f"Configuration Content:\n{content}"
            elif evidence_type == EvidenceType.LOG:
                # For logs, extract relevant entries
                return f"Log Content:\n{content}"
            elif evidence_type == EvidenceType.SCREENSHOT:
                # For screenshots, we'd need OCR processing (placeholder)
                return f"Screenshot Description: [OCR processing would extract text here]\nRaw content: {content[:200]}..."
            else:
                return content

        except Exception as e:
            logger.warning(f"Failed to decode evidence: {e}")
            return evidence_data  # Return as-is if decoding fails

    def _get_control_requirements(self, control_id: str) -> str:
        """Retrieve control requirements using RAG"""
        if not self.embedding_manager or not self.index:
            # Fallback to direct lookup
            control = self.control_details.get(normalize_control_id(control_id))
            if control:
                return f"Control {control['control_id']}: {control['title']}\nDescription: {control['description']}"
            return f"Control {control_id}: Requirements not found"

        # Use RAG to get relevant information
        query = f"What are the requirements for {control_id}?"
        relevant_docs = retrieve_relevant_docs(query, self.index, self.embedding_manager, top_k=5)

        requirements = f"Requirements for {control_id}:\n"
        for doc in relevant_docs:
            if control_id in doc:
                requirements += doc + "\n"

        return requirements

    def _evaluate_with_llm(self, control_requirements: str, evidence_content: str) -> Dict[str, Any]:
        """Use LLM to evaluate evidence against requirements"""

        prompt = f"""
You are an expert compliance assessor evaluating evidence against NIST 800-53 control requirements.

CONTROL REQUIREMENTS:
{control_requirements}

EVIDENCE PROVIDED:
{evidence_content}

TASK: Analyze whether the evidence demonstrates compliance with the control requirements.

Provide your analysis in the following JSON format:
{{
    "overall_compliance": "compliant|non-compliant|partial|insufficient_evidence",
    "compliance_score": 0.0-1.0,
    "confidence_level": 0.0-1.0,
    "findings": [
        {{
            "requirement": "specific requirement being evaluated",
            "status": "compliant|non-compliant|partial|insufficient_evidence",
            "explanation": "detailed explanation of the finding",
            "evidence_references": ["references to specific evidence"]
        }}
    ],
    "recommendations": [
        {{
            "priority": "high|medium|low",
            "action": "specific action to take",
            "rationale": "why this action is recommended"
        }}
    ]
}}

Be thorough, objective, and provide specific evidence references. If evidence is insufficient, clearly state what additional information is needed.
"""

        try:
            if self.llm_provider == 'openai':
                response = self.openai_client.chat.completions.create(
                    model=self.model,
                    messages=[{"role": "user", "content": prompt}],
                    temperature=0.1,  # Low temperature for consistent analysis
                    max_tokens=2000
                )
                result_text = response.choices[0].message.content

            elif self.llm_provider == 'anthropic':
                response = self.anthropic_client.messages.create(
                    model=self.model,
                    max_tokens=2000,
                    temperature=0.1,
                    messages=[{"role": "user", "content": prompt}]
                )
                result_text = response.content[0].text

            # Parse JSON response
            import json
            result = json.loads(result_text)
            return result

        except Exception as e:
            logger.error(f"LLM evaluation failed: {e}")
            return self._fallback_evaluation(control_requirements, evidence_content)

    def _fallback_evaluation(self, control_requirements: str, evidence_content: str) -> Dict[str, Any]:
        """Fallback evaluation when LLM fails"""
        return {
            "overall_compliance": "insufficient_evidence",
            "compliance_score": 0.0,
            "confidence_level": 0.3,
            "findings": [{
                "requirement": "General compliance check",
                "status": "insufficient_evidence",
                "explanation": "Automated evaluation failed. Manual review required.",
                "evidence_references": []
            }],
            "recommendations": [{
                "priority": "high",
                "action": "Conduct manual compliance assessment",
                "rationale": "Automated evaluation was unable to process the evidence"
            }]
        }

    async def evaluate_evidence(self, submission: EvidenceSubmission) -> EvaluationResult:
        """Main evaluation method"""
        start_time = time.time()

        # Generate evaluation ID
        evaluation_id = str(uuid.uuid4())

        # Normalize control ID
        normalized_control_id = normalize_control_id(submission.control_id)

        # Decode and preprocess evidence
        evidence_content = self._decode_evidence(submission.evidence_data, submission.evidence_type)

        # Get control requirements
        control_requirements = self._get_control_requirements(normalized_control_id)

        # Evaluate with LLM
        llm_result = self._evaluate_with_llm(control_requirements, evidence_content)

        # Convert to EvaluationResult model
        findings = [Finding(**f) for f in llm_result.get('findings', [])]
        recommendations = [Recommendation(**r) for r in llm_result.get('recommendations', [])]

        processing_time = time.time() - start_time

        result = EvaluationResult(
            evaluation_id=evaluation_id,
            control_id=normalized_control_id,
            overall_compliance=ComplianceLevel(llm_result.get('overall_compliance', 'insufficient_evidence')),
            compliance_score=llm_result.get('compliance_score', 0.0),
            confidence_level=llm_result.get('confidence_level', 0.5),
            findings=findings,
            recommendations=recommendations,
            processing_time_seconds=processing_time
        )

        logger.info(f"Evidence evaluation completed for {normalized_control_id}: {result.overall_compliance} (score: {result.compliance_score:.2f})")

        return result