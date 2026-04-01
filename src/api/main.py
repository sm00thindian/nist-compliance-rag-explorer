import logging
import os
from contextlib import asynccontextmanager
from typing import List

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .models import (
    EvidenceSubmission, EvaluationResult, APIResponse,
    ControlInfo, EvidenceSearchQuery
)
from .evidence_evaluator import EvidenceEvaluator

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Global evaluator instance
evaluator = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager"""
    global evaluator

    # Startup
    logger.info("Starting Evidence Evaluation API")
    try:
        evaluator = EvidenceEvaluator()
        logger.info("Evidence evaluator initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize evaluator: {e}")
        # Continue without evaluator for basic endpoints

    yield

    # Shutdown
    logger.info("Shutting down Evidence Evaluation API")

# Create FastAPI app
app = FastAPI(
    title="NIST Compliance Evidence Evaluation API",
    description="AI-powered evidence evaluation service for NIST 800-53 compliance",
    version="1.0.0",
    lifespan=lifespan
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "service": "evidence-evaluation-api"}

@app.get("/controls/{control_id}")
async def get_control_info(control_id: str):
    """Get information about a specific control"""
    if not evaluator or not evaluator.control_details:
        raise HTTPException(status_code=503, detail="Control data not available")

    normalized_id = evaluator.control_details.get(control_id.upper())
    if not normalized_id:
        raise HTTPException(status_code=404, detail=f"Control {control_id} not found")

    control = normalized_id
    return ControlInfo(
        control_id=control['control_id'],
        title=control['title'],
        description=control['description'],
        family=control['family'],
        baseline_levels=control.get('baseline_levels', [])
    )

@app.get("/controls")
async def list_controls(limit: int = 50, family: str = None):
    """List available controls"""
    if not evaluator or not evaluator.control_details:
        raise HTTPException(status_code=503, detail="Control data not available")

    controls = list(evaluator.control_details.values())

    if family:
        controls = [c for c in controls if c.get('family', '').upper() == family.upper()]

    # Convert to ControlInfo objects
    control_infos = [
        ControlInfo(
            control_id=c['control_id'],
            title=c['title'],
            description=c['description'][:200] + "..." if len(c['description']) > 200 else c['description'],
            family=c.get('family', 'Unknown'),
            baseline_levels=c.get('baseline_levels', [])
        )
        for c in controls[:limit]
    ]

    return {"controls": control_infos, "total": len(controls)}

@app.post("/evidence/evaluate", response_model=APIResponse)
async def evaluate_evidence(
    submission: EvidenceSubmission,
    background_tasks: BackgroundTasks
):
    """Submit evidence for AI evaluation"""
    if not evaluator:
        raise HTTPException(
            status_code=503,
            detail="Evidence evaluation service not available. Check API key configuration."
        )

    try:
        # Evaluate evidence (this is async but we'll await it for now)
        result = await evaluator.evaluate_evidence(submission)

        return APIResponse(
            success=True,
            message="Evidence evaluated successfully",
            data=result
        )

    except Exception as e:
        logger.error(f"Evidence evaluation failed: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Evaluation failed: {str(e)}"
        )

@app.get("/evaluations/{evaluation_id}")
async def get_evaluation(evaluation_id: str):
    """Get a specific evaluation result (placeholder for future storage)"""
    # TODO: Implement evaluation storage and retrieval
    raise HTTPException(
        status_code=501,
        detail="Evaluation storage not yet implemented"
    )

@app.post("/evaluations/search")
async def search_evaluations(query: EvidenceSearchQuery):
    """Search evaluation history (placeholder for future storage)"""
    # TODO: Implement evaluation search
    return APIResponse(
        success=True,
        message="Search functionality not yet implemented",
        data={"results": [], "total": 0}
    )

@app.get("/stats")
async def get_stats():
    """Get API usage statistics"""
    return {
        "controls_loaded": len(evaluator.control_details) if evaluator else 0,
        "rag_initialized": evaluator and evaluator.embedding_manager is not None,
        "llm_provider": evaluator.llm_provider if evaluator else None,
        "service_status": "operational" if evaluator else "initializing"
    }

# Error handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    return JSONResponse(
        status_code=exc.status_code,
        content=APIResponse(
            success=False,
            message=exc.detail,
            error_details={"status_code": exc.status_code}
        ).dict()
    )

@app.exception_handler(Exception)
async def general_exception_handler(request, exc):
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content=APIResponse(
            success=False,
            message="Internal server error",
            error_details={"error_type": type(exc).__name__}
        ).dict()
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "src.api.main:app",
        host="0.0.0.0",
        port=int(os.getenv("PORT", 8000)),
        reload=True
    )