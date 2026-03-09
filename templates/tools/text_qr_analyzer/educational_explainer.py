from fastapi import APIRouter
from pydantic import BaseModel, Field
from typing import List, Optional

from app.agents import generate_scan_explainer


explainer_router = APIRouter()


class ExplainerRequest(BaseModel):
    threat_type: str = Field(default="Suspicious Activity")
    target: str = Field(default="")
    risk_score: int = Field(default=50, ge=0, le=100)
    indicators: List[str] = Field(default_factory=list)
    user_level: Optional[str] = Field(default=None)


@explainer_router.post("/educational-explainer/analyze")
def educational_explainer(payload: ExplainerRequest):
    return generate_scan_explainer(
        threat_type=payload.threat_type,
        target=payload.target,
        risk_score=payload.risk_score,
        indicators=payload.indicators,
        user_level=payload.user_level,
    )