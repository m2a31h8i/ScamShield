from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional
from app.educational_explainer_agent import run_explainer_agent

explainer_router = APIRouter()


class ExplainerRequest(BaseModel):
    threat_type: str
    target: str
    risk_score: int
    indicators: list[str]
    user_level: Optional[str] = "beginner"


@explainer_router.post("/educational-explainer/analyze")
def analyze(payload: ExplainerRequest):

    result = run_explainer_agent(
        payload.threat_type,
        payload.target,
        payload.risk_score,
        payload.indicators,
        payload.user_level
    )

    return result