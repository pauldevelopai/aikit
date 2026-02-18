"""Recommendation Pydantic schemas."""
from pydantic import BaseModel, Field
from datetime import datetime
from uuid import UUID
from typing import Optional
from enum import Enum


class CitationType(str, Enum):
    """Types of citations for recommendations."""
    CDI_DATA = "cdi_data"
    PLAYBOOK = "playbook"
    REVIEW = "review"
    ACTIVITY = "activity"


class Citation(BaseModel):
    """Citation grounding a recommendation."""
    type: CitationType
    text: str
    source: Optional[str] = None
    rating: Optional[int] = None
    use_case: Optional[str] = None
    reviewer_type: Optional[str] = None
    helpful_count: Optional[int] = None


class ScoreBreakdown(BaseModel):
    """Breakdown of how a tool was scored."""
    cdi_fit: float = Field(..., description="CDI fit score (0-30)")
    use_case_match: float = Field(..., description="Use case match score (0-25)")
    review_signal: float = Field(..., description="Review signal score (0-20)")
    activity_relevance: float = Field(..., description="Activity relevance score (0-15)")
    profile_fit: float = Field(..., description="Profile fit score (0-10)")
    total: float = Field(..., description="Total score (0-100)")


class TrainingPlan(BaseModel):
    """Personalized training plan."""
    intensity: str = Field(..., description="beginner, intermediate, or advanced")
    duration: str = Field(..., description="Estimated onboarding duration")
    steps: list[str] = Field(default_factory=list, description="Training steps")
    tips: list[str] = Field(default_factory=list, description="Additional tips")


class RolloutApproach(BaseModel):
    """Personalized rollout approach."""
    pace: str = Field(..., description="fast-track, standard, or cautious")
    phases: list[dict] = Field(default_factory=list, description="Rollout phases")
    gates: list[str] = Field(default_factory=list, description="Required gates/checkpoints")


class TailoredGuidance(BaseModel):
    """Personalized implementation guidance for a tool."""
    training_plan: TrainingPlan
    rollout_approach: RolloutApproach
    workflow_tips: list[str] = Field(default_factory=list, description="Workflow integration tips")
    citations: list[Citation] = Field(default_factory=list)


class ToolRecommendation(BaseModel):
    """A scored tool recommendation with explanation."""
    tool_slug: str
    tool_name: str
    cluster_slug: str
    cluster_name: str
    fit_score: float = Field(..., ge=0, le=100, description="Overall fit score 0-100")
    score_breakdown: ScoreBreakdown
    explanation: str = Field(..., description="Why this tool is recommended")
    citations: list[Citation] = Field(default_factory=list)
    cdi_scores: dict = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)
    purpose: Optional[str] = None
    tailored_guidance: Optional[TailoredGuidance] = None


class UserContext(BaseModel):
    """Aggregated user context for personalization."""
    user_id: UUID

    # Profile attributes
    organisation_type: Optional[str] = None
    role: Optional[str] = None
    country: Optional[str] = None
    ai_experience_level: Optional[str] = None

    # Strategy preferences
    budget: Optional[str] = None
    risk_level: Optional[str] = None
    data_sensitivity: Optional[str] = None
    deployment_pref: Optional[str] = None
    use_cases: list[str] = Field(default_factory=list)

    # Activity signals
    searched_queries: list[str] = Field(default_factory=list)
    browsed_clusters: list[str] = Field(default_factory=list)
    viewed_tools: list[str] = Field(default_factory=list)
    reviewed_tools: list[str] = Field(default_factory=list)

    # Computed constraints
    max_cost: int = Field(default=10, ge=0, le=10)
    max_difficulty: int = Field(default=10, ge=0, le=10)
    max_invasiveness: int = Field(default=10, ge=0, le=10)


# API Response schemas
class RecommendationsResponse(BaseModel):
    """Response for /api/recommendations/for-me."""
    recommendations: list[ToolRecommendation]
    user_context_summary: dict = Field(default_factory=dict)
    query: Optional[str] = None
    use_case: Optional[str] = None


class ToolGuidanceResponse(BaseModel):
    """Response for /api/recommendations/for-tool/{slug}."""
    tool_slug: str
    tool_name: str
    fit_score: float
    explanation: str
    guidance: TailoredGuidance
    citations: list[Citation] = Field(default_factory=list)


class SuggestedBlockResponse(BaseModel):
    """Response for /api/recommendations/suggested."""
    location: str
    recommendations: list[ToolRecommendation]
    title: str = "Suggested for You"
    show_block: bool = True
