"""UseCase model for real-world AI implementations in newsrooms."""
from sqlalchemy import (
    Column, String, Boolean, DateTime, Integer, Text, Float,
    ForeignKey, CheckConstraint
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
import uuid
from app.db import Base


class UseCase(Base):
    """Real-world AI implementation case study from a newsroom.

    Use cases document how news organizations have implemented AI tools,
    including challenges faced, solutions applied, and outcomes achieved.
    Sources include: JournalismAI, news org tech blogs (AP, BBC Labs, etc.)
    """

    __tablename__ = "use_cases"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # Basic info
    title = Column(String, nullable=False, index=True)
    slug = Column(String, nullable=False, unique=True, index=True)

    # Organization details
    organization = Column(String, nullable=True, index=True)  # News org name
    country = Column(String, nullable=True, index=True)
    region = Column(String, nullable=True)  # e.g., "Europe", "North America"
    organization_type = Column(String, nullable=True)  # "newspaper", "broadcaster", "digital native", etc.

    # Case study content
    summary = Column(Text, nullable=True)  # Brief overview
    challenge = Column(Text, nullable=True)  # What problem they faced
    solution = Column(Text, nullable=True)  # What they implemented
    outcome = Column(Text, nullable=True)  # Results/impact
    lessons_learned = Column(Text, nullable=True)  # Key takeaways

    # Tool references
    tools_used = Column(JSONB, nullable=True, default=list)  # List of tool slugs used (from our kit)
    tools_mentioned = Column(JSONB, nullable=True, default=list)  # Tools mentioned but not in kit

    # Source information
    source_url = Column(String, nullable=True)  # Original case study URL
    source_name = Column(String, nullable=True)  # e.g., "JournalismAI", "AP Blog"
    source_date = Column(DateTime(timezone=True), nullable=True)  # Publication date

    # Discovery metadata
    source_type = Column(String, nullable=False, default="manual", index=True)  # "rss", "api", "scrape", "manual"
    discovered_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)

    # Review workflow
    status = Column(String, nullable=False, default="pending_review", index=True)
    # Status values: "pending_review", "approved", "rejected", "archived"
    confidence_score = Column(Float, nullable=False, default=0.5)
    reviewed_by = Column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True
    )
    reviewed_at = Column(DateTime(timezone=True), nullable=True)
    review_notes = Column(Text, nullable=True)

    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    # Relationships
    reviewer = relationship("User", foreign_keys=[reviewed_by])

    __table_args__ = (
        CheckConstraint(
            "status IN ('pending_review', 'approved', 'rejected', 'archived')",
            name='ck_use_case_status'
        ),
        CheckConstraint(
            "source_type IN ('rss', 'api', 'scrape', 'manual')",
            name='ck_use_case_source_type'
        ),
        CheckConstraint(
            'confidence_score >= 0.0 AND confidence_score <= 1.0',
            name='ck_use_case_confidence_score_range'
        ),
    )
