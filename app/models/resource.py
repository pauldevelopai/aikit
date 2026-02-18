"""DiscoveredResource model for AI/media resources discovered via automated pipeline."""
from sqlalchemy import (
    Column, String, Boolean, DateTime, Integer, Text, Float,
    ForeignKey, CheckConstraint
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
import uuid
from app.db import Base


class DiscoveredResource(Base):
    """Resource about AI and media discovered via automated pipeline.

    Resources are reports, studies, articles about AI in journalism/media.
    Sources include: Nieman Lab, Reuters Institute, Poynter, etc.
    """

    __tablename__ = "discovered_resources"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # Basic resource info
    title = Column(String, nullable=False, index=True)
    slug = Column(String, nullable=False, unique=True, index=True)
    url = Column(String, nullable=False, index=True)
    url_domain = Column(String, nullable=False, index=True)

    # Content
    summary = Column(Text, nullable=True)  # Brief summary
    ai_extract = Column(Text, nullable=True)  # AI-extracted key points
    themes = Column(JSONB, nullable=True, default=list)  # Key themes/topics

    # Source metadata
    source = Column(String, nullable=True)  # Publisher name (e.g., "Nieman Lab")
    publication_date = Column(DateTime(timezone=True), nullable=True)
    author = Column(String, nullable=True)
    resource_type = Column(String, nullable=True, index=True)  # "report", "study", "article", "guide"

    # Discovery metadata
    source_type = Column(String, nullable=False, index=True)  # "rss", "api", "scrape", "manual"
    source_url = Column(String, nullable=False)  # Where we found it
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
            name='ck_discovered_resource_status'
        ),
        CheckConstraint(
            "source_type IN ('rss', 'api', 'scrape', 'manual')",
            name='ck_discovered_resource_source_type'
        ),
        CheckConstraint(
            'confidence_score >= 0.0 AND confidence_score <= 1.0',
            name='ck_resource_confidence_score_range'
        ),
    )
