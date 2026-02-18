"""Playbook models for newsroom implementation guidance."""
from sqlalchemy import (
    Column, String, Boolean, DateTime, Integer, Text,
    ForeignKey, UniqueConstraint
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
import uuid
from app.db import Base


class ToolPlaybook(Base):
    """Newsroom playbook for a discovered or curated tool.

    Contains structured guidance extracted from real sources,
    not AI-generated content without grounding.
    """

    __tablename__ = "tool_playbooks"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # Link to tool (either discovered tool or curated kit tool)
    discovered_tool_id = Column(
        UUID(as_uuid=True),
        ForeignKey("discovered_tools.id", ondelete="CASCADE"),
        nullable=True,
        index=True
    )
    kit_tool_slug = Column(String, nullable=True, index=True)  # For curated tools

    # Status
    status = Column(String, nullable=False, default="draft", index=True)
    # Status values: "draft", "generating", "published", "archived"

    # Structured guidance sections (all sourced from scraped content)
    best_use_cases = Column(Text, nullable=True)  # Best newsroom use cases
    implementation_steps = Column(Text, nullable=True)  # Step-by-step how a newsroom would implement
    common_mistakes = Column(Text, nullable=True)  # Common mistakes / risks
    privacy_notes = Column(Text, nullable=True)  # Privacy + source protection notes
    replaces_improves = Column(Text, nullable=True)  # What this tool replaces or improves

    # Additional structured data
    key_features = Column(JSONB, nullable=True, default=list)  # List of key features for newsrooms
    pricing_summary = Column(Text, nullable=True)  # Pricing relevant to newsrooms
    integration_notes = Column(Text, nullable=True)  # Integration with common newsroom tools

    # Metadata about generation
    generation_model = Column(String, nullable=True)  # e.g., "claude-3-opus", "gpt-4"
    generation_prompt_version = Column(String, nullable=True)  # Track prompt versions
    source_count = Column(Integer, nullable=False, default=0)  # Number of sources used

    # Review tracking
    reviewed_by = Column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True
    )
    reviewed_at = Column(DateTime(timezone=True), nullable=True)
    review_notes = Column(Text, nullable=True)

    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    generated_at = Column(DateTime(timezone=True), nullable=True)  # When content was last generated

    # Relationships
    discovered_tool = relationship("DiscoveredTool", backref="playbook")
    reviewer = relationship("User", foreign_keys=[reviewed_by])
    sources = relationship("PlaybookSource", back_populates="playbook", cascade="all, delete-orphan")

    __table_args__ = (
        # Ensure at least one tool reference
        UniqueConstraint('discovered_tool_id', name='uq_playbook_discovered_tool'),
        UniqueConstraint('kit_tool_slug', name='uq_playbook_kit_tool'),
    )


class PlaybookSource(Base):
    """Scraped source used to generate playbook content.

    Stores both the URL and extracted content for verification.
    """

    __tablename__ = "playbook_sources"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    playbook_id = Column(
        UUID(as_uuid=True),
        ForeignKey("tool_playbooks.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )

    # Source info
    url = Column(String, nullable=False)
    source_type = Column(String, nullable=False, index=True)
    # Source types: "official_docs", "help_page", "blog_post", "case_study",
    #               "newsroom_example", "tutorial", "api_docs", "changelog"

    title = Column(String, nullable=True)  # Page title

    # Scraped content
    raw_content = Column(Text, nullable=True)  # Full scraped text
    extracted_content = Column(Text, nullable=True)  # Cleaned/relevant portions
    content_hash = Column(String, nullable=True)  # For change detection

    # Scraping metadata
    scraped_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    scrape_status = Column(String, nullable=False, default="pending")
    # Status: "pending", "success", "failed", "blocked"
    scrape_error = Column(Text, nullable=True)

    # Which sections this source contributed to
    contributed_sections = Column(JSONB, nullable=True, default=list)
    # e.g., ["best_use_cases", "implementation_steps"]

    # Quality/relevance
    relevance_score = Column(Integer, nullable=True)  # 1-10 how relevant to newsrooms
    is_primary = Column(Boolean, default=False, nullable=False)  # Primary/official source

    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    # Relationships
    playbook = relationship("ToolPlaybook", back_populates="sources")

    __table_args__ = (
        UniqueConstraint('playbook_id', 'url', name='uq_playbook_source_url'),
    )
