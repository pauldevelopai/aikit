"""Add tool playbook tables for newsroom guidance

Revision ID: 014
Revises: 013
Create Date: 2025-01-29

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision = '014'
down_revision = '013'
branch_labels = None
depends_on = None


def upgrade():
    # Create tool_playbooks table
    op.create_table(
        'tool_playbooks',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),

        # Link to tool (either discovered tool or curated kit tool)
        sa.Column('discovered_tool_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('kit_tool_slug', sa.String(), nullable=True),

        # Status
        sa.Column('status', sa.String(), nullable=False, server_default='draft'),

        # Structured guidance sections
        sa.Column('best_use_cases', sa.Text(), nullable=True),
        sa.Column('implementation_steps', sa.Text(), nullable=True),
        sa.Column('common_mistakes', sa.Text(), nullable=True),
        sa.Column('privacy_notes', sa.Text(), nullable=True),
        sa.Column('replaces_improves', sa.Text(), nullable=True),

        # Additional structured data
        sa.Column('key_features', postgresql.JSONB(), nullable=True, server_default='[]'),
        sa.Column('pricing_summary', sa.Text(), nullable=True),
        sa.Column('integration_notes', sa.Text(), nullable=True),

        # Generation metadata
        sa.Column('generation_model', sa.String(), nullable=True),
        sa.Column('generation_prompt_version', sa.String(), nullable=True),
        sa.Column('source_count', sa.Integer(), nullable=False, server_default='0'),

        # Review tracking
        sa.Column('reviewed_by', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('reviewed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('review_notes', sa.Text(), nullable=True),

        # Timestamps
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('generated_at', sa.DateTime(timezone=True), nullable=True),

        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['discovered_tool_id'], ['discovered_tools.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['reviewed_by'], ['users.id'], ondelete='SET NULL'),
        sa.UniqueConstraint('discovered_tool_id', name='uq_playbook_discovered_tool'),
        sa.UniqueConstraint('kit_tool_slug', name='uq_playbook_kit_tool'),
    )

    # Create indexes for tool_playbooks
    op.create_index('ix_tool_playbooks_discovered_tool_id', 'tool_playbooks', ['discovered_tool_id'])
    op.create_index('ix_tool_playbooks_kit_tool_slug', 'tool_playbooks', ['kit_tool_slug'])
    op.create_index('ix_tool_playbooks_status', 'tool_playbooks', ['status'])

    # Create playbook_sources table
    op.create_table(
        'playbook_sources',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),

        sa.Column('playbook_id', postgresql.UUID(as_uuid=True), nullable=False),

        # Source info
        sa.Column('url', sa.String(), nullable=False),
        sa.Column('source_type', sa.String(), nullable=False),
        sa.Column('title', sa.String(), nullable=True),

        # Scraped content
        sa.Column('raw_content', sa.Text(), nullable=True),
        sa.Column('extracted_content', sa.Text(), nullable=True),
        sa.Column('content_hash', sa.String(), nullable=True),

        # Scraping metadata
        sa.Column('scraped_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('scrape_status', sa.String(), nullable=False, server_default='pending'),
        sa.Column('scrape_error', sa.Text(), nullable=True),

        # Section contribution
        sa.Column('contributed_sections', postgresql.JSONB(), nullable=True, server_default='[]'),

        # Quality
        sa.Column('relevance_score', sa.Integer(), nullable=True),
        sa.Column('is_primary', sa.Boolean(), nullable=False, server_default='false'),

        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),

        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['playbook_id'], ['tool_playbooks.id'], ondelete='CASCADE'),
        sa.UniqueConstraint('playbook_id', 'url', name='uq_playbook_source_url'),
    )

    # Create indexes for playbook_sources
    op.create_index('ix_playbook_sources_playbook_id', 'playbook_sources', ['playbook_id'])
    op.create_index('ix_playbook_sources_source_type', 'playbook_sources', ['source_type'])
    op.create_index('ix_playbook_sources_scrape_status', 'playbook_sources', ['scrape_status'])


def downgrade():
    op.drop_table('playbook_sources')
    op.drop_table('tool_playbooks')
