"""Add tool discovery tables

Revision ID: 013
Revises: 012
Create Date: 2025-01-29

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision = '013'
down_revision = '012'
branch_labels = None
depends_on = None


def upgrade():
    # Create discovered_tools table
    op.create_table(
        'discovered_tools',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),

        # Basic tool info
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('slug', sa.String(), nullable=False),
        sa.Column('url', sa.String(), nullable=False),
        sa.Column('url_domain', sa.String(), nullable=False),
        sa.Column('docs_url', sa.String(), nullable=True),
        sa.Column('pricing_url', sa.String(), nullable=True),

        # Description
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('raw_description', sa.Text(), nullable=True),

        # Categorization
        sa.Column('categories', postgresql.JSONB(), nullable=True, server_default='[]'),
        sa.Column('tags', postgresql.JSONB(), nullable=True, server_default='[]'),

        # Discovery metadata
        sa.Column('source_type', sa.String(), nullable=False),
        sa.Column('source_url', sa.String(), nullable=False),
        sa.Column('source_name', sa.String(), nullable=False),
        sa.Column('discovered_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('last_seen_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('last_updated_signal', sa.String(), nullable=True),
        sa.Column('extra_data', postgresql.JSONB(), nullable=True, server_default='{}'),

        # Review workflow
        sa.Column('status', sa.String(), nullable=False, server_default='pending_review'),
        sa.Column('confidence_score', sa.Float(), nullable=False, server_default='0.5'),
        sa.Column('review_notes', sa.Text(), nullable=True),
        sa.Column('reviewed_by', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('reviewed_at', sa.DateTime(timezone=True), nullable=True),

        # Timestamps
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),

        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['reviewed_by'], ['users.id'], ondelete='SET NULL'),
        sa.UniqueConstraint('slug', name='uq_discovered_tool_slug'),
        sa.CheckConstraint(
            "status IN ('pending_review', 'approved', 'rejected', 'archived')",
            name='ck_discovered_tool_status'
        ),
        sa.CheckConstraint(
            "source_type IN ('github', 'producthunt', 'awesome_list', 'directory')",
            name='ck_discovered_tool_source_type'
        ),
        sa.CheckConstraint(
            'confidence_score >= 0.0 AND confidence_score <= 1.0',
            name='ck_confidence_score_range'
        ),
    )

    # Create indexes for discovered_tools
    op.create_index('ix_discovered_tools_name', 'discovered_tools', ['name'])
    op.create_index('ix_discovered_tools_slug', 'discovered_tools', ['slug'])
    op.create_index('ix_discovered_tools_url', 'discovered_tools', ['url'])
    op.create_index('ix_discovered_tools_url_domain', 'discovered_tools', ['url_domain'])
    op.create_index('ix_discovered_tools_source_type', 'discovered_tools', ['source_type'])
    op.create_index('ix_discovered_tools_status', 'discovered_tools', ['status'])
    op.create_index('ix_discovered_tools_discovered_at', 'discovered_tools', ['discovered_at'])
    op.create_index('ix_discovered_tools_confidence_score', 'discovered_tools', ['confidence_score'])
    op.create_index('ix_discovered_tools_reviewed_by', 'discovered_tools', ['reviewed_by'])

    # Create discovery_runs table
    op.create_table(
        'discovery_runs',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('started_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('status', sa.String(), nullable=False, server_default='running'),
        sa.Column('source_type', sa.String(), nullable=True),

        # Stats
        sa.Column('tools_found', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('tools_new', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('tools_updated', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('tools_skipped', sa.Integer(), nullable=False, server_default='0'),

        # Error tracking
        sa.Column('error_message', sa.Text(), nullable=True),

        # Configuration
        sa.Column('run_config', postgresql.JSONB(), nullable=True, server_default='{}'),
        sa.Column('triggered_by', sa.String(), nullable=True),

        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),

        sa.PrimaryKeyConstraint('id'),
        sa.CheckConstraint(
            "status IN ('running', 'completed', 'failed')",
            name='ck_discovery_run_status'
        ),
    )

    # Create indexes for discovery_runs
    op.create_index('ix_discovery_runs_started_at', 'discovery_runs', ['started_at'])
    op.create_index('ix_discovery_runs_status', 'discovery_runs', ['status'])

    # Create tool_matches table
    op.create_table(
        'tool_matches',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('tool_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('matched_tool_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('matched_kit_slug', sa.String(), nullable=True),

        # Match details
        sa.Column('match_type', sa.String(), nullable=False),
        sa.Column('match_score', sa.Float(), nullable=False),
        sa.Column('match_details', postgresql.JSONB(), nullable=True),

        # Resolution
        sa.Column('is_duplicate', sa.Boolean(), nullable=True),
        sa.Column('resolved_by', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('resolved_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('resolution_notes', sa.Text(), nullable=True),

        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),

        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['tool_id'], ['discovered_tools.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['matched_tool_id'], ['discovered_tools.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['resolved_by'], ['users.id'], ondelete='SET NULL'),
        sa.CheckConstraint(
            "match_type IN ('exact_url', 'domain', 'name_fuzzy', 'name_exact', 'description_similar')",
            name='ck_tool_match_type'
        ),
        sa.CheckConstraint(
            'match_score >= 0.0 AND match_score <= 1.0',
            name='ck_match_score_range'
        ),
        sa.CheckConstraint(
            'matched_tool_id IS NOT NULL OR matched_kit_slug IS NOT NULL',
            name='ck_match_target_required'
        ),
    )

    # Create indexes for tool_matches
    op.create_index('ix_tool_matches_tool_id', 'tool_matches', ['tool_id'])
    op.create_index('ix_tool_matches_matched_tool_id', 'tool_matches', ['matched_tool_id'])
    op.create_index('ix_tool_matches_matched_kit_slug', 'tool_matches', ['matched_kit_slug'])
    op.create_index('ix_tool_matches_is_duplicate', 'tool_matches', ['is_duplicate'])


def downgrade():
    op.drop_table('tool_matches')
    op.drop_table('discovery_runs')
    op.drop_table('discovered_tools')
