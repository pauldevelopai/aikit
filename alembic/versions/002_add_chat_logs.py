"""Add chat_logs table

Revision ID: 002
Revises: 001
Create Date: 2025-01-22

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, JSONB


# revision identifiers, used by Alembic.
revision = '002'
down_revision = '001'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create chat_logs table."""
    op.create_table(
        'chat_logs',
        sa.Column('id', UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('query', sa.Text(), nullable=False),
        sa.Column('answer', sa.Text(), nullable=False),
        sa.Column('citations', JSONB, nullable=False),
        sa.Column('similarity_score', JSONB, nullable=True),
        sa.Column('filters_applied', JSONB, nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )

    # Add index on created_at for efficient time-based queries
    op.create_index('ix_chat_logs_created_at', 'chat_logs', ['created_at'])


def downgrade() -> None:
    """Drop chat_logs table."""
    op.drop_index('ix_chat_logs_created_at', table_name='chat_logs')
    op.drop_table('chat_logs')
