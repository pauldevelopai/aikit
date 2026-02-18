"""Add missing chunk columns (heading, chunk_metadata, embedding)

Revision ID: 006
Revises: 005
Create Date: 2025-01-27

The toolkit_chunks table was created with cluster/section/tool_name/tags
columns, but the model was updated to use heading/chunk_metadata/embedding.
This migration adds the missing columns and enables pgvector.
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB


# revision identifiers, used by Alembic.
revision = '006'
down_revision = '005'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add heading, chunk_metadata, embedding columns to toolkit_chunks."""
    # pgvector extension must be enabled by a superuser before running this migration:
    # psql -d toolkitrag -c "CREATE EXTENSION IF NOT EXISTS vector;"

    # Add missing columns
    op.add_column('toolkit_chunks', sa.Column('heading', sa.String(), nullable=True))
    op.add_column('toolkit_chunks', sa.Column('chunk_metadata', JSONB, nullable=True))

    # Add embedding column (Vector(1536) for text-embedding-3-small)
    op.execute('ALTER TABLE toolkit_chunks ADD COLUMN embedding vector(1536)')


def downgrade() -> None:
    """Remove heading, chunk_metadata, embedding columns."""
    op.drop_column('toolkit_chunks', 'embedding')
    op.drop_column('toolkit_chunks', 'chunk_metadata')
    op.drop_column('toolkit_chunks', 'heading')
