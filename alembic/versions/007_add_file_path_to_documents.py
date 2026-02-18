"""Add file_path to toolkit_documents

Revision ID: 007
Revises: 006
Create Date: 2025-01-27

The model has file_path but the table was created without it.
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '007'
down_revision = '006'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add file_path column to toolkit_documents."""
    op.add_column('toolkit_documents', sa.Column('file_path', sa.String(), nullable=True))


def downgrade() -> None:
    """Remove file_path column."""
    op.drop_column('toolkit_documents', 'file_path')
