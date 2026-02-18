"""Add user profile fields

Revision ID: 005
Revises: 004
Create Date: 2025-01-27

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '005'
down_revision = '004'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add profile columns to users table."""
    op.add_column('users', sa.Column('display_name', sa.String(), nullable=True))
    op.add_column('users', sa.Column('organisation', sa.String(), nullable=True))
    op.add_column('users', sa.Column('organisation_type', sa.String(), nullable=True))
    op.add_column('users', sa.Column('role', sa.String(), nullable=True))
    op.add_column('users', sa.Column('country', sa.String(), nullable=True))
    op.add_column('users', sa.Column('interests', sa.Text(), nullable=True))
    op.add_column('users', sa.Column('ai_experience_level', sa.String(), nullable=True))


def downgrade() -> None:
    """Remove profile columns from users table."""
    op.drop_column('users', 'ai_experience_level')
    op.drop_column('users', 'interests')
    op.drop_column('users', 'country')
    op.drop_column('users', 'role')
    op.drop_column('users', 'organisation_type')
    op.drop_column('users', 'organisation')
    op.drop_column('users', 'display_name')
