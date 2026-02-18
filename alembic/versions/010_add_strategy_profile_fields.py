"""Add strategy profile fields to users table.

Revision ID: 010
Revises: 009
Create Date: 2026-01-28
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers
revision = '010'
down_revision = '009'
branch_labels = None
depends_on = None


def upgrade():
    # Add strategy preference fields to users table
    op.add_column('users', sa.Column('risk_level', sa.String(), nullable=True))
    op.add_column('users', sa.Column('data_sensitivity', sa.String(), nullable=True))
    op.add_column('users', sa.Column('budget', sa.String(), nullable=True))
    op.add_column('users', sa.Column('deployment_pref', sa.String(), nullable=True))
    op.add_column('users', sa.Column('use_cases', sa.Text(), nullable=True))


def downgrade():
    op.drop_column('users', 'use_cases')
    op.drop_column('users', 'deployment_pref')
    op.drop_column('users', 'budget')
    op.drop_column('users', 'data_sensitivity')
    op.drop_column('users', 'risk_level')
