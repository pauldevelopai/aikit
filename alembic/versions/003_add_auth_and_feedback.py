"""Add authentication and feedback tables

Revision ID: 003
Revises: 002
Create Date: 2025-01-22

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, JSONB


# revision identifiers, used by Alembic.
revision = '003'
down_revision = '002'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create users, sessions, and feedback tables; add user_id to chat_logs."""

    # Create users table
    op.create_table(
        'users',
        sa.Column('id', UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('email', sa.String(), nullable=False),
        sa.Column('username', sa.String(), nullable=False),
        sa.Column('hashed_password', sa.String(), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('is_admin', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index('ix_users_email', 'users', ['email'], unique=True)
    op.create_index('ix_users_username', 'users', ['username'], unique=True)

    # Create sessions table
    op.create_table(
        'sessions',
        sa.Column('id', UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('user_id', UUID(as_uuid=True), nullable=False),
        sa.Column('session_token', sa.String(), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
    )
    op.create_index('ix_sessions_user_id', 'sessions', ['user_id'])
    op.create_index('ix_sessions_session_token', 'sessions', ['session_token'], unique=True)

    # Add user_id to chat_logs (nullable for migration, we'll handle existing rows)
    op.add_column('chat_logs', sa.Column('user_id', UUID(as_uuid=True), nullable=True))

    # Create a default system user for existing chat logs
    op.execute("""
        INSERT INTO users (id, email, username, hashed_password, is_active, is_admin)
        VALUES (
            '00000000-0000-0000-0000-000000000000',
            'system@toolkit.local',
            'system',
            '$2b$12$dummy.hash.for.system.user',
            true,
            true
        )
        ON CONFLICT DO NOTHING;
    """)

    # Set existing chat logs to system user
    op.execute("""
        UPDATE chat_logs
        SET user_id = '00000000-0000-0000-0000-000000000000'
        WHERE user_id IS NULL;
    """)

    # Now make user_id non-nullable
    op.alter_column('chat_logs', 'user_id', nullable=False)

    # Add foreign key constraint
    op.create_foreign_key(
        'fk_chat_logs_user_id',
        'chat_logs', 'users',
        ['user_id'], ['id'],
        ondelete='CASCADE'
    )
    op.create_index('ix_chat_logs_user_id', 'chat_logs', ['user_id'])

    # Create feedback table
    op.create_table(
        'feedback',
        sa.Column('id', UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('chat_log_id', UUID(as_uuid=True), nullable=False),
        sa.Column('user_id', UUID(as_uuid=True), nullable=False),
        sa.Column('rating', sa.Integer(), nullable=False),
        sa.Column('issue_type', sa.String(), nullable=True),
        sa.Column('comment', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(['chat_log_id'], ['chat_logs.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
    )
    op.create_index('ix_feedback_chat_log_id', 'feedback', ['chat_log_id'])
    op.create_index('ix_feedback_user_id', 'feedback', ['user_id'])


def downgrade() -> None:
    """Drop feedback, sessions, and users tables; remove user_id from chat_logs."""
    op.drop_index('ix_feedback_user_id', table_name='feedback')
    op.drop_index('ix_feedback_chat_log_id', table_name='feedback')
    op.drop_table('feedback')

    op.drop_index('ix_chat_logs_user_id', table_name='chat_logs')
    op.drop_constraint('fk_chat_logs_user_id', 'chat_logs', type_='foreignkey')
    op.drop_column('chat_logs', 'user_id')

    op.drop_index('ix_sessions_session_token', table_name='sessions')
    op.drop_index('ix_sessions_user_id', table_name='sessions')
    op.drop_table('sessions')

    op.drop_index('ix_users_username', table_name='users')
    op.drop_index('ix_users_email', table_name='users')
    op.drop_table('users')
