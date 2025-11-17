"""add security tables

Revision ID: e0fd20a20cb1
Revises: 7135f9119659
Create Date: 2025-11-17 22:10:56.850947

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import open_webui.internal.db


# revision identifiers, used by Alembic.
revision: str = 'e0fd20a20cb1'
down_revision: Union[str, None] = '7135f9119659'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create user_ip_whitelist table
    op.create_table('user_ip_whitelist',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('user_id', sa.String(), nullable=False),
        sa.Column('ip_address', sa.String(), nullable=False),
        sa.Column('created_at', sa.BigInteger(), nullable=True),
        sa.Column('created_by', sa.String(), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_user_ip_whitelist_user_id', 'user_ip_whitelist', ['user_id'])

    # Create login_attempts table
    op.create_table('login_attempts',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('user_email', sa.String(), nullable=False),
        sa.Column('ip_address', sa.String(), nullable=True),
        sa.Column('success', sa.Boolean(), nullable=False),
        sa.Column('failure_reason', sa.String(), nullable=True),
        sa.Column('timestamp', sa.BigInteger(), nullable=False),
        sa.Column('user_agent', sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_login_attempts_user_email', 'login_attempts', ['user_email'])
    op.create_index('ix_login_attempts_timestamp', 'login_attempts', ['timestamp'])

    # Create user_lock_status table
    op.create_table('user_lock_status',
        sa.Column('user_email', sa.String(), nullable=False),
        sa.Column('is_locked', sa.Boolean(), nullable=True),
        sa.Column('lock_reason', sa.String(), nullable=True),
        sa.Column('locked_at', sa.BigInteger(), nullable=True),
        sa.Column('locked_until', sa.BigInteger(), nullable=True),
        sa.Column('failed_attempts', sa.Integer(), nullable=True),
        sa.Column('last_failed_at', sa.BigInteger(), nullable=True),
        sa.Column('last_success_at', sa.BigInteger(), nullable=True),
        sa.PrimaryKeyConstraint('user_email')
    )

    # Create password_policy table
    op.create_table('password_policy',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('user_email', sa.String(), nullable=False),
        sa.Column('password_set_at', sa.BigInteger(), nullable=True),
        sa.Column('password_expiry_interval', sa.BigInteger(), nullable=True),
        sa.Column('force_password_change', sa.Boolean(), nullable=True),
        sa.Column('last_reminder_at', sa.BigInteger(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_password_policy_user_email', 'password_policy', ['user_email'])

    # Create security_config table
    op.create_table('security_config',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('key', sa.String(), nullable=False),
        sa.Column('value', sa.String(), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=True),
        sa.Column('created_at', sa.BigInteger(), nullable=True),
        sa.Column('updated_at', sa.BigInteger(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('key')
    )


def downgrade() -> None:
    # Drop security_config table
    op.drop_table('security_config')
    
    # Drop password_policy table
    op.drop_index('ix_password_policy_user_email', table_name='password_policy')
    op.drop_table('password_policy')
    
    # Drop user_lock_status table
    op.drop_table('user_lock_status')
    
    # Drop login_attempts table
    op.drop_index('ix_login_attempts_timestamp', table_name='login_attempts')
    op.drop_index('ix_login_attempts_user_email', table_name='login_attempts')
    op.drop_table('login_attempts')
    
    # Drop user_ip_whitelist table
    op.drop_index('ix_user_ip_whitelist_user_id', table_name='user_ip_whitelist')
    op.drop_table('user_ip_whitelist')