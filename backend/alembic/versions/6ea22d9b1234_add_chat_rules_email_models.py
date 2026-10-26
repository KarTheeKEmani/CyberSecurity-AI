"""Add Chat Conversations, Detection Rules, Automation Executions, and Email Logs

Revision ID: 6ea22d9b1234
Revises: 5da11c8a819d
Create Date: 2026-10-09 10:50:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '6ea22d9b1234'
down_revision: Union[str, Sequence[str], None] = '5da11c8a819d'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. detection_rules
    op.create_table(
        'detection_rules',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('rule_type', sa.String(length=100), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('severity', sa.String(length=20), nullable=False),
        sa.Column('conditions', sa.JSON(), nullable=False),
        sa.Column('actions', sa.JSON(), nullable=False),
        sa.Column('enabled', sa.Boolean(), nullable=False),
        sa.Column('cooldown_minutes', sa.Integer(), nullable=False),
        sa.Column('last_triggered_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_detection_rules_id'), 'detection_rules', ['id'], unique=False)
    op.create_index(op.f('ix_detection_rules_name'), 'detection_rules', ['name'], unique=True)
    op.create_index(op.f('ix_detection_rules_rule_type'), 'detection_rules', ['rule_type'], unique=False)

    # 2. automation_executions
    op.create_table(
        'automation_executions',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('rule_id', sa.Integer(), nullable=True),
        sa.Column('rule_name', sa.String(length=255), nullable=False),
        sa.Column('trigger_event', sa.String(length=255), nullable=False),
        sa.Column('incident_id', sa.Integer(), nullable=True),
        sa.Column('status', sa.String(length=50), nullable=False),
        sa.Column('outcome_details', sa.JSON(), nullable=False),
        sa.Column('executed_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['incident_id'], ['incidents.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['rule_id'], ['detection_rules.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_automation_executions_id'), 'automation_executions', ['id'], unique=False)
    op.create_index(op.f('ix_automation_executions_incident_id'), 'automation_executions', ['incident_id'], unique=False)
    op.create_index(op.f('ix_automation_executions_rule_id'), 'automation_executions', ['rule_id'], unique=False)

    # 3. email_logs
    op.create_table(
        'email_logs',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('public_id', sa.String(length=50), nullable=False),
        sa.Column('rule_id', sa.Integer(), nullable=True),
        sa.Column('incident_id', sa.Integer(), nullable=True),
        sa.Column('recipient', sa.String(length=255), nullable=False),
        sa.Column('subject', sa.String(length=255), nullable=False),
        sa.Column('body_text', sa.Text(), nullable=False),
        sa.Column('status', sa.String(length=50), nullable=False),
        sa.Column('is_simulation', sa.Boolean(), nullable=False),
        sa.Column('provider_response', sa.Text(), nullable=True),
        sa.Column('retry_count', sa.Integer(), nullable=False),
        sa.Column('sent_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['incident_id'], ['incidents.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['rule_id'], ['detection_rules.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_email_logs_id'), 'email_logs', ['id'], unique=False)
    op.create_index(op.f('ix_email_logs_incident_id'), 'email_logs', ['incident_id'], unique=False)
    op.create_index(op.f('ix_email_logs_public_id'), 'email_logs', ['public_id'], unique=True)
    op.create_index(op.f('ix_email_logs_rule_id'), 'email_logs', ['rule_id'], unique=False)
    op.create_index(op.f('ix_email_logs_status'), 'email_logs', ['status'], unique=False)

    # 4. chat_conversations
    op.create_table(
        'chat_conversations',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('public_id', sa.String(length=50), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('incident_id', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['incident_id'], ['incidents.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_chat_conversations_id'), 'chat_conversations', ['id'], unique=False)
    op.create_index(op.f('ix_chat_conversations_incident_id'), 'chat_conversations', ['incident_id'], unique=False)
    op.create_index(op.f('ix_chat_conversations_public_id'), 'chat_conversations', ['public_id'], unique=True)
    op.create_index(op.f('ix_chat_conversations_user_id'), 'chat_conversations', ['user_id'], unique=False)

    # 5. chat_messages
    op.create_table(
        'chat_messages',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('conversation_id', sa.Integer(), nullable=False),
        sa.Column('role', sa.String(length=20), nullable=False),
        sa.Column('content', sa.Text(), nullable=False),
        sa.Column('evidence_sources', sa.JSON(), nullable=False),
        sa.Column('is_mock', sa.Boolean(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['conversation_id'], ['chat_conversations.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_chat_messages_conversation_id'), 'chat_messages', ['conversation_id'], unique=False)
    op.create_index(op.f('ix_chat_messages_id'), 'chat_messages', ['id'], unique=False)


def downgrade() -> None:
    op.drop_table('chat_messages')
    op.drop_table('chat_conversations')
    op.drop_table('email_logs')
    op.drop_table('automation_executions')
    op.drop_table('detection_rules')
