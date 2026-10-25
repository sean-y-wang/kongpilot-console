-- SQL048: approver in-app notifications are default-on. A row here only
-- records a user's explicit per-workspace choice; absence means enabled.
-- Owner-only writes go through NotificationOperationsService (audited,
-- idempotent). The fan-out reader treats approval_requests_enabled=false as
-- an opt-out and never widens who may approve or read a workflow.
CREATE TABLE IF NOT EXISTS user_notification_approval_settings (
 user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
 cluster_id uuid NOT NULL,
 workspace_id uuid NOT NULL,
 approval_requests_enabled boolean NOT NULL,
 revision integer NOT NULL DEFAULT 1 CHECK(revision>0),
 created_at timestamptz NOT NULL DEFAULT now(),
 updated_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(user_id,cluster_id,workspace_id),
 FOREIGN KEY(cluster_id,workspace_id) REFERENCES workspaces(cluster_id,id) ON DELETE RESTRICT
);
CREATE INDEX IF NOT EXISTS user_notification_approval_settings_scope ON user_notification_approval_settings(cluster_id,workspace_id) WHERE NOT approval_requests_enabled;
