-- Rollback of SQL048: drops explicit approver-notification opt-outs. Only use
-- together with rolling back the application release (the fan-out reader
-- queries this table).
DROP TABLE IF EXISTS user_notification_approval_settings;
