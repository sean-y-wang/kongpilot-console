-- Rollback of SQL044 / KP-003 unknown-result disposition. Refuses while any disposition exists.
DO $$BEGIN
 IF EXISTS(SELECT 1 FROM workflow_unknown_result_dispositions)
 THEN RAISE EXCEPTION 'SQL044 rollback refused: unknown-result dispositions exist' USING ERRCODE='55000';END IF;
END;$$;
DROP TRIGGER IF EXISTS mutation_operations_unknown_result_guard ON mutation_operations;
DROP TRIGGER IF EXISTS workflow_executions_unknown_result_guard ON workflow_executions;
DROP FUNCTION IF EXISTS m11_unknown_result_state_guard();
DROP TRIGGER IF EXISTS workflow_unknown_result_disposition_guard ON workflow_unknown_result_dispositions;
DROP TRIGGER IF EXISTS workflow_unknown_result_dispositions_immutable ON workflow_unknown_result_dispositions;
DROP TRIGGER IF EXISTS workflow_unknown_result_dispositions_no_truncate ON workflow_unknown_result_dispositions;
DROP FUNCTION IF EXISTS m11_unknown_result_disposition_insert();
DROP FUNCTION IF EXISTS m11_validate_unknown_result_disposition(workflow_unknown_result_dispositions);
DROP TABLE IF EXISTS workflow_unknown_result_dispositions;
DELETE FROM schema_migrations WHERE name='044_m11_unknown_result_disposition.sql';
