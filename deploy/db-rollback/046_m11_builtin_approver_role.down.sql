-- Rollback of SQL046. Refuses while the built-in approver role is bound.
DO $$BEGIN
 IF EXISTS(SELECT 1 FROM user_role_bindings b JOIN roles r ON r.id=b.role_id WHERE r.builtin_kind='approver')
  OR EXISTS(SELECT 1 FROM team_role_bindings b JOIN roles r ON r.id=b.role_id WHERE r.builtin_kind='approver')
 THEN RAISE EXCEPTION 'SQL046 rollback refused: approver role is bound' USING ERRCODE='55000';END IF;
END;$$;
-- Physical delete is otherwise forbidden; the operator rollback is the only exception.
ALTER TABLE role_permissions DISABLE TRIGGER role_permissions_soft_delete_only;
ALTER TABLE roles DISABLE TRIGGER roles_soft_delete_only;
DELETE FROM role_permissions WHERE role_id IN(SELECT id FROM roles WHERE builtin_kind='approver');
DELETE FROM roles WHERE builtin_kind='approver';
ALTER TABLE role_permissions ENABLE TRIGGER role_permissions_soft_delete_only;
ALTER TABLE roles ENABLE TRIGGER roles_soft_delete_only;
ALTER TABLE roles DROP CONSTRAINT roles_builtin_kind_check;
ALTER TABLE roles DROP CONSTRAINT roles_builtin_scope_check;
ALTER TABLE roles ADD CONSTRAINT roles_builtin_kind_check
 CHECK(builtin_kind IN ('super-admin','admin','read-only','workspace-super-admin','workspace-admin','workspace-read-only'));
ALTER TABLE roles ADD CONSTRAINT roles_builtin_scope_check
 CHECK(builtin_kind IS NULL OR (builtin_kind IN ('super-admin','admin','read-only') AND cluster_id IS NULL AND workspace_id IS NULL)
  OR(builtin_kind IN ('workspace-super-admin','workspace-admin','workspace-read-only') AND cluster_id IS NOT NULL AND workspace_id IS NOT NULL));
