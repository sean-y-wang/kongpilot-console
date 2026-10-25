-- SQL046: built-in global "approver" role (P2, approval-deadlock prevention).
-- Read + approve on every console module except secrets; no write/delete.
-- Approval itself still enforces requester!=approver and all stage policy.
-- Protected like the other built-ins (cannot be edited/deleted via API).
DO $s046$
DECLARE c record; n integer := 0;
BEGIN
 FOR c IN SELECT conname, pg_get_constraintdef(oid) AS definition FROM pg_constraint
  WHERE conrelid='roles'::regclass AND contype='c' AND pg_get_constraintdef(oid) LIKE '%builtin_kind%' LOOP
  IF c.definition LIKE '%''read-only''%' AND c.definition NOT LIKE '%builtin_kind = code%' AND c.definition NOT LIKE '%protected%' THEN
   EXECUTE format('ALTER TABLE roles DROP CONSTRAINT %I', c.conname); n := n + 1;
  END IF;
 END LOOP;
 IF n <> 2 THEN RAISE EXCEPTION 'SQL046 expected 2 builtin_kind CHECK constraints, found %', n USING ERRCODE='55000'; END IF;
END;$s046$;
ALTER TABLE roles ADD CONSTRAINT roles_builtin_kind_check
 CHECK(builtin_kind IN ('super-admin','admin','read-only','approver','workspace-super-admin','workspace-admin','workspace-read-only'));
ALTER TABLE roles ADD CONSTRAINT roles_builtin_scope_check
 CHECK(builtin_kind IS NULL OR (builtin_kind IN ('super-admin','admin','read-only','approver') AND cluster_id IS NULL AND workspace_id IS NULL)
  OR(builtin_kind IN ('workspace-super-admin','workspace-admin','workspace-read-only') AND cluster_id IS NOT NULL AND workspace_id IS NOT NULL));

DO $s046s$
DECLARE rid uuid; mod text; act text;
 mods text[] := ARRAY['services','routes','consumers','plugins','upstreams','certificates','ca_certificates','snis','clusters','data-sources','workspaces','annotations','overview','mutations','recycle-bin','users','teams','roles','permissions','monitoring','portal','developers','applications','audit','events','notifications','snapshots','gitops','toolbox','batches','drafts','governance','lint','drift','promote','workflows'];
BEGIN
 IF EXISTS(SELECT 1 FROM roles WHERE cluster_id IS NULL AND workspace_id IS NULL AND code='approver') THEN
  RAISE EXCEPTION 'SQL046 refused: a global role with code "approver" already exists; rename it first' USING ERRCODE='55000';
 END IF;
 INSERT INTO roles(code,name,description,builtin_kind,protected)
  VALUES('approver','approver','Built-in: read and approve on all console modules; no write/delete/secrets.','approver',true) RETURNING id INTO rid;
 FOREACH mod IN ARRAY mods LOOP
  FOREACH act IN ARRAY ARRAY['read','approve'] LOOP
   INSERT INTO role_permissions(role_id,module,action,scope_type) VALUES(rid,mod,act,'global');
  END LOOP;
 END LOOP;
END;$s046s$;
