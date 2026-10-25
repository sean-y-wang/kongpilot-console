-- A cluster-wide plan can contain several workspaces. Recovery graphs keep
-- their own entity workspace while retaining the original job/plan anchor.
ALTER TABLE configuration_recycle_graphs ADD COLUMN object_workspace_id uuid;
DROP TRIGGER configuration_recycle_graphs_immutable ON configuration_recycle_graphs;
UPDATE configuration_recycle_graphs SET object_workspace_id=workspace_id;
CREATE TRIGGER configuration_recycle_graphs_immutable BEFORE UPDATE OR DELETE ON configuration_recycle_graphs
 FOR EACH ROW EXECUTE FUNCTION m8_immutable();
ALTER TABLE configuration_recycle_graphs ALTER COLUMN object_workspace_id SET NOT NULL;
ALTER TABLE configuration_recycle_graphs ADD CONSTRAINT configuration_recycle_graphs_object_workspace_fk
 FOREIGN KEY(cluster_id,object_workspace_id) REFERENCES workspaces(cluster_id,id) ON DELETE RESTRICT;
ALTER TABLE configuration_recycle_graphs DROP CONSTRAINT configuration_recycle_graphs_execution_id_key;
ALTER TABLE configuration_recycle_graphs ADD CONSTRAINT configuration_recycle_graphs_execution_workspace_key
 UNIQUE(execution_id,object_workspace_id);
CREATE OR REPLACE FUNCTION m9_validate_configuration_recycle() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN
 IF TG_TABLE_NAME='configuration_recycle_graphs' THEN
  IF NOT EXISTS(SELECT 1 FROM configuration_executions e JOIN recycle_entries r ON r.cluster_id=e.cluster_id
   AND r.workspace_id=NEW.object_workspace_id AND r.actor_id=e.actor_id WHERE e.id=NEW.execution_id AND e.job_id=NEW.job_id
   AND e.plan_id=NEW.plan_id AND e.plan_revision=NEW.plan_revision AND e.plan_hash=NEW.plan_hash
   AND e.actor_id=NEW.actor_id AND e.state='executing' AND r.id=NEW.recycle_entry_id AND r.state='archived'
   AND(SELECT count(*) FROM recycle_nodes n WHERE n.entry_id=r.id AND n.affected)=NEW.delete_count)
  THEN RAISE EXCEPTION 'Composite recycle graph requires its real executing plan and complete workspace archive' USING ERRCODE='23503';END IF;
 ELSE
  IF NOT EXISTS(SELECT 1 FROM configuration_recycle_graphs g JOIN configuration_job_steps s
   ON s.cluster_id=g.cluster_id AND s.workspace_id=g.workspace_id AND s.job_id=g.job_id AND s.execution_id=g.execution_id
   AND s.object_workspace_id=g.object_workspace_id
   JOIN recycle_entries r ON r.cluster_id=s.cluster_id AND r.id=s.recycle_entry_id AND r.workspace_id=g.object_workspace_id
   JOIN mutation_operations m ON m.cluster_id=s.cluster_id AND m.id=s.receipt_operation_id AND m.workspace_id=g.object_workspace_id
   WHERE g.id=NEW.graph_id AND s.id=NEW.step_id AND s.state='succeeded' AND s.receipt_operation_id=NEW.operation_id
   AND r.id=NEW.recycle_entry_id AND r.mutation_id=m.id AND m.actor_id=g.actor_id AND m.state='succeeded' AND m.remote_completed)
  THEN RAISE EXCEPTION 'Composite membership requires an acknowledged native deletion receipt in its entity workspace' USING ERRCODE='23503';END IF;
 END IF;RETURN NEW;END;$$;
