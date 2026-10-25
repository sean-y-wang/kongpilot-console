-- Whole delete graphs are sealed before the first native packet. Individual
-- immutable configuration-step receipts remain the source of execution facts.
CREATE TABLE configuration_recycle_graphs (
 id uuid PRIMARY KEY,cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,job_id uuid NOT NULL,execution_id uuid NOT NULL,
 plan_id uuid NOT NULL,plan_revision integer NOT NULL,plan_hash text NOT NULL CHECK(m8_hex64(plan_hash)),
 actor_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,recycle_entry_id uuid NOT NULL,
 graph_hmac text NOT NULL CHECK(m8_hex64(graph_hmac)),delete_count integer NOT NULL CHECK(delete_count BETWEEN 2 AND 10000),
 created_at timestamptz NOT NULL DEFAULT now(),UNIQUE(execution_id),UNIQUE(cluster_id,workspace_id,id),
 UNIQUE(cluster_id,recycle_entry_id),
 FOREIGN KEY(cluster_id,workspace_id,execution_id,job_id,plan_revision,plan_hash)
 REFERENCES configuration_executions(cluster_id,workspace_id,id,job_id,plan_revision,plan_hash) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,recycle_entry_id) REFERENCES recycle_entries(cluster_id,id) ON DELETE RESTRICT
);
CREATE TABLE configuration_recycle_components (
 cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,graph_id uuid NOT NULL,step_id uuid NOT NULL,
 recycle_entry_id uuid NOT NULL,operation_id uuid NOT NULL,created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(cluster_id,recycle_entry_id),UNIQUE(step_id),
 FOREIGN KEY(cluster_id,workspace_id,graph_id) REFERENCES configuration_recycle_graphs(cluster_id,workspace_id,id) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,workspace_id,step_id) REFERENCES configuration_job_steps(cluster_id,workspace_id,id) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,recycle_entry_id) REFERENCES recycle_entries(cluster_id,id) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,operation_id) REFERENCES mutation_operations(cluster_id,id) ON DELETE RESTRICT
);
CREATE FUNCTION m9_validate_configuration_recycle() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN
 IF TG_TABLE_NAME='configuration_recycle_graphs' THEN
  IF NOT EXISTS(SELECT 1 FROM configuration_executions e JOIN recycle_entries r ON r.cluster_id=e.cluster_id
   AND r.workspace_id=e.workspace_id AND r.actor_id=e.actor_id WHERE e.id=NEW.execution_id AND e.job_id=NEW.job_id
   AND e.plan_id=NEW.plan_id AND e.plan_revision=NEW.plan_revision AND e.plan_hash=NEW.plan_hash
   AND e.actor_id=NEW.actor_id AND e.state='executing' AND r.id=NEW.recycle_entry_id AND r.state='archived'
   AND(SELECT count(*) FROM recycle_nodes n WHERE n.entry_id=r.id AND n.affected)=NEW.delete_count)
  THEN RAISE EXCEPTION 'Composite recycle graph requires its real executing plan and complete archive' USING ERRCODE='23503';END IF;
 ELSE
  IF NOT EXISTS(SELECT 1 FROM configuration_recycle_graphs g JOIN configuration_job_steps s
   ON s.cluster_id=g.cluster_id AND s.workspace_id=g.workspace_id AND s.job_id=g.job_id AND s.execution_id=g.execution_id
   JOIN recycle_entries r ON r.cluster_id=s.cluster_id AND r.id=s.recycle_entry_id
   JOIN mutation_operations m ON m.cluster_id=s.cluster_id AND m.id=s.receipt_operation_id
   WHERE g.id=NEW.graph_id AND s.id=NEW.step_id AND s.state='succeeded' AND s.receipt_operation_id=NEW.operation_id
   AND r.id=NEW.recycle_entry_id AND r.mutation_id=m.id AND m.actor_id=g.actor_id AND m.state='succeeded' AND m.remote_completed)
  THEN RAISE EXCEPTION 'Composite membership requires an acknowledged native deletion receipt' USING ERRCODE='23503';END IF;
 END IF;RETURN NEW;END;$$;
DO $$DECLARE tab text;BEGIN
 FOREACH tab IN ARRAY ARRAY['configuration_recycle_graphs','configuration_recycle_components'] LOOP
  EXECUTE format('CREATE TRIGGER %I BEFORE INSERT ON %I FOR EACH ROW EXECUTE FUNCTION m9_validate_configuration_recycle()',tab||'_origin',tab);
  EXECUTE format('CREATE TRIGGER %I BEFORE UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION m8_immutable()',tab||'_immutable',tab);
  EXECUTE format('CREATE TRIGGER %I BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION m8_immutable()',tab||'_no_truncate',tab);
 END LOOP;
END;$$;
