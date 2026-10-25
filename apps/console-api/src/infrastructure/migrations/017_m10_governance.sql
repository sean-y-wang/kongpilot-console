-- M10 readonly evidence, immutable policies and durable planner receipts.
-- No historical SQL000-016 checksum is changed. No table stores Kong DB rows.
CREATE TABLE governance_rules(
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,
 code text NOT NULL CHECK(code~'^[a-z][a-z0-9_.-]{0,95}$'),name text NOT NULL CHECK(length(name) BETWEEN 1 AND 160),
 owner_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,state text NOT NULL DEFAULT 'active' CHECK(state IN('active','deleted')),
 enabled boolean NOT NULL DEFAULT true,current_version integer NOT NULL DEFAULT 1 CHECK(current_version>0),revision integer NOT NULL DEFAULT 1 CHECK(revision>0),
 created_at timestamptz NOT NULL DEFAULT now(),updated_at timestamptz NOT NULL DEFAULT now(),deleted_at timestamptz,retention_until timestamptz,
 UNIQUE(cluster_id,workspace_id,id),UNIQUE(cluster_id,workspace_id,code),
 FOREIGN KEY(cluster_id,workspace_id) REFERENCES workspaces(cluster_id,id) ON DELETE RESTRICT,
 CHECK((state='deleted')=(deleted_at IS NOT NULL)),CHECK((deleted_at IS NULL)=(retention_until IS NULL))
);
CREATE TABLE governance_rule_versions(
 cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,rule_id uuid NOT NULL,version integer NOT NULL CHECK(version>0),
 content jsonb NOT NULL CHECK(jsonb_typeof(content)='object' AND octet_length(content::text)<=32768),content_hmac text NOT NULL CHECK(m8_hex64(content_hmac)),
 created_by uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,created_at timestamptz NOT NULL DEFAULT now(),PRIMARY KEY(cluster_id,workspace_id,rule_id,version),
 FOREIGN KEY(cluster_id,workspace_id,rule_id) REFERENCES governance_rules(cluster_id,workspace_id,id) ON DELETE RESTRICT
);
ALTER TABLE governance_rules ADD CONSTRAINT governance_rules_current_fk FOREIGN KEY(cluster_id,workspace_id,id,current_version)
 REFERENCES governance_rule_versions(cluster_id,workspace_id,rule_id,version) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;
CREATE TABLE governance_schedules(
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,name text NOT NULL CHECK(length(name) BETWEEN 1 AND 160),
 owner_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,transport_scope text NOT NULL CHECK(m8_hex64(transport_scope)),
 state text NOT NULL DEFAULT 'active' CHECK(state IN('active','paused','deleted')),current_version integer NOT NULL DEFAULT 1 CHECK(current_version>0),revision integer NOT NULL DEFAULT 1 CHECK(revision>0),
 next_run_at timestamptz NOT NULL,created_at timestamptz NOT NULL DEFAULT now(),updated_at timestamptz NOT NULL DEFAULT now(),deleted_at timestamptz,retention_until timestamptz,
 UNIQUE(cluster_id,workspace_id,id),UNIQUE(cluster_id,workspace_id,id,owner_user_id),
 FOREIGN KEY(cluster_id,workspace_id) REFERENCES workspaces(cluster_id,id) ON DELETE RESTRICT,
 CHECK((state='deleted')=(deleted_at IS NOT NULL)),CHECK((deleted_at IS NULL)=(retention_until IS NULL))
);
CREATE TABLE governance_schedule_versions(
 cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,schedule_id uuid NOT NULL,version integer NOT NULL CHECK(version>0),
 payload jsonb NOT NULL CHECK(jsonb_typeof(payload)='object' AND octet_length(payload::text)<=32768 AND payload->>'kind' IN('inspection','drift')),
 policy_hmac text NOT NULL CHECK(m8_hex64(policy_hmac)),created_by uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(cluster_id,workspace_id,schedule_id,version),FOREIGN KEY(cluster_id,workspace_id,schedule_id) REFERENCES governance_schedules(cluster_id,workspace_id,id) ON DELETE RESTRICT,
 CHECK((payload->>'kind'='drift')=(payload ? 'target'))
);
ALTER TABLE governance_schedules ADD CONSTRAINT governance_schedules_current_fk FOREIGN KEY(cluster_id,workspace_id,id,current_version)
 REFERENCES governance_schedule_versions(cluster_id,workspace_id,schedule_id,version) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;
CREATE TABLE governance_schedule_runs(
 id uuid PRIMARY KEY,cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,schedule_id uuid NOT NULL,schedule_version integer NOT NULL CHECK(schedule_version>0),
 scheduled_at timestamptz NOT NULL,creator_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,lease_generation integer NOT NULL DEFAULT 1 CHECK(lease_generation>0),lease_until timestamptz NOT NULL,
 state text NOT NULL DEFAULT 'running' CHECK(state IN('running','succeeded','incomplete','failed','paused_authority','uncertain')),run_id uuid,error_code text CHECK(error_code IS NULL OR error_code~'^[A-Z0-9_]{1,128}$'),
 created_at timestamptz NOT NULL DEFAULT now(),completed_at timestamptz,
 UNIQUE(schedule_id,schedule_version,scheduled_at),UNIQUE(cluster_id,workspace_id,id),UNIQUE(cluster_id,workspace_id,id,creator_id),
 FOREIGN KEY(cluster_id,workspace_id,schedule_id,schedule_version) REFERENCES governance_schedule_versions(cluster_id,workspace_id,schedule_id,version) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,workspace_id,schedule_id,creator_id) REFERENCES governance_schedules(cluster_id,workspace_id,id,owner_user_id) ON DELETE RESTRICT,
 CHECK((state='running')=(completed_at IS NULL)),CHECK(state NOT IN('succeeded','incomplete') OR run_id IS NOT NULL)
);
CREATE TABLE governance_runs(
 id uuid PRIMARY KEY,cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,actor_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
 origin_session_id uuid,origin_type text NOT NULL CHECK(origin_type IN('http','schedule')),schedule_run_id uuid,
 idempotency_key text NOT NULL CHECK(length(idempotency_key) BETWEEN 8 AND 128),request_hmac text NOT NULL CHECK(m8_hex64(request_hmac)),
 kind text NOT NULL CHECK(kind IN('inspection','comparison')),state text NOT NULL DEFAULT 'running' CHECK(state IN('running','succeeded','incomplete','failed','uncertain')),
 revision integer NOT NULL DEFAULT 1 CHECK(revision>0),input_secret text NOT NULL CHECK(m6_encrypted(input_secret)),error_code text CHECK(error_code IS NULL OR error_code~'^[A-Z0-9_]{1,128}$'),
 created_at timestamptz NOT NULL DEFAULT now(),completed_at timestamptz,
 UNIQUE(actor_id,idempotency_key),UNIQUE(cluster_id,workspace_id,id),UNIQUE(cluster_id,workspace_id,id,actor_id),
 FOREIGN KEY(cluster_id,workspace_id) REFERENCES workspaces(cluster_id,id) ON DELETE RESTRICT,
 FOREIGN KEY(origin_session_id,actor_id) REFERENCES auth_sessions(id,user_id) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,workspace_id,schedule_run_id,actor_id) REFERENCES governance_schedule_runs(cluster_id,workspace_id,id,creator_id) ON DELETE RESTRICT,
 CHECK((origin_type='http' AND origin_session_id IS NOT NULL AND schedule_run_id IS NULL) OR(origin_type='schedule' AND origin_session_id IS NULL AND schedule_run_id IS NOT NULL)),
 CHECK((state='running')=(completed_at IS NULL))
);
ALTER TABLE governance_schedule_runs ADD CONSTRAINT governance_schedule_runs_result_fk FOREIGN KEY(cluster_id,workspace_id,run_id,creator_id)
 REFERENCES governance_runs(cluster_id,workspace_id,id,actor_id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;
CREATE TABLE governance_reports(
 id uuid PRIMARY KEY,cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,run_id uuid NOT NULL UNIQUE,
 inventory_secret text NOT NULL CHECK(m6_encrypted(inventory_secret)),inventory_hmac text NOT NULL CHECK(m8_hex64(inventory_hmac)),engine_version text NOT NULL CHECK(length(engine_version) BETWEEN 1 AND 80),rules_hmac text NOT NULL CHECK(m8_hex64(rules_hmac)),
 quality text NOT NULL CHECK(quality IN('complete','partial','incomplete')),projection boolean NOT NULL,object_count integer NOT NULL CHECK(object_count BETWEEN 0 AND 10000),finding_count integer NOT NULL CHECK(finding_count BETWEEN 0 AND 50000),
 counts jsonb NOT NULL CHECK(jsonb_typeof(counts)='object' AND octet_length(counts::text)<=4096),coverage jsonb NOT NULL CHECK(jsonb_typeof(coverage)='object' AND octet_length(coverage::text)<=1048576),
 rule_results jsonb NOT NULL CHECK(jsonb_typeof(rule_results)='array' AND octet_length(rule_results::text)<=1048576),reason_codes text[] NOT NULL DEFAULT '{}' CHECK(cardinality(reason_codes)<=1000 AND array_position(reason_codes,NULL) IS NULL),
 observed_from timestamptz NOT NULL,observed_until timestamptz NOT NULL,created_at timestamptz NOT NULL DEFAULT now(),UNIQUE(cluster_id,workspace_id,id),
 FOREIGN KEY(cluster_id,workspace_id,run_id) REFERENCES governance_runs(cluster_id,workspace_id,id) ON DELETE RESTRICT,
 CHECK(observed_until>=observed_from),CHECK(NOT projection OR quality<>'complete')
);
CREATE TABLE governance_findings(
 id uuid PRIMARY KEY,cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,report_id uuid NOT NULL,finding_order integer NOT NULL CHECK(finding_order BETWEEN 1 AND 50000),
 rule_code text NOT NULL CHECK(length(rule_code) BETWEEN 1 AND 160),severity text NOT NULL CHECK(severity IN('error','warn','info')),
 entity_type text NOT NULL CHECK(entity_type IN('services','routes','consumers','plugins','upstreams','targets','certificates','ca_certificates','snis','cluster')),
 native_id uuid,parent_id uuid,object_workspace_id uuid,field_path text NOT NULL CHECK(length(field_path)<=1024),reason_code text NOT NULL CHECK(length(reason_code) BETWEEN 1 AND 160),description text NOT NULL CHECK(length(description)<=8192),
 safe_evidence jsonb NOT NULL CHECK(jsonb_typeof(safe_evidence)='object' AND octet_length(safe_evidence::text)<=32768),fix_actions jsonb NOT NULL CHECK(jsonb_typeof(fix_actions)='array' AND octet_length(fix_actions::text)<=8192),created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(report_id,finding_order),UNIQUE(cluster_id,workspace_id,report_id,id),UNIQUE(cluster_id,workspace_id,id),
 FOREIGN KEY(cluster_id,workspace_id,report_id) REFERENCES governance_reports(cluster_id,workspace_id,id) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,object_workspace_id) REFERENCES workspaces(cluster_id,id) ON DELETE RESTRICT,
 CHECK((entity_type='cluster')=(native_id IS NULL)),CHECK(parent_id IS NULL OR entity_type='targets')
);
CREATE TABLE governance_comparisons(
 id uuid PRIMARY KEY,cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,run_id uuid NOT NULL UNIQUE,target_cluster_id uuid NOT NULL,target_workspace_id uuid NOT NULL,
 source_inventory_secret text NOT NULL CHECK(m6_encrypted(source_inventory_secret)),target_inventory_secret text NOT NULL CHECK(m6_encrypted(target_inventory_secret)),source_inventory_hmac text NOT NULL CHECK(m8_hex64(source_inventory_hmac)),target_inventory_hmac text NOT NULL CHECK(m8_hex64(target_inventory_hmac)),
 policy jsonb NOT NULL CHECK(jsonb_typeof(policy)='object' AND octet_length(policy::text)<=32768),policy_hmac text NOT NULL CHECK(m8_hex64(policy_hmac)),quality text NOT NULL CHECK(quality IN('complete','incomplete')),
 counts jsonb NOT NULL CHECK(jsonb_typeof(counts)='object' AND octet_length(counts::text)<=8192),threshold integer NOT NULL CHECK(threshold BETWEEN 0 AND 10000),threshold_exceeded boolean NOT NULL,
 safe_changes jsonb NOT NULL CHECK(jsonb_typeof(safe_changes)='array' AND octet_length(safe_changes::text)<=16777216),created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(cluster_id,workspace_id,id),UNIQUE(cluster_id,workspace_id,id,target_cluster_id,target_workspace_id),
 FOREIGN KEY(cluster_id,workspace_id,run_id) REFERENCES governance_runs(cluster_id,workspace_id,id) ON DELETE RESTRICT,
 FOREIGN KEY(target_cluster_id,target_workspace_id) REFERENCES workspaces(cluster_id,id) ON DELETE RESTRICT,
 CHECK(quality='complete' OR NOT threshold_exceeded),CHECK(cluster_id<>target_cluster_id OR workspace_id<>target_workspace_id)
);
CREATE TABLE governance_promotions(
 id uuid PRIMARY KEY,cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,comparison_id uuid NOT NULL,target_cluster_id uuid NOT NULL,target_workspace_id uuid NOT NULL,
 actor_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,idempotency_key text NOT NULL CHECK(length(idempotency_key) BETWEEN 8 AND 128),request_hmac text NOT NULL CHECK(m8_hex64(request_hmac)),
 selection_secret text NOT NULL CHECK(m6_encrypted(selection_secret)),selection_hmac text NOT NULL CHECK(m8_hex64(selection_hmac)),source_inventory_hmac text NOT NULL CHECK(m8_hex64(source_inventory_hmac)),target_inventory_hmac text NOT NULL CHECK(m8_hex64(target_inventory_hmac)),
 state text NOT NULL DEFAULT 'planning' CHECK(state IN('planning','ready','blocked','uncertain')),configuration_job_id uuid,plan_id uuid,plan_revision integer,plan_hash text CHECK(plan_hash IS NULL OR m8_hex64(plan_hash)),error_code text CHECK(error_code IS NULL OR error_code~'^[A-Z0-9_]{1,128}$'),
 created_at timestamptz NOT NULL DEFAULT now(),updated_at timestamptz NOT NULL DEFAULT now(),UNIQUE(actor_id,idempotency_key),UNIQUE(cluster_id,workspace_id,id),
 UNIQUE(cluster_id,workspace_id,id,target_cluster_id,target_workspace_id,actor_id),
 FOREIGN KEY(cluster_id,workspace_id,comparison_id,target_cluster_id,target_workspace_id) REFERENCES governance_comparisons(cluster_id,workspace_id,id,target_cluster_id,target_workspace_id) ON DELETE RESTRICT,
 FOREIGN KEY(target_cluster_id,target_workspace_id,configuration_job_id,actor_id) REFERENCES configuration_jobs(cluster_id,workspace_id,id,actor_id) ON DELETE RESTRICT,
 FOREIGN KEY(target_cluster_id,target_workspace_id,plan_id,plan_revision,plan_hash) REFERENCES configuration_plan_versions(cluster_id,workspace_id,plan_id,plan_revision,plan_hash) ON DELETE RESTRICT,
 CHECK(num_nonnulls(plan_id,plan_revision,plan_hash) IN(0,3)),CHECK(state<>'ready' OR(configuration_job_id IS NOT NULL AND plan_id IS NOT NULL)),CHECK(plan_revision IS NULL OR plan_revision>0)
);
CREATE TABLE governance_metadata_requests(
 id uuid PRIMARY KEY,cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,actor_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
 resource_type text NOT NULL CHECK(resource_type IN('governance_rules','governance_schedules','entity_annotations')),resource_id uuid NOT NULL,operation text NOT NULL CHECK(operation IN('create','update','archive','restore')),
 idempotency_key text NOT NULL CHECK(length(idempotency_key) BETWEEN 8 AND 128),request_hmac text NOT NULL CHECK(m8_hex64(request_hmac)),payload_secret text NOT NULL CHECK(m6_encrypted(payload_secret)),payload_hmac text NOT NULL CHECK(m8_hex64(payload_hmac)),
 before_secret text CHECK(before_secret IS NULL OR m6_encrypted(before_secret)),before_hmac text NOT NULL CHECK(m8_hex64(before_hmac)),scope_secret text NOT NULL CHECK(m6_encrypted(scope_secret)),workflow_id uuid NOT NULL UNIQUE,created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(actor_id,idempotency_key),UNIQUE(cluster_id,workspace_id,id),UNIQUE(cluster_id,workspace_id,id,actor_id),
 FOREIGN KEY(cluster_id,workspace_id) REFERENCES workspaces(cluster_id,id) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,workspace_id,workflow_id) REFERENCES workflows(cluster_id,workspace_id,id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
 CHECK(resource_type<>'entity_annotations' OR operation IN('create','update'))
);
CREATE TABLE governance_fix_requests(
 id uuid PRIMARY KEY,cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,target_workspace_id uuid NOT NULL,report_id uuid NOT NULL,finding_id uuid NOT NULL,actor_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
 idempotency_key text NOT NULL CHECK(length(idempotency_key) BETWEEN 8 AND 128),request_hmac text NOT NULL CHECK(m8_hex64(request_hmac)),input_secret text NOT NULL CHECK(m6_encrypted(input_secret)),
 child_kind text CHECK(child_kind IS NULL OR child_kind IN('configuration','metadata')),child_request_hmac text CHECK(child_request_hmac IS NULL OR m8_hex64(child_request_hmac)),child_request_secret text CHECK(child_request_secret IS NULL OR m6_encrypted(child_request_secret)),
 state text NOT NULL DEFAULT 'planning' CHECK(state IN('planning','ready','blocked','uncertain')),configuration_job_id uuid,plan_id uuid,plan_revision integer,plan_hash text CHECK(plan_hash IS NULL OR m8_hex64(plan_hash)),
 metadata_operation_id uuid,metadata_domain text CHECK(metadata_domain IS NULL OR metadata_domain IN('iam','workflow')),workflow_id uuid,error_code text CHECK(error_code IS NULL OR error_code~'^[A-Z0-9_]{1,128}$'),
 created_at timestamptz NOT NULL DEFAULT now(),updated_at timestamptz NOT NULL DEFAULT now(),UNIQUE(actor_id,idempotency_key),UNIQUE(cluster_id,workspace_id,actor_id,idempotency_key),UNIQUE(cluster_id,workspace_id,id),
 FOREIGN KEY(cluster_id,workspace_id,report_id,finding_id) REFERENCES governance_findings(cluster_id,workspace_id,report_id,id) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,target_workspace_id) REFERENCES workspaces(cluster_id,id) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,target_workspace_id,configuration_job_id,actor_id) REFERENCES configuration_jobs(cluster_id,workspace_id,id,actor_id) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,target_workspace_id,plan_id,plan_revision,plan_hash) REFERENCES configuration_plan_versions(cluster_id,workspace_id,plan_id,plan_revision,plan_hash) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,target_workspace_id,workflow_id) REFERENCES workflows(cluster_id,workspace_id,id) ON DELETE RESTRICT,
 CHECK(num_nonnulls(plan_id,plan_revision,plan_hash) IN(0,3)),CHECK(plan_id IS NULL OR configuration_job_id IS NOT NULL),CHECK(plan_revision IS NULL OR plan_revision>0),
 CHECK((metadata_operation_id IS NULL)=(metadata_domain IS NULL)),CHECK((metadata_domain IS NOT DISTINCT FROM 'workflow')=(workflow_id IS NOT NULL)),
 CHECK(num_nonnulls(child_kind,child_request_hmac,child_request_secret) IN(0,3)),
 CHECK(configuration_job_id IS NULL OR metadata_operation_id IS NULL),CHECK(state<>'ready' OR(num_nonnulls(configuration_job_id,metadata_operation_id)=1 AND child_kind IS NOT NULL))
);
CREATE TABLE governance_fix_links(
 id uuid PRIMARY KEY,cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,target_workspace_id uuid NOT NULL,report_id uuid NOT NULL,finding_id uuid NOT NULL,actor_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
 idempotency_key text NOT NULL CHECK(length(idempotency_key) BETWEEN 8 AND 128),request_hmac text NOT NULL CHECK(m8_hex64(request_hmac)),configuration_job_id uuid,plan_id uuid,plan_revision integer,plan_hash text CHECK(plan_hash IS NULL OR m8_hex64(plan_hash)),
 metadata_operation_id uuid,metadata_domain text CHECK(metadata_domain IS NULL OR metadata_domain IN('iam','workflow')),created_at timestamptz NOT NULL DEFAULT now(),UNIQUE(actor_id,idempotency_key),
 FOREIGN KEY(cluster_id,workspace_id,report_id,finding_id) REFERENCES governance_findings(cluster_id,workspace_id,report_id,id) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,workspace_id,actor_id,idempotency_key) REFERENCES governance_fix_requests(cluster_id,workspace_id,actor_id,idempotency_key) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
 FOREIGN KEY(cluster_id,target_workspace_id) REFERENCES workspaces(cluster_id,id) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,target_workspace_id,configuration_job_id,actor_id) REFERENCES configuration_jobs(cluster_id,workspace_id,id,actor_id) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,target_workspace_id,plan_id,plan_revision,plan_hash) REFERENCES configuration_plan_versions(cluster_id,workspace_id,plan_id,plan_revision,plan_hash) ON DELETE RESTRICT,
 CHECK(num_nonnulls(configuration_job_id,metadata_operation_id)=1),CHECK(num_nonnulls(plan_id,plan_revision,plan_hash) IN(0,3)),CHECK(plan_id IS NULL OR configuration_job_id IS NOT NULL),CHECK((metadata_operation_id IS NULL)=(metadata_domain IS NULL))
);
CREATE TABLE governance_drift_states(
 cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,schedule_id uuid PRIMARY KEY,policy_hmac text NOT NULL CHECK(m8_hex64(policy_hmac)),last_comparison_id uuid NOT NULL,last_diff_hmac text NOT NULL CHECK(m8_hex64(last_diff_hmac)),
 threshold_exceeded boolean NOT NULL,revision integer NOT NULL DEFAULT 1 CHECK(revision>0),updated_at timestamptz NOT NULL DEFAULT now(),
 FOREIGN KEY(cluster_id,workspace_id,schedule_id) REFERENCES governance_schedules(cluster_id,workspace_id,id) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,workspace_id,last_comparison_id) REFERENCES governance_comparisons(cluster_id,workspace_id,id) ON DELETE RESTRICT
);
CREATE INDEX governance_runs_directory ON governance_runs(cluster_id,workspace_id,created_at DESC,id DESC);
CREATE INDEX governance_reports_directory ON governance_reports(cluster_id,workspace_id,created_at DESC,id DESC);
CREATE INDEX governance_comparisons_directory ON governance_comparisons(cluster_id,workspace_id,created_at DESC,id DESC);
CREATE INDEX governance_findings_directory ON governance_findings(cluster_id,workspace_id,report_id,finding_order);
CREATE INDEX governance_schedules_due ON governance_schedules(next_run_at,id) WHERE state='active';

CREATE FUNCTION m10_guard_mutable() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE oldj jsonb;newj jsonb;field text;identity_fields text[];
BEGIN
 IF TG_OP='DELETE' OR TG_OP='TRUNCATE' THEN RAISE EXCEPTION 'Governance facts and roots cannot be physically removed' USING ERRCODE='23514';END IF;
 oldj=to_jsonb(OLD);newj=to_jsonb(NEW);
 identity_fields=CASE TG_TABLE_NAME
  WHEN 'governance_rules' THEN ARRAY['id','cluster_id','workspace_id','code','owner_user_id','created_at']
  WHEN 'governance_schedules' THEN ARRAY['id','cluster_id','workspace_id','owner_user_id','transport_scope','created_at']
  WHEN 'governance_runs' THEN ARRAY['id','cluster_id','workspace_id','actor_id','origin_session_id','origin_type','schedule_run_id','idempotency_key','request_hmac','kind','input_secret','created_at']
  WHEN 'governance_schedule_runs' THEN ARRAY['id','cluster_id','workspace_id','schedule_id','schedule_version','scheduled_at','creator_id','lease_generation','lease_until','created_at']
  WHEN 'governance_promotions' THEN ARRAY['id','cluster_id','workspace_id','comparison_id','target_cluster_id','target_workspace_id','actor_id','idempotency_key','request_hmac','selection_secret','selection_hmac','source_inventory_hmac','target_inventory_hmac','created_at']
  WHEN 'governance_fix_requests' THEN ARRAY['id','cluster_id','workspace_id','target_workspace_id','report_id','finding_id','actor_id','idempotency_key','request_hmac','input_secret','created_at']
  WHEN 'governance_drift_states' THEN ARRAY['cluster_id','workspace_id','schedule_id'] END;
 FOREACH field IN ARRAY identity_fields LOOP IF oldj->field IS DISTINCT FROM newj->field THEN RAISE EXCEPTION 'Governance identity or frozen material cannot change' USING ERRCODE='23514';END IF;END LOOP;
 IF TG_TABLE_NAME IN('governance_rules','governance_schedules','governance_runs','governance_drift_states') THEN IF NEW.revision<>OLD.revision+1 THEN RAISE EXCEPTION 'Governance revision must advance exactly once' USING ERRCODE='23514';END IF;END IF;
 IF TG_TABLE_NAME IN('governance_rules','governance_schedules') THEN
  IF NEW.current_version NOT IN(OLD.current_version,OLD.current_version+1) THEN RAISE EXCEPTION 'Governance policy version must be monotonic' USING ERRCODE='23514';END IF;
  IF NEW.current_version=OLD.current_version AND(oldj-ARRAY['revision','updated_at','next_run_at']) IS DISTINCT FROM(newj-ARRAY['revision','updated_at','next_run_at']) THEN RAISE EXCEPTION 'Governance metadata changes require a new immutable version' USING ERRCODE='23514';END IF;
 ELSIF TG_TABLE_NAME IN('governance_runs','governance_schedule_runs') THEN
  IF OLD.state<>'running' OR NEW.state='running' THEN RAISE EXCEPTION 'Governance run terminal facts cannot be rewritten' USING ERRCODE='23514';END IF;
 ELSIF TG_TABLE_NAME IN('governance_promotions','governance_fix_requests') THEN
  IF TG_TABLE_NAME='governance_fix_requests' THEN
   IF OLD.child_kind IS NOT NULL AND ROW(NEW.child_kind,NEW.child_request_hmac,NEW.child_request_secret) IS DISTINCT FROM ROW(OLD.child_kind,OLD.child_request_hmac,OLD.child_request_secret) THEN RAISE EXCEPTION 'Fix child request descriptor is set once' USING ERRCODE='23514';END IF;
   IF OLD.state='planning' AND NEW.state='planning' AND OLD.child_kind IS NULL AND NEW.child_kind IS NOT NULL
     AND(oldj-ARRAY['child_kind','child_request_hmac','child_request_secret','updated_at']) IS NOT DISTINCT FROM(newj-ARRAY['child_kind','child_request_hmac','child_request_secret','updated_at']) THEN RETURN NEW;END IF;
  END IF;
  IF NOT(OLD.state='planning' AND NEW.state IN('ready','blocked','uncertain') OR OLD.state='uncertain' AND NEW.state='ready') THEN RAISE EXCEPTION 'Governance planner terminal receipt cannot replay' USING ERRCODE='23514';END IF;
 END IF;RETURN NEW;
END;$$;
CREATE FUNCTION m10_validate_result() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE r governance_reports%ROWTYPE;j governance_runs%ROWTYPE;s governance_schedule_runs%ROWTYPE;n bigint;first_order integer;last_order integer;c jsonb;wanted_report_id uuid;
BEGIN
 IF TG_TABLE_NAME IN('governance_reports','governance_findings') THEN
  IF TG_TABLE_NAME='governance_reports' THEN wanted_report_id=NEW.id;ELSE wanted_report_id=NEW.report_id;END IF;
  SELECT * INTO r FROM governance_reports WHERE id=wanted_report_id;
  SELECT * INTO j FROM governance_runs WHERE id=r.run_id AND cluster_id=r.cluster_id AND workspace_id=r.workspace_id;
  SELECT count(*),min(finding_order),max(finding_order),jsonb_build_object('error',count(*) FILTER(WHERE severity='error'),'warn',count(*) FILTER(WHERE severity='warn'),'info',count(*) FILTER(WHERE severity='info')) INTO n,first_order,last_order,c FROM governance_findings WHERE report_id=r.id;
  IF j.id IS NULL OR j.kind<>'inspection' OR j.state NOT IN('succeeded','incomplete') OR n<>r.finding_count OR(r.finding_count>0 AND(first_order<>1 OR last_order<>r.finding_count)) OR c<>r.counts THEN RAISE EXCEPTION 'Governance report must seal its complete scoped ordered findings and real run' USING ERRCODE='23514';END IF;
 ELSIF TG_TABLE_NAME='governance_comparisons' THEN
  SELECT * INTO j FROM governance_runs WHERE id=NEW.run_id AND cluster_id=NEW.cluster_id AND workspace_id=NEW.workspace_id;
  IF j.id IS NULL OR j.kind<>'comparison' OR j.state NOT IN('succeeded','incomplete') THEN RAISE EXCEPTION 'Comparison requires its actual scoped comparison run' USING ERRCODE='23514';END IF;
 ELSIF TG_TABLE_NAME='governance_runs' THEN
  IF NEW.state IN('succeeded','incomplete') AND NOT((NEW.kind='inspection' AND EXISTS(SELECT 1 FROM governance_reports WHERE run_id=NEW.id)) OR(NEW.kind='comparison' AND EXISTS(SELECT 1 FROM governance_comparisons WHERE run_id=NEW.id))) THEN RAISE EXCEPTION 'Successful governance run requires immutable analytical evidence' USING ERRCODE='23514';END IF;
 ELSE
  SELECT * INTO s FROM governance_schedule_runs WHERE id=NEW.id;
  IF s.run_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM governance_runs WHERE id=s.run_id AND cluster_id=s.cluster_id AND workspace_id=s.workspace_id AND actor_id=s.creator_id AND origin_type='schedule' AND schedule_run_id=s.id) THEN RAISE EXCEPTION 'Scheduled result must retain its exact occurrence and owner' USING ERRCODE='23503';END IF;
 END IF;RETURN NULL;
END;$$;
CREATE FUNCTION m10_validate_link() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE p governance_fix_requests%ROWTYPE;w workflows%ROWTYPE;c governance_comparisons%ROWTYPE;
BEGIN
 IF TG_TABLE_NAME='governance_fix_links' THEN
  SELECT * INTO p FROM governance_fix_requests WHERE cluster_id=NEW.cluster_id AND workspace_id=NEW.workspace_id AND actor_id=NEW.actor_id AND idempotency_key=NEW.idempotency_key;
  IF p.id IS NULL OR p.state<>'ready' OR p.target_workspace_id<>NEW.target_workspace_id OR p.report_id<>NEW.report_id OR p.finding_id<>NEW.finding_id OR p.request_hmac<>NEW.request_hmac
   OR p.configuration_job_id IS DISTINCT FROM NEW.configuration_job_id OR p.plan_id IS DISTINCT FROM NEW.plan_id OR p.plan_revision IS DISTINCT FROM NEW.plan_revision OR p.plan_hash IS DISTINCT FROM NEW.plan_hash
   OR p.metadata_operation_id IS DISTINCT FROM NEW.metadata_operation_id OR p.metadata_domain IS DISTINCT FROM NEW.metadata_domain THEN RAISE EXCEPTION 'Fix link must retain its actual ready parent and child receipt' USING ERRCODE='23503';END IF;
 ELSIF TG_TABLE_NAME='governance_fix_requests' THEN
  IF NOT EXISTS(SELECT 1 FROM governance_findings WHERE id=NEW.finding_id AND report_id=NEW.report_id AND cluster_id=NEW.cluster_id AND workspace_id=NEW.workspace_id AND coalesce(object_workspace_id,workspace_id)=NEW.target_workspace_id) THEN RAISE EXCEPTION 'Fix actual workspace must retain the sealed finding identity' USING ERRCODE='23503';END IF;
  IF NEW.state<>'ready' THEN RETURN NULL;END IF;
  IF NEW.configuration_job_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM configuration_jobs WHERE id=NEW.configuration_job_id AND cluster_id=NEW.cluster_id AND workspace_id=NEW.target_workspace_id AND actor_id=NEW.actor_id AND idempotency_key='governance-fix-'||NEW.id::text AND NEW.child_kind='configuration' AND kind='import' AND request_hmac=NEW.child_request_hmac) THEN RAISE EXCEPTION 'Fix native plan requires its exact deterministic child job and request' USING ERRCODE='23503';END IF;
  IF NEW.metadata_domain='iam' AND NOT EXISTS(SELECT 1 FROM iam_operations i JOIN governance_findings f ON f.cluster_id=i.cluster_id AND f.id=NEW.finding_id WHERE i.id=NEW.metadata_operation_id AND i.cluster_id=NEW.cluster_id AND i.workspace_id=NEW.target_workspace_id AND i.actor_id=NEW.actor_id AND i.idempotency_key='governance-fix-'||NEW.id::text AND i.module='annotations' AND i.target_id=f.native_id AND i.state='succeeded' AND i.remote_completed AND NEW.child_kind='metadata') THEN RAISE EXCEPTION 'Fix IAM receipt is foreign or not complete' USING ERRCODE='23503';END IF;
  IF NEW.metadata_domain='workflow' AND NOT EXISTS(SELECT 1 FROM governance_metadata_requests WHERE id=NEW.metadata_operation_id AND cluster_id=NEW.cluster_id AND workspace_id=NEW.target_workspace_id AND actor_id=NEW.actor_id AND workflow_id=NEW.workflow_id AND idempotency_key='governance-fix-'||NEW.id::text AND resource_type='entity_annotations' AND NEW.child_kind='metadata' AND request_hmac=NEW.child_request_hmac) THEN RAISE EXCEPTION 'Fix approval receipt is foreign' USING ERRCODE='23503';END IF;
 ELSIF TG_TABLE_NAME='governance_promotions' THEN
  SELECT * INTO c FROM governance_comparisons WHERE id=NEW.comparison_id AND cluster_id=NEW.cluster_id AND workspace_id=NEW.workspace_id;
  IF c.id IS NULL OR c.source_inventory_hmac<>NEW.source_inventory_hmac OR c.target_inventory_hmac<>NEW.target_inventory_hmac THEN RAISE EXCEPTION 'Promotion material must bind its actual dual-scope comparison' USING ERRCODE='23503';END IF;
  IF NEW.state='ready' AND NOT EXISTS(SELECT 1 FROM configuration_jobs j JOIN configuration_plan_versions v ON v.cluster_id=j.cluster_id AND v.workspace_id=j.workspace_id AND v.source_job_id=j.id WHERE j.id=NEW.configuration_job_id AND j.cluster_id=NEW.target_cluster_id AND j.workspace_id=NEW.target_workspace_id AND j.actor_id=NEW.actor_id AND v.plan_id=NEW.plan_id AND v.plan_revision=NEW.plan_revision AND v.plan_hash=NEW.plan_hash) THEN RAISE EXCEPTION 'Promotion ready receipt must link its actual target import plan' USING ERRCODE='23503';END IF;
 ELSIF TG_TABLE_NAME='governance_drift_states' THEN
  SELECT * INTO c FROM governance_comparisons WHERE id=NEW.last_comparison_id AND cluster_id=NEW.cluster_id AND workspace_id=NEW.workspace_id;
  IF c.id IS NULL OR c.quality<>'complete' OR c.policy_hmac<>NEW.policy_hmac OR c.threshold_exceeded<>NEW.threshold_exceeded OR NOT EXISTS(SELECT 1 FROM governance_schedules g JOIN governance_schedule_versions v ON v.cluster_id=g.cluster_id AND v.workspace_id=g.workspace_id AND v.schedule_id=g.id AND v.version=g.current_version WHERE g.id=NEW.schedule_id AND g.cluster_id=NEW.cluster_id AND g.workspace_id=NEW.workspace_id AND v.payload->>'kind'='drift' AND v.payload->'target'->>'clusterId'=c.target_cluster_id::text AND v.payload->'target'->>'workspaceId'=c.target_workspace_id::text) THEN RAISE EXCEPTION 'Drift baseline requires its real complete paired comparison' USING ERRCODE='23503';END IF;
 END IF;RETURN NULL;
END;$$;
DO $$DECLARE tab text;BEGIN
 FOREACH tab IN ARRAY ARRAY['governance_rule_versions','governance_schedule_versions','governance_reports','governance_findings','governance_comparisons','governance_fix_links','governance_metadata_requests'] LOOP
  EXECUTE format('CREATE TRIGGER %I BEFORE UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION m8_immutable()',tab||'_immutable',tab);
  EXECUTE format('CREATE TRIGGER %I BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION m8_immutable()',tab||'_no_truncate',tab);
 END LOOP;
 FOREACH tab IN ARRAY ARRAY['governance_rules','governance_schedules','governance_runs','governance_schedule_runs','governance_promotions','governance_fix_requests','governance_drift_states'] LOOP
  EXECUTE format('CREATE TRIGGER %I BEFORE UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION m10_guard_mutable()',tab||'_guard',tab);
  EXECUTE format('CREATE TRIGGER %I BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION m10_guard_mutable()',tab||'_no_truncate',tab);
 END LOOP;
 FOREACH tab IN ARRAY ARRAY['governance_reports','governance_findings','governance_comparisons','governance_runs','governance_schedule_runs'] LOOP
  EXECUTE format('CREATE CONSTRAINT TRIGGER %I AFTER INSERT OR UPDATE ON %I DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m10_validate_result()',tab||'_sealed_result',tab);
 END LOOP;
 FOREACH tab IN ARRAY ARRAY['governance_fix_links','governance_fix_requests','governance_promotions','governance_drift_states'] LOOP
  EXECUTE format('CREATE CONSTRAINT TRIGGER %I AFTER INSERT OR UPDATE ON %I DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m10_validate_link()',tab||'_typed_link',tab);
 END LOOP;
END;$$;

ALTER TABLE workflow_definitions DROP CONSTRAINT workflow_definitions_kind_check;
ALTER TABLE workflow_definitions ADD CONSTRAINT workflow_definitions_kind_check CHECK(kind IN('portal-publication','portal-credential-issue','portal-credential-rotate','portal-credential-revoke','portal-developer-review','portal-metadata','native-change','event-metadata','configuration_v2','configuration-metadata','toolbox-operation','workspace-migration','governance-metadata'));
ALTER TABLE workflows DROP CONSTRAINT workflows_kind_check;
ALTER TABLE workflows ADD CONSTRAINT workflows_kind_check CHECK(kind IN('portal-publication','portal-credential-issue','portal-credential-rotate','portal-credential-revoke','portal-developer-review','portal-metadata','native-change','event-metadata','configuration_v2','configuration-metadata','toolbox-operation','workspace-migration','governance-metadata'));
ALTER TABLE workflows DROP CONSTRAINT workflows_subject_type_check;
ALTER TABLE workflows ADD CONSTRAINT workflows_subject_type_check CHECK(subject_type IN('portal_settings','portal_developers','portal_applications','portal_publications','portal_content','portal_application_grants','notification_channels','event_subscriptions','event_deliveries','configuration_jobs','config_snapshots','config_snapshot_schedules','configuration_gitops_runs','toolbox_operations','workspace_migration_plans','governance_metadata_requests'));
-- Preserve the exact historical validator and its OID. The new kind has a
-- separate fixed reciprocal validator; every other historical branch remains.
DO $m10$ DECLARE definition text;BEGIN
 definition=pg_get_functiondef('m6_validate_workflow_subject()'::regprocedure);
 definition=regexp_replace(definition,'\mBEGIN\M',E'BEGIN\n IF NEW.kind=''governance-metadata'' THEN RETURN NULL;END IF;');
 EXECUTE definition;
END;$m10$;
CREATE FUNCTION m10_validate_metadata_workflow() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE w workflows%ROWTYPE;i governance_metadata_requests%ROWTYPE;
BEGIN
 IF TG_TABLE_NAME='workflows' THEN
  w=NEW;IF w.kind<>'governance-metadata' AND w.subject_type<>'governance_metadata_requests' THEN RETURN NULL;END IF;
  SELECT * INTO i FROM governance_metadata_requests WHERE id=w.subject_id AND cluster_id=w.cluster_id AND workspace_id=w.workspace_id;
 ELSIF TG_TABLE_NAME='governance_metadata_requests' THEN
  i=NEW;SELECT * INTO w FROM workflows WHERE id=i.workflow_id AND cluster_id=i.cluster_id AND workspace_id=i.workspace_id;
 ELSE
  IF NEW.handler IS DISTINCT FROM 'governance.metadata' AND NEW.entity_type<>'governance_metadata_requests' THEN RETURN NULL;END IF;
  SELECT * INTO w FROM workflows WHERE id=NEW.workflow_id AND cluster_id=NEW.cluster_id AND workspace_id=NEW.workspace_id;
  SELECT * INTO i FROM governance_metadata_requests WHERE id=NEW.entity_id AND cluster_id=NEW.cluster_id AND workspace_id=NEW.workspace_id;
 END IF;
 IF i.id IS NULL OR w.id IS NULL OR w.kind<>'governance-metadata' OR w.subject_type<>'governance_metadata_requests' OR w.subject_id<>i.id OR i.workflow_id<>w.id
  OR w.requester_type<>'console' OR w.requester_user_id<>i.actor_id OR w.execution_mode<>'approval' OR NOT w.approval_required OR w.idempotency_key<>i.idempotency_key
  OR(SELECT count(*) FROM workflow_steps WHERE workflow_id=w.id AND plan_revision=w.plan_revision)<>1
  OR NOT EXISTS(SELECT 1 FROM workflow_steps WHERE cluster_id=i.cluster_id AND workspace_id=i.workspace_id AND workflow_id=w.id AND plan_revision=w.plan_revision AND plan_hash=w.plan_hash
   AND kind='metadata' AND handler='governance.metadata' AND entity_type='governance_metadata_requests' AND entity_id=i.id AND step_key='governance.metadata' AND step_order=1
   AND operation_id IS NULL AND native_requests='[]'::jsonb AND parent_id IS NULL AND credential_kind IS NULL AND dependencies='{}'::uuid[]
   AND metadata_before_hmac=i.before_hmac AND permission_action=CASE WHEN i.operation='archive' THEN 'delete' ELSE 'write' END)
  OR NOT EXISTS(SELECT 1 FROM workflow_versions WHERE cluster_id=w.cluster_id AND workspace_id=w.workspace_id AND workflow_id=w.id AND plan_revision=w.plan_revision AND plan_hash=w.plan_hash AND native_request_count=0 AND step_count=1 AND created_by=i.actor_id)
  THEN RAISE EXCEPTION 'Governance metadata workflow must retain its fixed scope owner intent handler and no native authority' USING ERRCODE='23514';END IF;RETURN NULL;
END;$$;
CREATE CONSTRAINT TRIGGER workflows_governance_intent AFTER INSERT OR UPDATE ON workflows DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m10_validate_metadata_workflow();
CREATE CONSTRAINT TRIGGER governance_metadata_requests_workflow AFTER INSERT ON governance_metadata_requests DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m10_validate_metadata_workflow();
CREATE CONSTRAINT TRIGGER workflow_steps_governance_intent AFTER INSERT OR UPDATE ON workflow_steps DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m10_validate_metadata_workflow();
