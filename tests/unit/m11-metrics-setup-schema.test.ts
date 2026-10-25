import {readFileSync} from 'node:fs';
import {describe,expect,it} from 'vitest';
const read=(name:string)=>readFileSync(new URL('../../apps/console-api/src/infrastructure/migrations/'+name,import.meta.url),'utf8'),sql=read('032_m11_metrics_setup_approvals.sql'),code=sql.replace(/--[^\n]*/g,'');
const old=read('030_m11_iam_metadata_approvals.sql');
/** SOURCE assertions. They do not claim real PostgreSQL compilation, role
 * privileges or deferred-trigger execution; Root performs a rollback trial. */
describe('SQL032 exact monitoring SOURCE graph (console only)',()=>{
 it('extends all SQL030 kind/subject allowlist members without dropping any old capability',()=>{for(const match of old.matchAll(/CHECK\((?:kind|subject_type) IN\(([^)]*)\)\)/g))for(const member of match[1].matchAll(/'([^']+)'/g))expect(code).toContain(`'${member[1]}'`);
  expect(code.match(/'metrics-setup'/g)?.length).toBeGreaterThan(2);expect(code).toContain("'metrics_setup_requests'");});
 it('grants no authority and touches no historical rows, migrations or triggers',()=>{expect(code).not.toMatch(/\b(?:INSERT INTO|UPDATE|DELETE FROM|TRUNCATE)\s+(?:workflows|workflow_versions|workflow_steps|workflow_executions|mutation_operations|metrics_settings|metrics_credentials)\b/i);
  expect(code).not.toMatch(/\bGRANT\b|SECURITY DEFINER|DISABLE TRIGGER|session_replication_role|current_setting|set_config|SET ROLE|kong_database|kong_db/i);
  expect(code).not.toMatch(/DROP\s+(?:TRIGGER|FUNCTION|TABLE)/i);});
 it('delegates only the new kind while retaining SQL030 and every original m6 subject branch',()=>{expect(code).toContain("pg_get_functiondef('m6_validate_workflow_subject()'::regprocedure)");
  expect(code).toContain("IF NEW.kind=''metrics-setup'' THEN RETURN NULL;END IF;");expect(code).not.toContain("IF NEW.kind=''iam-metadata'' THEN");});
 it.each(['metrics_setup_intents','metrics_setup_plugin_material','metrics_setup_requests','metrics_setup_completion_facts'])('retains append-only %s facts and strict relations',table=>{expect(code).toContain('CREATE TABLE '+table);
  expect(code).toContain(`'${table}'`);expect(code).toContain('BEFORE UPDATE OR DELETE ON %I');expect(code).toContain('BEFORE TRUNCATE ON %I');expect(code).toContain('REVOKE UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER ON %I FROM PUBLIC');});
 it.each(['s.user_id<>u.id','s.revoked_at IS NOT NULL','s.credential_epoch<>u.credential_epoch','NEW.credential_epoch<>u.credential_epoch','NEW.expires_at>s.expires_at',
  "NEW.permission_version IS DISTINCT FROM (u.id::text||':'||u.permissions_epoch::text||':'||epoch::text)","c.execution_mode<>'approval'","NOT wid.is_default","ds.type<>'prometheus'",'ds.revision<>NEW.source_revision'])('author cannot bypass real identity or source condition %s',condition=>{expect(code).toContain(condition);});
 it('requires existing current collector ingestion generation, never creates or rotates it',()=>{expect(code).toContain("purpose='collector_ingest' AND audience='collector' AND status='active'");expect(code).toContain("CHECK(mode<>'collector' OR credential_generation>0)");
  expect(code).not.toMatch(/token_secret|http_endpoint|\bpassword\b|base_url|auth_secret|UPDATE metrics_credentials|INSERT INTO metrics_credentials/);});
 it('requires the whole material manifest at prepare transaction commit and exactly 1/2 native requests',()=>{expect(code).toContain("count_plugins<>(CASE WHEN i.mode='collector' THEN 2 ELSE 1 END)");
  expect(code).toContain('metrics_setup_intent_material AFTER INSERT');expect(code).toContain('metrics_setup_plugin_material_complete AFTER INSERT');expect(code).toContain('DEFERRABLE INITIALLY DEFERRED');
  expect(code).toContain('jsonb_array_length(s.native_requests)<>1');expect(code).toContain("s.mutation_idempotency_key IS DISTINCT FROM ('metrics-approved-'||i.id::text||'-'||p.name)");});
 it.each(['r.material_hmac<>i.material_hmac','r.request_hmac<>i.request_hmac','w.plan_revision<>1','w.approval_format<>2',"s.entity_type<>'plugins'",'s.entity_id IS DISTINCT FROM p.native_id',
  's.before_fingerprint<>p.before_hmac','s.mutation_payload_hmac<>p.payload_hmac',"s.handler IS DISTINCT FROM 'metrics.setup.settings'",'s.metadata_revision<>i.settings_revision'])('does not waive exact plan binding %s',condition=>{expect(code).toContain(condition);});
 it('requires original Native operation tuple and actual acknowledged outcomes before terminal settings',()=>{expect(code).toContain("m.state='succeeded' AND m.remote_started AND m.remote_completed");expect(code).toContain('m.workflow_execution_id=e.id AND m.workflow_step_id=ns.id');
  expect(code).toContain('m.workflow_plan_revision=1 AND m.workflow_plan_hash=NEW.plan_hash');expect(code).toContain('observed IS DISTINCT FROM NEW.native_operation_ids');
  expect(code).toContain("w.state<>'succeeded' OR e.state<>'succeeded' OR s.state<>'succeeded'");expect(code).toContain('settings.revision<>NEW.after_settings_revision');expect(code).toContain('NEW.credential_generation<>i.credential_generation');});
 it('retains zero-to-two bootstrap revision semantics instead of a fictitious revision one',()=>{expect(code).toContain('CHECK(after_settings_revision=CASE WHEN before_settings_revision=0 THEN 2 ELSE before_settings_revision+1 END)');});
 it('keeps settings success dependent on committed metadata and current source/generation',()=>{expect(code).toContain('metrics_setup_completion_exact AFTER INSERT ON metrics_setup_completion_facts DEFERRABLE INITIALLY DEFERRED');
  expect(code).toContain("s.kind<>'metadata' OR s.handler IS DISTINCT FROM 'metrics.setup.settings'");expect(code).toContain('settings.active_source_id IS DISTINCT FROM i.source_id');expect(code).toContain('ds.revision<>i.source_revision');
  expect(code).toContain('e.approval_set_id IS DISTINCT FROM w.approval_set_id OR e.approval_set_hmac IS DISTINCT FROM w.approval_set_hmac');});
});
