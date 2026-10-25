import {readFileSync} from 'node:fs';
import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {randomUUID} from 'node:crypto';
import {workflowScheduledFixture} from './helpers/workflow-scheduled-fixture';
import {assertWorkflowScheduledPlan,workflowSchedulePlanSeal} from '../../apps/console-api/src/modules/workflows/workflow-schedule.repository';
beforeEach(()=>vi.stubEnv('CONSOLE_ENCRYPTION_KEY','ae'.repeat(32)));afterEach(()=>vi.unstubAllEnvs());

/** SOURCE schema contracts only. PostgreSQL trigger execution, current roles
 * and same-transaction commit/rollback require Root's real migration trial. */
const read=(name:string)=>readFileSync(new URL('../../apps/console-api/src/infrastructure/migrations/'+name,import.meta.url),'utf8');
const old=read('019_m11_approval_policy.sql'),foundation=read('026_m11_workflow_schedules.sql');
const sql=read('029_m11_business_schedule_revisions.sql'),code=sql.replace(/--[^\n]*/g,'');
const bindingGuard=(source:string)=>source.match(/CREATE (?:OR REPLACE )?FUNCTION m11_guard_approval_bindings\(\)[\s\S]*?AS \$\$([\s\S]*?)\$\$;/)![1];
const compact=(v:string)=>v.replace(/\s+/g,' ').trim();
describe('SQL029 first unvoted business schedule revision has a narrow approval pointer transition',()=>{
 it('preserves the entire old binding guard except for the exact candidate transition predicate',()=>{
  const modified=bindingGuard(sql).replace(/\s+AND NOT m11_business_schedule_pointer_advance\(OLD::workflows,NEW::workflows\)/,'');
  expect(compact(modified)).toBe(compact(bindingGuard(old)));
  expect(code.match(/CREATE OR REPLACE FUNCTION[^\n]+/g)).toEqual(['CREATE OR REPLACE FUNCTION m11_guard_approval_bindings() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN']);
 });
 it('never disables, drops or recreates legacy approval/identity/policy triggers or their protected history',()=>{
  expect(code).not.toMatch(/DROP\s+(?:TRIGGER|TABLE|FUNCTION|CONSTRAINT)|ALTER TABLE|DISABLE TRIGGER|ENABLE TRIGGER|session_replication_role|SECURITY DEFINER|current_setting|set_config|\bGRANT\b/);
  expect(code).not.toMatch(/\b(?:UPDATE|DELETE FROM|INSERT INTO|TRUNCATE)\s+(?:workflows|workflow_versions|workflow_steps|workflow_stages|workflow_candidate_versions|workflow_candidates|workflow_approvals|workflow_executions)/);
 });
 it.each(["old_workflow.approval_format IS DISTINCT FROM 2","new_workflow.approval_format IS DISTINCT FROM 2",
  "old_workflow.state IS DISTINCT FROM 'pending'","new_workflow.state IS DISTINCT FROM 'pending'",
  "old_workflow.kind NOT IN('configuration_v2','portal-credential-issue')",'new_workflow.plan_revision IS DISTINCT FROM old_workflow.plan_revision+1',
  'new_workflow.revision IS DISTINCT FROM old_workflow.revision+1','new_workflow.plan_hash IS NOT DISTINCT FROM old_workflow.plan_hash',
  'old_workflow.approval_set_id IS NOT NULL','new_workflow.approval_set_id IS NOT NULL',
  'old_workflow.approved_by IS NOT NULL','new_workflow.approved_by IS NOT NULL'])('requires %s before allowing the intermediate NULL pointer',value=>{
  expect(code).toContain(value);
 });
 it('keeps every other workflow field unchanged, including scope, requester, definition and expiry',()=>{
  const allowed=code.match(/to_jsonb\(new_workflow\)-ARRAY\[([^\]]+)\]/)![1].match(/'[^']+'/g)!.map(v=>v.slice(1,-1));
  expect(allowed).toEqual(['plan_revision','plan_hash','revision','updated_at','not_before','window_start','window_end','candidate_version','candidate_manifest_hmac']);
  for(const field of ['id','cluster_id','workspace_id','kind','subject_type','subject_id','requester_type','requester_user_id','requester_developer_id','definition_id','definition_version','expires_at','created_at','request_hash','idempotency_key','approval_set_id','approved_by'])expect(allowed).not.toContain(field);
 });
 it.each(['workflow_approvals','workflow_approval_sets','workflow_approval_set_members','workflow_executions','mutation_operations','configuration_executions',
  'workflow_execution_origins','workflow_configuration_execution_origins'])('requires all historical %s facts to be absent, across every plan revision',table=>{
  expect(code).toContain(`NOT EXISTS(SELECT 1 FROM ${table} WHERE workflow_id=fid)`);
 });
 it('uses the actual configuration_executions schema, never a fixture-only invented table',()=>{
  expect(code).not.toContain('configuration_job_executions');expect(code).toContain('configuration_executions WHERE workflow_id=fid');
 });
 it('requires unchanged pending native steps and rechecks zero effects at commit',()=>{
  expect(code).toContain("state IS DISTINCT FROM 'pending' OR operation_id IS NOT NULL OR receipt_secret IS NOT NULL OR started_at IS NOT NULL OR completed_at IS NOT NULL");
  expect(code).toContain('OR NOT m11_business_schedule_revision_unused(old_workflow.id)');
  expect(code).toContain('OR NOT m11_business_schedule_revision_unused(w.id)');
 });
 it('rejects an existing schedule or preexisting new-revision artifacts instead of reusing or deleting them',()=>{
  expect(code).toContain('EXISTS(SELECT 1 FROM workflow_schedules WHERE workflow_id=old_workflow.id)');
  for(const table of ['workflow_versions','workflow_steps','workflow_stages','workflow_candidate_versions'])expect(code).toContain(`EXISTS(SELECT 1 FROM ${table} WHERE workflow_id=old_workflow.id AND plan_revision=new_workflow.plan_revision)`);
 });
 it('permits only the initial NULL-to-scheduled window and never extends the original expiry',()=>{
  expect(code).toContain('old_workflow.not_before IS NOT NULL OR old_workflow.window_start IS NOT NULL OR old_workflow.window_end IS NOT NULL');
  expect(code).toContain('new_workflow.window_end>old_workflow.expires_at');expect(code).toContain('s.window_end>s.expires_at');
  expect(code).toContain('s.not_before,s.window_start,s.window_end,s.expires_at');
 });
 it('requires same-transaction deferred completion while leaving the original V2 validation active',()=>{
  expect(code).toMatch(/CREATE CONSTRAINT TRIGGER workflows_business_schedule_revision_complete AFTER UPDATE ON workflows\s+DEFERRABLE INITIALLY DEFERRED/);
  expect(code).toContain('PERFORM m11_assert_approval_facts(w.id,w.plan_revision,w.plan_hash)');
  expect(code).toContain("USING ERRCODE='23514'");expect(foundation).toContain('CREATE TRIGGER workflow_business_schedule_pre_vote BEFORE INSERT');
 });
 it('requires one real new 026 draft and delegation, a shared newly resealed base hash and pristine progress',()=>{
  expect(code).toContain('(SELECT count(*) FROM workflow_schedules WHERE workflow_id=w.id)<>1');
  expect(code).toContain('(SELECT count(*) FROM workflow_executor_delegations WHERE workflow_id=w.id)<>1');
  expect(code).toContain('s.base_plan_hash IS DISTINCT FROM d.base_plan_hash');expect(code).toContain('s.base_plan_hash IS NOT DISTINCT FROM OLD.plan_hash');
  expect(code).toContain("p.state IS DISTINCT FROM 'pending-approval' OR p.claim_id IS NOT NULL OR p.revision<>1");
  for(const table of ['workflow_schedule_activations','workflow_schedule_claims','workflow_schedule_outcomes'])expect(code).toContain(`EXISTS(SELECT 1 FROM ${table} WHERE schedule_id=s.id)`);
 });
 it('requires a fresh candidate version1 and changed complete manifest on the new plan tuple',()=>{
  expect(code).toContain('candidate_version=1');expect(code).toContain('w.candidate_version IS DISTINCT FROM 1');
  expect(code).toContain('w.candidate_manifest_hmac IS NOT DISTINCT FROM OLD.candidate_manifest_hmac');
  expect(code).toContain('c.plan_revision,c.plan_hash,c.definition_id,c.definition_version,c.policy_hash,c.manifest_hmac');
 });
 it('preserves separate Portal requester identity while the new revision has its actual Console author',()=>{
  expect(code).toContain('v.created_by');expect(code).toContain('s.owner_id)');expect(code).toContain('v.created_by_developer_id IS NOT NULL');
  expect(code).toContain("IS DISTINCT FROM (CASE WHEN w.requester_type='console' THEN w.requester_user_id ELSE w.requester_developer_id END)");
  expect(code).not.toMatch(/IS DISTINCT FROM\s+CASE\b/);
  expect(code).toContain('FROM portal_developers developer');expect(code).toContain('NOT developer.must_change_password');
  expect(code).toContain('developer.credential_epoch=s.requester_credential_epoch');
 });
 it('locks and rechecks actual owner credentials without treating a fake SQL session variable as an HTTP SID',()=>{
  expect(code).toContain('SELECT version INTO current_iam FROM iam_epoch WHERE singleton=true FOR SHARE');
  expect(code).toContain('SELECT * INTO u FROM users WHERE id=s.owner_id FOR SHARE');
  expect(code).toContain('u.credential_epoch IS DISTINCT FROM s.owner_credential_epoch');expect(code).toContain('u.force_password_change');
  expect(code).not.toMatch(/auth_sessions|session_id|sessionId|SET ROLE|SET SESSION/);
 });
 it('uses the actual resealed new-revision base contract rather than the predecessor hash',()=>{
  const f=workflowScheduledFixture(),{scheduling:_,...previous}=f.plan,oldHash=f.secrets.fingerprint(previous);
  const remap=new Map(previous.steps.map((s:any)=>[s.id,randomUUID()]));
  const base={...previous,planRevision:2,steps:previous.steps.map((s:any)=>({...s,id:remap.get(s.id),dependencies:s.dependencies.map((d:string)=>remap.get(d))}))};
  const draft=structuredClone(f.draft);draft.binding.workflowPlanRevision=2;draft.binding.basePlanHash=f.secrets.fingerprint(base);
  draft.delegation.workflowPlanRevision=2;draft.delegation.basePlanHash=draft.binding.basePlanHash;draft.delegationHmac=f.secrets.fingerprint(draft.delegation);
  const plan={...base,scheduling:workflowSchedulePlanSeal(draft)};draft.binding.workflowPlanHash=f.secrets.fingerprint(plan);
  expect(()=>assertWorkflowScheduledPlan(plan as any,draft,f.secrets)).not.toThrow();expect(draft.binding.basePlanHash).not.toBe(oldHash);
  expect(draft.delegation.basePlanHash).toBe(draft.binding.basePlanHash);
  expect(code).not.toContain('s.base_plan_hash IS DISTINCT FROM OLD.plan_hash');
 });
 it('keeps direct Portal mode unchanged while requiring fresh format2 approval candidates',()=>{
  expect(code).toContain('old_workflow.execution_mode IS DISTINCT FROM new_workflow.execution_mode');
  expect(code).toContain("old_workflow.kind='configuration_v2' AND old_workflow.execution_mode IS DISTINCT FROM 'approval'");
  expect(code).toContain("old_workflow.kind='portal-credential-issue' AND old_workflow.execution_mode NOT IN('direct','approval')");
  expect(code).toContain('w.execution_mode IS DISTINCT FROM registry.execution_mode');
  expect(code).not.toContain("old_workflow.execution_mode IS DISTINCT FROM 'approval' OR new_workflow.execution_mode IS DISTINCT FROM 'approval'");
 });
});
