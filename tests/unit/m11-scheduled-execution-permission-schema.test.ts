import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {AuthorizationService} from '../../apps/console-api/src/modules/authorization/authorization.service';
import {KongExecutionContextService} from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import {workflowScheduledFixture} from './helpers/workflow-scheduled-fixture';
import {assertWorkflowScheduledPlan,workflowSchedulePlanSeal} from '../../apps/console-api/src/modules/workflows/workflow-schedule.repository';
beforeEach(()=>vi.stubEnv('CONSOLE_ENCRYPTION_KEY','ad'.repeat(32)));afterEach(()=>vi.unstubAllEnvs());

/** SQL migration SOURCE contract checks. These tests do not execute PostgreSQL
 * or certify trigger behavior; Root must run the real role/rollback trial. */
const read=(name:string)=>readFileSync(new URL('../../apps/console-api/src/infrastructure/migrations/'+name,import.meta.url),'utf8');
const old=read('008_m6_portal.sql'),foundation=read('026_m11_workflow_schedules.sql'),target=read('027_m11_target_result_observations.sql');
const sql=read('028_m11_scheduled_execution_permission.sql'),code=sql.replace(/--[^\n]*/g,'');
const identity=(source:string)=>source.match(/CREATE TRIGGER workflow_executions_identity[\s\S]*?m6_guard_identity\('([^']+)'\)/)![1].split(',');
const permissionPattern=new RegExp(sql.match(/permission_version ~ '([^']+)'/)![1]);

describe('SQL028 scheduled actual execution permission fact',()=>{
 it('does not rewrite the accepted 026/027 migration artifacts',()=>{
  expect(createHash('sha256').update(foundation).digest('hex')).toBe('a447e5027a9045d2bd72795ed1892de96f1d01a068960cfe03b41f5ca0f46ca4');
  expect(createHash('sha256').update(target).digest('hex')).toBe('967ee9e56c57ba7be4f4c558c33ed6a5af8a683a316db234443d04375d8c169f');
 });
 it('keeps the new column nullable with no authority backfill for historical HTTP rows',()=>{
  expect(code).toMatch(/ALTER TABLE workflow_executions ADD COLUMN permission_version text\s*;/);
  expect(code).toContain('permission_version IS NULL OR');expect(code).not.toMatch(/\b(?:UPDATE|INSERT INTO|DELETE FROM|TRUNCATE)\s+(?:workflow_executions|workflows|workflow_execution_origins)\b/);
  expect(code).not.toMatch(/permission_version text\s+(?:NOT NULL|DEFAULT)|ALTER COLUMN permission_version/);
 });
 it('retains every original M6 immutable identity column and adds only permission_version',()=>{
  expect(identity(sql)).toEqual([...identity(old),'permission_version']);
  expect(code.match(/DROP TRIGGER[^;]+;/g)).toEqual(['DROP TRIGGER workflow_executions_identity ON workflow_executions;']);
  expect(code).toMatch(/BEFORE UPDATE OR DELETE ON workflow_executions/);expect(old).toContain("IF TG_OP='DELETE' THEN RAISE EXCEPTION");
  expect(old).toContain('old_row->column_name IS DISTINCT FROM new_row->column_name');
 });
 it('leaves old approval, snapshot, progress and origin triggers enabled',()=>{
  expect(code).not.toMatch(/(?:DISABLE|ENABLE) TRIGGER|session_replication_role|DROP FUNCTION|CREATE OR REPLACE FUNCTION|DROP CONSTRAINT|DROP TABLE/);
  expect(code).not.toMatch(/DROP TRIGGER (?:workflow_business_origin|workflow_executions_approval_fact|workflow_executions_approval_bindings|workflow_executions_progress)\b/);
  expect(foundation).toContain('CREATE TRIGGER workflow_business_origin BEFORE INSERT ON workflow_execution_origins');
  expect(code).toContain('CREATE TRIGGER workflow_business_origin_permission BEFORE INSERT ON workflow_execution_origins');
 });
 it('supplements origin validation with locked actual IAM facts rather than a client permission string',()=>{
  expect(code).toContain('SELECT version INTO current_iam FROM iam_epoch WHERE singleton=true FOR SHARE');
  expect(code).toContain('SELECT * INTO u FROM users WHERE id=NEW.executor_id FOR SHARE');
  expect(code.indexOf('FROM iam_epoch')).toBeLessThan(code.indexOf('FROM users'));
  expect(code).toContain("expected_permission=u.id::text||':'||u.permissions_epoch::text||':'||current_iam::text");
  expect(code).toContain('e.permission_version IS DISTINCT FROM expected_permission');expect(code).toContain("USING ERRCODE='23514'");
  expect(code).not.toMatch(/current_setting|set_config|SECURITY DEFINER|EXECUTE\s+(?!FUNCTION)/);
 });
 it.each(['current_iam IS NULL','u.id IS NULL',"u.status IS DISTINCT FROM 'active'",'u.deleted_at IS NOT NULL','u.force_password_change',
  'u.credential_epoch IS DISTINCT FROM s.executor_credential_epoch','s.owner_id IS DISTINCT FROM s.executor_id',
  's.owner_credential_epoch IS DISTINCT FROM s.executor_credential_epoch','e.execution_actor_id IS DISTINCT FROM s.executor_id',
  'c.authority_expires_at<=clock_timestamp()','clock_timestamp()>=s.window_end'])('keeps %s as a rejection condition',condition=>{
  expect(code).toContain(condition);
 });
 it('does not substitute SQL epoch equality for current entity/secret grants or add runtime privileges',()=>{
  expect(code).not.toMatch(/\bGRANT\b|SET ROLE|SET SESSION AUTHORIZATION|auth_sessions|kong_database|kong_db|m6_rejected_impact_collision/);
  expect(code).toContain('SELECT * INTO c FROM workflow_schedule_claims WHERE id=NEW.claim_id');
  expect(code).toContain('SELECT * INTO e FROM workflow_executions WHERE id=NEW.execution_id');
  expect(code).toContain('SELECT * INTO w FROM workflows WHERE id=NEW.workflow_id');
 });
 it('retains separate developer requester liveness and epochs',()=>{
  expect(code).toContain("s.requester_type='developer' AND NOT EXISTS");expect(code).toContain('FROM portal_developers d');
  expect(code).toContain('NOT d.must_change_password');expect(code).toContain('d.credential_epoch=s.requester_credential_epoch');
 });
 it('preserves genuine direct-mode Portal plans with mandatory approval instead of silently changing their native mode',()=>{
  const f=workflowScheduledFixture('portal-credential-issue'),{scheduling:_,...base}=f.plan;
  base.executionMode='direct';const draft=structuredClone(f.draft);draft.binding.basePlanHash=f.secrets.fingerprint(base);
  draft.delegation.basePlanHash=draft.binding.basePlanHash;draft.delegationHmac=f.secrets.fingerprint(draft.delegation);
  const plan={...base,scheduling:workflowSchedulePlanSeal(draft)};draft.binding.workflowPlanHash=f.secrets.fingerprint(plan);
  expect(()=>assertWorkflowScheduledPlan(plan as any,draft,f.secrets)).not.toThrow();expect(plan.approvalRequired).toBe(true);expect(plan.executionMode).toBe('direct');
  expect(code).toContain('e.execution_mode IS DISTINCT FROM w.execution_mode');expect(code).toContain('w.execution_mode IS DISTINCT FROM registry.execution_mode');
  expect(code).toContain("s.kind='configuration_v2' AND w.execution_mode IS DISTINCT FROM 'approval'");
  expect(code).toContain("s.kind='portal-credential-issue' AND w.execution_mode NOT IN('direct','approval')");
  expect(code).toContain('e.approval_required IS DISTINCT FROM true OR w.approval_required IS DISTINCT FROM true');
  expect(code).not.toContain("e.execution_mode IS DISTINCT FROM 'approval'");
 });
 it.each(['1','9223372036854775807'])('accepts the actual AuthorizationService bigint epoch format %s',async version=>{
  const user={id:'aa110000-0000-4000-8000-000000000001',username:'source-fixture',superAdmin:false};
  const db:any={one:vi.fn(async(sql:string)=>sql.includes('FROM users')?{...user,permissions_epoch:version,credential_epoch:'1'}:sql.includes('FROM iam_epoch')?{version}:null)};
  const auth=new AuthorizationService(db,{}as any,{}as any,new KongExecutionContextService());
  const actual=await auth.permissionVersion(user);expect(actual).toBe(`${user.id}:${version}:${version}`);expect(permissionPattern.test(actual)).toBe(true);
 });
 it.each(['','fake-permission','aa110000-0000-4000-8000-000000000001:0:1','aa110000-0000-4000-8000-000000000001:1:0',
  'aa110000-0000-4000-8000-000000000001:-1:1','aa110000-0000-4000-8000-000000000001:01:1'])('refuses a noncanonical new permission fact %s',value=>{
  expect(permissionPattern.test(value)).toBe(false);
 });
});
