import {describe,it,expect,vi,beforeEach,afterEach} from 'vitest';
import {WorkflowPlansService} from '../../apps/console-api/src/modules/workflows/workflow-plans.service';
import {WORKFLOW_KINDS} from '../../apps/console-api/src/modules/workflows/workflow.types';
import {SecretService} from '../../apps/console-api/src/infrastructure/secret.service';

const cid='50000000-0000-4000-8000-000000000001',wid='50000000-0000-4000-8000-000000000002',actor='50000000-0000-4000-8000-000000000003';
/** Explicit synthetic deferred constraints. Actual PostgreSQL commits and
 * concurrency are verified by the separate isolated storage integration. */
function fixture(){
 const state={definitions:[]as any[],versions:[]as any[],stages:[]as any[]},trace:string[]=[];let failStage=false,reviewerRoleActive=true;
 const check=()=>{if(state.definitions.some(d=>!state.versions.some(v=>v.id===d.id)))throw Object.assign(Error('synthetic current version FK'),{code:'23503'});if(state.versions.some(v=>state.stages.filter(s=>s.id===v.id).length!==1))throw Object.assign(Error('synthetic incomplete stage'),{code:'23514'});};
 const tx:any={one:vi.fn(async(sql:string,p:any[]=[])=>{
  if(sql==="SELECT id FROM roles WHERE builtin_kind='super-admin' AND code='super-admin' AND cluster_id IS NULL AND workspace_id IS NULL AND status='active' AND deleted_at IS NULL"){
   expect(p).toEqual([]);return reviewerRoleActive?{id:'50000000-0000-4000-8000-000000000005'}:null;
  }
  if(sql==='SELECT id FROM workflow_definitions WHERE cluster_id=$1 AND workspace_id=$2 AND code=$3')return state.definitions.find(d=>d.cid===p[0]&&d.wid===p[1]&&d.kind===p[2])??null;
  throw Error(`UNEXPECTED_DEFINITION_READ:${sql}`);
 }),exec:vi.fn(async(sql:string,p:any[])=>{
  if(sql.includes('pg_advisory_xact_lock')){expect(p).toEqual([`workflow-definitions:${cid}:${wid}`]);trace.push('lock');return 1;}
  if(sql.startsWith('INSERT INTO workflow_definitions(')){state.definitions.push({id:p[0],cid:p[1],wid:p[2],kind:p[3],actor:p[4]});trace.push('definition');}
  if(sql.startsWith('INSERT INTO workflow_definition_versions')){state.versions.push({id:p[2],policy:JSON.parse(p[3]),hash:p[4],actor:p[5]});trace.push('version');}
  if(sql.startsWith('INSERT INTO workflow_definition_stages')){if(failStage)throw Error('synthetic stage write failure');state.stages.push({id:p[2]});trace.push('stage');}
  return 1;
 })};
 const db:any={one:vi.fn(async()=>null),exec:vi.fn(async(sql:string,p:any[])=>{await tx.exec(sql,p);check();return 1;}),transaction:vi.fn(async(fn:any)=>{const original=structuredClone(state);trace.push('begin');try{const result=await fn(tx);check();trace.push('commit');return result;}catch(e){Object.assign(state,original);trace.push('rollback');throw e;}})};
 const plans=new WorkflowPlansService(db,new SecretService(),{}as any);return{plans,db,tx,state,trace,failStage:()=>{failStage=true;},disableReviewerRole:()=>{reviewerRoleActive=false;},check};
}
beforeEach(()=>{vi.stubEnv('CONSOLE_ENCRYPTION_KEY','de'.repeat(32));vi.stubEnv('APP_SECRET','synthetic-workflow-source-secret-minimum-32-characters');});afterEach(()=>vi.unstubAllEnvs());
describe('M8 workflow definitions initialize atomically',()=>{
 it('reproduces why an old standalone root INSERT autocommit violates the deferred current-version FK',async()=>{const f=fixture();await expect(f.db.exec('INSERT INTO workflow_definitions(',['synthetic-id',cid,wid,'configuration_v2',actor])).rejects.toMatchObject({code:'23503'});});
 it('uses one actual method transaction and scope lock for complete immutable defaults',async()=>{const f=fixture();await f.plans.definitions(cid,wid,actor);expect(f.db.transaction).toHaveBeenCalledTimes(1);expect(f.db.exec).not.toHaveBeenCalled();expect(f.trace[0]).toBe('begin');expect(f.trace[1]).toBe('lock');expect(f.trace.at(-1)).toBe('commit');expect(f.state.definitions.map(d=>d.kind)).toEqual(WORKFLOW_KINDS);expect(f.state.versions).toHaveLength(WORKFLOW_KINDS.length);expect(f.state.stages).toHaveLength(WORKFLOW_KINDS.length);
  for(const version of f.state.versions){
   expect(version.actor).toBe(actor);expect(version.policy.allowSelfApproval).toBe(false);
   if(['iam-metadata','metrics-setup','control-metadata','entity-annotation'].includes(version.policy.kind)){
    expect(version.policy).toEqual({version:2,kind:version.policy.kind,allowSelfApproval:false,distinctAcrossStages:true,intentTtlHours:24,stages:[{level:1,name:'管理员审批',mode:'any',threshold:1,selector:{roles:['50000000-0000-4000-8000-000000000005']}}]});
   }else expect(version.policy).toEqual({version:1,mode:'single',allowSelfApproval:false,kind:version.policy.kind});
  }
 });
 it('rolls every default back when the actual global built-in reviewer role is unavailable',async()=>{const f=fixture();f.disableReviewerRole();await expect(f.plans.definitions(cid,wid,actor)).rejects.toMatchObject({response:{code:'IAM_WORKFLOW_DEFAULT_REVIEWER_ROLE_UNAVAILABLE'}});expect(f.state).toEqual({definitions:[],versions:[],stages:[]});expect(f.trace.at(-1)).toBe('rollback');});
 it('uses the caller transaction and rolls all initialized defaults back on a later submission failure',async()=>{const f=fixture();await expect(f.db.transaction(async(tx:any)=>{await f.plans.definitions(cid,wid,actor,tx);throw Error('synthetic wrapper persistence failure');})).rejects.toThrow('synthetic wrapper persistence failure');expect(f.db.transaction).toHaveBeenCalledTimes(1);expect(f.state).toEqual({definitions:[],versions:[],stages:[]});expect(f.trace.at(-1)).toBe('rollback');});
 it('rolls all three related tables back if creating a stage fails',async()=>{const f=fixture();f.failStage();await expect(f.plans.definitions(cid,wid,actor)).rejects.toThrow('synthetic stage write failure');expect(f.state).toEqual({definitions:[],versions:[],stages:[]});});
 it('reuses existing definitions and their original owner without rewriting versions',async()=>{const f=fixture();await f.plans.definitions(cid,wid,actor);const original=structuredClone(f.state);f.tx.exec.mockClear();await f.plans.definitions(cid,wid,'50000000-0000-4000-8000-000000000004');expect(f.state).toEqual(original);expect(f.tx.exec).toHaveBeenCalledTimes(1);});
});
