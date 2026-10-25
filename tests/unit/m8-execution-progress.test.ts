import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {ForbiddenException} from '@nestjs/common';
import {ConfigurationRepositoryService,INITIALIZE_EXECUTION_PROGRESS_QUERY} from '../../apps/console-api/src/modules/config-storage/configuration-repository.service';
import {SecretService} from '../../apps/console-api/src/infrastructure/secret.service';

const id=(n:number)=>`75000000-0000-4000-8000-${String(n).padStart(12,'0')}`;
beforeEach(()=>vi.stubEnv('CONSOLE_ENCRYPTION_KEY','6'.repeat(64)));
afterEach(()=>vi.unstubAllEnvs());
/** Real repository with explicit synthetic transactions. Actual PostgreSQL
 * trigger, locking and runtime-role checks live in the isolated SQL suite. */
function fixture(kind='apply'){
 const scope:any={clusterId:id(1),workspaceId:id(2),transportScope:'a'.repeat(64),kind:'workspace',rootIds:[]};
 const handle=Object.freeze({}),identity={jobId:id(3),planId:id(4),planRevision:1,planHash:'b'.repeat(64)};
 let row:any={id:identity.jobId,cluster_id:scope.clusterId,workspace_id:scope.workspaceId,transport_scope:scope.transportScope,scope_kind:scope.kind,root_ids:[],
  kind,state:'pending',revision:2,plan_id:identity.planId,plan_revision:1,plan_hash:identity.planHash,safe_progress:{},error_code:null,created_at:new Date(),completed_at:null};
 const trace:string[]=[];
 const tx:any={one:vi.fn(async(sql:string,params:any[])=>{
  if(sql==='SELECT * FROM configuration_jobs WHERE id=$1 FOR UPDATE'){trace.push('lock');expect(params).toEqual([identity.jobId]);return structuredClone(row);}
  expect(sql).toBe(INITIALIZE_EXECUTION_PROGRESS_QUERY);trace.push('cas');
  expect(params.slice(2)).toEqual([scope.clusterId,scope.workspaceId,2,identity.planId,1,identity.planHash]);
  row={...row,safe_progress:JSON.parse(params[1]),revision:row.revision+1};return structuredClone(row);
 })};
 const db:any={transaction:vi.fn(async(fn:any)=>{const before=structuredClone(row);trace.push('begin');try{const result=await fn(tx);trace.push('commit');return result;}catch(e){row=before;trace.push('rollback');throw e;}})};
 const policy:any={assertStorage:vi.fn(async(candidate:any,input:any,transaction:any)=>{
  expect(candidate).toBe(handle);expect(transaction).toBe(tx);expect(input.scope).toEqual(scope);expect(input.phase).toBe('plan');trace.push('authority');
  return{scope,actorId:id(6),expiresAt:Date.now()+60000};
 })};
 const repo=new ConfigurationRepositoryService(db,new SecretService(),{}as any,policy);
 const input={identity,revision:2,safeProgress:{baselineSnapshotId:id(5),baselineVersion:1,name:'Synthetic execution',key:'SyntheticPrivateDoNotPersist'}};
 return{repo,db,tx,policy,handle,identity,input,trace,get row(){return row;},set row(value:any){row=value;}};
}
describe('M8 execution progress before any native claim',()=>{
 it.each(['apply','rollback'])('binds %s to its exact frozen plan with one revision advance',async kind=>{const f=fixture(kind),result=await f.repo.initializeExecutionProgress(f.handle,f.input);
  expect(result).toMatchObject({id:f.identity.jobId,state:'pending',revision:3,safeProgress:{...f.identity,baselineSnapshotId:id(5),baselineVersion:1}});
  expect(f.trace).toEqual(['begin','lock','authority','cas','authority','commit']);expect(f.row.safe_progress.key).not.toBe('SyntheticPrivateDoNotPersist');
  expect(f.tx.one.mock.calls).toHaveLength(2);expect(f.policy.assertStorage.mock.calls[1][1]).toMatchObject(f.identity);
 });
 it.each([{revision:3},{state:'failed'},{state:'succeeded'},{state:'running'},{state:'waiting_approval'},{kind:'import'},{kind:'export'},
  {plan_id:id(99)},{plan_revision:2},{plan_hash:'c'.repeat(64)}])('refuses changed or terminal job %j before CAS',async change=>{const f=fixture();f.row={...f.row,...change};const original=structuredClone(f.row);
  await expect(f.repo.initializeExecutionProgress(f.handle,f.input)).rejects.toMatchObject({response:{code:'CONFIGURATION_EXECUTION_PROGRESS_CONFLICT'}});
  expect(f.trace).not.toContain('cas');expect(f.row).toEqual(original);
 });
 it('cannot initialize the same committed revision twice',async()=>{const f=fixture();await f.repo.initializeExecutionProgress(f.handle,f.input);const original=structuredClone(f.row);
  await expect(f.repo.initializeExecutionProgress(f.handle,f.input)).rejects.toMatchObject({response:{code:'CONFIGURATION_EXECUTION_PROGRESS_CONFLICT'}});expect(f.row).toEqual(original);
 });
 it('fails current authorization before any write',async()=>{const f=fixture();f.policy.assertStorage.mockRejectedValueOnce(new ForbiddenException({code:'CONFIGURATION_AUTHORITY_REVOKED'}));
  await expect(f.repo.initializeExecutionProgress(f.handle,f.input)).rejects.toMatchObject({status:403});expect(f.row.revision).toBe(2);expect(f.trace).not.toContain('cas');
 });
 it('rolls back progress if authority changes after CAS',async()=>{const f=fixture(),original=structuredClone(f.row);f.policy.assertStorage.mockImplementationOnce(async()=>({scope:{clusterId:id(1),workspaceId:id(2),transportScope:'a'.repeat(64),kind:'workspace',rootIds:[]},actorId:id(6),expiresAt:Date.now()+60000}));
  f.policy.assertStorage.mockRejectedValueOnce(new ForbiddenException({code:'CONFIGURATION_AUTHORITY_REVOKED'}));
  await expect(f.repo.initializeExecutionProgress(f.handle,f.input)).rejects.toMatchObject({status:403});expect(f.trace).toContain('cas');expect(f.trace.at(-1)).toBe('rollback');expect(f.row).toEqual(original);
 });
 it('does not treat a zero-row CAS as a success',async()=>{const f=fixture(),actual=f.tx.one.getMockImplementation()!;f.tx.one.mockImplementation(async(sql:string,params:any[])=>sql===INITIALIZE_EXECUTION_PROGRESS_QUERY?null:actual(sql,params));
  await expect(f.repo.initializeExecutionProgress(f.handle,f.input)).rejects.toMatchObject({response:{code:'CONFIGURATION_EXECUTION_PROGRESS_CONFLICT'}});expect(f.row.revision).toBe(2);
 });
 it.each([{baselineSnapshotId:'invalid'},{baselineVersion:0},{baselineVersion:'1'}])('refuses invalid baseline %j without a transaction',async change=>{const f=fixture();
  await expect(f.repo.initializeExecutionProgress(f.handle,{...f.input,safeProgress:{...f.input.safeProgress,...change}})).rejects.toMatchObject({status:400});expect(f.db.transaction).not.toHaveBeenCalled();
 });
});
