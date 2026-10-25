import 'reflect-metadata';
import {randomUUID} from 'node:crypto';
import {beforeEach,afterEach,describe,it,expect,vi} from 'vitest';
import {SecretService} from '../../apps/console-api/src/infrastructure/secret.service';
import {portalReadbackReceipt} from '../../apps/console-api/src/modules/workflows/workflow-portal-readback-receipt';

beforeEach(()=>vi.stubEnv('CONSOLE_ENCRYPTION_KEY','ca'.repeat(32)));
afterEach(()=>vi.unstubAllEnvs());
function fixture(wrapped=false){
 const secrets=new SecretService(),nativeId=randomUUID(),operationId=randomUUID(),executionId=randomUUID();
 const payload={id:nativeId,username:'source-consumer'},entity={...payload,created_at:1700000000,tags:[]};
 const step:any={id:randomUUID(),entityType:'consumers',mutationAction:'create',mutationPayloadHmac:secrets.fingerprint(payload),
  beforeFingerprint:secrets.fingerprint(null),nativeRequests:[{nativeId}]};
 const plan:any={workflowId:randomUUID(),planRevision:2,clusterId:randomUUID(),workspaceId:randomUUID(),steps:[step],scheduling:{executorId:randomUUID()}};
 const hash=secrets.fingerprint(plan),row:any={id:step.id,state:'running',plan_hash:hash,operation_id:operationId};
 const operation:any={id:operationId,state:'succeeded',remote_started:true,remote_completed:true,actor_id:plan.scheduling.executorId,
  workflow_id:plan.workflowId,workflow_execution_id:executionId,workflow_step_id:step.id,workflow_plan_revision:2,workflow_plan_hash:hash,
  cluster_id:plan.clusterId,workspace_id:plan.workspaceId,entity_type:'consumers',entity_id:nativeId,action:'create',parent_id:null,credential_kind:null,
  payload_secret:secrets.encrypt(payload,`mutation:${operationId}:payload`),before_secret:secrets.encrypt(null,`mutation:${operationId}:before`),
  result_secret:secrets.encrypt(wrapped?{entity}:entity,`mutation:${operationId}:result`)};
 return{secrets,entity,payload,step,plan,row,operation,executionId,read:()=>portalReadbackReceipt(plan,step,executionId,row,operation,secrets)};
}
describe('Portal durable raw and wrapped mutation readback receipts',()=>{
 it.each([false,true])('binds the original encrypted entity with wrapped=%s without changing stored material',wrapped=>{
  const f=fixture(wrapped),before=JSON.stringify(f.operation),result=f.read();
  expect(result).toEqual({operation:f.secrets.fingerprint(f.operation),result:f.secrets.fingerprint(f.entity)});
  expect(JSON.stringify(f.operation)).toBe(before);expect(Object.isFrozen(result)).toBe(true);
  expect(JSON.stringify(result)).not.toContain('source-consumer');
 });
 it.each(['actor_id','workflow_id','workflow_execution_id','workflow_step_id','workflow_plan_revision','workflow_plan_hash',
  'cluster_id','workspace_id','entity_type','entity_id','action','parent_id','credential_kind','state','remote_started','remote_completed'])('rejects changed receipt binding %s',field=>{
  const f=fixture();f.operation[field]=field.startsWith('remote_')?false:'foreign';
  expect(f.read).toThrow(expect.objectContaining({response:{code:'WORKFLOW_BUSINESS_PORTAL_READBACK_RECEIPT_REQUIRED'}}));
 });
 it.each(['id','state','plan_hash','operation_id'])('rejects changed original step row %s',field=>{
  const f=fixture();f.row[field]='foreign';expect(f.read).toThrow();
 });
 it.each(['payload','before','result'])('rejects authenticated but different %s material',kind=>{
  const f=fixture(),value=kind==='payload'?{...f.payload,username:'changed'}:kind==='before'?{id:f.entity.id}:{...f.entity,id:randomUUID()};
  f.operation[kind+'_secret']=f.secrets.encrypt(value,`mutation:${f.operation.id}:${kind}`);expect(f.read).toThrow();
 });
 it.each([null,[],{entity:{}},{entity:{id:'foreign'}}])('rejects an unusable result shape %j',value=>{
  const f=fixture();f.operation.result_secret=f.secrets.encrypt(value,`mutation:${f.operation.id}:result`);expect(f.read).toThrow();
 });
 it('requires the exact AEAD result context and returns a fixed error without ciphertext',()=>{
  const f=fixture();f.operation.result_secret=f.secrets.encrypt(f.entity,`mutation:${randomUUID()}:result`);
  try{f.read();throw Error('expected denial');}catch(e:any){expect(e.getResponse()).toEqual({code:'WORKFLOW_BUSINESS_PORTAL_READBACK_RECEIPT_REQUIRED'});expect(JSON.stringify(e)).not.toContain(f.operation.result_secret);}
 });
 it('does not treat a later entity change as the original receipt',()=>{
  const f=fixture(),first=f.read();expect(first.result).not.toBe(f.secrets.fingerprint({...f.entity,username:'changed-after-send'}));
 });
});
