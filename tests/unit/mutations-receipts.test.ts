import 'reflect-metadata';
import { ForbiddenException } from '@nestjs/common';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { MutationService } from '../../apps/console-api/src/modules/mutations/mutation.service';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { defaultWorkspaceId,workspaceFixture } from './workspace-test-fixture';
import { executionFixture } from './execution-test-fixture';

const clusterId='ed2ac7ad-28d6-4f92-a47d-c229f3c74858';
const actor={id:'058ef7f4-5e9d-4d0e-a66f-93709cec34c9',username:'admin',superAdmin:true};
function fixture(){
 const secrets=new SecretService();
 const row={id:'durable-operation',cluster_id:clusterId,workspace_id:defaultWorkspaceId,actor_id:actor.id,entity_type:'plugins',entity_id:'plugin',action:'update',
  state:'uncertain',remote_started:true,remote_completed:true,error_code:'LOCK_LOST',safe_result:{id:'plugin',config:{password:'raw-private-value'}},
  before_secret:secrets.encrypt({id:'plugin',tags:['team:pay']},'mutation:durable-operation:before'),
  result_secret:secrets.encrypt({id:'plugin',tags:['team:pay'],config:{password:'raw-private-value'}},'mutation:durable-operation:result'),
  payload_secret:'never-return-payload',request_hash:'never-return-hash',created_at:'2026-10-10',updated_at:'2026-10-10'};
 const db={one:vi.fn(async(sql:string,params:any[])=>{
  if(!sql.includes('FROM mutation_operations'))throw new Error('Unexpected SQL');
  return params[0]===row.cluster_id&&(sql.includes('actor_id=$3')?params[1]==='stable-key'&&params[2]===row.actor_id:params[1]===row.id)?row:null;
 })};
 const authz={assertCluster:vi.fn().mockResolvedValue(undefined),assertEntity:vi.fn().mockResolvedValue(undefined),isPlatformAdmin:vi.fn(async(user:any)=>user.superAdmin===true)};
 const service=new MutationService(db as any,{} as any,secrets,{} as any,{} as any,authz as any,workspaceFixture(clusterId).resolver,executionFixture());
 return {service,row,db,authz};
}

describe('durable mutation receipt lookup after a lost response',()=>{
 beforeEach(()=>vi.stubEnv('CONSOLE_ENCRYPTION_KEY','9b'.repeat(32)));
 afterEach(()=>vi.unstubAllEnvs());

 it('returns uncertain state with no encrypted payload or plaintext result and rechecks entity scope',async()=>{
  const {service,row,db,authz}=fixture();
  const receipt=await service.operationByKey(clusterId,'stable-key',actor);
  expect(receipt).toMatchObject({id:row.id,state:'uncertain',error_code:'LOCK_LOST',remote_completed:true});
  expect(JSON.stringify(receipt)).not.toContain('raw-private-value');
  expect(receipt).not.toHaveProperty('before_secret');expect(receipt).not.toHaveProperty('result_secret');expect(receipt).not.toHaveProperty('payload_secret');expect(receipt).not.toHaveProperty('request_hash');
  expect(db.one).toHaveBeenCalledWith(expect.stringContaining('actor_id=$3'),[clusterId,'stable-key',actor.id]);
  expect(authz.assertEntity).toHaveBeenCalledTimes(2);
  expect(authz.assertEntity).toHaveBeenCalledWith(actor,clusterId,'plugins','read',expect.objectContaining({tags:['team:pay']}),defaultWorkspaceId);
 });

 it('conceals another actor same-key operation even from a super administrator',async()=>{
  const {service}=fixture();
  await expect(service.operationByKey(clusterId,'stable-key',{...actor,id:'another-admin'})).rejects.toMatchObject({status:404});
 });

 it('binds the lookup to the original cluster and returns 404 for an absent key',async()=>{
  const {service}=fixture();
  await expect(service.operationByKey('another-cluster','stable-key',actor)).rejects.toMatchObject({status:404});
  await expect(service.operationByKey(clusterId,'not-started',actor)).rejects.toMatchObject({status:404});
 });

 it('rejects revoked entity access before exposing any operation receipt',async()=>{
  const {service,authz}=fixture();authz.assertEntity.mockRejectedValue(new ForbiddenException());
  await expect(service.operationByKey(clusterId,'stable-key',actor)).rejects.toMatchObject({status:403});
 });

 it('rejects a malformed key without a database lookup',async()=>{
  const {service,db}=fixture();
  await expect(service.operationByKey(clusterId,"' OR 1=1",actor)).rejects.toMatchObject({status:400});
  expect(db.one).not.toHaveBeenCalled();
 });

 it('applies the same redaction and scope checks to an operation-ID receipt',async()=>{
  const {service,row,authz}=fixture();
  const receipt=await service.operation(clusterId,row.id,actor);
  expect(receipt.safe_result.config.password).toMatch(/^\[REDACTED:/);
  expect(authz.assertEntity).toHaveBeenCalledTimes(2);
 });
});
