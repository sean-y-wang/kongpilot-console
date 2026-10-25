import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {randomUUID} from 'node:crypto';
import {SecretService} from '../../apps/console-api/src/infrastructure/secret.service';
import {ConfigurationService} from '../../apps/console-api/src/modules/configuration/configuration.service';
import {WorkflowPlansService} from '../../apps/console-api/src/modules/workflows/workflow-plans.service';
import {ConfigurationRepositoryService} from '../../apps/console-api/src/modules/config-storage/configuration-repository.service';
import {SnapshotCryptoService} from '../../apps/console-api/src/modules/config-storage/snapshot-crypto.service';
import {DURABLE_CONFIGURATION_PRESENCE_QUERY} from '../../apps/console-api/src/modules/configuration/configuration-durable.repository';
const marker={authority_domain:'durable-configuration-v1',durable_issue_id:'10000000-0000-4000-8000-000000000001'};
const legacy={authority_domain:null,durable_issue_id:null,has_durable_issue:false,has_durable_binding:false};
beforeEach(()=>{vi.stubEnv('CONSOLE_ENCRYPTION_KEY','23'.repeat(32));});afterEach(()=>{vi.unstubAllEnvs();});
function wrap(){const cid=randomUUID(),wid=randomUUID(),job=randomUUID(),plan=randomUUID();return{version:1,kind:'configuration_v2',clusterId:cid,workspaceId:wid,workflowId:randomUUID(),planRevision:1,subject:{type:'configuration_jobs',id:job},requester:{type:'console',id:randomUUID()},prerequisites:[],steps:[{id:randomUUID(),order:1,kind:'metadata',handler:'configuration_v2',entityType:'configuration_jobs',entityId:job,permissionAction:'write',dependencies:[],nativeRequests:[],metadata:{jobId:job,planId:plan,planRevision:1,planHash:'a'.repeat(64)}}]}as any;}
describe('real missing-provider entrypoints reject durable evidence (strict synthetic SQL)',()=>{
 it.each([marker,{...legacy,authority_domain:'unknown-domain'},{...legacy,durable_issue_id:marker.durable_issue_id},{...legacy,has_durable_issue:true},{...legacy,has_durable_binding:true},{authority_domain:null,durable_issue_id:null},{has_durable_issue:false,has_durable_binding:false},{...legacy,authority_domain:undefined},{...legacy,durable_issue_id:undefined},null])('ConfigurationService rejects %j without the actual durable provider',async(row)=>{
  const plan=wrap(),one=vi.fn(async(sql:string,args:unknown[])=>{expect(sql).toBe(DURABLE_CONFIGURATION_PRESENCE_QUERY);expect(args).toEqual([plan.subject.id,plan.clusterId,plan.workspaceId]);return row;});
  const service=new ConfigurationService({one}as any,{}as any,{}as any,{}as any,{}as any,{}as any,{}as any,{}as any,{}as any,{}as any,{}as any,{}as any,{}as any,{}as any,{}as any,{}as any,{}as any);
  await expect((service as any).assertDurableWorkflow(plan)).rejects.toMatchObject({response:{code:'CONFIGURATION_DURABLE_PROVIDER_UNAVAILABLE'}});
 });
 it('ConfigurationService permits a genuinely proven legacy row only and its legacy-origin fallback also consults this fence',async()=>{
  const plan=wrap(),calls:string[]=[],one=vi.fn(async(sql:string,args:unknown[])=>{calls.push(sql);expect(args).toEqual([plan.subject.id,plan.clusterId,plan.workspaceId]);if(sql===DURABLE_CONFIGURATION_PRESENCE_QUERY)return legacy;if(sql.includes('has_job_origin'))return{required_origin_kind:null,required_origin_id:null,required_origin_hmac:null,has_job_origin:false,has_plan_origin:false};throw Error('UNEXPECTED_SQL');});
  const service=new ConfigurationService({one}as any,{}as any,{}as any,{}as any,{}as any,{}as any,{}as any,{}as any,{}as any,{}as any,{}as any,{}as any,{}as any,{}as any,{}as any,{}as any,{}as any);
  await expect((service as any).assertLegacyOrigin(plan)).resolves.toBeUndefined();expect(calls[0]).toBe(DURABLE_CONFIGURATION_PRESENCE_QUERY);
 });
 it.each([marker,{...legacy,durable_issue_id:marker.durable_issue_id},{...legacy,authority_domain:'unknown-domain'},{...legacy,has_durable_issue:true},{...legacy,has_durable_binding:true},null])('stored/scheduled WorkflowPlans fallback rejects %j',async(row)=>{
  const plan=wrap(),one=vi.fn(async(sql:string,args:unknown[])=>{expect(args).toEqual([plan.subject.id,plan.clusterId,plan.workspaceId]);if(sql==='SELECT * FROM configuration_jobs WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3')return{...row,required_origin_kind:null,required_origin_id:null,required_origin_hmac:null};if(sql===DURABLE_CONFIGURATION_PRESENCE_QUERY)return row;throw Error('UNEXPECTED_SQL');});
  const db={one},plans=new WorkflowPlansService(db as any,new SecretService(),{}as any);
  await expect((plans as any).storedConfigurationOrigin(plan,db)).rejects.toThrow();
 });
 it('stored WorkflowPlans permits only complete negative SQL domain evidence when no delegate exists',async()=>{
  const plan=wrap(),one=vi.fn(async(sql:string,args:unknown[])=>{expect(args).toEqual([plan.subject.id,plan.clusterId,plan.workspaceId]);if(sql==='SELECT * FROM configuration_jobs WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3')return{...legacy,required_origin_kind:null,required_origin_id:null,required_origin_hmac:null};if(sql===DURABLE_CONFIGURATION_PRESENCE_QUERY)return legacy;throw Error('UNEXPECTED_SQL');});
  const db={one},plans=new WorkflowPlansService(db as any,new SecretService(),{}as any);await expect((plans as any).storedConfigurationOrigin(plan,db)).resolves.toBeUndefined();
 });
 it.each([{...marker},{authority_domain:'unknown-domain',durable_issue_id:null},{authority_domain:null,durable_issue_id:marker.durable_issue_id},{...legacy,has_durable_binding:true},{...legacy,has_durable_issue:true},legacy])('actual encrypted readPlan requires complete negative domain proof without verifier (%j)',async(rowMarkers)=>{
  const secrets=new SecretService(),crypto=new SnapshotCryptoService(secrets),actorId=randomUUID(),job=randomUUID(),planId=randomUUID();
  const scope={clusterId:randomUUID(),workspaceId:randomUUID(),transportScope:secrets.fingerprint('transport'),kind:'workspace',rootIds:[]},plan:any={scope,steps:[],mode:'merge',expiresAt:new Date(Date.now()+60000).toISOString()};
  const identity={clusterId:scope.clusterId,workspaceId:scope.workspaceId,jobId:job,materialId:randomUUID(),artifactId:randomUUID(),artifactKind:'plan' as const},wrapped=crypto.createWrappedKey(identity);
  const ciphertext=await crypto.withKey(identity,wrapped,async key=>crypto.encrypt(key,identity,{section:'manifest',key:'plan'},plan));
  const row:any={...rowMarkers,id:identity.materialId,cluster_id:scope.clusterId,workspace_id:scope.workspaceId,job_id:job,source_job_id:job,artifact_id:identity.artifactId,artifact_kind:'plan',wrapped_key_secret:wrapped,manifest_ciphertext:ciphertext,material_state:'available',transport_scope:scope.transportScope};
  const one=vi.fn(async(sql:string,args:unknown[])=>{
   if(sql.startsWith('SELECT v.*,m.id')){expect(args).toEqual([scope.clusterId,scope.workspaceId,planId,1,secrets.fingerprint(plan)]);return row;}
   if(sql==='SELECT cluster_id,workspace_id,transport_scope,scope_kind,root_ids FROM configuration_jobs WHERE cluster_id=$1 AND workspace_id=$2 AND id=$3'){expect(args).toEqual([scope.clusterId,scope.workspaceId,job]);return{cluster_id:scope.clusterId,workspace_id:scope.workspaceId,transport_scope:scope.transportScope,scope_kind:'workspace',root_ids:[]};}
   if(sql===DURABLE_CONFIGURATION_PRESENCE_QUERY){expect(args).toEqual([job,scope.clusterId,scope.workspaceId]);return{...legacy,...rowMarkers};}
   if(sql==='SELECT required_origin_kind,required_origin_id,required_origin_hmac FROM configuration_jobs WHERE id=$1'){expect(args).toEqual([job]);return{required_origin_kind:null,required_origin_id:null,required_origin_hmac:null};}
   throw Error('UNEXPECTED_SQL');
  });
  const db:any={one,transaction:async(fn:any)=>fn(db)},access:any={assertStorage:vi.fn(async()=>({actorId,scope,expiresAt:Date.now()+60000}))};
  const repo=new ConfigurationRepositoryService(db,secrets,crypto,access),read=()=>repo.readPlan(Object.freeze({})as any,{scope:scope as any,planId,planRevision:1,planHash:secrets.fingerprint(plan)});if(rowMarkers===legacy)await expect(read()).resolves.toEqual(plan);else await expect(read()).rejects.toMatchObject({response:{code:'CONFIGURATION_DURABLE_POLICY_UNAVAILABLE'}});
 });
});
