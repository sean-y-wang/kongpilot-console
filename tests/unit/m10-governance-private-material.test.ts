import 'reflect-metadata';
import {randomUUID} from 'node:crypto';
import {ForbiddenException} from '@nestjs/common';
import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {SecretService} from '../../apps/console-api/src/infrastructure/secret.service';
import {GovernanceService} from '../../apps/console-api/src/modules/governance/governance.service';
import {GovernanceRepositoryService} from '../../apps/console-api/src/modules/governance/governance-repository.service';
import {decryptComparisonMaterial,governanceComparisonEnvelope} from '../../apps/console-api/src/modules/governance/governance-comparison-material';
import {promotionInput} from '../../apps/console-api/src/modules/governance/governance-input';

let previous:string|undefined;
beforeEach(()=>{previous=process.env.CONSOLE_ENCRYPTION_KEY;process.env.CONSOLE_ENCRYPTION_KEY='bc'.repeat(32);});
afterEach(()=>{if(previous===undefined)delete process.env.CONSOLE_ENCRYPTION_KEY;else process.env.CONSOLE_ENCRYPTION_KEY=previous;});
function materialFixture(){
 const secrets=new SecretService(),cid=randomUUID(),wid=randomUUID(),peerCid=randomUUID(),peerWid=randomUUID(),id=randomUUID(),consumer=randomUUID(),service=randomUUID();
 const inventory:any={id:randomUUID(),scope:{clusterId:cid,workspaceId:wid,kind:'workspace',rootIds:[],transportScope:'a'.repeat(64)},objects:[
  {entityType:'consumers',nativeId:consumer,objectWorkspaceId:wid,payload:{id:consumer,username:'unchanged-developer',tags:[]}},
  {entityType:'services',nativeId:service,objectWorkspaceId:wid,payload:{id:service,name:'api-service',host:'internal-only.invalid',port:443,tags:[]},sensitiveFields:[]},
 ],schemas:{},pluginSchemas:{},enabledPlugins:[],version:'1.5.1',completeness:'complete',projection:false,coverage:{},observedFrom:new Date().toISOString(),observedUntil:new Date().toISOString()};
 const target=structuredClone(inventory);Object.assign(target.scope,{clusterId:peerCid,workspaceId:peerWid,transportScope:'b'.repeat(64)});for(const o of target.objects)o.objectWorkspaceId=peerWid;
 const native=Object.fromEntries(inventory.objects.map((o:any)=>[`${o.entityType}:${o.nativeId}`,secrets.fingerprint({...o.payload,hidden:'synthetic-only-secret'})])),targetNative=Object.fromEntries(target.objects.map((o:any)=>[`${o.entityType}:${o.nativeId}`,secrets.fingerprint(o.payload)]));
 const sourceEnvelope=governanceComparisonEnvelope(inventory,native),targetEnvelope=governanceComparisonEnvelope(target,targetNative),policy={includeEnvironmentFields:false};
 const row:any={id,cluster_id:cid,workspace_id:wid,target_cluster_id:peerCid,target_workspace_id:peerWid,quality:'complete',counts:{sourceOnly:0,targetOnly:0,changed:1,unchanged:1},threshold:0,threshold_exceeded:true,safe_changes:[{entityType:'services',sourceNativeId:service,targetNativeId:service,action:'changed',fields:[{path:'/retries',source:1,target:2}]}],created_at:new Date(),policy,policy_hmac:secrets.fingerprint(policy),source_inventory_secret:secrets.encrypt(sourceEnvelope,`governance:comparison-source:${id}`),target_inventory_secret:secrets.encrypt(targetEnvelope,`governance:comparison-target:${id}`),source_inventory_hmac:secrets.fingerprint(sourceEnvelope),target_inventory_hmac:secrets.fingerprint(targetEnvelope)};
 return{secrets,cid,wid,peerCid,peerWid,id,consumer,service,inventory,target,native,targetNative,row};
}
describe('M10 encrypted private native comparison evidence',()=>{
 it('authenticates private maps inside the existing envelope while public repo returns only inventories',()=>{
  const f=materialFixture(),repo=new GovernanceRepositoryService({} as any,f.secrets),privateMaterial=decryptComparisonMaterial(f.row,f.secrets);
  expect(privateMaterial.source.nativeFingerprints).toEqual(f.native);expect(repo.comparisonInventories(f.row)).toEqual({source:f.inventory,target:f.target});
  const publicJSON=JSON.stringify(repo.comparisonInventories(f.row));for(const digest of Object.values(f.native))expect(publicJSON).not.toContain(digest);
  expect(publicJSON).not.toContain('nativeFingerprints');expect(publicJSON).not.toContain('synthetic-only-secret');
 });
 it('supports legacy diagnostics without upgrading a missing map into verified hidden fields',()=>{
  const f=materialFixture();f.row.source_inventory_secret=f.secrets.encrypt(f.inventory,`governance:comparison-source:${f.id}`);f.row.source_inventory_hmac=f.secrets.fingerprint(f.inventory);
  expect(decryptComparisonMaterial(f.row,f.secrets).source).toEqual({inventory:f.inventory,nativeFingerprints:null});
 });
 it('detects a hidden native change even when the public inventory is identical',()=>{
  const f=materialFixture(),changed={...f.native,[`consumers:${f.consumer}`]:f.secrets.fingerprint({id:f.consumer,hidden:'synthetic-rotated-secret'})};
  expect(f.secrets.fingerprint(governanceComparisonEnvelope(f.inventory,changed))).not.toBe(f.row.source_inventory_hmac);
 });
 it.each(['missing','extra','malformed'] as const)('rejects %s private receipt maps',mode=>{
  const f=materialFixture(),map={...f.native};if(mode==='missing')delete map[`consumers:${f.consumer}`];if(mode==='extra')map[`consumers:${randomUUID()}`]='a'.repeat(64);if(mode==='malformed')map[`consumers:${f.consumer}`]='client-approved';
  expect(()=>governanceComparisonEnvelope(f.inventory,map)).toThrow();
 });
 it('refuses side swaps, whole-envelope HMAC mismatch and unsupported envelope fields',()=>{
  const f=materialFixture();expect(()=>decryptComparisonMaterial({...f.row,source_inventory_secret:f.row.target_inventory_secret},f.secrets)).toThrow();expect(()=>decryptComparisonMaterial({...f.row,source_inventory_hmac:'f'.repeat(64)},f.secrets)).toThrow();
  const forged={...governanceComparisonEnvelope(f.inventory,f.native),approved:true};expect(()=>decryptComparisonMaterial({...f.row,source_inventory_secret:f.secrets.encrypt(forged,`governance:comparison-source:${f.id}`),source_inventory_hmac:f.secrets.fingerprint(forged)},f.secrets)).toThrow();
 });
 it('requires a literal credential opt-in with a unique fixed whitelist instead of credential UUIDs/proofs',()=>{
  const base={confirmed:true,confirm_name:'PROMOTE synthetic',includeCredentials:true};expect(promotionInput({...base,credentialKinds:['key-auth','basic-auth','oauth2']}).credentialKinds).toEqual(['key-auth','basic-auth','oauth2']);
  for(const body of [{...base,includeCredentials:false,credentialKinds:['jwt']},{...base,credentialKinds:['jwt','jwt']},{...base,credentialKinds:[randomUUID()]},{...base,credentialKinds:[]},{...base,sourceProof:{approved:true}}])expect(()=>promotionInput(body)).toThrow();
 });
});

function pickerFixture(){
 const f=materialFixture(),uid=randomUUID(),actor={user:{id:uid,username:'source-picker',superAdmin:false},workspaceId:f.wid},state={denyTarget:false,epoch:'epoch-1'},repo=new GovernanceRepositoryService({} as any,f.secrets);
 repo.comparison=vi.fn(async()=>f.row);const authz:any={permissionVersion:async()=>state.epoch,assertCluster:vi.fn(async(_u:any,cid:string)=>{if(state.denyTarget&&cid===f.peerCid)throw new ForbiddenException({code:'TARGET_READ_DENIED'});}),assertScopedResource:vi.fn(async()=>undefined),assertEntity:vi.fn(async()=>undefined),hasWholeWorkspace:vi.fn(async()=>true)};
 const service=new GovernanceService({} as any,{} as any,f.secrets,{} as any,authz,{resolve:async(_cid:string,wid:string)=>({id:wid})} as any,{} as any,{} as any,repo,{} as any,{} as any,{} as any);
 return{...f,uid,actor,state,repo,authz,governance:service};
}
describe('M10 authorized source object selection',()=>{
 it('lists unchanged Consumers independently of drift rows without payloads, hidden hashes or target addresses',async()=>{
  const f=pickerFixture(),result=await f.governance.sourceObjects(f.cid,f.id,{size:20},f.actor);
  expect(result.items).toContainEqual({objectKey:`consumers:${f.consumer}`,entityType:'consumers',nativeId:f.consumer,name:'unchanged-developer',referenceOnly:false,objectWorkspaceId:f.wid,eligible:true});
  const json=JSON.stringify(result);expect(json).not.toContain('payload');expect(json).not.toContain('internal-only.invalid');for(const hash of Object.values(f.native))expect(json).not.toContain(hash);
 });
 it('uses stable filtered server pagination with cursors fenced by filter and permission epoch',async()=>{
  const f=pickerFixture(),first=await f.governance.sourceObjects(f.cid,f.id,{size:1},f.actor);expect(first.items).toHaveLength(1);expect(first.nextCursor).toBeTruthy();
  const second=await f.governance.sourceObjects(f.cid,f.id,{size:1,cursor:first.nextCursor},f.actor);expect(second.items[0].objectKey).not.toBe(first.items[0].objectKey);
  await expect(f.governance.sourceObjects(f.cid,f.id,{size:1,cursor:first.nextCursor,entityType:'services'},f.actor)).rejects.toThrow();f.state.epoch='epoch-2';await expect(f.governance.sourceObjects(f.cid,f.id,{size:1,cursor:first.nextCursor},f.actor)).rejects.toThrow();
 });
 it('checks current permissions on both environments before returning any descriptors',async()=>{
  const f=pickerFixture();f.state.denyTarget=true;await expect(f.governance.sourceObjects(f.cid,f.id,{},f.actor)).rejects.toBeInstanceOf(ForbiddenException);expect(f.authz.assertEntity).not.toHaveBeenCalled();
 });
 it('marks shared references and Portal-managed rows ineligible rather than presenting them as writable selections',async()=>{
  const f=pickerFixture();Object.assign(f.inventory.objects[0],{managedBoundary:'portal'});Object.assign(f.inventory.objects[1],{referenceOnly:true});const envelope=governanceComparisonEnvelope(f.inventory,f.native);f.row.source_inventory_secret=f.secrets.encrypt(envelope,`governance:comparison-source:${f.id}`);f.row.source_inventory_hmac=f.secrets.fingerprint(envelope);
  expect((await f.governance.sourceObjects(f.cid,f.id,{},f.actor)).items.every((item:any)=>item.eligible===false)).toBe(true);
 });
 it('keeps legacy comparison readable while disabling new publish capability until re-comparison',async()=>{
  const f=pickerFixture();f.row.source_inventory_secret=f.secrets.encrypt(f.inventory,`governance:comparison-source:${f.id}`);f.row.source_inventory_hmac=f.secrets.fingerprint(f.inventory);
  expect((await f.governance.sourceObjects(f.cid,f.id,{},f.actor)).capabilities.promotePlan).toBe(false);
 });
});

describe('M10 safe discovery for dedicated metadata roles',()=>{
 it.each(['lint','drift','promote'])('serves the fixed catalog to %s-only readers without granting other modules or writes',async module=>{
  const cid=randomUUID(),wid=randomUUID(),authz:any={assertCluster:vi.fn(async(_u:any,_c:string,m:string)=>{if(m!==module)throw new ForbiddenException({code:'MODULE_DENIED'});}),permissionVersion:async()=> 'epoch'},service=new GovernanceService({} as any,{} as any,new SecretService(),{} as any,authz,{resolve:async()=>({id:wid})} as any,{} as any,{} as any,{} as any,{} as any,{} as any,{} as any);
  await expect(service.catalog(cid,{user:{id:randomUUID(),username:'dedicated-role',superAdmin:false},workspaceId:wid})).resolves.toMatchObject({engineVersion:'kong-1.5-governance-v1'});
  expect(authz.assertCluster.mock.calls.every((args:any[])=>args[3]==='read')).toBe(true);
 });
 it('denies discovery when none of the four current module grants match',async()=>{
  const authz:any={assertCluster:vi.fn(async()=>{throw new ForbiddenException();})},service=new GovernanceService({} as any,{} as any,new SecretService(),{} as any,authz,{resolve:async()=>({id:randomUUID()})} as any,{} as any,{} as any,{} as any,{} as any,{} as any,{} as any);
  await expect(service.catalog(randomUUID(),{user:{id:randomUUID(),username:'unauthorized',superAdmin:false}})).rejects.toBeInstanceOf(ForbiddenException);
 });
});
