import 'reflect-metadata';
import {randomUUID} from 'node:crypto';
import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {KongExecutionContextService} from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import {SecretService} from '../../apps/console-api/src/infrastructure/secret.service';
import {SnapshotCryptoService} from '../../apps/console-api/src/modules/config-storage/snapshot-crypto.service';
import {ConfigurationRepositoryService} from '../../apps/console-api/src/modules/config-storage/configuration-repository.service';
import {ConfigurationAccessService} from '../../apps/console-api/src/modules/configuration/configuration-access.service';
import {ConfigurationOriginService} from '../../apps/console-api/src/modules/configuration/configuration-origin.service';
import {ConfigurationService} from '../../apps/console-api/src/modules/configuration/configuration.service';
import {GovernancePromotionSourceService} from '../../apps/console-api/src/modules/governance/governance-promotion-source.service';
import {GovernanceRepositoryService} from '../../apps/console-api/src/modules/governance/governance-repository.service';
import {GovernanceAuthorityService} from '../../apps/console-api/src/modules/governance/governance-authority.service';
import {governanceComparisonEnvelope} from '../../apps/console-api/src/modules/governance/governance-comparison-material';
import {AuthorizationService} from '../../apps/console-api/src/modules/authorization/authorization.service';
import {NativeKongPolicyService} from '../../apps/console-api/src/modules/authorization/native-kong-policy.service';
import {WorkspaceResolverService} from '../../apps/console-api/src/modules/workspaces/workspace-resolver.service';
import {ENTITIES} from '../../apps/console-api/src/infrastructure/kong/policy';
import {workspaceTag} from '../../apps/console-api/src/infrastructure/kong/tags';
import type {ComparisonInventory} from '../../apps/console-api/src/modules/governance/comparison-types';

/** Actual Repo/ConfigAccess/GovernanceAuthority/Origin/source provider crypto,
 * WeakMaps and current grants. SQL tuples, locks and inventory wire capture are
 * explicit boundaries; SQL018 real PostgreSQL rollback script owns DB proof. */
function fixture(selectedFence=false){
 const secrets=new SecretService(),context=new KongExecutionContextService(),uid=randomUUID(),reviewer=randomUUID(),sid=randomUUID(),sourceCid=randomUUID(),targetCid=randomUUID(),sourceWid=randomUUID(),targetWid=randomUUID(),promotionId=randomUUID(),comparisonId=randomUUID();
 const actor={user:{id:uid,username:'origin-requester',superAdmin:false},workspaceId:targetWid,requestId:randomUUID(),ip:'192.0.2.11'};
 const sourceCluster={id:sourceCid,admin_url:'http://source-kong:8001',transport_scope:'a'.repeat(64),version:'1.5.1',execution_mode:'direct',revision:1,status:'healthy',enabled_plugins:[]};
 const targetCluster={id:targetCid,admin_url:'http://target-kong:8001',transport_scope:'b'.repeat(64),version:'1.5.1',execution_mode:'approval',revision:1,status:'healthy',enabled_plugins:[]};
 const sourceWorkspace={id:sourceWid,cluster_id:sourceCid,code:'source',name:'source',status:'active',revision:1,is_default:false},targetWorkspace={id:targetWid,cluster_id:targetCid,code:'target',name:'target',status:'active',revision:1,is_default:false};
 const users=new Map([uid,reviewer].map(id=>[id,{id,username:id,super_admin:false,status:'active',deleted_at:null,force_password_change:false,permissions_epoch:1,credential_epoch:1}]));
 const grant=(cid:string,wid:string,module:string,action:string)=>({cluster_id:cid,workspace_id:wid,module,action,scope_type:'workspace',scope_values:[wid]});
 const grants=new Map([uid,reviewer].map(id=>[id,[...[[sourceCid,sourceWid],[targetCid,targetWid]].flatMap(([cid,wid])=>['promote',...ENTITIES,'annotations'].map(module=>grant(cid,wid,module,'read'))),...[[sourceCid,sourceWid],[targetCid,targetWid]].map(([cid,wid])=>grant(cid,wid,'promote',id===uid?'write':'read')),grant(targetCid,targetWid,'snapshots','write'),grant(targetCid,targetWid,'snapshots','read')]]));
 const scope=(cid:string,wid:string,physical:string)=>({clusterId:cid,workspaceId:wid,transportScope:physical,kind:'workspace' as const,rootIds:[]});
 const source:ComparisonInventory={scope:scope(sourceCid,sourceWid,sourceCluster.transport_scope),objects:[{entityType:'services',nativeId:randomUUID(),objectWorkspaceId:sourceWid,payload:{name:'source-service',host:'source.internal',tags:['workspace:source']}}],schemas:{},pluginSchemas:{},enabledPlugins:[],version:'1.5.1',adapterVersion:'kong-1.5',completeness:'complete',projection:false,consistency:'console_fenced_best_effort'};
 const target:ComparisonInventory={...structuredClone(source),scope:scope(targetCid,targetWid,targetCluster.transport_scope),objects:[]};
 const sourceCertificate={entityType:'certificates' as const,nativeId:randomUUID(),objectWorkspaceId:sourceWid,payload:{tags:['workspace:source']},certificate:{state:'valid' as const,fingerprint:'e'.repeat(64)}};
 const targetCertificate={...structuredClone(sourceCertificate),nativeId:randomUUID(),objectWorkspaceId:targetWid,payload:{tags:['workspace:target']}};
 source.objects=[...source.objects,sourceCertificate];target.objects=[targetCertificate];
 const rawSource=new Map(source.objects.map(object=>[`${object.entityType}:${object.nativeId}`,{...object.payload,id:object.nativeId,...(object.entityType==='certificates'?{cert:'fixture-source-certificate',key:'fixture-source-private-key'}:{})}])),
   rawTarget=new Map(target.objects.map(object=>[`${object.entityType}:${object.nativeId}`,{...object.payload,id:object.nativeId,cert:'fixture-target-certificate',key:'fixture-target-private-key'}]));
 const fingerprints=(raw:Map<string,any>)=>Object.fromEntries([...raw].map(([key,payload])=>[key,secrets.fingerprint(payload)]));
 const sourceEnvelope=governanceComparisonEnvelope(source,fingerprints(rawSource)),targetEnvelope=governanceComparisonEnvelope(target,fingerprints(rawTarget));
 const selection={targetWorkspaceCode:'target',includeSecrets:false,includeCredentials:false},policy={includeSecrets:false,includeCredentials:false};
 const parent:any={id:promotionId,comparison_id:comparisonId,actor_id:uid,cluster_id:sourceCid,workspace_id:sourceWid,target_cluster_id:targetCid,target_workspace_id:targetWid,state:'planning',request_hmac:'c'.repeat(64),selection_secret:secrets.encrypt(selection,`governance:promotion-selection:${promotionId}`),selection_hmac:secrets.fingerprint(selection),source_inventory_hmac:secrets.fingerprint(sourceEnvelope),target_inventory_hmac:secrets.fingerprint(targetEnvelope)};
 const comparison:any={id:comparisonId,cluster_id:sourceCid,workspace_id:sourceWid,target_cluster_id:targetCid,target_workspace_id:targetWid,actor_id:uid,quality:'complete',policy,policy_hmac:secrets.fingerprint(policy),source_inventory_secret:secrets.encrypt(sourceEnvelope,`governance:comparison-source:${comparisonId}`),target_inventory_secret:secrets.encrypt(targetEnvelope,`governance:comparison-target:${comparisonId}`),source_inventory_hmac:secrets.fingerprint(sourceEnvelope),target_inventory_hmac:secrets.fingerprint(targetEnvelope)};
 const state:any={epoch:1,sessionActive:true,sessions:new Set([sid]),jobs:new Map(),bindings:new Map(),planOrigins:new Map(),failEvidence:false};const copy=(v:any)=>v==null?v:structuredClone(v);
 const db:any={one:vi.fn(async(sql:string,p:any[]=[])=>{
  if(sql.includes('iam_epoch'))return{version:state.epoch};
  if(sql.includes('FROM users')){const u=users.get(p[0]);return u?.status==='active'&&!u.deleted_at?copy(u):null;}
  if(sql.includes('FROM auth_sessions'))return state.sessionActive&&state.sessions.has(p[0])&&p[1]===uid?{id:p[0],expires_at:new Date(Date.now()+600000),credential_epoch:1}:null;
  if(sql.includes('FROM governance_promotions'))return p[0]===promotionId?copy(parent):null;
  if(sql.includes('FROM promotion_recovery_bindings'))return null;
  if(sql.includes('FROM governance_comparisons'))return p[0]===comparisonId&&p[1]===sourceCid&&p[2]===sourceWid?copy(comparison):null;
  if(sql.includes('FROM configuration_job_origin_bindings'))return copy(state.bindings.get(p[2]));
  if(sql.startsWith('SELECT j.required_origin_kind,j.required_origin_id,j.required_origin_hmac FROM configuration_plans'))return copy(state.planOrigins.get(p[0]));
  if(sql.includes('FROM metrics_write_fences'))return{count:'0',latest_time:null,latest_id:null,unsettled:'0'};
  if(sql.includes('FROM mutation_operations'))return{count:'0'};
  if(sql.includes('FROM clusters'))return copy(p[0]===sourceCid?sourceCluster:p[0]===targetCid?targetCluster:null);
  if(sql.includes('FROM workspaces'))return copy(p[0]===sourceCid&&p[1]===sourceWid?sourceWorkspace:p[0]===targetCid&&p[1]===targetWid?targetWorkspace:null);
  if(sql.startsWith('INSERT INTO configuration_jobs')){
   const[id,cluster_id,workspace_id,transport_scope,actor_id,origin_session_id,authority_expires_at,kind,idempotency_key,request_hmac,request_id,scope_kind,root_ids,input_secret,permission_version,credential_epoch,cluster_revision,workspace_revision,capture_epoch,execution_mode,approval_required,origin_type,required_origin_kind,required_origin_id,required_origin_hmac]=p;
   if(p.length!==25||cluster_id!==targetCid||workspace_id!==targetWid||actor_id!==uid||origin_session_id!==sid)throw new Error('Configuration origin INSERT tuple mismatch');
   const row={id,cluster_id,workspace_id,transport_scope,actor_id,origin_session_id,authority_expires_at,kind,idempotency_key,request_hmac,request_id,scope_kind,root_ids,input_secret,permission_version,credential_epoch,cluster_revision,workspace_revision,capture_epoch,execution_mode,approval_required,origin_type,required_origin_kind,required_origin_id,required_origin_hmac,state:'pending',revision:1,lease_generation:1,safe_progress:{},created_at:new Date().toISOString()};state.jobs.set(id,row);return copy(row);
  }
  if(sql.includes('FROM configuration_jobs'))return copy(sql.includes('cluster_id=$1')?[...state.jobs.values()].find((j:any)=>j.cluster_id===p[0]&&j.workspace_id===p[1]&&j.actor_id===p[2]&&j.idempotency_key===p[3]):state.jobs.get(p[0]));
  throw new Error(`Unexpected SQL one: ${sql}`);
 }),query:vi.fn(async(sql:string,p:any[]=[])=>{if(sql.includes('FROM iam_effective_grants'))return copy(grants.get(p[0])??[]);if(sql.includes('FROM clusters'))return copy([sourceCluster,targetCluster]);throw new Error(`Unexpected SQL list: ${sql}`);}),
 exec:vi.fn(async(sql:string,p:any[]=[])=>{
  if(sql.startsWith('INSERT INTO workspaces'))return 0;if(sql.startsWith('SELECT pg_advisory_xact_lock'))return 1;
  if(sql.startsWith('INSERT INTO configuration_job_origin_bindings')){if(p.length!==9||p[0]!==targetCid||p[1]!==targetWid||p[3]!=='governance-promote'||p[4]!==promotionId||p[6]!==sourceCid||p[7]!==sourceWid||p[8]!==comparisonId||!state.jobs.has(p[2]))throw new Error('Origin binding INSERT tuple mismatch');state.bindings.set(p[2],{cluster_id:p[0],workspace_id:p[1],job_id:p[2],origin_kind:p[3],origin_id:p[4],material_hmac:p[5],source_cluster_id:p[6],source_workspace_id:p[7],comparison_id:p[8]});return 1;}
  throw new Error(`Unexpected SQL write: ${sql}`);
 }),transaction:vi.fn(async(fn:any)=>{const before=copy(state);try{return await fn(db);}catch(e){Object.assign(state,before);throw e;}})};
 const workspaces=new WorkspaceResolverService(db),kong:any={request:vi.fn(async()=>{throw new Error('Metadata provenance test must not call Kong');})};
 const authz=new AuthorizationService(db,workspaces,kong,context),governanceRepo=new GovernanceRepositoryService(db,secrets),authority=new GovernanceAuthorityService(db,secrets,context,authz,workspaces,kong);authority.onModuleInit();
 const origin=new ConfigurationOriginService(db,secrets,context),configuration:any={installGovernancePromotionSourcePolicy:(policy:any)=>origin.install(policy)};
 context.installPromotionPlanningPolicy(origin.planningPolicy());
 const privateReceipts=new WeakMap<object,{handle:object;fingerprints:Record<string,string>}>(),inventory:any={capture:vi.fn(async(handle:any)=>{
   const isSource=(await authority.description(handle)).scope.clusterId===sourceCid,value=copy(isSource?source:target);privateReceipts.set(value,{handle,fingerprints:fingerprints(isSource?rawSource:rawTarget)});return value;
  }),privateFingerprints:vi.fn(async(handle:object,value:object)=>{const receipt=privateReceipts.get(value);if(!receipt||receipt.handle!==handle)throw new Error('Original private inventory receipt required');return{...receipt.fingerprints};})};
 if(selectedFence)inventory.selectedFingerprints=vi.fn(async(handle:any,selected:any[])=>{
  if((await authority.description(handle)).scope.clusterId!==sourceCid)throw new Error('Original source handle required');
  const current=fingerprints(rawSource),out:Record<string,string>={};for(const o of selected){const key=`${o.entityType}:${o.nativeId}`;if(current[key])out[key]=current[key];}return out;});
 const sourceProvider=new GovernancePromotionSourceService(db,secrets,context,governanceRepo,authority,inventory,configuration);sourceProvider.onModuleInit();
 const access=new ConfigurationAccessService(db,secrets,authz,workspaces,kong,context,{}as any,origin);access.onModuleInit();
 const repo=new ConfigurationRepositoryService(db,secrets,new SnapshotCryptoService(secrets),access);repo.installOriginPolicy(origin.storagePolicy());
 const ref=()=>((origin as any).load(promotionId) as Promise<any>).then(loaded=>loaded.ref);
 const run=<T>(fn:()=>Promise<T>)=>context.runHttp({requestId:actor.requestId},async()=>{context.bindHttpActor(actor.user,sid);const close=context.captureHttpCloser();try{return await context.runActor({actor:actor.user,clusterId:targetCid,workspaceId:targetWid,module:'snapshots',action:'write'},()=>origin.run(fn));}finally{close();}});
 const runSource=<T>(fn:()=>Promise<T>)=>context.runHttp({requestId:actor.requestId},async()=>{context.bindHttpActor(actor.user,sid);const close=context.captureHttpCloser();try{return await context.runActor({actor:actor.user,clusterId:sourceCid,workspaceId:sourceWid,module:'promote',action:'write'},()=>origin.run(fn));}finally{close();}});
 const prepare=async()=>{const originRef=await ref();await origin.prepare(originRef,actor);const handle=await access.acquireJob({actor:actor.user,clusterId:targetCid,workspaceId:targetWid,kind:'workspace',rootIds:[],purpose:'import',kindOfJob:'import',idempotencyKey:'original-promotion-plan'});origin.permitJob(handle,originRef);return{originRef,handle};};
 const create=async(handle:any,originRef:any)=>repo.createJob(handle,{scope:target.scope,kind:'import',idempotencyKey:'original-promotion-plan',input:{documentHash:'d'.repeat(64)},originRef,expiresAt:new Date(Date.now()+120000).toISOString(),writeEvidence:async()=>{if(state.failEvidence)throw new Error('Audit storage failed');}});
 return{context,secrets,actor,uid,reviewer,sid,sourceCid,targetCid,sourceWid,targetWid,sourceCluster,targetCluster,sourceWorkspace,targetWorkspace,parent,comparison,source,target,state,grants,users,origin,access,repo,sourceProvider,db,kong,authz,workspaces,authority,run,runSource,prepare,create,ref,rawSource,rawTarget,inventory,privateReceipts};
}
beforeEach(()=>vi.stubEnv('CONSOLE_ENCRYPTION_KEY','ac'.repeat(32)));afterEach(()=>vi.unstubAllEnvs());
describe('M10 actual repository and fixed source-origin provider integration',()=>{
 it('registers the exact original immutable provenance via genuine target ConfigAccess and a live source Gov read handle',async()=>{
  const f=fixture();await f.run(async()=>{const {handle,originRef}=await f.prepare(),result=await f.create(handle,originRef);
   expect(f.state.jobs.get(result.id)).toMatchObject({actor_id:f.uid,origin_session_id:f.sid,required_origin_kind:'governance-promote',required_origin_id:f.parent.id,required_origin_hmac:originRef.materialHmac});
   expect(f.state.bindings.get(result.id)).toMatchObject({source_cluster_id:f.sourceCid,source_workspace_id:f.sourceWid,origin_id:f.parent.id,comparison_id:f.comparison.id});
   await expect(f.origin.assertJob(f.state.jobs.get(result.id),'read',f.uid)).resolves.toBeUndefined();
  });expect(f.kong.request).not.toHaveBeenCalled();
 });
 it('a copied ConfigAccess handle or pasted originRef cannot create a job or provenance row',async()=>{
  const f=fixture();await f.run(async()=>{const {handle,originRef}=await f.prepare();await expect(f.create({...handle},originRef)).rejects.toMatchObject({response:{code:'CONFIGURATION_AUTHORITY_REQUIRED'}});});expect(f.state.jobs.size).toBe(0);expect(f.state.bindings.size).toBe(0);
 });
 it('a genuine target handle without the actual prepared source permit fails and rolls back the job',async()=>{
  const f=fixture();await f.run(async()=>{const originRef=await f.ref(),handle=await f.access.acquireJob({actor:f.actor.user,clusterId:f.targetCid,workspaceId:f.targetWid,kind:'workspace',rootIds:[],purpose:'import',kindOfJob:'import',idempotencyKey:'original-promotion-plan'});
   await expect(f.create(handle,originRef)).rejects.toMatchObject({response:{code:'CONFIGURATION_ORIGIN_JOB_PERMIT_REQUIRED'}});
  });expect(f.state.jobs.size).toBe(0);expect(f.state.bindings.size).toBe(0);
 });
 it.each(['source-promote','target-promote','source-native','inactive','password-reset','foreign-workspace','restricted-scope','material'])('revoked/changed %s source eligibility stops registration before a native request',async(kind)=>{
  const f=fixture();await f.run(async()=>{const {handle,originRef}=await f.prepare(),g=f.grants.get(f.uid)!;
   if(kind==='source-promote')f.grants.set(f.uid,g.filter(x=>!(x.cluster_id===f.sourceCid&&x.module==='promote')));if(kind==='target-promote')f.grants.set(f.uid,g.filter(x=>!(x.cluster_id===f.targetCid&&x.module==='promote')));if(kind==='source-native')f.grants.set(f.uid,g.filter(x=>!(x.cluster_id===f.sourceCid&&x.module==='services')));
   if(kind==='inactive')f.users.get(f.uid)!.status='disabled';if(kind==='password-reset')f.users.get(f.uid)!.force_password_change=true;if(kind==='foreign-workspace')g.filter(x=>x.cluster_id===f.sourceCid).forEach(x=>{x.workspace_id=randomUUID();x.scope_values=[x.workspace_id];});if(kind==='restricted-scope')g.filter(x=>x.module==='promote').forEach(x=>{x.scope_type='tag_group';x.scope_values=['team:pay'];});if(kind==='material')f.parent.selection_hmac='e'.repeat(64);
   await expect(f.create(handle,originRef)).rejects.toBeDefined();
  });expect(f.state.jobs.size).toBe(0);expect(f.state.bindings.size).toBe(0);expect(f.kong.request).not.toHaveBeenCalled();
 });
 it('business-audit failure rolls back both configuration job and exact immutable origin binding',async()=>{
  const f=fixture();await f.run(async()=>{const {handle,originRef}=await f.prepare();f.state.failEvidence=true;await expect(f.create(handle,originRef)).rejects.toThrow('Audit storage failed');});expect(f.state.jobs.size).toBe(0);expect(f.state.bindings.size).toBe(0);
 });
 it('the independent reviewer SQL source-grant checks do not adopt their identity or borrow executor SID',async()=>{
  const f=fixture(),snap=vi.spyOn((f.access as any).authz,'snapshot');await f.run(async()=>{const {handle,originRef}=await f.prepare(),created=await f.create(handle,originRef);await expect(f.sourceProvider.assertGrants(f.parent.id,f.reviewer,'approve')).resolves.toBeUndefined();
   expect(f.context.current().actor!.id).toBe(f.uid);expect(f.context.current().sessionId).toBe(f.sid);await expect(f.origin.assertJob(f.state.jobs.get(created.id),'read',f.reviewer)).resolves.toBeUndefined();
  });expect(snap.mock.calls.every(([actor]:any)=>actor.id===f.uid)).toBe(true);expect(f.db.one.mock.calls.some(([sql,p]:any)=>sql.includes('FROM auth_sessions')&&p[1]===f.reviewer)).toBe(false);
 });
 it('all fixed policies reject a second bootstrap installation',()=>{const f=fixture();expect(()=>f.repo.installOriginPolicy(f.origin.storagePolicy())).toThrow();expect(()=>f.sourceProvider.onModuleInit()).toThrow();});
 it.each(['source','target']as const)('rejects a redacted %s secret-only change despite unchanged public inventory',async(side)=>{
  const f=fixture(),raw=side==='source'?f.rawSource:f.rawTarget,certificate=[...raw.values()].find(value=>value.key)!;certificate.key='fixture-secret-changed-after-comparison';
  await expect(f.run(()=>f.prepare())).rejects.toMatchObject({response:{code:'CONFIGURATION_ORIGIN_SOURCE_CHANGED'}});expect(f.state.jobs.size).toBe(0);expect(f.kong.request).not.toHaveBeenCalled();
 });
 it('approved per-packet fence re-checks only the selected source objects against plan-time fingerprints and still stops on a changed raw-only secret',async()=>{
  const f=fixture(true);await f.run(async()=>{const {handle,originRef}=await f.prepare(),created=await f.create(handle,originRef);
   await expect(f.origin.beforeNativeSend(created.id,f.uid)).resolves.toBeUndefined();
   expect(f.inventory.selectedFingerprints).toHaveBeenCalledTimes(1);
   const selected=f.inventory.selectedFingerprints.mock.calls[0][1];expect(selected.length).toBeGreaterThan(0);
   expect(f.inventory.capture).toHaveBeenCalledTimes(2); // initial source/target only; no full source rescan per packet
   [...f.rawSource.values()].find(value=>value.key)!.key='fixture-changed-between-native-packets';
   await expect(f.origin.beforeNativeSend(created.id,f.uid)).rejects.toMatchObject({response:{code:'CONFIGURATION_ORIGIN_SOURCE_CHANGED'}});
   expect(f.inventory.capture).toHaveBeenCalledTimes(2);
  });expect(f.kong.request).not.toHaveBeenCalled();
 });
 it('approved per-packet fence fails closed when a selected source object disappears',async()=>{
  const f=fixture(true);await f.run(async()=>{const {handle,originRef}=await f.prepare(),created=await f.create(handle,originRef);
   const first=f.source.objects.find((o:any)=>f.rawSource.has(`${o.entityType}:${o.nativeId}`))!;
   for(const o of f.inventory.selectedFingerprints.mock.calls[0]?.[1]??[first])f.rawSource.delete(`${o.entityType}:${o.nativeId}`);
   await expect(f.origin.beforeNativeSend(created.id,f.uid)).rejects.toMatchObject({response:{code:'CONFIGURATION_ORIGIN_SOURCE_CHANGED'}});
  });
 });
 it('reuses the actual source handle and stops each native packet on a newly changed raw-only secret',async()=>{
  const f=fixture();await f.run(async()=>{const {handle,originRef}=await f.prepare(),created=await f.create(handle,originRef);
   await expect(f.origin.beforeNativeSend(created.id,f.uid)).resolves.toBeUndefined();
   [...f.rawSource.values()].find(value=>value.key)!.key='fixture-changed-between-native-packets';
   await expect(f.origin.beforeNativeSend(created.id,f.uid)).rejects.toMatchObject({response:{code:'CONFIGURATION_ORIGIN_SOURCE_CHANGED'}});
   const sourceCalls=f.inventory.capture.mock.calls.map(([candidate]:any)=>candidate);
   expect(f.inventory.capture).toHaveBeenCalledTimes(4); // initial source/target + two fresh source scans
   expect(sourceCalls[2]).toBe(sourceCalls[0]);expect(sourceCalls[3]).toBe(sourceCalls[0]);expect(sourceCalls[1]).not.toBe(sourceCalls[0]);expect(f.state.jobs.size).toBe(1);
  });expect(f.kong.request).not.toHaveBeenCalled();
 });
 it('reads authenticated legacy comparison history but never fills in missing native proof for a new Promote',async()=>{
  const f=fixture();for(const side of ['source','target']as const){const value=f[side];f.comparison[`${side}_inventory_secret`]=f.secrets.encrypt(value,`governance:comparison-${side}:${f.comparison.id}`);
   f.comparison[`${side}_inventory_hmac`]=f.secrets.fingerprint(value);f.parent[`${side}_inventory_hmac`]=f.comparison[`${side}_inventory_hmac`];}
  await expect(f.ref()).resolves.toMatchObject({kind:'governance-promote'});
  await expect(f.run(()=>f.prepare())).rejects.toMatchObject({response:{code:'CONFIGURATION_ORIGIN_PRIVATE_MANIFEST_REQUIRED'}});expect(f.inventory.capture).not.toHaveBeenCalled();expect(f.state.jobs.size).toBe(0);
 });
});

describe('M10 server-owned cross-cluster planning origin',()=>{
 it.each(['write','read']as const)('anchors nested public plan reads to the live outer %s facade frame without renewing the source handle or budget',async(action)=>{
  const f=fixture(),planId=randomUUID(),service=Object.assign(Object.create(ConfigurationService.prototype),{context:f.context,origins:f.origin});let outer:any,child:any,created:any,originRef:any;
  new NativeKongPolicyService(f.db,f.secrets,f.kong,f.context,f.authz,f.workspaces).install();
  await f.run(()=>service.withActor(f.targetCid,f.actor,action,async()=>{
   outer=f.context.current();originRef=await f.ref();f.state.planOrigins.set(planId,{required_origin_kind:originRef.kind,required_origin_id:originRef.originId,required_origin_hmac:originRef.materialHmac});
   await f.origin.preparePlan(planId,f.actor);const sourceHandle=f.inventory.capture.mock.calls[0][0];expect(f.inventory.capture).toHaveBeenCalledTimes(2);
   const read=()=>f.authority.runRead(sourceHandle,async()=>{
    const ticket=await f.context.authorizeRequest(f.sourceCluster,'GET','/services',undefined,{size:100,tags:workspaceTag('source')});
    await f.context.assertGovernanceBeforeSend(ticket);await f.context.authorizeResponse(ticket,{data:[],next:null});
   });await read();const consumed=f.authority.usage(sourceHandle);expect(consumed).toMatchObject({calls:1,pages:1});expect(consumed.bytes).toBeGreaterThan(0);
   await service.withActor(f.targetCid,f.actor,'read',async()=>{
    child=f.context.current();expect(child).not.toBe(outer);await f.origin.preparePlan(planId,f.actor);
    expect(f.inventory.capture).toHaveBeenCalledTimes(2);expect(f.authority.usage(sourceHandle)).toEqual(consumed);
   });
   expect(()=>f.context.assertGovernanceOrigin(child,f.uid,f.sid)).toThrow(expect.objectContaining({response:expect.objectContaining({code:'KONG_EXECUTION_CONTEXT_EXPIRED'})}));
   expect(f.context.current()).toBe(outer);await f.origin.preparePlan(planId,f.actor);expect(f.inventory.capture).toHaveBeenCalledTimes(2);
   await read();expect(f.authority.usage(sourceHandle)).toMatchObject({calls:2,pages:2,bytes:consumed.bytes*2});
   const {handle}=await f.prepare();created=await f.create(handle,originRef);await f.origin.beforeNativeSend(created.id,f.uid);
   expect(f.inventory.capture).toHaveBeenCalledTimes(3);expect(f.inventory.capture.mock.calls[2][0]).toBe(sourceHandle);
   expect(f.context.current().sessionId).toBe(f.sid);
  }));
  expect(()=>f.context.assertGovernanceOrigin(outer,f.uid,f.sid)).toThrow(expect.objectContaining({response:expect.objectContaining({code:'KONG_EXECUTION_CONTEXT_EXPIRED'})}));
  await expect(f.run(()=>f.origin.run(async()=>f.origin.beforeNativeSend(created.id,f.uid)))).rejects.toMatchObject({response:{code:'CONFIGURATION_ORIGIN_READ_PROOF_REQUIRED'}});
  expect(f.inventory.capture).toHaveBeenCalledTimes(3);expect(f.kong.request).not.toHaveBeenCalled();
 });
 const privateJob=async(f:ReturnType<typeof fixture>,purpose:'capture'|'apply',key:string)=>{
  const handle=await f.access.acquireJob({actor:f.actor.user,clusterId:f.targetCid,workspaceId:f.targetWid,kind:'workspace',rootIds:[],purpose,kindOfJob:purpose,idempotencyKey:key});
  const job=await f.repo.createJob(handle,{scope:f.target.scope,kind:purpose,idempotencyKey:key,input:{testBoundary:'explicit-synthetic-storage'},expiresAt:new Date(Date.now()+120000).toISOString(),writeEvidence:async()=>undefined});
  return{handle:await f.access.acquire(job.id),job};
 };
 it('retains planning restrictions across a genuine readonly target ConfigAccess capture and rejects a genuine write-job escalation',async()=>{
  const f=fixture(),wire:any[]=[],writeCallback=vi.fn(async()=>undefined);let writable:Awaited<ReturnType<typeof privateJob>>;
  new NativeKongPolicyService(f.db,f.secrets,f.kong,f.context,f.authz,f.workspaces).install();
  await f.run(async()=>{writable=await privateJob(f,'apply','outside-planning-original-apply');});
  await f.runSource(()=>f.origin.runTargetPlanning(f.parent.id,f.actor,async()=>{
   const readonly=await privateJob(f,'capture','inside-planning-original-capture');
   await f.access.runJob(readonly.handle,()=>f.access.runRead(readonly.handle,['/services'],async()=>{
    const frame=f.context.current();expect(frame).toMatchObject({clusterId:f.targetCid,workspaceId:f.targetWid,actor:{id:f.uid},sessionId:f.sid,kind:'internal-read',purpose:'capture'});
    const ticket=await f.context.authorizeRequest(f.targetCluster,'GET','/services',undefined,{size:100});await f.context.assertGovernanceBeforeSend(ticket);
    wire.push({method:'GET',clusterId:frame.clusterId,sessionId:frame.sessionId});await expect(f.context.authorizeResponse(ticket,{data:[],next:null})).resolves.toEqual({data:[],next:null});
    await expect(f.access.runJob(writable!.handle,writeCallback)).rejects.toMatchObject({response:{code:'PROMOTION_PLANNING_NATIVE_FORBIDDEN'}});
    expect(()=>f.context.runOperation({actor:f.actor.user,clusterId:f.targetCid,workspaceId:f.targetWid,operationId:randomUUID(),entityType:'services',entityId:randomUUID(),action:'update'},writeCallback)).toThrow(expect.objectContaining({response:expect.objectContaining({code:'PROMOTION_PLANNING_NATIVE_FORBIDDEN'})}));
   }));
  }));expect(writeCallback).not.toHaveBeenCalled();expect(wire).toEqual([{method:'GET',clusterId:f.targetCid,sessionId:f.sid}]);expect(f.kong.request).not.toHaveBeenCalled();
 });
 it('rechecks source grants after target capture GET authorization and before its simulated send boundary',async()=>{
  const f=fixture(),wire:any[]=[],nativePolicy=new NativeKongPolicyService(f.db,f.secrets,f.kong,f.context,f.authz,f.workspaces);nativePolicy.install();
  await expect(f.runSource(()=>f.origin.runTargetPlanning(f.parent.id,f.actor,async()=>{
   const readonly=await privateJob(f,'capture','planning-source-revocation-capture');
   await f.access.runJob(readonly.handle,()=>f.access.runRead(readonly.handle,['/services'],async()=>{
    const ticket=await f.context.authorizeRequest(f.targetCluster,'GET','/services',undefined,{size:100});
    f.grants.set(f.uid,f.grants.get(f.uid)!.filter(grant=>!(grant.cluster_id===f.sourceCid&&grant.module==='promote'&&grant.action==='write')));
    await f.context.assertGovernanceBeforeSend(ticket);wire.push('would-send');
   }));
  }))).rejects.toMatchObject({response:{code:'GOVERNANCE_PROMOTE_SCOPE_DENIED'}});
  expect(wire).toHaveLength(0);expect(f.kong.request).not.toHaveBeenCalled();expect([...f.state.jobs.values()].every((job:any)=>job.kind==='capture')).toBe(true);
 });
 it('registers the actual immutable target job origin inside the planning bridge using fresh genuine Gov and ConfigAccess handles',async()=>{
  const f=fixture();await f.runSource(()=>f.origin.runTargetPlanning(f.parent.id,f.actor,()=>f.context.runActor({actor:f.actor.user,clusterId:f.targetCid,workspaceId:f.targetWid,module:'snapshots',action:'write'},async()=>{
   const {handle,originRef}=await f.prepare(),created=await f.create(handle,originRef);
   expect(f.state.jobs.get(created.id)).toMatchObject({cluster_id:f.targetCid,workspace_id:f.targetWid,actor_id:f.uid,origin_session_id:f.sid,required_origin_id:f.parent.id,required_origin_hmac:originRef.materialHmac});
   expect(f.state.bindings.get(created.id)).toMatchObject({source_cluster_id:f.sourceCid,source_workspace_id:f.sourceWid,comparison_id:f.comparison.id});
   await expect(f.origin.assertJob(f.state.jobs.get(created.id),'plan',f.uid)).resolves.toBeUndefined();
  })));
  expect(f.inventory.capture).toHaveBeenCalledTimes(2);expect(f.kong.request).not.toHaveBeenCalled();
 });
 it('enters only the exact target planning namespace with the original actor and SID, then destroys the private claim',async()=>{
  const f=fixture(),entry=vi.spyOn(f.context,'runPromotionPlanning');let minted:object|undefined;
  await f.runSource(async()=>{
   expect(()=>f.context.runActor({actor:f.actor.user,clusterId:f.targetCid,workspaceId:f.targetWid,module:'snapshots',action:'write'},async()=>undefined)).toThrow(expect.objectContaining({response:expect.objectContaining({code:'KONG_ACTOR_SCOPE_MISMATCH'})}));
   await f.origin.runTargetPlanning(f.parent.id,f.actor,async()=>{
    minted=entry.mock.calls[0][0];expect(f.context.current()).toMatchObject({actor:{id:f.uid},sessionId:f.sid,clusterId:f.targetCid,workspaceId:f.targetWid});
    const proof=await f.origin.planningPolicy().verifyHandle(minted!);expect(proof).toMatchObject({promotionId:f.parent.id,sourceClusterId:f.sourceCid,sourceWorkspaceId:f.sourceWid,clusterId:f.targetCid,workspaceId:f.targetWid,transportScope:f.target.scope.transportScope});
    await f.context.runActor({actor:f.actor.user,clusterId:f.targetCid,workspaceId:f.targetWid,module:'snapshots',action:'write'},async()=>expect(f.context.current().sessionId).toBe(f.sid));
    await expect(f.origin.planningPolicy().verifyHandle({...minted})).rejects.toMatchObject({response:{code:'CONFIGURATION_ORIGIN_PLANNING_HANDLE_REQUIRED'}});
   });expect(f.context.current().clusterId).toBe(f.sourceCid);
  });
  await expect(f.origin.planningPolicy().verifyHandle(minted!)).rejects.toMatchObject({response:{code:'CONFIGURATION_ORIGIN_PLANNING_HANDLE_REQUIRED'}});
  expect(f.kong.request).not.toHaveBeenCalled();expect(f.state.jobs.size).toBe(0);
 });
 it.each(['ready','blocked']as const)('keeps only grant verification valid after planning ends in %s, without permitting a new source capture',async(state)=>{
  const f=fixture(),entry=vi.spyOn(f.context,'runPromotionPlanning');
  await f.runSource(()=>f.origin.runTargetPlanning(f.parent.id,f.actor,async()=>{
   f.parent.state=state;await expect(f.origin.planningPolicy().verifyHandle(entry.mock.calls[0][0])).resolves.toMatchObject({promotionId:f.parent.id});
   if(state==='blocked')await expect(f.sourceProvider.acquire(f.parent.id,f.actor)).rejects.toMatchObject({response:{code:'GOVERNANCE_PROMOTION_SOURCE_UNAVAILABLE'}});
  }));expect(f.inventory.capture).not.toHaveBeenCalled();expect(f.kong.request).not.toHaveBeenCalled();
 });
 it.each(['source-permission','target-permission','session','iam-epoch','user-epoch','credential-epoch','inactive','password-reset','selection','source-transport','target-transport','foreign-owner','uncertain']as const)('revalidates %s before continuing a genuine planning claim',async(kind)=>{
  const f=fixture(),entry=vi.spyOn(f.context,'runPromotionPlanning');
  await expect(f.runSource(()=>f.origin.runTargetPlanning(f.parent.id,f.actor,async()=>{
   const grants=f.grants.get(f.uid)!;
   if(kind==='source-permission')f.grants.set(f.uid,grants.filter(g=>!(g.cluster_id===f.sourceCid&&g.module==='promote')));
   if(kind==='target-permission')f.grants.set(f.uid,grants.filter(g=>!(g.cluster_id===f.targetCid&&g.module==='promote')));
   if(kind==='session')f.state.sessionActive=false;if(kind==='iam-epoch')f.state.epoch++;if(kind==='user-epoch')f.users.get(f.uid)!.permissions_epoch++;
   if(kind==='credential-epoch')f.users.get(f.uid)!.credential_epoch++;if(kind==='inactive')f.users.get(f.uid)!.status='disabled';if(kind==='password-reset')f.users.get(f.uid)!.force_password_change=true;
   if(kind==='selection'){const selection={targetWorkspaceCode:'target',includeSecrets:false,includeCredentials:false,includeEnvironmentFields:true};f.parent.selection_secret=f.secrets.encrypt(selection,`governance:promotion-selection:${f.parent.id}`);f.parent.selection_hmac=f.secrets.fingerprint(selection);}
   if(kind==='source-transport')f.sourceCluster.transport_scope='c'.repeat(64);if(kind==='target-transport')f.targetCluster.transport_scope='d'.repeat(64);
   if(kind==='foreign-owner')f.parent.actor_id=f.reviewer;if(kind==='uncertain')f.parent.state='uncertain';
   await f.origin.planningPolicy().verifyHandle(entry.mock.calls[0][0]);
  }))).rejects.toBeDefined();expect(f.kong.request).not.toHaveBeenCalled();expect(f.state.jobs.size).toBe(0);
 });
 it('cannot mint the planning claim from a target HTTP actor or a different request user',async()=>{
  const f=fixture();await expect(f.run(()=>f.origin.runTargetPlanning(f.parent.id,f.actor,async()=>undefined))).rejects.toMatchObject({response:{code:'CONFIGURATION_ORIGIN_PLANNING_SOURCE_REQUIRED'}});
  await expect(f.runSource(()=>f.origin.runTargetPlanning(f.parent.id,{...f.actor,user:{...f.actor.user,id:f.reviewer}},async()=>undefined))).rejects.toMatchObject({response:{code:'CONFIGURATION_ORIGIN_PLANNING_SOURCE_REQUIRED'}});
  expect(f.kong.request).not.toHaveBeenCalled();
 });
 it('does not widen a blocked parent into a reusable source refresh',async()=>{
  const f=fixture();await f.run(async()=>{const loaded=await(f.origin as any).load(f.parent.id),material=await f.sourceProvider.acquire(f.parent.id,f.actor),count=f.inventory.capture.mock.calls.length;
   f.parent.state='blocked';await expect(f.sourceProvider.refresh(f.parent.id,material.handle,f.actor)).rejects.toMatchObject({response:{code:'GOVERNANCE_PROMOTION_SOURCE_UNAVAILABLE'}});expect(f.inventory.capture).toHaveBeenCalledTimes(count);
   expect(loaded.parent.state).toBe('planning');
  });expect(f.kong.request).not.toHaveBeenCalled();
 });
});

describe('M10 marked job verifier without ambient Kong ALS',()=>{
 const markedApply=async(f:ReturnType<typeof fixture>)=>{
  const originRef=await f.ref();await f.origin.prepare(originRef,f.actor);
  const key='actual-marked-apply-verifier',handle=await f.access.acquireJob({actor:f.actor.user,clusterId:f.targetCid,workspaceId:f.targetWid,kind:'workspace',rootIds:[],purpose:'apply',kindOfJob:'apply',idempotencyKey:key});
  f.origin.permitJob(handle,originRef);
  const job=await f.repo.createJob(handle,{scope:f.target.scope,kind:'apply',idempotencyKey:key,input:{testBoundary:'synthetic-persisted-apply'},originRef,expiresAt:new Date(Date.now()+120000).toISOString(),writeEvidence:async()=>undefined});
  return{handle:await f.access.acquire(job.id),job,originRef};
 };
 it('verifies a genuine marked execution job through actual storage.exit using private source proof, then keeps per-packet checks tied to the real actor and SID',async()=>{
  const f=fixture(),ambient:any[]=[],originVerifier=vi.spyOn(f.origin,'assertJobVerifier'),delegate=vi.spyOn(f.sourceProvider,'assertVerifierCurrent'),nativeCurrent=vi.spyOn(f.sourceProvider,'assertCurrent');
  await f.run(async()=>{
   const job=await markedApply(f),original=f.access.verifyHandle.bind(f.access);
   vi.spyOn(f.access,'verifyHandle').mockImplementation(async handle=>{ambient.push(f.context.peek());return original(handle);});
   const beforeCapture=f.inventory.capture.mock.calls.length;
   await f.access.runJob(job.handle,async()=>{
    expect(ambient[0]).toBeNull();expect(f.context.current()).toMatchObject({actor:{id:f.uid},sessionId:f.sid,clusterId:f.targetCid,workspaceId:f.targetWid});
    expect(originVerifier).toHaveBeenCalledWith(expect.objectContaining({id:job.job.id,actor_id:f.uid,origin_session_id:f.sid}),'step',f.uid,f.sid,f.db);
    expect(delegate).toHaveBeenCalled();expect(f.inventory.capture).toHaveBeenCalledTimes(beforeCapture);
    await f.origin.beforeNativeSend(job.job.id,f.uid);expect(f.inventory.capture).toHaveBeenCalledTimes(beforeCapture+1);expect(nativeCurrent).toHaveBeenCalled();
   });
  });expect(f.kong.request).not.toHaveBeenCalled();
 });
 it.each(['actor','session','copied-config-handle','copied-source-handle','source-frame','closed-source-frame','revoked-source','revoked-session','changed-material']as const)('rejects %s at the private execution verifier boundary before dispatch',async(kind)=>{
  const f=fixture(),dispatch=vi.fn(async()=>undefined);await f.run(async()=>{
   const job=await markedApply(f),row=f.state.jobs.get(job.job.id),sourceHandle=f.inventory.capture.mock.calls[0][0],originalFrame=f.context.current();
   if(kind==='actor')row.actor_id=f.reviewer;if(kind==='session')row.origin_session_id=randomUUID();
   if(kind==='revoked-source')f.grants.set(f.uid,f.grants.get(f.uid)!.filter(g=>!(g.cluster_id===f.sourceCid&&g.module==='promote'&&g.action==='write')));
   if(kind==='revoked-session')f.state.sessionActive=false;if(kind==='changed-material')f.parent.selection_hmac='a'.repeat(64);
   if(kind==='closed-source-frame')f.context.captureHttpCloser()();
   if(kind==='copied-source-handle'||kind==='source-frame'){
    await expect(f.sourceProvider.assertVerifierCurrent(f.parent.id,kind==='copied-source-handle'?{...sourceHandle}:sourceHandle,{actorId:f.uid,sessionId:f.sid,frame:kind==='source-frame'?{...originalFrame}:originalFrame})).rejects.toMatchObject({response:{code:'GOVERNANCE_PROMOTE_VERIFIER_SOURCE_REQUIRED'}});
   }else await expect(f.access.runJob(kind==='copied-config-handle'?{...job.handle}as any:job.handle,dispatch)).rejects.toBeDefined();
  });expect(dispatch).not.toHaveBeenCalled();expect(f.inventory.capture).toHaveBeenCalledTimes(2);expect(f.kong.request).not.toHaveBeenCalled();
 });
 it('does not widen the ordinary source assertion into an ambient-free sender capability',async()=>{
  const f=fixture();await f.run(async()=>{
   const job=await markedApply(f),sourceHandle=f.inventory.capture.mock.calls[0][0],frame=f.context.current();
   await f.context.runConfigurationJob(job.handle,async()=>{
    await expect(f.sourceProvider.assertVerifierCurrent(f.parent.id,sourceHandle,{actorId:f.reviewer,sessionId:f.sid,frame})).rejects.toMatchObject({response:{code:'GOVERNANCE_PROMOTE_VERIFIER_SOURCE_REQUIRED'}});
    await expect(f.sourceProvider.assertVerifierCurrent(f.parent.id,sourceHandle,{actorId:f.uid,sessionId:randomUUID(),frame})).rejects.toMatchObject({response:{code:'GOVERNANCE_PROMOTE_VERIFIER_SOURCE_REQUIRED'}});
   });
   const verify=f.access.verifyHandle.bind(f.access);
   vi.spyOn(f.access,'verifyHandle').mockImplementation(async handle=>{
    expect(f.context.peek()).toBeNull();
    await expect(f.sourceProvider.assertCurrent(f.parent.id,sourceHandle)).rejects.toMatchObject({response:{code:'KONG_EXECUTION_CONTEXT_REQUIRED'}});
    await expect(f.origin.beforeNativeSend(job.job.id,f.uid)).rejects.toMatchObject({response:{code:'KONG_EXECUTION_CONTEXT_REQUIRED'}});
    return verify(handle);
   });await f.access.runJob(job.handle,async()=>undefined);
  });expect(f.kong.request).not.toHaveBeenCalled();
 });
 it('keeps a newly authenticated original owner able to read old plan provenance and safe receipts without borrowing the old execution SID',async()=>{
  const f=fixture(),planId=randomUUID(),newSid=randomUUID();let oldJob:any;
  await f.run(async()=>{const{handle,originRef}=await f.prepare();oldJob=await f.create(handle,originRef);f.state.planOrigins.set(planId,{required_origin_kind:originRef.kind,required_origin_id:originRef.originId,required_origin_hmac:originRef.materialHmac});});
  f.state.sessions.add(newSid);
  await f.context.runHttp({requestId:randomUUID()},async()=>{
   f.context.bindHttpActor(f.actor.user,newSid);const close=f.context.captureHttpCloser();try{
    await f.context.runActor({actor:f.actor.user,clusterId:f.targetCid,workspaceId:f.targetWid,module:'snapshots',action:'read'},()=>f.origin.run(async()=>{
     await f.origin.preparePlan(planId,f.actor);const row=f.state.jobs.get(oldJob.id);expect(row.origin_session_id).toBe(f.sid);
     await expect(f.origin.assertJobVerifier(row,'read',f.uid,newSid)).resolves.toBeUndefined();
     await expect(f.origin.assertJobVerifier(row,'step',f.uid,newSid)).rejects.toMatchObject({response:{code:'CONFIGURATION_ORIGIN_VERIFIER_PROOF_REQUIRED'}});
     const receipt=await f.access.acquireReceipt(row.id);await expect(f.repo.getJob(receipt,row.id)).resolves.toMatchObject({id:row.id});
     await expect(f.access.runJob(receipt,async()=>undefined)).rejects.toMatchObject({response:{code:'CONFIGURATION_JOB_REQUIRED'}});
    }));
   }finally{close();}
  });expect(f.kong.request).not.toHaveBeenCalled();
 });
});
