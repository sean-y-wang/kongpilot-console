import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {businessAbsenceFixture as fixture,observe} from './helpers/workflow-business-absence-fixture';
import {WorkflowBusinessScopedReadService} from '../../apps/console-api/src/modules/workflows/workflow-business-scoped-read.service';
import {SnapshotCryptoService} from '../../apps/console-api/src/modules/config-storage/snapshot-crypto.service';
import {isServiceHostReferencePoint,isServiceHostTargetCollection,validServiceHostReference} from '../../apps/console-api/src/modules/workflows/workflow-service-host-reference';
import {WorkflowScheduleCandidateReadService} from '../../apps/console-api/src/modules/workflows/workflow-schedule-candidate-read.service';
const id=(n:number)=>`9b000000-0000-4000-8000-${String(n).padStart(12,'0')}`;
type Fixture=Awaited<ReturnType<typeof fixture>>;
beforeEach(()=>vi.stubEnv('CONSOLE_ENCRYPTION_KEY','ca'.repeat(32)));afterEach(()=>vi.unstubAllEnvs());
async function reseal(f:Fixture){
 const {nested,job,secrets,tables}=f,version=tables.configuration_plan_versions[0],material=tables.configuration_materials[0];
 const identity={clusterId:f.cid,workspaceId:f.wid,jobId:version.source_job_id,materialId:material.id,artifactId:version.artifact_id,artifactKind:'plan' as const};
 const crypto=new SnapshotCryptoService(secrets);
 await crypto.withKey(identity,material.wrapped_key_secret,async key=>{
  nested.steps.forEach((s:any)=>{s.bodyHmac=secrets.fingerprint(s.body);s.beforeHmac=secrets.fingerprint(s.before??null);
   s.nativeRequests.forEach((r:any)=>{r.bodyHmac=secrets.fingerprint(r.body);r.beforeHmac=s.beforeHmac;});});
  const hash=secrets.fingerprint(nested);job.plan_hash=hash;version.plan_hash=hash;version.input_hmac=hash;
  version.steps_hmac=secrets.fingerprint(nested.steps);version.step_count=nested.steps.length;
  version.native_packet_count=nested.steps.reduce((n:number,s:any)=>n+s.nativeRequests.length,0);
  version.manifest_ciphertext=crypto.encrypt(key,identity,{section:'manifest',key:'plan'},nested);
  tables.configuration_plan_objects=nested.steps.map((s:any)=>({cluster_id:f.cid,workspace_id:f.wid,plan_id:job.plan_id,plan_revision:1,step_id:s.stepId,step_order:s.stepOrder,
   object_workspace_id:s.objectWorkspaceId,entity_type:s.entityType,mutation_action:s.mutationAction,body_hmac:s.bodyHmac,before_hmac:s.beforeHmac,reference_only:false,
   blocker_codes:[],dependencies:s.dependencies,native_id:s.nativeId??null,allocated_native_id:s.allocatedNativeId??null,parent_id:s.parentId??null,credential_kind:s.credentialKind??null,
   payload_ciphertext:crypto.encrypt(key,identity,{section:'plan-step',key:s.stepId,entityType:s.entityType,nativeId:s.nativeId??s.allocatedNativeId??null,
    parentId:s.parentId??null,credentialKind:s.credentialKind??null},s),native_requests:s.nativeRequests.map((r:any)=>({method:r.method,path_hmac:secrets.fingerprint(r.canonicalPath),body_hmac:r.bodyHmac,before_hmac:r.beforeHmac}))}));
  f.plan.steps[0].metadata.planHash=hash;f.plan.steps[0].metadataPayloadHmac=secrets.fingerprint(f.plan.steps[0].metadata);
 });
 f.persist();f.input.draft.binding.workflowPlanHash=secrets.fingerprint(f.plan);
 f.input.draft.binding.subjectSeal=await f.compiler.subjectSealForPlan(f.plan,f.db);
}

async function setup(kind:'global'|'workspace'|'tag_group'='workspace',host='echo'){
 const f=await fixture();f.nested.steps[0].body.host=host;f.nested.steps[0].body.tags.push('team-pay');await reseal(f);f.compiler.installScopedReadBridge(new WorkflowBusinessScopedReadService());
 const read={user_id:f.actor,module:'upstreams',action:'read',cluster_id:f.cid,workspace_id:f.wid,scope_type:kind,scope_values:kind==='workspace'?[f.wid]:kind==='tag_group'?['team-pay']:[]};
 f.input.principal.grants=[...f.input.principal.grants,read];f.tables.iam_effective_grants=f.input.principal.grants;
 const parent={id:id(90),name:host,tags:['kos-ws-default','team-pay']};
 const point=(await f.compiler.resolveAbsenceReadScope(f.input)).resources.find(r=>r.serviceHostReference&&r.kind==='point')!;
 return{...f,parent,point};
}
const target=(f:Awaited<ReturnType<typeof setup>>,n=91)=>({id:id(n),target:'echo:8080',weight:100,upstream:{id:f.parent.id},tags:['team-pay']});
async function record(f:Awaited<ReturnType<typeof setup>>,r:any,value:any,status=200){await f.compiler.authorizeResponse({...f.input,resource:r,response:value,status});}
/** SQL/AES/material/grants are exercised here. These domain callbacks do not
 * authenticate an SDK404 or mint a transport handle; the fixed Runtime and
 * Validation observer tests cover that separate original-provenance gate. */
describe('fixed Service host relation material',()=>{
 it('compiles the genuine sealed long-name regression and authorizes only its exact parent',async()=>{
  const host='m11-b7cac3c8-configuration-after-revision-fixture-20261018-upstream',f=await setup('workspace',host);
  expect(host.length).toBe(67);expect(f.point.path).toBe(`/upstreams/${host}`);expect(f.point.serviceHostReference).toEqual({host,serviceIds:[f.service.id]});
  expect((await f.compiler.resolveAbsenceReadScope(f.input)).resources.some(r=>r.path==='/upstreams')).toBe(false);
  await f.compiler.runResponseScope(async()=>{await record(f,f.point,f.parent);
   const child=await f.compiler.resolveServiceHostTargetResource(f.input,f.point,f.parent);expect(child.path).toBe(`/upstreams/${f.parent.id}/targets`);
   await record(f,child,{data:[],next:null});await f.compiler.assertServiceHostReadComplete(f.input,f.point,f.parent,true);
  });expect(f.db.exec).not.toHaveBeenCalled();
 });

 it.each(['global','workspace','tag_group']as const)('uses only the exact current named upstream for %s principals and completes genuine full child EOF',async kind=>{
  const f=await setup(kind);expect(f.point).toMatchObject({path:'/upstreams/echo',entityType:'upstreams',required:false,allowAbsent:true,serviceHostReference:{host:'echo',serviceIds:[f.service.id]}});
  expect(f.point.entityId).toBeUndefined();expect((await f.compiler.resolveAbsenceReadScope(f.input)).resources.some(r=>r.path==='/upstreams')).toBe(false);
  await f.compiler.runResponseScope(async()=>{await record(f,f.point,f.parent);const child=await f.compiler.resolveServiceHostTargetResource(f.input,f.point,f.parent);
   expect(isServiceHostTargetCollection(child)).toBe(true);expect(child.path).toBe(`/upstreams/${f.parent.id}/targets`);expect(child.query).toEqual({size:100});
   await record(f,child,{data:[target(f)],next:null});await f.compiler.assertServiceHostReadComplete(f.input,f.point,f.parent,true);
  });expect(f.db.exec).not.toHaveBeenCalled();
 });
 it('does not include unrelated workspace rows in the compiled upstream relation scope',async()=>{
  const f=await setup();f.tables.workspaces.push({...f.workspace,id:id(80),code:'other',is_default:false});
  const scope=await f.compiler.resolveAbsenceReadScope(f.input);expect(scope.resources.filter(r=>r.entityType==='upstreams').map(r=>r.path)).toEqual(['/upstreams/echo']);
 });
 it('groups shared Service hosts into canonical sorted UUID selectors',async()=>{
  const f=await setup(),copy=structuredClone(f.nested.steps[0]);copy.stepId=id(81);copy.stepOrder=2;copy.allocatedNativeId=id(82);copy.objectKey=`services:${id(82)}`;copy.body.id=id(82);copy.body.name='second';copy.nativeRequests[0].body=copy.body;f.nested.steps.push(copy);await reseal(f);
  const refs=(await f.compiler.resolveAbsenceReadScope(f.input)).resources.filter(r=>r.serviceHostReference);expect(refs).toHaveLength(1);expect(refs[0].serviceHostReference?.serviceIds).toEqual([f.service.id,id(82)]);
 });
 it('uses the sealed effective before host for a retries-only Service PATCH',async()=>{
  const f=await setup(),s=f.nested.steps[0];s.nativeId=f.service.id;s.allocatedNativeId=null;s.mutationAction='update';s.before={...f.service,retries:5};s.body={retries:4};s.nativeRequests=[{method:'PATCH',canonicalPath:`/services/${f.service.id}`,body:s.body}];await reseal(f);
  expect((await f.compiler.resolveAbsenceReadScope(f.input)).resources.find(r=>r.serviceHostReference)?.serviceHostReference?.host).toBe('echo');
 });
 it.each(['127.0.0.1','::1','[::1]'])('does not invent an upstream name lookup for IP host %s',async host=>{
  const f=await setup();f.nested.steps[0].body.host=host;await reseal(f);expect((await f.compiler.resolveAbsenceReadScope(f.input)).resources.some(r=>r.serviceHostReference)).toBe(false);
 });
 it.each([id(77),'../other','other/path','bad?host',''])('rejects ambiguous or unsafe fixed host %s',async host=>{
  const f=await setup();f.nested.steps[0].body.host=host;await reseal(f);await expect(f.compiler.resolveAbsenceReadScope(f.input)).rejects.toThrow();
 });
 it.each(['wrong-name','invalid-id','other-workspace','no-read','wrong-reference','changed-host','secret-parent']as const)('poisons the current relation for %s',async reason=>{
  const f=await setup();if(reason==='other-workspace')f.tables.workspaces.push({...f.workspace,id:id(80),code:'other',is_default:false});
  const raw={...f.parent,...(reason==='wrong-name'?{name:'other'}:reason==='invalid-id'?{id:'not-a-uuid'}:reason==='other-workspace'?{tags:['kos-ws-other']}:reason==='secret-parent'?{password:'fixture-only-not-live'}:{})};
  if(reason==='no-read'){f.input.principal.grants=f.input.principal.grants.filter((g:any)=>g.module!=='upstreams');f.tables.iam_effective_grants=f.input.principal.grants;}
  if(reason==='changed-host'){f.nested.steps[0].body.host='other';await reseal(f);}
  const resource=reason==='wrong-reference'?{...f.point,serviceHostReference:{host:'echo',serviceIds:[id(99)]}}:f.point;
  await expect(f.compiler.runResponseScope(async()=>{await expect(record(f,resource,raw)).rejects.toThrow();await expect(f.compiler.assertServiceHostReadComplete(f.input,f.point,f.parent,false)).rejects.toThrow();})).rejects.toThrow();
 });
 it.each(['executor','reviewer']as const)('rechecks each current %s READ/member independently from the same original raw fact',async role=>{
  const f=await setup();f.input.role=role;
  if(role==='reviewer'){const reviewer=id(88);f.tables.users.push({...f.user,id:reviewer});f.input.principal={...f.input.principal,user:{...f.input.principal.user,id:reviewer},permissionVersion:`${reviewer}:1:1`,grants:f.input.principal.grants.map((g:any)=>({...g,user_id:reviewer}))};f.tables.iam_effective_grants=[...f.tables.iam_effective_grants,...f.input.principal.grants];}
  await f.compiler.runResponseScope(async()=>{await record(f,f.point,f.parent);await f.compiler.assertServiceHostReadComplete(f.input,f.point,f.parent,false);});
  f.input.principal.grants=f.input.principal.grants.filter((g:any)=>g.module!=='upstreams');f.tables.iam_effective_grants=f.input.principal.grants;
  await expect(f.compiler.runResponseScope(()=>record(f,f.point,f.parent))).rejects.toThrow();
 });
 it.each(['missing-observation','forged-parent','changed-parent','revoked-read','old-scope']as const)('rejects %s when deriving a child collection',async reason=>{
  const f=await setup();let old:any;
  if(reason==='old-scope')await f.compiler.runResponseScope(async()=>{await record(f,f.point,f.parent);old=await f.compiler.resolveServiceHostTargetResource(f.input,f.point,f.parent);});
  await expect(f.compiler.runResponseScope(async()=>{
   if(!['missing-observation','old-scope'].includes(reason))await record(f,f.point,f.parent);
   if(reason==='revoked-read')f.tables.iam_effective_grants=f.input.principal.grants.filter((g:any)=>g.module!=='upstreams');
   if(reason==='old-scope')await record(f,old,{data:[],next:null});
   else await f.compiler.resolveServiceHostTargetResource(f.input,f.point,reason==='forged-parent'?{...f.parent,id:id(99)}:reason==='changed-parent'?{...f.parent,tags:['kos-ws-default']}:f.parent);
  })).rejects.toThrow();
 });
 it('does not treat optional selection as an observed parent or completed Targets EOF',async()=>{
  const f=await setup();await expect(f.compiler.runResponseScope(()=>f.compiler.assertServiceHostReadComplete(f.input,f.point,null,false))).rejects.toThrow();
  await expect(f.compiler.runResponseScope(async()=>{await record(f,f.point,f.parent);await f.compiler.assertServiceHostReadComplete(f.input,f.point,f.parent,true);})).rejects.toThrow();
 });
 it.each(['wrong-parent','row-no-read','partial-eof']as const)('rejects current Targets %s',async reason=>{
  const f=await setup('tag_group');await expect(f.compiler.runResponseScope(async()=>{
   await record(f,f.point,f.parent);const child=await f.compiler.resolveServiceHostTargetResource(f.input,f.point,f.parent);
   const raw={...target(f),...(reason==='wrong-parent'?{upstream:{id:id(99)}}:reason==='row-no-read'?{tags:['team-other']}:{})};
   await record(f,child,{data:[raw],next:reason==='partial-eof'?'http://kong:8001/next?offset=cursor':null});
   await f.compiler.assertServiceHostReadComplete(f.input,f.point,f.parent,true);
  })).rejects.toThrow();
 });
 it('accepts only an already-observed missing name for absence closure and never derives Targets from it',async()=>{
  const f=await setup();await f.compiler.runResponseScope(async()=>{await record(f,f.point,null,404);await f.compiler.assertServiceHostReadComplete(f.input,f.point,null,true);});
  await expect(f.compiler.runResponseScope(async()=>{await record(f,f.point,null,404);await f.compiler.resolveServiceHostTargetResource(f.input,f.point,f.parent);})).rejects.toThrow();
 });
 it.each([403,500,401])('does not convert response status %s to a missing upstream',async status=>{
  const f=await setup();await expect(f.compiler.runResponseScope(()=>record(f,f.point,null,status))).rejects.toThrow();
 });
 it('does not invent upstream READ for a missing upstream under a Service entity-only scope',async()=>{
  const f=await setup();f.input.principal.grants=f.input.principal.grants.filter((g:any)=>g.module!=='upstreams').map((g:any)=>({...g,cluster_id:f.cid,workspace_id:f.wid,scope_type:'entity',scope_values:[{entity_type:'services',entity_id:f.service.id}]}));f.tables.iam_effective_grants=f.input.principal.grants;
  await f.compiler.assertServiceHostParticipant(f.input,f.point,null,404,[],true,{serviceId:f.service.id,before:null});
  // A present row cannot be relabeled as missing by this fixed domain path;
  // the Runtime must retain the original private SDK status association.
  await expect(f.compiler.assertServiceHostParticipant(f.input,f.point,f.parent,200,[],false)).rejects.toThrow();
 });
 it('rejects a missing-name participant after the original current Service feature scope is revoked',async()=>{
  const f=await setup();f.input.principal.grants=f.input.principal.grants.filter((g:any)=>g.module!=='upstreams');f.tables.iam_effective_grants=f.input.principal.grants;
  f.tables.iam_effective_grants=f.tables.iam_effective_grants.filter((g:any)=>g.module!=='snapshots');
  await expect(f.compiler.assertServiceHostParticipant(f.input,f.point,null,404,[],false,{serviceId:f.service.id,before:null})).rejects.toThrow();
 });
});

describe('fixed Service host participant checks',()=>{
 it('requires the original current Service observation for a missing-name participant',async()=>{
  const f=await setup();await expect(f.compiler.assertServiceHostParticipant(f.input,f.point,null,404,[],false)).rejects.toThrow();
 });
 it('checks actual current Service READ/write and feature scopes while requiring no READ on a nonexistent upstream',async()=>{
  const f=await setup(),step=f.nested.steps[0];step.nativeId=f.service.id;step.allocatedNativeId=null;step.mutationAction='update';step.before={...f.service,retries:5};step.body={retries:4};step.nativeRequests=[{method:'PATCH',canonicalPath:`/services/${f.service.id}`,body:step.body}];await reseal(f);
  f.input.principal.grants=f.input.principal.grants.filter((g:any)=>g.module!=='upstreams').map((g:any)=>({...g,cluster_id:f.cid,workspace_id:f.wid,scope_type:'entity',scope_values:[{entity_type:'services',entity_id:f.service.id}]}));f.tables.iam_effective_grants=f.input.principal.grants;
  await f.compiler.assertServiceHostParticipant(f.input,f.point,null,404,[],true,{serviceId:f.service.id,before:step.before});
 });
 it.each(['missing-service-read','missing-service-write','foreign-service-id','historical-before','missing-feature-scope']as const)('rejects %s without inventing an upstream grant',async reason=>{
  const f=await setup(),step=f.nested.steps[0];step.nativeId=f.service.id;step.allocatedNativeId=null;step.mutationAction='update';step.before={...f.service,retries:5};step.body={retries:4};step.nativeRequests=[{method:'PATCH',canonicalPath:`/services/${f.service.id}`,body:step.body}];await reseal(f);
  f.input.principal.grants=f.input.principal.grants.filter((g:any)=>g.module!=='upstreams'&&!(reason==='missing-service-read'&&g.module==='services'&&g.action==='read')&&!(reason==='missing-service-write'&&g.module==='services'&&g.action==='write')&&!(reason==='missing-feature-scope'&&g.module==='snapshots'));f.tables.iam_effective_grants=f.input.principal.grants;
  const observation={serviceId:reason==='foreign-service-id'?id(99):f.service.id,before:reason==='historical-before'?{...step.before,retries:3}:step.before};
  await expect(f.compiler.assertServiceHostParticipant(f.input,f.point,null,404,[],false,observation)).rejects.toThrow();
 });
 it('uses a callback-free separate current-principal scope and restores an unmodified original executor scope',async()=>{
  const f=await setup();await f.compiler.runResponseScope(async()=>{
   await record(f,f.point,f.parent);const oldChild=await f.compiler.resolveServiceHostTargetResource(f.input,f.point,f.parent);
   const reviewer=id(88),input={...f.input,role:'reviewer',principal:{...f.input.principal,user:{...f.input.principal.user,id:reviewer},permissionVersion:`${reviewer}:1:1`,grants:f.input.principal.grants.map((g:any)=>({...g,user_id:reviewer}))}};
   f.tables.users.push({...f.user,id:reviewer});f.tables.iam_effective_grants=[...f.tables.iam_effective_grants,...input.principal.grants];
   await f.compiler.assertServiceHostParticipant(input,f.point,f.parent,200,[{data:[target(f)],next:null}],true);
   expect(await f.compiler.resolveServiceHostTargetResource(f.input,f.point,f.parent)).toEqual(oldChild);
   await f.compiler.assertServiceHostReadComplete(f.input,f.point,f.parent,false);
  });
 });
 it('does not make participant parent witnesses reusable in a later round',async()=>{
  const f=await setup();await f.compiler.assertServiceHostParticipant(f.input,f.point,f.parent,200,[{data:[],next:null}],true);
  await expect(f.compiler.runResponseScope(()=>f.compiler.resolveServiceHostTargetResource(f.input,f.point,f.parent))).rejects.toThrow();
 });
 it.each(['no-eof','early-eof','duplicate-id','page-size','page-count','unexpected-pages','false-absent-parent','wrong-target-parent']as const)('rejects %s in fixed observed pages',async reason=>{
  const f=await setup();let pages:any[]=[{data:[target(f)],next:null}],include=true,status:200|404=200,raw:any=f.parent;
  if(reason==='no-eof')pages=[{data:[],next:'http://kong:8001/next?offset=cursor'}];
  if(reason==='early-eof')pages=[{data:[],next:null},{data:[],next:null}];
  if(reason==='duplicate-id')pages=[{data:[target(f)],next:'cursor'},{data:[target(f)],next:null}];
  if(reason==='page-size')pages=[{data:Array.from({length:101},(_,i)=>target(f,100+i)),next:null}];
  if(reason==='page-count')pages=Array.from({length:6},()=>({data:[],next:null}));
  if(reason==='unexpected-pages')include=false;
  if(reason==='false-absent-parent'){status=404;raw=null;}
  if(reason==='wrong-target-parent')pages=[{data:[{...target(f),upstream:{id:id(99)}}],next:null}];
  await expect(f.compiler.assertServiceHostParticipant(f.input,f.point,raw,status,pages,include)).rejects.toThrow();
 });
 it('poisons an outer scope when a participant check fails, even if a caller catches it',async()=>{
  const f=await setup();await expect(f.compiler.runResponseScope(async()=>{
   await record(f,f.point,f.parent);await expect(f.compiler.assertServiceHostParticipant(f.input,f.point,{...f.parent,name:'other'},200,[],false)).rejects.toThrow();
   await expect(f.compiler.assertServiceHostReadComplete(f.input,f.point,f.parent,false)).rejects.toThrow();
  })).rejects.toThrow();
 });
 it('does not relax the generic response-scope reentry guard',async()=>{
  const f=await setup();await f.compiler.runResponseScope(async()=>{await expect(f.compiler.runResponseScope(async()=>{})).rejects.toThrow();});
 });
 it('rejects a late participant inherited from an already-closed original outer scope',async()=>{
  const f=await setup();let release!:()=>void,late!:Promise<void>;const barrier=new Promise<void>(resolve=>{release=resolve;});
  await f.compiler.runResponseScope(async()=>{late=(async()=>{await barrier;await f.compiler.assertServiceHostParticipant(f.input,f.point,f.parent,200,[],false);})();});
  release();await expect(late).rejects.toThrow();
 });
 it('rejects expiry queued after the last inner callback check but before the fixed method continuation',async()=>{
  const f=await setup(),als=(f.compiler as any).responses,original=als.run.bind(als);
  vi.spyOn(als,'run').mockImplementation((state:any,fn:any)=>original(state,async()=>{const result=await fn();queueMicrotask(()=>{state.expiresAt=Date.now()-1;});return result;}));
  await expect(f.compiler.assertServiceHostParticipant(f.input,f.point,f.parent,200,[],false)).rejects.toThrow();
 });
});
describe('fixed Service host selector structure',()=>{
 it('accepts only optional exact-name fixed resources and canonical service ID sets',async()=>{
  const f=await setup();expect(isServiceHostReferencePoint(f.point)).toBe(true);expect(validServiceHostReference(f.point.serviceHostReference)).toBe(true);
  for(const ref of [{host:'echo',serviceIds:[id(91),id(90)]},{host:'echo',serviceIds:[id(90),id(90)]},{host:'echo',serviceIds:[]},{host:id(90),serviceIds:[id(90)]},{host:'echo',serviceIds:[id(90)],extra:true}])expect(validServiceHostReference(ref)).toBe(false);
  for(const r of [{...f.point,required:true},{...f.point,entityId:id(90)},{...f.point,query:{size:100}},{...f.point,path:'/upstreams/other'},{...f.point,secrets:true}])expect(isServiceHostReferencePoint(r)).toBe(false);
 });
 it('normalizes optional selectors without granting candidate traffic or broadening ordinary point UUID validation',async()=>{
  const f=await setup(),candidate:any=new WorkflowScheduleCandidateReadService({}as any,f.secrets,{}as any,{}as any,{}as any,{}as any);
  const stored:any={draft:{binding:{clusterId:f.cid,workspaceId:f.wid,subjectSeal:{sourceScopes:[]}}}};
  const scope=await f.compiler.resolveAbsenceReadScope(f.input);expect(candidate.normalizeScope(scope,stored).resources.some((r:any)=>isServiceHostReferencePoint(r))).toBe(true);
  expect(()=>candidate.normalizeScope({...scope,resources:[{...f.point,serviceHostReference:undefined}]},stored)).toThrow();
  expect(()=>candidate.normalizeScope({...scope,resources:[{...f.point,required:true}]},stored)).toThrow();
 });
});
