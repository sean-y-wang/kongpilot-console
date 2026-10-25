import 'reflect-metadata';
import { afterEach,beforeEach,describe,expect,it,vi } from 'vitest';
import { BadRequestException,ForbiddenException,ServiceUnavailableException } from '@nestjs/common';
import { AuthorizationService } from '../../apps/console-api/src/modules/authorization/authorization.service';
import { MutationService,MutationContext } from '../../apps/console-api/src/modules/mutations/mutation.service';
import { deriveImpact,impactOverlaps } from '../../apps/console-api/src/modules/mutations/mutation-impact';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { workspaceFixture,payWorkspaceId,opsWorkspaceId } from './workspace-test-fixture';
import { executionFixture } from './execution-test-fixture';
const cid='efc85a7f-d60d-45b9-8685-1efc6d4e776c',alias='aec85a7f-d60d-45b9-8685-1efc6d4e776c',physical='a'.repeat(64);
const actor={id:'a35313a2-9968-4818-9f31-7b3066ce1728',username:'writer',superAdmin:false};
function fixture(){
 const operations=new Map<string,any>(),secrets=new SecretService(),ws=workspaceFixture(cid),aliasWs=workspaceFixture(alias);
 const db:any={query:vi.fn(async(_sql:string,p:any[])=>[...operations.values()].filter(o=>['running','uncertain'].includes(o.state)&&o.id!==p[1])),one:vi.fn(async(sql:string,p:any[])=>{
  if(sql.includes('FROM clusters'))return {id:p[0],version:'1.5.1',execution_mode:'direct'};
  if(sql.includes('FROM recycle_entries'))return null;
  if(sql.includes('FROM mutation_operations'))return [...operations.values()].find(o=>o.cluster_id===p[0]&&(o.id===p[1]||o.idempotency_key===p[1]))??operations.get(p[0])??null;
  return null;
 }),exec:vi.fn(async(sql:string,p:any[])=>{
  if(sql.startsWith('INSERT INTO mutation_operations')){const [id,cluster_id,actor_id,action,idempotency_key,request_hash,workflow_id,request_id,entity_type,entity_id,before_secret,payload_secret,workspace_id,transport_scope,impact,parent_id,credential_kind]=p;operations.set(id,{id,cluster_id,actor_id,action,idempotency_key,request_hash,workflow_id,request_id,entity_type,entity_id,before_secret,payload_secret,workspace_id,transport_scope,impact:JSON.parse(impact),parent_id,credential_kind,state:'running'});return 1;}
  const o=operations.get(p[0]);if(!o)return 0;
  if(sql.includes('remote_started=true'))o.remote_started=true;
  else if(sql.includes('remote_completed=true'))Object.assign(o,{remote_completed:true,entity_id:p[1],result_secret:p[2]});
  else if(sql.includes("state='succeeded'"))Object.assign(o,{state:'succeeded',safe_result:JSON.parse(p[1])});
  else if(sql.includes('SET state=$2'))Object.assign(o,{state:p[1],error_code:p[2]});
  else if(sql.includes('SET impact=$2'))o.impact=JSON.parse(p[1]);
  return 1;
 }),transaction:vi.fn()};db.transaction.mockImplementation(async(fn:any)=>fn(db));
 const authz:any={assertCluster:vi.fn(async()=>{}),assertEntity:vi.fn(async()=>{}),isPlatformAdmin:vi.fn(async()=>false)};
 const kong:any={transportScope:vi.fn(async()=>physical),request:vi.fn(async(_cid:any,_method:any,path:string)=>({id:path.split('/').pop(),name:'public-name',host:'example.test',tags:['kos-ws-pay']}))};
 const redis:any={withLock:vi.fn(async(_key:any,fn:any)=>fn()),assertLeaseOwnership:vi.fn(async()=>{})},audit:any={append:vi.fn(async()=>{})};
 const resolver:any=Object.create(ws.resolver);for(const method of ['resolve','get','listScope','classify'])resolver[method]=(...args:any[])=>(args[0]===alias?aliasWs.resolver:ws.resolver)[method](...args);
 const mutations=new MutationService(db,redis,secrets,audit,kong,authz,resolver,executionFixture());
 const context:MutationContext={clusterId:cid,workspaceId:payWorkspaceId,actor,entityType:'services',action:'create',idempotencyKey:'first',payload:{name:'public-name',host:'example.test',tags:['kos-ws-pay']}};
 return {mutations,context,operations,db,kong,redis,audit,authz,secrets};
}
beforeEach(()=>{vi.stubEnv('APP_SECRET','unresolved-test-private-key-minimum-32-characters');vi.stubEnv('CONSOLE_ENCRYPTION_KEY','bd'.repeat(32));});
afterEach(()=>vi.unstubAllEnvs());
const unknown=()=>new ServiceUnavailableException({code:'KONG_WRITE_RESULT_UNKNOWN',message:'response lost'});
async function createUnknown(f:ReturnType<typeof fixture>){await expect(f.mutations.execute(f.context,async()=>{throw unknown();})).rejects.toMatchObject({status:503});return [...f.operations.values()][0];}

describe('M4 durable unresolved-operation exclusion',()=>{
 it('blocks a new key for the same named object even after browser recovery expires',async()=>{
  const f=fixture();const operation=await createUnknown(f),write=vi.fn();
  operation.created_at=new Date(Date.now()-30*86400000);
  await expect(f.mutations.execute({...f.context,idempotencyKey:'after-cache-expiry'},write)).rejects.toMatchObject({status:409,response:{code:'MUTATION_RECONCILIATION_REQUIRED',operationId:operation.id}});
  expect(write).not.toHaveBeenCalled();expect(f.operations.size).toBe(1);expect(f.redis.withLock).toHaveBeenLastCalledWith(`mutation:${physical}`,expect.anything());
 });
 it('blocks another actor and workspace from recreating a global natural name without exposing operation IDs',async()=>{
  const f=fixture();await createUnknown(f);const write=vi.fn();
  await expect(f.mutations.execute({...f.context,workspaceId:opsWorkspaceId,actor:{...actor,id:'ccba7e66-e5be-4d91-a0a4-9b761acdaffc'},idempotencyKey:'other-actor',payload:{name:'public-name',tags:['kos-ws-ops']}},write)).rejects.toMatchObject({response:{code:'MUTATION_RECONCILIATION_REQUIRED'}});
  try{await f.mutations.execute({...f.context,actor:{...actor,id:'ccba7e66-e5be-4d91-a0a4-9b761acdaffc'},idempotencyKey:'another'},write);}catch(e:any){expect(e.getResponse()).not.toHaveProperty('operationId');}
  expect(write).not.toHaveBeenCalled();
 });
 it('shares exclusion across registered aliases for the same physical Admin URL',async()=>{
  const f=fixture();await createUnknown(f);const write=vi.fn();
  await expect(f.mutations.execute({...f.context,clusterId:alias,idempotencyKey:'alias'},write)).rejects.toMatchObject({response:{code:'MUTATION_RECONCILIATION_REQUIRED'}});expect(write).not.toHaveBeenCalled();
 });
 it('keeps same-key uncertainty handling before the overlap guard',async()=>{
  const f=fixture();const operation=await createUnknown(f);f.db.query.mockClear();
  await expect(f.mutations.execute(f.context,vi.fn())).rejects.toMatchObject({response:{code:'MUTATION_RESULT_UNCERTAIN',operationId:operation.id}});expect(f.db.query).not.toHaveBeenCalled();
 });
 it('does not block unrelated natural names after a named uncertainty, or a recorded terminal validation failure',async()=>{
  const f=fixture();await createUnknown(f);const write=vi.fn(async()=>({id:'different',name:'different-name',tags:['kos-ws-pay']}));
  await expect(f.mutations.execute({...f.context,idempotencyKey:'unrelated',payload:{name:'different-name',host:'different.example',tags:['kos-ws-pay']}},write)).resolves.toMatchObject({id:'different'});
  const second=fixture();await expect(second.mutations.execute(second.context,async()=>{throw new BadRequestException({code:'KONG_VALIDATION_ERROR'});})).rejects.toMatchObject({status:400});
  await expect(second.mutations.execute({...second.context,idempotencyKey:'explicit-corrected'},write)).resolves.toMatchObject({id:'different'});
 });
 it('blocks a crashed running record even if remote_started=false',async()=>{
  const f=fixture();const operation=await createUnknown(f);Object.assign(operation,{state:'running',remote_started:false});
  await expect(f.mutations.execute({...f.context,idempotencyKey:'new'},vi.fn())).rejects.toMatchObject({response:{code:'MUTATION_RECONCILIATION_REQUIRED'}});
 });
 it('conservatively blocks invalid legacy NULL workspace evidence instead of treating it as default',async()=>{
  const f=fixture();const operation=await createUnknown(f);Object.assign(operation,{workspace_id:null,transport_scope:null,impact:null,before_secret:f.secrets.encrypt({id:'legacy',tags:['kos-ws-unknown']},`mutation:${operation.id}:before`)});
  await expect(f.mutations.execute({...f.context,idempotencyKey:'legacy-bypass',payload:{name:'unrelated',tags:['kos-ws-pay']}},vi.fn())).rejects.toMatchObject({response:{code:'MUTATION_RECONCILIATION_REQUIRED'}});expect(f.operations.size).toBe(1);
 });
 it('checks a captured graph against unresolved children before any destructive callback continues',async()=>{
  const f=fixture();await createUnknown(f);const write=vi.fn();
  const context={...f.context,entityType:'consumers',idempotencyKey:'graph-root',payload:{username:'customer',tags:['kos-ws-pay']}};
  await expect(f.mutations.execute(context,async()=>{await f.mutations.claimGraphImpact(context,[{type:'services',id:'affected-child',data:{name:'public-name',tags:['kos-ws-pay']}}]);return write();})).rejects.toMatchObject({response:{code:'MUTATION_RECONCILIATION_REQUIRED'}});
  expect(write).not.toHaveBeenCalled();expect(f.redis.assertLeaseOwnership).toHaveBeenCalled();
 });
 it('rederives legacy impacts after signing-key rotation so old uncertain writes remain blocked',async()=>{
  const f=fixture();await createUnknown(f);vi.stubEnv('APP_SECRET','rotated-test-private-key-minimum-32-characters');
  await expect(f.mutations.execute({...f.context,idempotencyKey:'rotated'},vi.fn())).rejects.toMatchObject({response:{code:'MUTATION_RECONCILIATION_REQUIRED'}});
 });
 it('reports post-write permission revocation as an uncertain 503 with the durable original receipt',async()=>{
  const f=fixture();f.authz.assertEntity.mockRejectedValue(new ForbiddenException());
  await expect(f.mutations.execute(f.context,async()=>({id:'created',tags:['kos-ws-pay']}))).rejects.toMatchObject({status:503,response:{code:'MUTATION_RESULT_UNCERTAIN',state:'uncertain'}});
  expect([...f.operations.values()][0]).toMatchObject({state:'uncertain',remote_completed:true});
 });
 it('returns an owner-only write-authorized safe receipt without requiring general read permission',async()=>{
  const f=fixture();const operation=await createUnknown(f);operation.safe_result={entity:{id:'object',config:{private:'private-value'}},secret:'private-value',entryId:'entry',state:'uncertain'};
  f.authz.assertCluster.mockImplementation(async(_actor:any,_cid:any,module:string,action:string)=>{if(module==='mutations'&&action==='read')throw new ForbiddenException();});
  const receipt=await f.mutations.operationByKey(cid,'first',actor,payWorkspaceId);
  expect(receipt.safe_result).toEqual({entity:{id:'object'},entryId:'entry',state:'uncertain'});expect(JSON.stringify(receipt)).not.toContain('private-value');
 });
});

describe('M4 server-derived secret-free impact identities',()=>{
 it('matches Target address across immutable history IDs and includes its real Upstream',()=>{
  const first=deriveImpact({entityType:'targets',entityId:'old',parentId:'upstream',action:'update',before:{target:'host:9000',weight:1}}),next=deriveImpact({entityType:'targets',entityId:'new',parentId:'upstream',action:'create',payload:{target:'host:9000'}});
  expect(impactOverlaps(first,next)).toBe(true);expect(impactOverlaps(first,deriveImpact({entityType:'upstreams',entityId:'upstream',action:'update'}))).toBe(true);
 });
 it('covers certificate/SNI, Service/Upstream and composite Plugin references',()=>{
  expect(impactOverlaps(deriveImpact({entityType:'certificates',action:'create',payload:{cert:'public',key:'SECRET',snis:['api.example']}}),deriveImpact({entityType:'snis',action:'create',payload:{name:'api.example'}}))).toBe(true);
  expect(impactOverlaps(deriveImpact({entityType:'services',action:'create',payload:{name:'svc',host:'pool'}}),deriveImpact({entityType:'upstreams',action:'create',payload:{name:'pool'}}))).toBe(true);
  expect(impactOverlaps(deriveImpact({entityType:'plugins',action:'create',payload:{name:'key-auth',service:{id:'svc'},consumer:{id:'customer'}}}),deriveImpact({entityType:'consumers',entityId:'customer',action:'delete'}))).toBe(true);
 });
 it('uses HMACs without leaking credential/config contents and conservatively covers anonymous native creation',()=>{
  const secret='API-secret-not-searchable',impact=deriveImpact({entityType:'credentials',action:'create',parentId:'consumer',credentialKind:'key-auth',payload:{key:secret,password:secret,config:{secret}}});
  expect(JSON.stringify(impact)).not.toContain(secret);expect(impact.keys.every(k=>/^[a-f0-9]{64}$/.test(k))).toBe(true);
  expect(impactOverlaps(deriveImpact({entityType:'certificates',action:'create',payload:{cert:'cert',key:secret}}),deriveImpact({entityType:'certificates',entityId:'existing',action:'update'}))).toBe(true);
  expect(impactOverlaps(deriveImpact({entityType:'certificates',action:'create',payload:{cert:'cert',key:secret}}),deriveImpact({entityType:'services',entityId:'svc',action:'update'}))).toBe(false);
 });
});


describe('M4 annotation mutation uses the real native identity and complete grants',()=>{
 function annotationFixture(){
  const f=fixture(),id='0d407e90-c9ae-42a3-8c99-885e66cf3472';
  let grants:any[]=['services','annotations'].map(module=>({module,action:'write',scope_type:'entity',cluster_id:cid,workspace_id:payWorkspaceId,
   scope_values:[{entity_type:'services',entity_id:id}]}));
  const execution=executionFixture(),resolver=workspaceFixture(cid).resolver;
  const authz=new AuthorizationService(f.db,resolver,f.kong,execution);
  vi.spyOn(authz,'snapshot').mockImplementation(async()=>({user:actor,grants,version:'current-epoch'}));
  const service=new MutationService(f.db,f.redis,f.secrets,f.audit,f.kong,authz,resolver,execution);
  const context:MutationContext={...f.context,entityType:'annotations',entityId:id,action:'update',
   before:{id,name:'public-name',host:'example.test',tags:['kos-ws-pay']},
   payload:{entityType:'services',entityId:id,workspaceId:payWorkspaceId,input:{revision:0,description:'example'}}};
  return {...f,service,context,id,setGrants:(next:any[])=>{grants=next;},getGrants:()=>grants};
 }
 it('accepts a typed Service whitelist grant for both native and annotation write without requiring an impossible annotations entity type',async()=>{
  const f=annotationFixture(),write=vi.fn(async()=>({kong_id:f.id,entity_type:'services',revision:1}));
  await expect(f.service.execute(f.context,write)).resolves.toMatchObject({kong_id:f.id,revision:1});
  expect(write).toHaveBeenCalledTimes(1);expect(f.kong.request).toHaveBeenCalledWith(cid,'GET',`/services/${f.id}`);
 });
 it('requires the native write grant independently of a valid annotation whitelist',async()=>{
  const f=annotationFixture();f.setGrants(f.getGrants().filter(g=>g.module==='annotations'));const write=vi.fn();
  await expect(f.service.execute(f.context,write)).rejects.toMatchObject({status:403});expect(write).not.toHaveBeenCalled();expect(f.operations.size).toBe(0);
 });
 it('does not splice annotation read on this object with annotation write on a sibling',async()=>{
  const f=annotationFixture(),native=f.getGrants()[0],annotation=f.getGrants()[1];
  f.setGrants([native,{...annotation,action:'read'},{...annotation,scope_values:[{entity_type:'services',entity_id:'0d407e90-c9ae-42a3-8c99-885e66cf3473'}]}]);
  await expect(f.service.execute(f.context,vi.fn())).rejects.toMatchObject({status:403});expect(f.operations.size).toBe(0);
 });
 it('refuses forged unsupported native types or a mismatched server-derived native ID before allocating a ledger',async()=>{
  const f=annotationFixture();for(const payload of [{...(f.context.payload as any),entityType:'annotations'},{...(f.context.payload as any),entityId:'different'}]){
   await expect(f.service.execute({...f.context,payload},vi.fn())).rejects.toMatchObject({status:403,response:{code:'ANNOTATION_SCOPE_UNVERIFIABLE'}});
  }expect(f.operations.size).toBe(0);
 });
 it('checks the fresh native fingerprint before metadata execution and preserves zero ledger writes on drift',async()=>{
  const f=annotationFixture();f.kong.request.mockResolvedValue({...f.context.before,host:'changed.example'});
  await expect(f.service.execute(f.context,vi.fn())).rejects.toMatchObject({status:409,response:{code:'ENTITY_CHANGED'}});expect(f.operations.size).toBe(0);
 });
 it('revocation denies a same-key annotation replay despite an already succeeded operation',async()=>{
  const f=annotationFixture(),write=vi.fn(async()=>({kong_id:f.id,entity_type:'services',revision:1}));await f.service.execute(f.context,write);
  f.setGrants(f.getGrants().filter(g=>g.module==='services'));
  await expect(f.service.execute(f.context,write)).rejects.toMatchObject({status:403});expect(write).toHaveBeenCalledTimes(1);
 });
 it('keeps the safe own receipt available to a write-only typed annotation principal using its original native identity',async()=>{
  const f=annotationFixture();await f.service.execute(f.context,async()=>({kong_id:f.id,entity_type:'services',revision:1,metadata:{internal:'private-config'}}));
  const receipt=await f.service.operationByKey(cid,f.context.idempotencyKey!,actor,payWorkspaceId);
  expect(receipt).toMatchObject({state:'succeeded',remote_completed:true,entity_id:f.id});expect(JSON.stringify(receipt)).not.toContain('private-config');
 });
});

describe('M4 historical mutation receipt minimizes child identifiers after demotion',()=>{
 function historicalFixture(action='delete'){
  const f=fixture(),serviceId='0d407e90-c9ae-42a3-8c99-885e66cf3472',pluginId='219293bb-c101-4250-a419-4a7c4d6af8e3',consumerId='441293bb-c101-4250-a419-4a7c4d6af8e3';
  let platform=true;
  const actorWithStaleFlag={...actor,superAdmin:true},execution=executionFixture(),resolver=workspaceFixture(cid).resolver;
  const authz=new AuthorizationService(f.db,resolver,f.kong,execution);
  const grants:any[]=['read','write','delete'].map(operation=>({module:'services',action:operation,scope_type:'entity',cluster_id:cid,
   workspace_id:payWorkspaceId,scope_values:[{entity_type:'services',entity_id:serviceId}]}));
  vi.spyOn(authz,'snapshot').mockImplementation(async()=>({user:{...actorWithStaleFlag,superAdmin:platform},grants,version:platform?'initial-platform':'demoted-service-only'}));
  const service=new MutationService(f.db,f.redis,f.secrets,f.audit,f.kong,authz,resolver,execution);
  const before={id:serviceId,name:'public-name',host:'example.test',tags:['kos-ws-pay']};
  const context:MutationContext={...f.context,actor:actorWithStaleFlag,entityType:'services',entityId:serviceId,action,before,
   payload:{confirmed:true,confirm_name:'public-name'}};
  const result=action==='delete'?{entryId:'historical-entry',state:'deleted',deleted:[{type:'services',id:serviceId},{type:'plugins',id:pluginId},{type:'consumers',id:consumerId}]}
   :{entryId:'historical-entry',state:'restored',entity:before,restored:[{type:'plugins',originalId:pluginId,restoredId:pluginId},{type:'consumers',originalId:consumerId,restoredId:consumerId}]};
  return {...f,service,context,result,serviceId,pluginId,consumerId,demote:()=>{platform=false;}};
 }
 it('retains authorized root, operation/entry/state and count while hiding a historical Plugin and Consumer binding identity',async()=>{
  const f=historicalFixture();await f.service.execute(f.context,async()=>f.result);f.demote();f.kong.request.mockClear();
  const receipt=await f.service.operationByKey(cid,f.context.idempotencyKey!,f.context.actor,payWorkspaceId);
  expect(receipt).toMatchObject({entity_id:f.serviceId,state:'succeeded',remote_completed:true,safe_result:{entryId:'historical-entry',state:'deleted',deleted_count:3}});
  expect(receipt.safe_result).not.toHaveProperty('deleted');expect(JSON.stringify(receipt)).not.toContain(f.pluginId);expect(JSON.stringify(receipt)).not.toContain(f.consumerId);
  expect(f.kong.request).not.toHaveBeenCalled();
 });
 it('uses the same projection for completed DELETE and exact-key execution replay without another write or archived graph scan',async()=>{
  const f=historicalFixture(),write=vi.fn(async()=>f.result);await f.service.execute(f.context,write);f.demote();
  const completed=await f.service.completed({...f.context,before:undefined});
  const replayed=await f.service.execute(f.context,write);
  expect(completed).toEqual({entryId:'historical-entry',state:'deleted',deleted_count:3});expect(replayed).toEqual(completed);expect(write).toHaveBeenCalledTimes(1);
  expect(f.db.one.mock.calls.filter(call=>String(call[0]).includes('FROM recycle_entries'))).toHaveLength(0);
 });
 it('keeps child IDs for a freshly verified platform administrator, then ignores a stale superAdmin flag after demotion',async()=>{
  const f=historicalFixture();await f.service.execute(f.context,async()=>f.result);
  const platform=await f.service.completed({...f.context,before:undefined});expect(platform).toEqual(f.result);
  f.demote();expect(f.context.actor.superAdmin).toBe(true);
  const demoted=await f.service.completed({...f.context,before:undefined});expect(demoted).not.toHaveProperty('deleted');expect(demoted).toMatchObject({deleted_count:3});
 });
 it('hides restored child identity arrays while preserving the independently authorized restored root',async()=>{
  const f=historicalFixture('restore');await f.service.execute(f.context,async()=>f.result);f.demote();
  const receipt=await f.service.operationByKey(cid,f.context.idempotencyKey!,f.context.actor,payWorkspaceId);
  expect(receipt.safe_result).toMatchObject({entity:{id:f.serviceId},restored_count:2});expect(receipt.safe_result).not.toHaveProperty('restored');
  expect(JSON.stringify(receipt)).not.toContain(f.pluginId);expect(JSON.stringify(receipt)).not.toContain(f.consumerId);
 });
});
