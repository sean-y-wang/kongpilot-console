import { executionFixture } from './execution-test-fixture';
import 'reflect-metadata';
import { afterEach,beforeEach,describe,expect,it,vi } from 'vitest';
import { randomUUID } from 'node:crypto';
import { BadGatewayException,BadRequestException,ForbiddenException,NotFoundException } from '@nestjs/common';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { GraphCapturerService } from '../../apps/console-api/src/modules/recycle-bin/graph-capturer.service';
import { WorkspaceMigrationService } from '../../apps/console-api/src/modules/workspaces/workspace-migration.service';
import { payWorkspaceId,opsWorkspaceId,workspaceFixture } from './workspace-test-fixture';

const cid='efc85a7f-d60d-45b9-8685-1efc6d4e776c';
const user={id:'a35313a2-9968-4818-9f31-7b3066ce1728',username:'admin',superAdmin:true};
const actor={user,workspaceId:payWorkspaceId,requestId:'migration-test'};
const pay=['kos-ws-pay','team-pay'],ops=['kos-ws-ops','team-pay'];
const kinds=['key-auth','basic-auth','jwt','oauth2','hmac-auth','acls'];

/** Stateful adapters exercise the actual capture/migration engines and their native request bodies. */
function fixture(){
 const secrets=new SecretService(),ws=workspaceFixture(cid),remote=new Map<string,any>(),plans=new Map<string,any>(),steps=new Map<string,Map<string,any>>(),operations=new Map<string,any>();
 const hooks:{beforeEnter?:()=>void|Promise<void>;beforeReconcile?:()=>void|Promise<void>;beforePatch?: (path:string,body:any)=>void;afterPatch?: (path:string,body:any)=>void;failNextGet?:string}={};
 const add=(type:string,data:any,parentId?:string)=>{const path=kinds.includes(type)?`/consumers/${parentId}/${type}/${data.id}`:type==='targets'?`/upstreams/${parentId}/targets/${data.id}`:`/${type}/${data.id}`;remote.set(path,structuredClone(data));return path;};
 const listItems=(path:string):any[]=>{
  const nested=path.match(/^\/(consumers|upstreams|services|certificates)\/([^/]+)\/(key-auth|basic-auth|jwt|oauth2|hmac-auth|acls|targets(?:\/all)?|routes|snis)$/);
  if(nested){const [,parentType,parent,kind]=nested;if(kinds.includes(kind)||kind.startsWith('targets'))return [...remote.entries()].filter(([key])=>key.startsWith(`/${parentType}/${parent}/${kind.replace('/all','')}/`)).map(([,data])=>structuredClone(data)).filter(data=>kind!=='targets'||data.weight>0);
   const type=kind;const foreign=type==='routes'?'service':'certificate';return [...remote.entries()].filter(([key,data])=>key.startsWith(`/${type}/`)&&data[foreign]?.id===parent).map(([,data])=>structuredClone(data));}
  return [...remote.entries()].filter(([key])=>key.split('/').length===3&&key.startsWith(`${path}/`)).map(([,data])=>structuredClone(data));
 };
 const kong:any={transportScope:vi.fn().mockResolvedValue(cid),list:vi.fn(async(_cid:string,path:string,query:any)=>({items:listItems(path),nextCursor:null,size:query?.size??100})),request:vi.fn(async(_cid:string,method:string,path:string,body:any)=>{
  if(method==='GET'){
   if(hooks.failNextGet===path){hooks.failNextGet=undefined;throw new BadGatewayException({code:'KONG_UNAVAILABLE',message:'readback disconnected'});}
   let value=remote.get(path);if(!value&&path.startsWith('/upstreams/'))value=[...remote.values()].find(data=>data.name===decodeURIComponent(path.split('/')[2]));
   if(!value)throw new NotFoundException();return structuredClone(value);
  }
  if(method==='PATCH'){hooks.beforePatch?.(path,body);const current=remote.get(path);if(!current)throw new NotFoundException();const after={...current,...structuredClone(body),updated_at:2};remote.set(path,after);hooks.afterPatch?.(path,body);return structuredClone(after);}
  throw new Error(`Unexpected native write ${method}`);
 })};
 const db:any={one:vi.fn(async(sql:string,p:any[])=>{if(sql.includes('FROM workspace_migration_plans'))return structuredClone(plans.get(p[1])??null);if(sql.includes('FROM mutation_operations'))return structuredClone(operations.get(p[1])??null);return null;}),
  query:vi.fn(async(sql:string,p:any[])=>sql.includes('FROM workspace_migration_steps')?[...(steps.get(p[1])?.values()??[])].map(value=>structuredClone(value)):[]),
  exec:vi.fn(async(sql:string,p:any[])=>{
   if(sql.startsWith('INSERT INTO workspace_migration_plans')){const [id,cluster_id,actor_id,source_workspace_id,target_workspace_id,plan_hash,payload_secret,expires_at]=p;plans.set(id,{id,cluster_id,actor_id,source_workspace_id,target_workspace_id,plan_hash,payload_secret,expires_at,state:'planned',operation_id:null,steps:[],created_at:new Date(),updated_at:new Date()});steps.set(id,new Map());return 1;}
   if(sql.startsWith('INSERT INTO workspace_migration_steps')){const map=steps.get(p[1])!;if(p.length===3){for(const entry of JSON.parse(p[2]))map.set(entry.key,{...entry,error_code:null});}else{if(plans.get(p[1])?.operation_id!==p[8])return 0;map.set(p[2],{key:p[2],type:p[3],id:p[4],status:p[5],after_fingerprint:p[6],error_code:p[7]});}return 1;}
   if(sql.startsWith('UPDATE workspace_migration_plans')){const row=plans.get(p[1]);if(!row)return 0;if(sql.includes("state='running'")){row.state='running';row.operation_id=p[2];}else row.state=p[2];if(sql.includes('payload_secret=$4')){row.payload_secret=p[3];row.plan_hash=p[4];}if(sql.includes('expires_at=$6'))row.expires_at=p[5];return 1;}
   if(sql.startsWith('UPDATE mutation_operations')){const row=operations.get(p[1]);if(!row)return 0;Object.assign(row,{state:'succeeded',remote_completed:true,result_secret:p[2],safe_result:JSON.parse(p[3])});return 1;}
   return 1;
  }),transaction:vi.fn()};
 db.transaction.mockImplementation(async(fn:any)=>{const snapshots={plans:structuredClone(plans),steps:structuredClone(steps),operations:structuredClone(operations)};try{return await fn(db);}catch(error){plans.clear();for(const [id,row]of snapshots.plans)plans.set(id,row);steps.clear();for(const [id,row]of snapshots.steps)steps.set(id,row);operations.clear();for(const [id,row]of snapshots.operations)operations.set(id,row);throw error;}});
 const authz:any={isPlatformAdmin:vi.fn().mockResolvedValue(true),assertMigrationEntity:vi.fn().mockResolvedValue(undefined),assertCluster:vi.fn().mockResolvedValue(undefined),assertEntity:vi.fn().mockResolvedValue(undefined),permissionVersion:vi.fn().mockResolvedValue('v1')},audit:any={append:vi.fn().mockResolvedValue(undefined)},index:any={upsert:vi.fn().mockResolvedValue(undefined)};
 const mutations:any={execute:vi.fn(async(ctx:any,fn:any)=>{await hooks.beforeEnter?.();ctx.operationId=randomUUID();const operation={id:ctx.operationId,cluster_id:cid,actor_id:ctx.actor.id,entity_type:ctx.entityType,entity_id:ctx.entityId,workspace_id:ctx.workspaceId,state:'running'};operations.set(ctx.operationId,operation);try{const result=await fn();Object.assign(operation,{state:'succeeded',remote_completed:true});return result;}catch(error:any){operation.state=error?.getStatus?.()>=500?'uncertain':'failed';throw error;}})};
 const redis:any={withLock:vi.fn(async(_key:string,fn:any)=>{await hooks.beforeReconcile?.();return fn();}),assertLeaseOwnership:vi.fn().mockResolvedValue(undefined)};
 const captures=new GraphCapturerService(kong,{getRestorePayload:vi.fn().mockRejectedValue(new Error('Historical password must not be read during migration'))} as any,executionFixture());
 authz.assertMigrationEntity.mockImplementation((...args:any[])=>authz.assertEntity(...args.slice(0,6)));
 const engine=new WorkspaceMigrationService(db,redis,secrets,kong,authz,audit,captures,mutations,ws.resolver,index,executionFixture());
 const plan=async(roots:any[])=>engine.plan(cid,{source_workspace_id:payWorkspaceId,target_workspace_id:opsWorkspaceId,roots},actor);
 const apply=async(view:any)=>engine.apply(cid,view.id,{confirmed:true,confirm_name:'ops',plan_hash:view.plan_hash},actor);
 const reconcile=async(view:any)=>engine.reconcile(cid,view.id,{plan_hash:view.plan_hash},actor);
 const writes=()=>kong.request.mock.calls.filter(call=>call[1]!=='GET');
 return {engine,remote,plans,steps,operations,hooks,add,plan,apply,reconcile,writes,kong,secrets,ws,db,authz,audit,mutations,redis};
}

beforeEach(()=>vi.stubEnv('CONSOLE_ENCRYPTION_KEY','cb'.repeat(32)));
afterEach(()=>vi.unstubAllEnvs());

describe('M3 independent workspace migration engine behavior',()=>{
 it('keeps an in-use certificate/service closure together and refuses incomplete inbound references before writing',async()=>{
  const f=fixture(),certificate=randomUUID(),service=randomUUID();f.add('certificates',{id:certificate,cert:'public-cert',key:'private-key',tags:pay,snis:[]});f.add('services',{id:service,name:'pay-service',host:'api.example.test',tags:pay,client_certificate:{id:certificate}});
  const incomplete=await f.plan([{type:'certificates',id:certificate}]);expect(incomplete.conflicts).toMatchObject([{code:'CROSS_WORKSPACE_REFERENCE'}]);expect(JSON.stringify(incomplete)).not.toContain('private-key');
  await expect(f.apply(incomplete)).rejects.toMatchObject({response:{code:'MIGRATION_REFERENCE_CONFLICT'}});expect(f.writes()).toHaveLength(0);
  const complete=await f.plan([{type:'certificates',id:certificate},{type:'services',id:service}]);expect(complete.conflicts).toEqual([]);await expect(f.apply(complete)).resolves.toMatchObject({state:'succeeded'});
  expect(f.writes().map(call=>({path:call[2],body:{...call[3],tags:[...call[3].tags].sort()}}))).toEqual([{path:`/certificates/${certificate}`,body:{tags:[...ops].sort()}},{path:`/services/${service}`,body:{tags:[...ops].sort()}}]);
 });
 it('preserves every credential secret with six tags-only PATCH calls and performs no Target native writes',async()=>{
  const f=fixture(),consumer=randomUUID(),upstream=randomUUID(),target=randomUUID();f.add('consumers',{id:consumer,username:'pay-client',tags:pay});f.add('upstreams',{id:upstream,name:'pay-upstream',tags:pay});f.add('targets',{id:target,target:'127.0.0.1:9000',weight:100,upstream:{id:upstream},tags:pay},upstream);
  const credentialPaths=kinds.map(kind=>f.add(kind,{id:randomUUID(),consumer:{id:consumer},tags:pay,...(kind==='key-auth'?{key:'unchanged-key'}:kind==='basic-auth'?{username:'client',password:'unchanged-hash'}:kind==='jwt'?{key:'jwt-key',secret:'unchanged-jwt',algorithm:'HS256'}:kind==='oauth2'?{client_id:'client-id',client_secret:'unchanged-oauth',redirect_uris:['https://client.example/cb']}:kind==='hmac-auth'?{username:'client',secret:'unchanged-hmac'}:{group:'pay'})},consumer));
  const originals=credentialPaths.map(path=>structuredClone(f.remote.get(path)));const view=await f.plan([{type:'consumers',id:consumer},{type:'upstreams',id:upstream}]);expect(view.conflicts).toEqual([]);expect(JSON.stringify(view)).not.toMatch(/unchanged-(key|hash|jwt|oauth|hmac)/);
  await expect(f.apply(view)).resolves.toMatchObject({state:'succeeded'});
  for(let index=0;index<credentialPaths.length;index++){const {tags:_old,updated_at:_created,...before}=originals[index],{tags,updated_at:_updated,...after}=f.remote.get(credentialPaths[index]);expect(after).toEqual(before);expect([...tags].sort()).toEqual([...ops].sort());}
  expect(f.writes()).toHaveLength(8);expect(f.writes().every(call=>call[1]==='PATCH'&&Object.keys(call[3]).join(',')==='tags')).toBe(true);expect(f.writes().some(call=>String(call[2]).includes('/targets/'))).toBe(false);
 });
 it('rejects a stale preview hash again after waiting for the mutation lock',async()=>{
  const f=fixture(),id=randomUUID();f.add('services',{id,name:'pay-service',host:'api.example.test',tags:pay});const view=await f.plan([{type:'services',id}]);f.hooks.beforeEnter=()=>{f.plans.get(view.id).plan_hash='rebased-plan-hash';};
  await expect(f.apply(view)).rejects.toMatchObject({response:{code:'MIGRATION_PLAN_HASH_MISMATCH'}});expect(f.writes()).toHaveLength(0);
 });
 it('rejects a stale reconcile hash again after waiting for the same mutation lock',async()=>{
  const f=fixture(),id=randomUUID();f.add('services',{id,name:'pay-service',host:'api.example.test',tags:pay});const view=await f.plan([{type:'services',id}]);f.hooks.beforeReconcile=()=>{f.plans.get(view.id).plan_hash='rebased-plan-hash';};
  await expect(f.reconcile(view)).rejects.toMatchObject({response:{code:'MIGRATION_PLAN_HASH_MISMATCH'}});expect(f.writes()).toHaveLength(0);expect(f.audit.append.mock.calls.filter(call=>call[0].action==='reconcile')).toHaveLength(0);
 });
 it('stops when a plan expires while waiting for the mutation lock',async()=>{
  const f=fixture(),id=randomUUID();f.add('services',{id,name:'pay-service',host:'api.example.test',tags:pay});const view=await f.plan([{type:'services',id}]);f.hooks.beforeEnter=()=>{f.plans.get(view.id).expires_at=new Date(Date.now()-1);};
  await expect(f.apply(view)).rejects.toMatchObject({response:{code:'MIGRATION_PLAN_EXPIRED'}});expect(f.writes()).toHaveLength(0);
 });
 it('does not miss a credential added after the Consumer plan was captured',async()=>{
  const f=fixture(),consumer=randomUUID();f.add('consumers',{id:consumer,username:'pay-client',tags:pay});const view=await f.plan([{type:'consumers',id:consumer}]);f.add('key-auth',{id:randomUUID(),consumer:{id:consumer},key:'new-credential',tags:pay},consumer);
  await expect(f.apply(view)).rejects.toBeDefined();expect(f.writes()).toHaveLength(0);
 });
 it('reconciles uncertain readback from fresh native proof without replaying the PATCH or rotating a credential',async()=>{
  const f=fixture(),id=randomUUID(),path=f.add('services',{id,name:'pay-service',host:'api.example.test',tags:pay});const view=await f.plan([{type:'services',id}]);f.hooks.afterPatch=()=>{f.hooks.failNextGet=path;};
  await expect(f.apply(view)).rejects.toMatchObject({response:{code:'MIGRATION_RESULT_UNCERTAIN'}});expect(f.writes()).toHaveLength(1);
  const afterFailure=await f.engine.get(cid,view.id,actor);expect(afterFailure.state).toBe('partial');const checked=await f.reconcile(afterFailure);expect(checked.state).toBe('succeeded');expect(f.writes()).toHaveLength(1);
  expect([...f.operations.values()][0]).toMatchObject({state:'succeeded',remote_completed:true});expect(f.audit.append.mock.calls.find(call=>call[0].action==='reconcile')?.[0].after).toMatchObject({native_writes:0});
 });
 it('refuses reconciliation when non-tag credential configuration changed after an uncertain write',async()=>{
  const f=fixture(),consumer=randomUUID();f.add('consumers',{id:consumer,username:'pay-client',tags:pay});const path=f.add('key-auth',{id:randomUUID(),consumer:{id:consumer},key:'unchanged-key',tags:pay},consumer),view=await f.plan([{type:'consumers',id:consumer}]);
  f.hooks.afterPatch=(patched)=>{if(patched===path)f.hooks.failNextGet=path;};await expect(f.apply(view)).rejects.toMatchObject({status:503});f.remote.get(path).key='externally-rotated';const receipt=await f.engine.get(cid,view.id,actor),beforeWrites=f.writes().length;
  await expect(f.reconcile(receipt)).rejects.toMatchObject({response:{code:'MIGRATION_OBJECT_CHANGED'}});expect(f.writes()).toHaveLength(beforeWrites);expect([...f.operations.values()][0].state).toBe('uncertain');
 });
 it('re-authorizes every encrypted plan object before exposing names, tags or conflicts',async()=>{
  const f=fixture(),id=randomUUID();f.add('services',{id,name:'private-service-name',host:'api.example.test',tags:pay});const view=await f.plan([{type:'services',id}]);f.authz.assertEntity.mockRejectedValue(new ForbiddenException({code:'PERMISSION_DENIED'}));
  await expect(f.engine.get(cid,view.id,actor)).rejects.toMatchObject({status:403});expect(f.writes()).toHaveLength(0);
 });
 it('requires a fresh hash and renamed target confirmation after metadata rebase, renewing the review TTL',async()=>{
  const f=fixture(),id=randomUUID();f.add('services',{id,name:'pay-service',host:'api.example.test',tags:pay});const view=await f.plan([{type:'services',id}]);
  const target=f.ws.rows.find(row=>row.id===opsWorkspaceId)!;target.name='production-ops';target.revision++;f.plans.get(view.id).expires_at=new Date(Date.now()-1);
  const rebased=await f.reconcile(view);expect(rebased.plan_hash).not.toBe(view.plan_hash);expect(rebased.target_workspace_name).toBe('production-ops');expect(Date.parse(String(rebased.expires_at))).toBeGreaterThan(Date.now()+1_700_000);expect(f.writes()).toHaveLength(0);
  await expect(f.apply(view)).rejects.toMatchObject({response:{code:'MIGRATION_PLAN_HASH_MISMATCH'}});
  await expect(f.apply(rebased)).rejects.toMatchObject({response:{code:'CONFIRMATION_REQUIRED'}});expect(f.writes()).toHaveLength(0);
  await expect(f.engine.apply(cid,rebased.id,{confirmed:true,confirm_name:'production-ops',plan_hash:rebased.plan_hash},actor)).resolves.toMatchObject({state:'succeeded'});expect(f.writes()).toHaveLength(1);
 });
 it('rejects normalized step rows whose object type, id, count or completion fingerprint disagrees with the encrypted graph',async()=>{
  for(const tamper of ['missing','wrong-type','wrong-id','missing-success-proof','wrong-status']){
   const f=fixture(),id=randomUUID();f.add('services',{id,name:'pay-service',host:'api.example.test',tags:pay});const view=await f.plan([{type:'services',id}]),map=f.steps.get(view.id)!;
   const step=[...map.values()][0];if(tamper==='missing')map.clear();if(tamper==='wrong-type')step.type='consumers';if(tamper==='wrong-id')step.id=randomUUID();if(tamper==='missing-success-proof')step.status='succeeded';if(tamper==='wrong-status')step.status='approved';
   await expect(f.engine.get(cid,view.id,actor)).rejects.toMatchObject({response:{code:'MIGRATION_PLAN_INVALID'}});await expect(f.apply(view)).rejects.toMatchObject({response:{code:'MIGRATION_PLAN_INVALID'}});expect(f.writes()).toHaveLength(0);
  }
 });
 it('resumes a partially applied plan only after explicit fresh proof, skipping objects already migrated',async()=>{
  const f=fixture(),ids=[randomUUID(),randomUUID()];for(const id of ids)f.add('services',{id,name:`pay-${id}`,host:'api.example.test',tags:pay});const view=await f.plan(ids.map(id=>({type:'services',id})));
  const firstPath=`/services/${view.affected[0].id}`,secondPath=`/services/${view.affected[1].id}`;f.hooks.beforePatch=path=>{if(path===secondPath)throw new BadRequestException({code:'KONG_VALIDATION_ERROR'});};
  const partial=await f.apply(view);expect(partial.state).toBe('partial');expect(f.remote.get(firstPath).tags).toEqual(expect.arrayContaining(ops));expect(f.remote.get(secondPath).tags).toEqual(pay);
  f.hooks.beforePatch=undefined;const checked=await f.reconcile(partial);expect(checked.state).toBe('partial');expect(checked.affected.map((node:any)=>node.status)).toEqual(['succeeded','pending']);
  await expect(f.apply(checked)).resolves.toMatchObject({state:'succeeded'});expect(f.writes().filter(call=>call[2]===firstPath)).toHaveLength(1);expect(f.writes().filter(call=>call[2]===secondPath)).toHaveLength(2);expect(f.writes().every(call=>call[1]==='PATCH')).toBe(true);
 });
 it('cannot combine source business-tag permission with an unrelated target module grant',async()=>{
  const denyTarget=async(_actor:any,_cid:string,_type:string,action:string,entity:any,workspaceId?:string)=>{if(action==='write'&&workspaceId===opsWorkspaceId&&entity.tags.includes('team-pay'))throw new ForbiddenException({code:'ENTITY_SCOPE_DENIED'});};
  const planning=fixture(),id=randomUUID();planning.add('services',{id,name:'pay-service',host:'api.example.test',tags:pay});planning.authz.assertEntity.mockImplementation(denyTarget);
  await expect(planning.plan([{type:'services',id}])).rejects.toMatchObject({response:{code:'ENTITY_SCOPE_DENIED'}});expect(planning.plans.size).toBe(0);expect(planning.writes()).toHaveLength(0);
  const executing=fixture();executing.add('services',{id,name:'pay-service',host:'api.example.test',tags:pay});const view=await executing.plan([{type:'services',id}]);executing.authz.assertEntity.mockImplementation(denyTarget);
  await expect(executing.apply(view)).rejects.toMatchObject({response:{code:'ENTITY_SCOPE_DENIED'}});expect(executing.writes()).toHaveLength(0);
 });
 it('cannot commit reconciliation proof after its trusted mutation lease has been lost',async()=>{
  const f=fixture(),id=randomUUID();f.add('services',{id,name:'pay-service',host:'api.example.test',tags:pay});const view=await f.plan([{type:'services',id}]),before=structuredClone(f.plans.get(view.id));
  f.redis.assertLeaseOwnership.mockRejectedValue(new BadGatewayException({code:'LOCK_LOST'}));await expect(f.reconcile(view)).rejects.toMatchObject({response:{code:'LOCK_LOST'}});
  expect(f.plans.get(view.id)).toEqual(before);expect(f.audit.append.mock.calls.some(call=>call[0].action==='reconcile')).toBe(false);expect(f.writes()).toHaveLength(0);
 });
 it('rolls back every reconciled step and plan change if the linked durable receipt belongs to another actor',async()=>{
  const f=fixture(),id=randomUUID(),path=f.add('services',{id,name:'pay-service',host:'api.example.test',tags:pay}),view=await f.plan([{type:'services',id}]);f.hooks.afterPatch=()=>{f.hooks.failNextGet=path;};
  await expect(f.apply(view)).rejects.toMatchObject({status:503});const partial=await f.engine.get(cid,view.id,actor),operation=[...f.operations.values()][0];operation.actor_id=randomUUID();
  const beforePlan=structuredClone(f.plans.get(view.id)),beforeSteps=structuredClone(f.steps.get(view.id));
  await expect(f.reconcile(partial)).rejects.toMatchObject({response:{code:'MIGRATION_RECEIPT_MISMATCH'}});expect(f.plans.get(view.id)).toEqual(beforePlan);expect(f.steps.get(view.id)).toEqual(beforeSteps);expect([...f.operations.values()][0].state).toBe('uncertain');expect(f.writes()).toHaveLength(1);
 });
});
