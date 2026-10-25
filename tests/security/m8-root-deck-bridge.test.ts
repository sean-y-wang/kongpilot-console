import {describe,it,expect,vi,beforeEach,afterEach} from 'vitest';
import {ConfigurationDeckService} from '../../apps/console-api/src/modules/configuration/configuration-deck.service';
import {KongExecutionContextService} from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import {SecretService} from '../../apps/console-api/src/infrastructure/secret.service';

const id=(n:number)=>`50000000-0000-4000-8000-${String(n).padStart(12,'0')}`;
beforeEach(()=>vi.stubEnv('CONSOLE_ENCRYPTION_KEY','3'.repeat(64)));
afterEach(()=>vi.unstubAllEnvs());
/** Real bridge and HTTP frames, synthetic session/storage rows. No private
 * authority substitute is installed into a production provider or database. */
function fixture(){
 const ctx=new KongExecutionContextService(),secrets=new SecretService();
 const user={id:id(1),username:'deck-root-unit',superAdmin:false},handle=Object.freeze({});
 const scope={clusterId:id(3),workspaceId:id(4),transportScope:'a'.repeat(64),kind:'workspace',rootIds:[]};
 const expiresAt=new Date(Date.now()+600000).toISOString();
 const locator:any={id:id(6),actorId:user.id,sessionId:id(2),jobId:id(5),clusterId:scope.clusterId,workspaceId:scope.workspaceId,transportScope:scope.transportScope,
  permissionVersion:'v1',credentialEpoch:1,purpose:'read',expiresAt,revision:1};
 const state={actor:user,sessionId:locator.sessionId,scope,jobId:locator.jobId,purpose:'compare',permissionVersion:'v1',credentialEpoch:1,expiresAt:Date.parse(expiresAt)};
 const row:any={id:locator.id,actor_id:locator.actorId,session_id:locator.sessionId,job_id:locator.jobId,cluster_id:locator.clusterId,workspace_id:locator.workspaceId,
  transport_scope:locator.transportScope,permission_version:locator.permissionVersion,credential_epoch:1,purpose:'read',expires_at:expiresAt};
 const graph:any={kongVersion:'1.5.1',versionId:id(7),scope,objects:Array.from({length:101},(_,n)=>({entityType:'services',nativeId:id(100+n),objectKey:`services:${id(100+n)}`,
  objectWorkspaceId:scope.workspaceId,ownershipTags:[],beforeHmac:'b'.repeat(64),payload:{id:id(100+n),host:`service-${n}.test`,tags:[]},recovery:{state:'complete',blockerCodes:[]}}))};
 const db:any={one:vi.fn(async(sql:string)=>{
  if(sql.includes('FROM users'))return{id:user.id,username:user.username,super_admin:false};
  if(sql.includes('FROM configuration_deck_sessions'))return row;
  if(sql.includes('SELECT safe_progress'))return{safe_progress:{snapshotId:id(8)}};
  throw new Error('unexpected bridge query');
 })};
 const access:any={acquireReadJob:vi.fn(async()=>{expect(ctx.current().actor).toEqual(user);expect(ctx.current().sessionId).toBe(locator.sessionId);return handle;}),
  description:vi.fn(async(candidate:any)=>{expect(candidate).toBe(handle);return{...state};}),assertHistoricalGraph:vi.fn(async()=>undefined)};
 const repo:any={readSnapshot:vi.fn(async()=>structuredClone(graph)),chargeDeckSessionBudget:vi.fn(async()=>undefined)};
 const configuration:any={deckGraphObjects:vi.fn(async(_:any,value:any)=>value),executeDeckPacket:vi.fn()};
 const bridge=new ConfigurationDeckService(db,ctx,access,repo,configuration,secrets,{}as any);
 const frame=<T>(fn:()=>Promise<T>)=>ctx.runHttp({requestId:id(9)},fn);
 return{bridge,ctx,secrets,user,handle,scope,locator,state,row,graph,db,access,repo,configuration,frame};
}
describe('M8 Root decK authority bridge',()=>{
 it('authenticates in its isolated verification frame before binding the outer actor once',async()=>{const f=fixture();await f.frame(async()=>{
  expect(f.ctx.current().actor).toBeUndefined();const a=await f.bridge.acquireDeckSession(f.locator);
  expect(f.ctx.current().actor).toBeUndefined();f.ctx.bindHttpActor(a.user,a.sessionId);await f.bridge.assertDeckCurrent(a,'request');
  expect(()=>f.ctx.bindHttpActor(a.user,a.sessionId)).toThrow();
 });});
 it('rejects copied authority despite identical valid JSON fields',async()=>{const f=fixture();await f.frame(async()=>{const a=await f.bridge.acquireDeckSession(f.locator);
  for(const b of [{...a},{handle:f.handle,user:f.user,sessionId:f.locator.sessionId,locator:f.locator}])await expect(f.bridge.assertDeckCurrent(b as any,'request')).rejects.toThrow();
 });});
 it.each(['actor_id','session_id','job_id','cluster_id','workspace_id','transport_scope','permission_version','credential_epoch','purpose','expires_at'])('rejects current session row %s substitution',async(field)=>{const f=fixture();await f.frame(async()=>{const a=await f.bridge.acquireDeckSession(f.locator);
  f.row[field]=field==='credential_epoch'?2:field==='expires_at'?new Date(Date.now()+999999).toISOString():field==='purpose'?'write':field==='permission_version'?'v2':field==='transport_scope'?'c'.repeat(64):id(99);
  await expect(f.bridge.assertDeckCurrent(a,'response')).rejects.toThrow();
 });});
 it('pages the complete captured graph at 100 and binds cursors to graph/actor permissions',async()=>{const f=fixture();await f.frame(async()=>{const a=await f.bridge.acquireDeckSession(f.locator),first=await f.bridge.readDeckCollection(a,{type:'services',size:100});
  expect(first.items).toHaveLength(100);expect(first.nextCursor).toBeTruthy();
  const last=await f.bridge.readDeckCollection(a,{type:'services',size:100,cursor:first.nextCursor!});expect(last.items).toHaveLength(1);expect(last.nextCursor).toBeNull();
  f.graph.objects[0].payload.host='changed.test';await expect(f.bridge.readDeckCollection(a,{type:'services',size:100,cursor:first.nextCursor!})).rejects.toThrow();
 });});
 it('never exposes unrecoverable Basic hashes through fixed CLI dump',async()=>{const f=fixture();f.graph.objects=[{entityType:'credentials',credentialKind:'basic-auth',nativeId:id(100),parentId:id(101),payload:{id:id(100),password:'synthetic-native-hash'},recovery:{state:'requires_secret_input'}}];
  await f.frame(async()=>{const a=await f.bridge.acquireDeckSession(f.locator);await expect(f.bridge.readDeckRoot(a)).rejects.toMatchObject({response:{code:'CONFIGURATION_DECK_BASIC_PASSWORD_UNAVAILABLE'}});});
 });
 it('charges full returned page payload and refuses current raw-secret denial before any page',async()=>{const f=fixture();await f.frame(async()=>{const a=await f.bridge.acquireDeckSession(f.locator),page=await f.bridge.readDeckCollection(a,{type:'services',size:100});
  expect(f.repo.chargeDeckSessionBudget).toHaveBeenCalledWith(f.handle,f.locator.id,{pages:1,records:100,bytes:Buffer.byteLength(JSON.stringify(page.items)),calls:0});
  f.access.assertHistoricalGraph.mockRejectedValueOnce(new Error('synthetic secret grant revoked'));f.repo.chargeDeckSessionBudget.mockClear();
  await expect(f.bridge.readDeckCollection(a,{type:'services',size:100})).rejects.toThrow();expect(f.repo.chargeDeckSessionBudget).not.toHaveBeenCalled();
 });});
 it('refuses write packets in a read-only session before entering a native execution',async()=>{const f=fixture();await f.frame(async()=>{const a=await f.bridge.acquireDeckSession(f.locator);
  await expect(f.bridge.executeDeckPacket(a,{method:'POST',type:'services',kind:'entity',path:'/services',collection:true,query:{size:100},body:{host:'bad.test'}})).rejects.toThrow();
  expect(f.configuration.executeDeckPacket).not.toHaveBeenCalled();
 });});
});
