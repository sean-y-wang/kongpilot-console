import { executionFixture } from './execution-test-fixture';
import 'reflect-metadata';
import { afterEach,beforeEach,describe,expect,it,vi } from 'vitest';
import { NotFoundException } from '@nestjs/common';
import { GraphCapturerService,GraphNode,RecycleGraph } from '../../apps/console-api/src/modules/recycle-bin/graph-capturer.service';
import { RecycleService } from '../../apps/console-api/src/modules/recycle-bin/recycle.service';
import { MutationService } from '../../apps/console-api/src/modules/mutations/mutation.service';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { defaultWorkspaceId,payWorkspaceId,opsWorkspaceId,workspaceFixture } from './workspace-test-fixture';
const cid='efc85a7f-d60d-45b9-8685-1efc6d4e776c',actor={id:'a35313a2-9968-4818-9f31-7b3066ce1728',username:'admin',superAdmin:true};
const pay=['kos-ws-pay','team-pay'],ops=['kos-ws-ops','team-ops'];
function graphNode(type:string,id:string,tags=pay,dependencies:string[]=[],affected=true,data:any={}):GraphNode{return {key:`${type}:${id}`,type,id,path:`/${type}/${id}`,data:{id,name:id,tags,...data},restoreData:{id,name:id,tags,...data},dependencies,affected,restorable:true};}
function graphOf(...nodes:GraphNode[]):RecycleGraph{return {rootKey:nodes[0].key,nodes,complete:true,capturedAt:new Date().toISOString(),purpose:'recycle'};}
function recycleFixture(graph=graphOf(graphNode('services','service'))){
 const secrets=new SecretService(),ws=workspaceFixture(cid),entry:any={id:'4b25f0dd-f78e-4f54-b58c-9fdd0687a5c4',cluster_id:cid,workspace_id:payWorkspaceId,root_type:graph.nodes[0].type,original_id:graph.nodes[0].id,root_name:graph.nodes[0].data.name,node_count:graph.nodes.length,revision:1,state:'deleted',payload_secret:secrets.encrypt(graph,'recycle:4b25f0dd-f78e-4f54-b58c-9fdd0687a5c4'),created_at:new Date(),expires_at:new Date()};
 const remote=new Map(graph.nodes.filter(node=>!node.affected).map(node=>[node.path,structuredClone(node.data)]));
 const db:any={one:vi.fn(async(sql:string,p:any[])=>sql.includes('m11_recycle_purge_available')?{eligible:true}:sql.includes('FROM recycle_entries')?entry:sql.includes('FROM recycle_nodes')?{delete_state:'deleted',restore_state:'pending'}:null),query:vi.fn().mockResolvedValue([]),exec:vi.fn(async(sql:string,p:any[])=>{if(sql.includes('SET workspace_id=$2'))entry.workspace_id=p[1];return 1;}),transaction:vi.fn()};db.transaction.mockImplementation(async(fn:any)=>fn(db));
 const kong:any={request:vi.fn(async(_cid:string,method:string,path:string,body:any)=>{if(method==='GET'){if(!remote.has(path))throw new NotFoundException();return structuredClone(remote.get(path));}if(method==='POST'){remote.set(`${path}/${body.id}`,body);return body;}if(method==='DELETE'){remote.delete(path);return null;}throw new Error('Unexpected method');}),list:vi.fn()};
 const authz:any={isPlatformAdmin:vi.fn(async(user:any)=>user.superAdmin===true),assertCluster:vi.fn().mockResolvedValue(undefined),assertEntity:vi.fn().mockResolvedValue(undefined),permissionVersion:vi.fn().mockResolvedValue('v1')},audit:any={append:vi.fn()},mutations:any={claimGraphImpact:vi.fn(),execute:vi.fn(async(_ctx:any,fn:any)=>fn())};
 authz.assertArchivedEntity=authz.assertEntity;
 const recycle=new RecycleService(db,secrets,kong,mutations,{capture:vi.fn().mockResolvedValue(graph)} as any,authz,audit,{save:vi.fn(),remove:vi.fn()} as any,{upsert:vi.fn(),remove:vi.fn()} as any,ws.resolver,executionFixture());
 return {recycle,entry,graph,db,kong,remote,authz,audit,mutations,ws};
}
function mutationFixture(){
 const ws=workspaceFixture(cid),secrets=new SecretService(),records=new Map<string,any>();
 const db:any={query:vi.fn(async()=>[...records.values()].filter(row=>['running','uncertain'].includes(row.state))),one:vi.fn(async(sql:string,p:any[])=>sql.includes('FROM clusters')?{id:cid,execution_mode:'direct',version:'1.5.1'}:sql.includes('FROM mutation_operations')?[...records.values()].find(row=>p[1]===row.id||p[1]===row.idempotency_key)??null:null),exec:vi.fn(async(sql:string,p:any[])=>{
  if(sql.startsWith('INSERT INTO mutation_operations')){const [id,cluster_id,actor_id,action,idempotency_key,request_hash,workflow_id,request_id,entity_type,entity_id,before_secret,payload_secret,workspace_id,transport_scope,impact]=p;records.set(idempotency_key,{id,cluster_id,actor_id,action,idempotency_key,request_hash,workflow_id,request_id,entity_type,entity_id,before_secret,payload_secret,workspace_id,transport_scope,impact:JSON.parse(impact),state:'running'});return 1;}
  const row=[...records.values()].find(value=>value.id===p[0]);if(!row)return 0;
  if(sql.includes('workspace_id=$2'))row.workspace_id=p[1];if(sql.includes('remote_completed=true'))Object.assign(row,{entity_id:p[1],result_secret:p[2]});if(sql.includes("state='succeeded'"))Object.assign(row,{state:'succeeded',safe_result:JSON.parse(p[1])});return 1;
 }),transaction:vi.fn()};db.transaction.mockImplementation(async(fn:any)=>fn(db));
 const authz:any={isPlatformAdmin:vi.fn(async(user:any)=>user.superAdmin===true),assertCluster:vi.fn().mockResolvedValue(undefined),assertEntity:vi.fn().mockResolvedValue(undefined)},audit:any={append:vi.fn()},kong:any={transportScope:vi.fn(async()=>cid),request:vi.fn().mockResolvedValue({id:'service',name:'service',tags:pay}),list:vi.fn().mockResolvedValue({items:[],nextCursor:null,size:100})},redis:any={withLock:vi.fn(async(_key:any,fn:any)=>fn())};
 const mutations=new MutationService(db,redis,secrets,audit,kong,authz,ws.resolver,executionFixture());
 const context={clusterId:cid,workspaceId:payWorkspaceId,actor,entityType:'services',action:'create',idempotencyKey:'scoped',payload:{name:'service',tags:pay}};
 return {mutations,context,records,db,authz,audit,kong,redis,secrets,ws};
}

beforeEach(()=>{vi.stubEnv('CONSOLE_ENCRYPTION_KEY','ba'.repeat(32));vi.stubEnv('APP_SECRET','scope-test-signing-material-at-least-32-characters');});
afterEach(()=>vi.unstubAllEnvs());

describe('M3 graph capture purposes and aggregate budgets',()=>{
 it('captures unknown Basic-auth credentials for tags migration without obtaining a restore secret',async()=>{
  const credentials={getRestorePayload:vi.fn().mockRejectedValue(new Error('unknown historical password'))};
  const kong:any={transportScope:vi.fn(async()=>cid),request:vi.fn().mockResolvedValue({id:'consumer',username:'consumer',tags:pay}),list:vi.fn(async(_cid,path)=>({items:path.endsWith('/basic-auth')?[{id:'basic',consumer:{id:'consumer'},password:'remote-hash',tags:pay}]:[],nextCursor:null,size:100}))};
  const capturer=new GraphCapturerService(kong,credentials as any,executionFixture()),graph=await capturer.capture(cid,'consumers','consumer',{purpose:'migration'});
  expect(graph.purpose).toBe('migration');expect(graph.budget).toMatchObject({pages:7,records:1,nodes:2});expect(graph.nodes.find(node=>node.type==='basic-auth')?.restoreData).toBeUndefined();expect(credentials.getRestorePayload).not.toHaveBeenCalled();
  await expect(capturer.capture(cid,'consumers','consumer')).rejects.toThrow('unknown historical password');
 });
 it('keeps certificate deletion protection while allowing tags migration of an in-use certificate',async()=>{
  const kong:any={transportScope:vi.fn(async()=>cid),request:vi.fn().mockResolvedValue({id:'cert',cert:'public',key:'private',tags:pay}),list:vi.fn(async(_cid,path)=>({items:path==='/services'?[{id:'service',client_certificate:{id:'cert'}}]:[],nextCursor:null,size:100}))};
  const capture=new GraphCapturerService(kong,{} as any,executionFixture());
  await expect(capture.capture(cid,'certificates','cert')).rejects.toMatchObject({response:{code:'CERTIFICATE_IN_USE'}});
  kong.list.mockClear();expect((await capture.capture(cid,'certificates','cert',{purpose:'migration'})).budget?.pages).toBe(1);expect(kong.list).not.toHaveBeenCalledWith(cid,'/services',expect.anything(),expect.anything());
 });
 it('enforces remaining page, record and node budgets before further traversal',async()=>{
  const kong:any={transportScope:vi.fn(async()=>cid),request:vi.fn().mockResolvedValue({id:'consumer'}),list:vi.fn().mockResolvedValue({items:[],nextCursor:null,size:100})};
  const capture=new GraphCapturerService(kong,{} as any,executionFixture());
  await expect(capture.capture(cid,'consumers','consumer',{purpose:'migration',budget:{maxPages:1}})).rejects.toMatchObject({response:{code:'RECYCLE_CAPTURE_LIMIT'}});expect(kong.list).toHaveBeenCalledTimes(1);
  kong.request.mockClear();kong.list.mockClear();await expect(capture.capture(cid,'consumers','consumer',{budget:{maxPages:0}})).rejects.toMatchObject({status:409});expect(kong.request).not.toHaveBeenCalled();expect(kong.list).not.toHaveBeenCalled();
  await expect(capture.capture(cid,'consumers','consumer',{budget:{maxNodes:10001}})).rejects.toMatchObject({status:400});
  kong.request.mockResolvedValue({id:'route',service:{id:'service'}});await expect(capture.capture(cid,'routes','route',{purpose:'migration',budget:{maxNodes:1}})).rejects.toMatchObject({status:409});expect(kong.request).toHaveBeenCalledTimes(1);
 });
 it('stops large paginated data at its byte budget before accumulating the next page',async()=>{
  const payload='x'.repeat(350_000);
  const kong:any={transportScope:vi.fn(async()=>cid),request:vi.fn().mockResolvedValue({id:'service'}),list:vi.fn(async(_cid,path,_query,cursor)=>path.endsWith('/routes')?{items:[{id:cursor?'second':'first',service:{id:'service'},config:payload}],nextCursor:cursor?null:'page-two',size:100}:{items:[],nextCursor:null,size:100})};
  await expect(new GraphCapturerService(kong,{} as any,executionFixture()).capture(cid,'services','service',{purpose:'migration',budget:{maxBytes:600_000}})).rejects.toMatchObject({response:{code:'RECYCLE_CAPTURE_LIMIT'}});
  expect(kong.list).toHaveBeenCalledTimes(2);expect(kong.request.mock.calls.every(call=>call[1]==='GET')).toBe(true);
 });
});

describe('M3 Target current-state proof uses the real upstream-scoped effective collection',()=>{
 const upstreamId='b45d6b5a-df8f-4c2f-b5fa-1971fbc7c4e6',otherUpstream='b080b62f-82da-471e-9aab-350f2c63c285',targetId='cfe5c0b5-319f-44ab-bf48-7ac4cf31e89b',replacementId='31a54911-c1e6-4d31-903e-e4e6c249ba19',address='shared.example:9000';
 const target=()=>({id:targetId,target:address,weight:100,upstream:{id:upstreamId},tags:pay});
 it('captures a current Target even when another Upstream has the same address and the global address GET returns 404',async()=>{
  const kong:any={request:vi.fn(async(_cid,method,path)=>{if(path===`/upstreams/${upstreamId}/targets/${targetId}`)return target();if(path===`/upstreams/${upstreamId}`)return {id:upstreamId,name:'pay-upstream',tags:pay};throw new NotFoundException();}),list:vi.fn(async(_cid,path)=>({items:path===`/upstreams/${upstreamId}/targets`?[target()]:[{...target(),upstream:{id:otherUpstream}}],nextCursor:null,size:100}))};
  const graph=await new GraphCapturerService(kong,{} as any,executionFixture()).capture(cid,'targets',targetId,{parentId:upstreamId});expect(graph.budget).toMatchObject({pages:1,records:1,nodes:2});
  expect(kong.list.mock.calls.map(call=>call[1])).toEqual([`/upstreams/${upstreamId}/targets`]);expect(kong.request.mock.calls.some(call=>call[2].endsWith(encodeURIComponent(address)))).toBe(false);
 });
 it('does not archive a readable historical UUID when the scoped collection now has a replacement UUID',async()=>{
  const kong:any={request:vi.fn(async(_cid,_method,path)=>path.endsWith(targetId)?target():{id:upstreamId,tags:pay}),list:vi.fn().mockResolvedValue({items:[{...target(),id:replacementId,weight:200}],nextCursor:null,size:100})};
  await expect(new GraphCapturerService(kong,{} as any,executionFixture()).capture(cid,'targets',targetId,{parentId:upstreamId})).rejects.toMatchObject({response:{code:'TARGET_NOT_EFFECTIVE'}});expect(kong.request.mock.calls.every(call=>call[1]==='GET')).toBe(true);
 });
 it('charges scoped verification pages to the graph budget and never accepts an early match from an incomplete collection',async()=>{
  const kong:any={request:vi.fn(async(_cid,_method,path)=>path.endsWith(targetId)?target():{id:upstreamId,tags:pay}),list:vi.fn().mockResolvedValue({items:[target()],nextCursor:'later-page',size:100})};
  await expect(new GraphCapturerService(kong,{} as any,executionFixture()).capture(cid,'targets',targetId,{parentId:upstreamId,budget:{maxPages:1}})).rejects.toMatchObject({status:409,response:{code:'TARGET_LOOKUP_LIMIT'}});expect(kong.list).toHaveBeenCalledTimes(1);
 });
 it('allows a current Target mutation using collection proof and only UUID GET for result readback',async()=>{
  const f=mutationFixture(),before=target(),result={...before,id:replacementId,weight:200},write=vi.fn().mockResolvedValue(result);f.kong.list.mockResolvedValue({items:[before],nextCursor:null,size:100});f.kong.request.mockResolvedValue(result);
  await expect(f.mutations.execute({...f.context,entityType:'targets',entityId:targetId,action:'update',parentId:upstreamId,before,payload:{target:address,weight:200}},write)).resolves.toEqual(result);
  expect(write).toHaveBeenCalledTimes(1);expect(f.kong.request).toHaveBeenCalledWith(cid,'GET',`/upstreams/${upstreamId}/targets/${replacementId}`);expect(f.kong.request.mock.calls.some(call=>call[2].endsWith(encodeURIComponent(address)))).toBe(false);
 });
 it('stops a stale Target mutation before durable operation allocation or the callback, even though its historical UUID still exists',async()=>{
  const f=mutationFixture(),before=target(),write=vi.fn();f.kong.list.mockResolvedValue({items:[{...before,id:replacementId}],nextCursor:null,size:100});
  await expect(f.mutations.execute({...f.context,entityType:'targets',entityId:targetId,action:'update',parentId:upstreamId,before,payload:{target:address,weight:200}},write)).rejects.toMatchObject({response:{code:'ENTITY_CHANGED'}});expect(write).not.toHaveBeenCalled();expect(f.records.size).toBe(0);expect(f.kong.request).not.toHaveBeenCalled();
 });
 it('checks later-page Target conflicts before Recycle sends any DELETE',async()=>{
  const parent=graphNode('upstreams',upstreamId,pay,[],false),node=graphNode('targets',targetId,pay,[parent.key],true,target());delete node.data.name;delete node.restoreData.name;node.path=`/upstreams/${upstreamId}/targets/${targetId}`;const f=recycleFixture(graphOf(node,parent));
  f.kong.list.mockImplementation(async(_cid,path,_query,cursor)=>({items:cursor?[{...target(),id:replacementId}]:[target()],nextCursor:cursor?null:'second',size:100}));
  await expect(f.recycle.archiveAndDelete({clusterId:cid,workspaceId:payWorkspaceId,actor,entityType:'targets',entityId:targetId,parentId:upstreamId,before:node.data,action:'delete',confirmed:true,confirmName:address})).rejects.toMatchObject({response:{code:'RECYCLE_DELETE_INCOMPLETE',cause:'KONG_INVALID_TARGET_LIST'}});expect(f.kong.request.mock.calls.every(call=>call[1]==='GET')).toBe(true);expect(f.kong.list).toHaveBeenCalledTimes(2);
 });
});

describe('M3 recycle original workspace and inherited children',()=>{
 it('rejects cross-workspace preview and restore before a native write',async()=>{
  const f=recycleFixture();await expect(f.recycle.preview(cid,f.entry.id,actor,opsWorkspaceId)).rejects.toMatchObject({status:403});
  await expect(f.recycle.restore(cid,f.entry.id,actor,{confirmed:true,confirm_name:'service'},{workspaceId:opsWorkspaceId})).rejects.toMatchObject({status:403});expect(f.kong.request).not.toHaveBeenCalled();
 });
 it('binds legacy NULL entries from the archived root and never aliases unknown tags to default',async()=>{
  const f=recycleFixture();f.entry.workspace_id=null;await expect(f.recycle.preview(cid,f.entry.id,actor)).rejects.toMatchObject({status:403});expect(f.entry.workspace_id).toBeNull();
  await f.recycle.preview(cid,f.entry.id,actor,payWorkspaceId);expect(f.entry.workspace_id).toBe(payWorkspaceId);
  const invalid=recycleFixture(graphOf(graphNode('services','unknown',['kos-ws-unknown'])));invalid.entry.workspace_id=null;await expect(invalid.recycle.preview(cid,invalid.entry.id,actor)).rejects.toMatchObject({status:403});expect(invalid.entry.workspace_id).toBeNull();
 });
 it('uses the real Consumer workspace while preserving credential business tags for authorization',async()=>{
  const consumer=graphNode('consumers','consumer',pay,[],false),credential=graphNode('key-auth','key',[],[consumer.key],true,{consumer:{id:'consumer'},key:'hidden-credential'});
  const f=recycleFixture(graphOf(credential,consumer));f.entry.workspace_id=null;await f.recycle.preview(cid,f.entry.id,actor,payWorkspaceId);
  expect(f.entry.workspace_id).toBe(payWorkspaceId);expect(f.authz.assertArchivedEntity).toHaveBeenCalledWith(actor,cid,'key-auth','read',expect.objectContaining({tags:[]}),payWorkspaceId,f.graph.nodes);
 });
 it('blocks a mismatched affected child before an archive or DELETE',async()=>{
  const service=graphNode('services','service'),route=graphNode('routes','route',ops,[service.key],true,{service:{id:'service'}}),f=recycleFixture(graphOf(service,route));
  await expect(f.recycle.archiveAndDelete({clusterId:cid,workspaceId:payWorkspaceId,actor,entityType:'services',entityId:'service',action:'delete',confirmed:true,confirmName:'service'})).rejects.toMatchObject({status:403});
  expect(f.db.exec).not.toHaveBeenCalled();expect(f.kong.request).not.toHaveBeenCalled();
 });
 it('requires explicit platform archived context for preview/purge and rejects deleted-workspace restore',async()=>{
  const f=recycleFixture();f.ws.rows.find(row=>row.id===payWorkspaceId)!.status='deleted';
  expect((await f.recycle.preview(cid,f.entry.id,actor,payWorkspaceId)).entry.workspace_id).toBe(payWorkspaceId);
  await expect(f.recycle.preview(cid,f.entry.id,{...actor,superAdmin:false},payWorkspaceId)).rejects.toMatchObject({status:403});
  await expect(f.recycle.preview(cid,f.entry.id,actor)).rejects.toMatchObject({status:403});
  await expect(f.recycle.restore(cid,f.entry.id,actor,{confirmed:true,confirm_name:'service'},{workspaceId:payWorkspaceId})).rejects.toMatchObject({status:403});
  await f.recycle.purge(cid,f.entry.id,actor,{confirmed:true,confirm_name:'service'},{workspaceId:payWorkspaceId});expect(f.mutations.execute).toHaveBeenCalledWith(expect.objectContaining({workspaceId:payWorkspaceId,archivedWorkspace:true}),expect.any(Function));expect(f.kong.request).not.toHaveBeenCalled();
 });
 it('preflights all current shared dependencies before any POST on restore',async()=>{
  const cert=graphNode('certificates','cert',pay,[],false),service=graphNode('services','service',pay,[cert.key]),f=recycleFixture(graphOf(service,cert));f.remote.set(cert.path,{...cert.data,tags:ops});
  await expect(f.recycle.restore(cid,f.entry.id,actor,{confirmed:true,confirm_name:'service'},{workspaceId:payWorkspaceId})).rejects.toMatchObject({status:403});expect(f.kong.request.mock.calls.every(call=>call[1]==='GET')).toBe(true);
 });
 it('binds signed recycle cursors to workspace revision and scope',async()=>{
  const f=recycleFixture();f.db.query.mockResolvedValue([f.entry,{...f.entry,id:'113c1ac4-10b7-4ec6-af3b-927b916ad9b7'}]);
  const page=await f.recycle.list(cid,actor,{workspaceId:payWorkspaceId,size:1});expect(page.nextCursor).toBeTruthy();
  await expect(f.recycle.list(cid,actor,{workspaceId:opsWorkspaceId,size:1,cursor:page.nextCursor})).rejects.toMatchObject({response:{code:'INVALID_CURSOR'}});
  f.ws.rows.find(row=>row.id===payWorkspaceId)!.revision++;await expect(f.recycle.list(cid,actor,{workspaceId:payWorkspaceId,size:1,cursor:page.nextCursor})).rejects.toMatchObject({response:{code:'INVALID_CURSOR'}});
 });
});

describe('M3 durable mutation workspace binding',()=>{
 it('persists workspace in both requested/result audit and isolates idempotency replay',async()=>{
  const f=mutationFixture(),write=vi.fn().mockResolvedValue({id:'service',tags:pay});await f.mutations.execute({...f.context},write);
  expect(f.records.get('scoped').workspace_id).toBe(payWorkspaceId);expect(f.audit.append.mock.calls.every(call=>call[0].workspaceId===payWorkspaceId)).toBe(true);
  await expect(f.mutations.execute({...f.context,workspaceId:opsWorkspaceId},write)).rejects.toMatchObject({status:403});expect(write).toHaveBeenCalledTimes(1);
  expect((await f.mutations.operationByKey(cid,'scoped',actor,payWorkspaceId)).workspace_id).toBe(payWorkspaceId);await expect(f.mutations.operationByKey(cid,'scoped',actor,opsWorkspaceId)).rejects.toMatchObject({status:403});
 });
 it('checks cached DELETE historical workspace before returning a succeeded acknowledgment',async()=>{
  const f=mutationFixture(),ctx={...f.context,action:'delete',entityId:'service',before:{id:'service',name:'service',tags:pay},payload:{confirmed:true}};
  await f.mutations.execute(ctx,async()=>({entryId:'archive',state:'deleted'}));expect(await f.mutations.completed({...ctx})).toMatchObject({entryId:'archive'});
  await expect(f.mutations.completed({...ctx,workspaceId:opsWorkspaceId})).rejects.toMatchObject({status:403});
 });
 it('lazily binds NULL native history only from its decrypted entity tags',async()=>{
  const f=mutationFixture();await f.mutations.execute({...f.context},async()=>({id:'service',tags:pay}));const row=f.records.get('scoped');row.workspace_id=null;
  await expect(f.mutations.operationByKey(cid,'scoped',actor)).rejects.toMatchObject({status:403});expect(row.workspace_id).toBeNull();
  await f.mutations.operationByKey(cid,'scoped',actor,payWorkspaceId);expect(row.workspace_id).toBe(payWorkspaceId);
  row.workspace_id=null;row.before_secret=f.secrets.encrypt({id:'service',tags:['kos-ws-unknown']},`mutation:${row.id}:before`);await expect(f.mutations.operationByKey(cid,'scoped',actor)).rejects.toMatchObject({status:403});expect(row.workspace_id).toBeNull();
 });
 it('revalidates the current native object before returning a cached creation result',async()=>{
  const f=mutationFixture(),write=vi.fn().mockResolvedValue({id:'service',tags:pay});await f.mutations.execute({...f.context},write);
  f.kong.request.mockResolvedValue({id:'service',name:'service',tags:ops});
  await expect(f.mutations.execute({...f.context},write)).rejects.toMatchObject({response:{code:'WORKSPACE_ENTITY_MISMATCH'}});expect(write).toHaveBeenCalledTimes(1);
 });
 it('allows restricted platform workspace metadata activation but blocks native mutations in inactive workspaces',async()=>{
  const f=mutationFixture();f.ws.rows.find(row=>row.id===payWorkspaceId)!.status='disabled';
  const fn=vi.fn().mockResolvedValue({id:'metadata'});await f.mutations.execute({...f.context,entityType:'workspaces',action:'update'},fn);expect(fn).toHaveBeenCalledTimes(1);
  await expect(f.mutations.execute({...f.context,idempotencyKey:'native'},fn)).rejects.toMatchObject({status:409,response:{code:'WORKSPACE_DISABLED'}});expect(fn).toHaveBeenCalledTimes(1);
 });
});
