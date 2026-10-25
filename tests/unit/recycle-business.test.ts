import {afterEach,beforeEach,describe,expect,it,vi}from'vitest';
import {ForbiddenException,HttpException,NotFoundException,ServiceUnavailableException}from'@nestjs/common';
import {randomUUID}from'node:crypto';
import {SecretService}from'../../apps/console-api/src/infrastructure/secret.service';
import {RecycleService,graphOrder,recycleName}from'../../apps/console-api/src/modules/recycle-bin/recycle.service';
import type {GraphNode,RecycleGraph}from'../../apps/console-api/src/modules/recycle-bin/graph-capturer.service';
import {defaultWorkspaceId,workspaceFixture}from'./workspace-test-fixture';
import {executionFixture}from'./execution-test-fixture';

const actor={id:randomUUID(),username:'admin',superAdmin:true},clusterId=randomUUID();
function node(type:string,id:string,data:any,dependencies:string[]=[],affected=true,parent?:string):GraphNode{
  return{key:`${type}:${id}`,type,id,data:{id,...data},dependencies,affected,restorable:true,
    restoreData:{id,...data},path:parent?`/upstreams/${parent}/targets/${id}`:`/${type}/${id}`};
}
function serviceGraph():RecycleGraph{
  const cert=node('certificates','cert',{cert:'public certificate',key:'private-certificate-key'},[],false);
  const consumer=node('consumers','consumer',{username:'shared-consumer'},[],false);
  const service=node('services','service',{name:'orders',host:'orders.internal',client_certificate:{id:'cert'}},[cert.key]);
  const route=node('routes','route',{name:'orders-route',paths:['/orders'],service:{id:'service'}},[service.key]);
  const plugin=node('plugins','plugin',{name:'key-auth',config:{key_names:['apikey']},route:{id:'route'},consumer:{id:'consumer'}},[route.key,consumer.key]);
  return{rootKey:service.key,nodes:[plugin,route,service,cert,consumer],complete:true,capturedAt:new Date().toISOString()};
}
function fixture(graph=serviceGraph()){
  const secrets=new SecretService(),entries=new Map<string,any>(),statuses=new Map<string,any>();
  const remote=new Map(graph.nodes.map(item=>[item.path,structuredClone(item.data)]));
  const effects:any[]=[];
  const db:any={one:vi.fn(async(sql:string,params:any[])=>{
    if(sql.includes('m11_recycle_purge_available'))return {eligible:true};
    if(sql.includes('FROM recycle_entries')){const entry=entries.get(params[1]);return entry?.cluster_id===params[0]?entry:null;}
    if(sql.includes('FROM recycle_nodes'))return statuses.get(`${params[0]}:${params[1]}`)??null;
    return null;
  }),exec:vi.fn(async(sql:string,p:any[])=>{
    effects.push({kind:'db',sql});
    if(sql.startsWith('INSERT INTO recycle_entries'))entries.set(p[0],{id:p[0],revision:1,cluster_id:p[1],actor_id:p[2],root_type:p[3],original_id:p[4],root_name:p[5],parent_id:p[6],credential_kind:p[7],node_count:p[8],payload_secret:p[9],state:'archived',expires_at:new Date(Date.now()+86400000),created_at:new Date(),mutation_id:p[11],workspace_id:p[12]});
    if(sql.startsWith('INSERT INTO recycle_nodes'))statuses.set(`${p[0]}:${p[1]}`,{restore_state:p[7],delete_state:p[6],restored_id:null});
    if(sql.startsWith('UPDATE recycle_entries')){
      const entry=entries.get(sql.includes("state='purged'")?p[1]:p[0]);
      if(entry){entry.revision++;const state=/SET state='([^']+)'/.exec(sql)?.[1];if(state)entry.state=state;if(state==='purged'){entry.payload_secret=null;entry.purged_at=new Date();}}
    }
    if(sql.startsWith('UPDATE recycle_nodes')){
      const item=statuses.get(`${p[0]}:${p[1]}`);if(item){
        if(sql.includes("delete_state='deleted'"))item.delete_state='deleted';else if(sql.includes('delete_state=$3'))item.delete_state=p[2];
        if(sql.includes("restore_state='restored'")){item.restore_state='restored';item.restored_id=p[2];}else if(sql.includes('restore_state=$3'))item.restore_state=p[2];
      }
    }
    return 1;
  }),query:vi.fn(async()=>[])};
  db.transaction=vi.fn(async(fn:any)=>fn(db));
  const kong:any={request:vi.fn(async(cid:string,method:string,path:string,body:any)=>{
    effects.push({kind:'kong',method,path,body});
    if(method==='GET'){if(remote.has(path))return structuredClone(remote.get(path));throw new NotFoundException('missing');}
    if(method==='DELETE'){
      if(![...entries.values()].some(entry=>entry.payload_secret&&secrets.decrypt<RecycleGraph>(entry.payload_secret,`recycle:${entry.id}`).complete))throw new Error('DELETE before archive');
      if(path.includes('/targets/')){const value=remote.get(path);if(value)remote.set(path.replace(/[^/]+$/,encodeURIComponent(value.target)),{...value,id:randomUUID(),weight:0});}
      else{
        const value=remote.get(path);
        if(path.startsWith('/snis/')&&value?.certificate?.id){const certificate=remote.get(`/certificates/${value.certificate.id}`);if(certificate?.snis)certificate.snis=certificate.snis.filter((name:string)=>name!==value.name);}
        remote.delete(path);
      }return null;
    }
    if(method==='POST'){
      const value={...body,id:path.endsWith('/targets')?randomUUID():body.id,
        ...(path.endsWith('/targets')?{upstream:{id:decodeURIComponent(path.split('/')[2])}}:{})};
      remote.set(`${path}/${value.id}`,value);
      if(path.endsWith('/targets'))remote.set(`${path}/${encodeURIComponent(value.target)}`,value);
      return value;
    }
    throw new Error('unexpected method');
  }),list:vi.fn(async(cid:string,path:string)=>({items:[...remote.entries()].filter(([key,value])=>key.startsWith(`${path}/`)&&key.endsWith(encodeURIComponent(value.target))&&value.weight>0).map(([,value])=>value),nextCursor:null,size:100}))};
  const mutations:any={claimGraphImpact:vi.fn(async(_context:any,nodes:any[])=>{effects.push({kind:'impact',nodes:nodes.map(n=>n.key)});}),execute:vi.fn(async(context:any,fn:any)=>{context.operationId=randomUUID();return fn();})};
  const capturer:any={capture:vi.fn(async()=>graph)};
  const authz:any={isPlatformAdmin:vi.fn(async(user:any)=>user.superAdmin===true),assertCluster:vi.fn().mockResolvedValue(undefined),assertEntity:vi.fn().mockResolvedValue(undefined),permissionVersion:vi.fn(async(user:any)=>`${user.id}:v1`)};
  // Explicitly model the new sealed-archive delegate. The real authority
  // negative cases live in the M8 Authorization/Recycle boundary suites.
  authz.assertArchivedEntity=authz.assertEntity;
  const audit:any={append:vi.fn().mockResolvedValue(undefined)},credentials:any={remove:vi.fn(),save:vi.fn()},index:any={remove:vi.fn(),upsert:vi.fn()};
  const recycle=new RecycleService(db,secrets,kong,mutations,capturer,authz,audit,credentials,index,workspaceFixture(clusterId).resolver,executionFixture());
  const root=graph.nodes.find(item=>item.key===graph.rootKey)!;
  const deletion={clusterId,workspaceId:defaultWorkspaceId,actor,entityType:root.type,entityId:root.id,before:root.data,action:'delete',confirmed:true,confirmName:recycleName(root),parentId:root.type==='targets'?root.data.upstream.id:undefined};
  return{recycle,secrets,db,kong,mutations,capturer,authz,audit,credentials,index,graph,entries,statuses,remote,effects,deletion};
}

describe('Recycle durable archive and dependency recovery',()=>{
  beforeEach(()=>{vi.stubEnv('CONSOLE_ENCRYPTION_KEY','cd'.repeat(32));vi.stubEnv('APP_SECRET','signed-cursor-key-with-at-least-32-characters');vi.stubEnv('RECYCLE_RETENTION_DAYS','30');});
  afterEach(()=>vi.unstubAllEnvs());

  it('persists the complete encrypted graph before DELETE, deletes children first and retains shared parents',async()=>{
    const f=fixture(),result=await f.recycle.archiveAndDelete(f.deletion);
    expect(result.state).toBe('deleted');
    expect(f.effects.filter(item=>item.kind==='kong'&&item.method==='DELETE').map(item=>item.path)).toEqual(['/plugins/plugin','/routes/route','/services/service']);
    expect(f.remote.has('/certificates/cert')).toBe(true);expect(f.remote.has('/consumers/consumer')).toBe(true);
    const entry=f.entries.get(result.entryId)!;
    expect(entry.payload_secret).not.toContain('private-certificate-key');
    expect(f.secrets.decrypt<RecycleGraph>(entry.payload_secret,`recycle:${entry.id}`).nodes).toHaveLength(5);
    expect(f.index.remove).toHaveBeenCalledTimes(3);
    expect(entry.mutation_id).toBeTruthy();
    expect(f.mutations.claimGraphImpact).toHaveBeenCalledWith(expect.objectContaining({operationId:entry.mutation_id}),f.graph.nodes);
    const claim=f.effects.findIndex(e=>e.kind==='impact'),archive=f.effects.findIndex(e=>e.kind==='db'&&e.sql.startsWith('INSERT INTO recycle_entries'));
    const firstDelete=f.effects.findIndex(e=>e.kind==='kong'&&e.method==='DELETE');
    expect(claim).toBeGreaterThanOrEqual(0);expect(claim).toBeLessThan(archive);expect(archive).toBeLessThan(firstDelete);
  });

  it('does not archive or delete when the durable graph-impact guard rejects an unresolved child',async()=>{
    const f=fixture();f.mutations.claimGraphImpact.mockRejectedValue(new HttpException({code:'MUTATION_RECONCILIATION_REQUIRED'},409));
    await expect(f.recycle.archiveAndDelete(f.deletion)).rejects.toMatchObject({status:409});
    expect(f.entries.size).toBe(0);expect(f.effects.filter(e=>e.kind==='kong'&&e.method==='DELETE')).toEqual([]);
  });

  it('never calls DELETE if graph persistence fails or capture is incomplete',async()=>{
    const f=fixture();f.db.exec.mockImplementation(async(sql:string)=>{if(sql.startsWith('INSERT INTO recycle_entries'))throw new Error('disk unavailable');return 1;});
    await expect(f.recycle.archiveAndDelete(f.deletion)).rejects.toThrow('disk unavailable');
    expect(f.kong.request.mock.calls.some((call:any[])=>call[1]==='DELETE')).toBe(false);
    f.capturer.capture.mockRejectedValueOnce(new HttpException({code:'RECYCLE_CAPTURE_LIMIT'},409));
    await expect(f.recycle.archiveAndDelete(f.deletion)).rejects.toMatchObject({status:409});
    expect(f.kong.request.mock.calls.some((call:any[])=>call[1]==='DELETE')).toBe(false);
  });

  it('requires exact confirmation and authorization for every affected node before archive',async()=>{
    const f=fixture();await expect(f.recycle.archiveAndDelete({...f.deletion,confirmName:'different'})).rejects.toMatchObject({status:400});
    f.authz.assertEntity.mockImplementation(async(user:any,cid:string,type:string,action:string)=>{if(type==='routes'&&action==='delete')throw new HttpException('forbidden',403);});
    await expect(f.recycle.archiveAndDelete(f.deletion)).rejects.toMatchObject({status:403});
    expect(f.entries.size).toBe(0);expect(f.kong.request).not.toHaveBeenCalled();
  });

  it('deletes expanded certificate SNI relationships without treating its own child removal as external drift',async()=>{
    const cert=node('certificates','cert',{cert:'public certificate',key:'private-key',snis:['api.example.com']});
    cert.restoreData={id:'cert',cert:'public certificate',key:'private-key'};
    const sni=node('snis','sni',{name:'api.example.com',certificate:{id:'cert'}},[cert.key]);
    const f=fixture({rootKey:cert.key,nodes:[cert,sni],complete:true,capturedAt:new Date().toISOString()});
    const result=await f.recycle.archiveAndDelete(f.deletion);
    expect(result.state).toBe('deleted');
    expect(f.kong.request.mock.calls.filter((call:any[])=>call[1]==='DELETE').map((call:any[])=>call[2])).toEqual(['/snis/sni','/certificates/cert']);
  });

  it('restores original IDs in dependency order with authoritative reads and per-object audit',async()=>{
    const f=fixture(),deleted=await f.recycle.archiveAndDelete(f.deletion);f.effects.length=0;
    const restored=await f.recycle.restore(clusterId,deleted.entryId,actor,{confirmed:true,confirm_name:'orders'});
    expect(restored.state).toBe('restored');
    expect(f.effects.filter(item=>item.kind==='kong'&&item.method==='POST').map(item=>item.path)).toEqual(['/services','/routes','/plugins']);
    expect(restored.restored.map((item:any)=>[item.originalId,item.restoredId])).toEqual([['service','service'],['route','route'],['plugin','plugin']]);
    expect(f.audit.append.mock.calls.filter((call:any[])=>call[0].action==='restore')).toHaveLength(3);
    expect(f.index.upsert).toHaveBeenCalledTimes(3);
  });

  it('persists partial restore and continues completed steps without duplicate creations',async()=>{
    const f=fixture(),deleted=await f.recycle.archiveAndDelete(f.deletion),normal=f.kong.request.getMockImplementation()!;
    let fail=true;
    f.kong.request.mockImplementation(async(cid:string,method:string,path:string,body:any)=>{if(method==='POST'&&path==='/routes'&&fail){fail=false;throw new ServiceUnavailableException('temporary');}return normal(cid,method,path,body);});
    await expect(f.recycle.restore(clusterId,deleted.entryId,actor,{confirmed:true,confirm_name:'orders'})).rejects.toMatchObject({status:503});
    expect(f.entries.get(deleted.entryId)?.state).toBe('partially_restored');
    expect(f.statuses.get(`${deleted.entryId}:services:service`)?.restore_state).toBe('restored');
    expect((await f.recycle.restore(clusterId,deleted.entryId,actor,{confirmed:true,confirm_name:'orders'})).state).toBe('restored');
    expect(f.kong.request.mock.calls.filter((call:any[])=>call[1]==='POST'&&call[2]==='/services')).toHaveLength(1);
  });

  it('refuses to overwrite an original ID now occupied by a different configuration',async()=>{
    const f=fixture(),deleted=await f.recycle.archiveAndDelete(f.deletion);f.remote.set('/services/service',{...f.graph.nodes.find(item=>item.type==='services')!.data,host:'conflicting.example'});
    await expect(f.recycle.restore(clusterId,deleted.entryId,actor,{confirmed:true,confirm_name:'orders'})).rejects.toMatchObject({status:503});
    expect(f.remote.get('/services/service')?.host).toBe('conflicting.example');
    expect(f.kong.request.mock.calls.some((call:any[])=>call[1]==='POST')).toBe(false);
  });

  it('validates Target effective removal while preserving history and recreates a new effective ID',async()=>{
    const upstream=node('upstreams','upstream',{name:'pool'},[],false);
    const target=node('targets','old-target',{target:'127.0.0.1:9000',weight:100,upstream:{id:'upstream'}},[upstream.key],true,'upstream');
    const f=fixture({rootKey:target.key,nodes:[target,upstream],complete:true,capturedAt:new Date().toISOString()});
    f.remote.set('/upstreams/upstream/targets/127.0.0.1%3A9000',target.data);
    const deleted=await f.recycle.archiveAndDelete(f.deletion);
    expect(f.remote.has('/upstreams/upstream/targets/old-target')).toBe(true);
    const restored=await f.recycle.restore(clusterId,deleted.entryId,actor,{confirmed:true,confirm_name:'127.0.0.1:9000'});
    const record=restored.restored[0];expect(record.originalId).toBe('old-target');expect(record.restoredId).not.toBe('old-target');
    expect(f.kong.request.mock.calls.some((call:any[])=>call[1]==='POST'&&call[2]==='/upstreams/upstream/targets')).toBe(true);
  });

  it('keeps a durable archive and uncertain node result when DELETE responses fail',async()=>{
    const f=fixture(),normal=f.kong.request.getMockImplementation()!;
    f.kong.request.mockImplementation(async(cid:string,method:string,path:string,body:any)=>{if(method==='DELETE')throw new ServiceUnavailableException({code:'KONG_WRITE_RESULT_UNKNOWN'});return normal(cid,method,path,body);});
    await expect(f.recycle.archiveAndDelete(f.deletion)).rejects.toMatchObject({status:503});
    const entry=[...f.entries.values()][0];expect(entry.state).toBe('partially_deleted');expect(entry.payload_secret).toBeTruthy();
    expect(f.statuses.get(`${entry.id}:plugins:plugin`)?.delete_state).toBe('uncertain');
  });

  it('rechecks archived child configuration before deleting an object changed by another writer',async()=>{
    const f=fixture();f.remote.set('/plugins/plugin',{...f.remote.get('/plugins/plugin'),enabled:false});
    await expect(f.recycle.archiveAndDelete(f.deletion)).rejects.toMatchObject({status:503,response:{cause:'ENTITY_CHANGED_DURING_DELETE'}});
    expect(f.kong.request.mock.calls.some((call:any[])=>call[1]==='DELETE')).toBe(false);
    expect(f.remote.get('/plugins/plugin')?.enabled).toBe(false);
  });

  it('refuses stale Target IDs when the same address acquired a new effective record',async()=>{
    const upstream=node('upstreams','upstream',{name:'pool'},[],false),target=node('targets','old-target',{target:'127.0.0.1:9000',weight:100,upstream:{id:'upstream'}},[upstream.key],true,'upstream');
    const f=fixture({rootKey:target.key,nodes:[target,upstream],complete:true,capturedAt:new Date().toISOString()});
    f.remote.set('/upstreams/upstream/targets/127.0.0.1%3A9000',{...target.data,id:'new-effective-target',weight:200});
    await expect(f.recycle.archiveAndDelete(f.deletion)).rejects.toMatchObject({status:503,response:{cause:'ENTITY_CHANGED_DURING_DELETE'}});
    expect(f.kong.request.mock.calls.some((call:any[])=>call[1]==='DELETE')).toBe(false);
  });

  it('returns only redacted previews, rejects cross-cluster IDs and requires confirmed payload destruction',async()=>{
    const f=fixture(),deleted=await f.recycle.archiveAndDelete(f.deletion);
    const preview=await f.recycle.preview(clusterId,deleted.entryId,actor);
    expect(JSON.stringify(preview)).not.toContain('private-certificate-key');expect(preview.entry.payload_secret).toBeUndefined();
    await expect(f.recycle.preview(randomUUID(),deleted.entryId,actor)).rejects.toMatchObject({status:404});
    await expect(f.recycle.purge(clusterId,deleted.entryId,actor,{confirmed:true,confirm_name:'wrong'})).rejects.toMatchObject({status:400});
    expect(await f.recycle.purge(clusterId,deleted.entryId,actor,{confirmed:true,confirm_name:'orders'})).toEqual({id:deleted.entryId,purged:true});
    expect(f.entries.get(deleted.entryId)?.payload_secret).toBeNull();
    await expect(f.recycle.restore(clusterId,deleted.entryId,actor,{confirmed:true,confirm_name:'orders'})).rejects.toMatchObject({status:409});
  });

  it('binds recycle cursors to the actor and search filters, keeps search parameterized',async()=>{
    const f=fixture(),deleted=await f.recycle.archiveAndDelete(f.deletion),entry=f.entries.get(deleted.entryId)!;
    const rows=[entry,{...entry,id:randomUUID()}];f.db.query.mockResolvedValue(rows);
    const page=await f.recycle.list(clusterId,actor,{size:1,search:"orders' OR 1=1 --"});
    expect(page.nextCursor).toBeTruthy();
    expect(f.db.query.mock.calls.at(-1)?.[1][6]).toBe("orders' OR 1=1 --");
    expect(f.db.query.mock.calls.at(-1)?.[0]).not.toContain("orders' OR 1=1 --");
    await expect(f.recycle.list(clusterId,{...actor,id:randomUUID()},{size:1,search:"orders' OR 1=1 --",cursor:page.nextCursor})).rejects.toMatchObject({status:400});
    await expect(f.recycle.list(clusterId,actor,{size:1,search:'changed',cursor:page.nextCursor})).rejects.toMatchObject({status:400});
  });

  it('skips recycle entries whose live parent is gone instead of failing the whole page, without exposing them',async()=>{
    const f=fixture(),deleted=await f.recycle.archiveAndDelete(f.deletion),entry=f.entries.get(deleted.entryId)!;
    const orphan={...entry,id:randomUUID()},denied={...entry,id:randomUUID()};f.db.query.mockResolvedValue([orphan,entry,denied]);
    const secrets=(f.recycle as any).secrets,decrypt=secrets.decrypt.bind(secrets);
    vi.spyOn(secrets,'decrypt').mockImplementation((value:any,aad:any)=>decrypt(value,[orphan.id,denied.id].some(id=>aad===`recycle:${id}`)?`recycle:${entry.id}`:aad));
    const original=(f.recycle as any).bindEntry.bind(f.recycle);
    const spy=vi.spyOn(f.recycle as any,'bindEntry').mockImplementation(async(...args:any[])=>{
      if(args[0].id===orphan.id)throw new NotFoundException({code:'KONG_VALIDATION_ERROR',message:'Not found'});
      if(args[0].id===denied.id)throw new ForbiddenException();return original(...args);});
    const page=await f.recycle.list(clusterId,actor,{size:20});
    expect(page.items.map((item:any)=>item.id)).toEqual([entry.id]);expect(page.unavailableCount).toBe(1);
    expect(JSON.stringify(page)).not.toContain(orphan.id);expect(JSON.stringify(page)).not.toContain(denied.id);
    spy.mockRejectedValueOnce(new ServiceUnavailableException());await expect(f.recycle.list(clusterId,actor,{size:20})).rejects.toMatchObject({status:503});
  });

  it('detects incomplete dependencies/cycles and never uses secret keys as names',()=>{
    const graph=serviceGraph();graph.nodes[0].dependencies.push(graph.nodes[0].key);expect(()=>graphOrder(graph)).toThrow();
    expect(recycleName(node('key-auth','safe-id',{key:'secret-key'}))).toBe('safe-id');
  });
});
