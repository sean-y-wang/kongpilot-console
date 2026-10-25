// @ts-nocheck -- real cleanup functions, pure RAM BFF DTO transport only.
import { describe, expect, it } from 'vitest';
import { randomUUID } from 'node:crypto';
import { M8Harness, sha256 } from './lib/m8-harness.mjs';
import { beginM8Cleanup, m8CleanupAcceptance, m8CleanupConfiguration, m8CleanupNative, m8CleanupIdentity } from './lib/m8-cleanup-acceptance.mjs';

function fixture(change=''){
 const direct={cid:randomUUID(),wid:randomUUID()},approval={cid:randomUUID(),wid:randomUUID()},foreign={cid:direct.cid,wid:randomUUID()},tag='m8-source-cleanup';
 const session=label=>({label,user:{id:randomUUID(),username:`${tag}-${label}`},sid:randomUUID(),cookie:`synthetic-${label}=ram`,csrf:'synthetic-csrf'});
 const actors={admin:session('admin'),owner:session('owner'),other:session('other-owner'),approver:session('approver'),bootstrap:session('bootstrap-provisioner')},readonly=session('read-only');
 const users=new Map(),roles=new Map(),workspaces=new Map(),native=new Map(),archives=new Map(),calls=[],saves=[],metadata=[];
 const originalRequest={index:0,key:randomUUID(),method:'POST',path:`/api/v1/clusters/${direct.cid}/configuration/imports`,query:`?workspaceId=${direct.wid}`,clusterId:direct.cid,workspaceId:direct.wid,
  actorId:actors.admin.user.id,sessionId:actors.admin.sid,body:{scope:'services',serviceIds:[randomUUID()]},bodySha256:'synthetic-preserved-original-hash',state:'response_observed',status:500,requestId:randomUUID()};
 const state={version:1,milestone:'M8',testTag:tag,phase:'http-complete',inFlight:null,scopes:{direct,approval,foreign},nativeFixture:{area:direct},httpAcceptanceComplete:true,
  rbacAcceptance:{complete:true},deckAcceptance:{complete:true},requests:[originalRequest],secrets:[],configurationOperations:[],cliIntents:[],proxyChecks:[],privateHistoryRefs:[{file:'synthetic-retained-history.json',sha256:'1'.repeat(64),bytes:1}],
  sessions:{admin:actors.admin,owner:actors.owner,'other-owner':actors.other,approver:actors.approver,'read-only':readonly,'bootstrap-provisioner':actors.bootstrap},accounts:[],fixtures:[],
  originalClusterModes:{[direct.cid]:{mode:'direct',revision:1},[approval.cid]:{mode:'direct',revision:1}},c2ModeChanged:true,
  manualUiJournal:{phase:'complete',attempts:Array.from({length:12},()=>({state:'succeeded'})),sessions:{admin:structuredClone(actors.admin),owner:structuredClone(actors.owner),readonly:structuredClone(readonly)}}};
 const ownerRole={id:randomUUID(),name:`${tag} owner role`,status:'active',revision:5,cluster_id:direct.cid,workspace_id:direct.wid};roles.set(ownerRole.id,ownerRole);
 for(const actor of[actors.admin,actors.owner,actors.other,readonly,actors.approver]){
  const area=actor===actors.approver?approval:actor===actors.admin?null:direct,role=actor===actors.owner||actor===actors.other?ownerRole:{id:randomUUID(),name:`${tag} ${actor.label} role`,status:'active',revision:4,cluster_id:area?.cid??null,workspace_id:area?.wid??null};
  roles.set(role.id,role);users.set(actor.user.id,{id:actor.user.id,username:actor.user.username,status:'active',revision:3});
  state.accounts.push({label:actor.label,userId:actor.user.id,username:actor.user.username,role:structuredClone(role),cid:area?.cid??null,wid:area?.wid??null});
  state.fixtures.push({type:'users',id:actor.user.id,name:actor.user.username},{type:'roles',id:role.id,name:role.name,cid:area?.cid,wid:area?.wid});
 }
 for(const area of[direct,approval,foreign]){const row={id:area.wid,cluster_id:area.cid,name:`${tag} workspace ${area.wid}`,status:'active',revision:7,is_default:false};workspaces.set(area.wid,row);state.fixtures.push({type:'workspaces',id:area.wid,cid:area.cid,wid:area.wid,name:row.name});}
 const makeNative=(type,area=direct,parentId)=>{const row={id:randomUUID(),name:`${tag} ${type}`,tags:[tag],...(parentId&&type!=='targets'?{consumer:{id:parentId}}:{})};
  native.set(`${area.cid}:${area.wid}:${type}:${row.id}`,{row,type,area,parentId,deleted:false});state.fixtures.push({...area,type:['key-auth'].includes(type)?'credentials':type,id:row.id,name:row.name,...(parentId?{parentId}:{ }),...(type==='key-auth'?{credentialKind:type}:{})});return row;};
 const service=makeNative('services'),route=makeNative('routes'),plugin=makeNative('plugins'),consumer=makeNative('consumers'),credential=makeNative('key-auth',direct,consumer.id),
  upstream=makeNative('upstreams'),target=makeNative('targets',direct,upstream.id),certificate=makeNative('certificates'),sni=makeNative('snis'),ca=makeNative('ca_certificates');
 state.fixtures.push(structuredClone(state.fixtures.find(f=>f.id===route.id))); // Same original, no second DELETE.
 const makeMetadata=(type,owner,area=direct,stateValue='ready',roots=[])=>{const row={id:randomUUID(),name:type==='snapshots'&&stateValue==='failed'?'internal failed preview':`${tag} ${type} ${owner.label}`,
  clusterId:area.cid,workspaceId:area.wid,scopeKind:roots.length?'services':'workspace',rootIds:roots,state:stateValue,revision:2,ownerUserId:owner.user.id,
  ...(type==='snapshots/schedules'?{intervalMinutes:60,timezone:'UTC',retentionDays:7}:{})};metadata.push({row,type,owner});return row;};
 makeMetadata('snapshots/schedules',actors.admin,direct,'active');makeMetadata('snapshots/schedules',actors.owner,direct,'paused');
 makeMetadata('snapshots',actors.admin);makeMetadata('snapshots',actors.admin,direct,'failed',originalRequest.body.serviceIds);makeMetadata('snapshots',actors.owner);
 const jobs=new Map(),clusters=[{id:direct.cid,execution_mode:'direct',revision:8},{id:approval.cid,execution_mode:'approval',revision:9}],keyed=new Map();
 const page=(items,url)=>{const size=Number(url.searchParams.get('size')),offset=Number(url.searchParams.get('cursor')??0);return{items:items.slice(offset,offset+size),size,total:null,nextCursor:offset+size<items.length?String(offset+size):null};};
 const h={state,public:{},checks:[],check:M8Harness.prototype.check,data:M8Harness.prototype.data,assertWritable:M8Harness.prototype.assertWritable,
  save(extra={}){Object.assign(state,extra);saves.push(state.cleanupJournal&&structuredClone(state.cleanupJournal));},async poll(read,predicate){const value=await read();h.check(predicate(value),'RAM known original terminal job');return value;},
  async request(actor,path,method='GET',body,options={}){
   const url=new URL(`http://source.invalid/api/v1${path}`),p=url.pathname,op=state.cleanupJournal?.operations[state.cleanupJournal.inFlight];
   calls.push({actorId:actor.user.id,sessionId:actor.sid,path,method,body:body&&structuredClone(body),prepared:op&&structuredClone(op)});
   if(op)expect(saves.at(-1).operations[op.index].state).toBe('prepared');
   const packet=!['GET','HEAD'].includes(method)?{index:state.requests.length,key:options.key??randomUUID(),path:p,query:url.search,method,body:structuredClone(body),bodySha256:sha256(JSON.stringify(body)),actorId:actor.user.id,sessionId:actor.sid,
    clusterId:p.match(/\/clusters\/([a-f\d-]{36})/)?.[1]??null,workspaceId:url.searchParams.get('workspaceId'),state:'prepared'}:undefined;
   if(packet){h.assertWritable();state.requests.push(packet);h.save({phase:'request-in-flight',inFlight:packet.index});}
   if(change==='unknownPause'&&op?.name==='snapshots/schedules-pause'){packet.state='response_unknown';h.save({phase:'stopped-unknown'});throw Error('synthetic lost pause response');}
   let status=200,data,error;const cid=p.match(/\/clusters\/([a-f\d-]{36})/)?.[1],wid=url.searchParams.get('workspaceId');
   if(p==='/api/v1/auth/me')data={user:actor.user};
   else if(p==='/api/v1/auth/me/sessions')data={items:[{id:actor.sid,current:true}],nextCursor:null,total:null,size:100};
   else if(p==='/api/v1/clusters')data=structuredClone(clusters);
   else if(p===`/api/v1/clusters/${approval.cid}`&&method==='PATCH'){const row=clusters[1];expect(body).toEqual({revision:row.revision,execution_mode:'direct'});Object.assign(row,{execution_mode:'direct',revision:row.revision+1});data=structuredClone(row);}
   else if(/\/snapshots(?:\/schedules)?$/.test(p)&&method==='GET'){
    const type=p.endsWith('/schedules')?'snapshots/schedules':'snapshots',roots=url.searchParams.get('serviceIds')?.split(',')??[];
    const rows=metadata.filter(v=>v.type===type&&v.row.clusterId===cid&&v.row.workspaceId===wid&&v.row.scopeKind===url.searchParams.get('scope')&&JSON.stringify(v.row.rootIds)===JSON.stringify(roots))
     .map(v=>({...structuredClone(v.row),capabilities:{delete:v.row.state!=='deleted'&&v.owner.user.id===actor.user.id}}));
    data=page(rows,url);if(change==='cursorCycle'&&type==='snapshots')data.nextCursor='same-cursor';
   }else if(/\/snapshots\/(?:schedules\/)?[a-f\d-]{36}(?:\/archive)?$/.test(p)&&method!=='GET'){
    const id=p.split('/').filter(Boolean).at(p.endsWith('/archive')?-2:-1),item=metadata.find(v=>v.row.id===id);expect(item).toBeDefined();expect(actor.user.id).toBe(item.owner.user.id);expect(body.revision).toBe(item.row.revision);expect(body.confirm_name).toBe(item.row.name);
    if(change==='failedArchive409'&&item.row.state==='failed'){status=409;error={code:'SNAPSHOT_REVISION_CONFLICT'};}
    else{item.row.state=method==='PATCH'?'paused':'deleted';item.row.revision++;
     const receipt={domain:'configuration',durable:true,id:randomUUID(),actorId:actor.user.id,clusterId:cid,workspaceId:wid,originalScope:{clusterId:cid,workspaceId:wid},idempotencyKey:packet.key,kind:'compare',state:'succeeded',executionCompleted:true,
      resourceId:id,resourceType:item.type==='snapshots'?'config_snapshots':'config_snapshot_schedules',operation:method==='PATCH'?'update':'archive'};receipt.jobId=receipt.id;jobs.set(packet.key,receipt);status=method==='POST'?201:200;data={...receipt,entity:structuredClone(item.row)};}
   }else if(p.includes('/configuration/jobs/by-key/'))data=structuredClone(jobs.get(p.split('/').at(-1)));
   else if(/\/entities\/[a-z_]+$/.test(p))data=page([...native.values()].filter(n=>n.type===p.split('/').at(-1)&&n.area.cid===cid&&n.area.wid===wid&&!n.deleted).map(n=>structuredClone(n.row)),url);
   else if(p.endsWith('/recycle-bin'))data=page([],url);
   else if(/\/recycle-bin\/[a-f\d-]{36}$/.test(p)){
    data=structuredClone(archives.get(p.split('/').at(-1)));if(change==='referenceNode'&&data.entry.root_type==='services'){data.nodes.find(n=>n.entity_type==='routes').affected=false;data.graph.nodes.find(n=>n.type==='routes').affected=false;}
    if(data.entry.root_type==='consumers'){
     const child=data.graph.nodes.find(n=>n.type==='key-auth'),row=data.nodes.find(n=>n.entity_type==='key-auth');
     if(change==='wrongChildNodeKey')row.node_key=`key-auth:${randomUUID()}:${child.id}`;
     if(change==='wrongChildDependency')child.dependencies=[`consumers:${randomUUID()}`];
     if(change==='wrongChildDataIdentity')child.data.id=randomUUID();
    }
   }else if(/\/entities\/[a-z_]+\/[a-f\d-]{36}$/.test(p)){
    const[type,id]=p.split('/').slice(-2),root=native.get(`${cid}:${wid}:${type}:${id}`);expect(root).toBeDefined();
    if(method==='GET'){if(root.deleted||change==='unproven404'&&type==='services'){status=404;error={code:'KONG_NOT_FOUND'};}else data={entity:structuredClone(root.row)};}
    else{
     expect(state.cleanupJournal.sourcesDeactivated).toBe(true);expect(metadata.every(m=>m.row.state==='deleted')).toBe(true);expect(body).toEqual({confirmed:true,confirm_name:root.row.name});
     const ids=type==='services'?[service.id,route.id,plugin.id]:type==='consumers'?[consumer.id,credential.id]:type==='upstreams'?[upstream.id,target.id]:type==='certificates'?[certificate.id,sni.id]:[id];
     const affected=[...native.values()].filter(n=>ids.includes(n.row.id)),entryId=randomUUID();affected.forEach(n=>n.deleted=true);
     const nodes=affected.map(n=>({node_key:n.parentId?`${n.type}:${n.parentId}:${n.row.id}`:`${n.type}:${n.row.id}`,entity_type:n.type,original_id:n.row.id,affected:true,delete_state:'deleted'}));
     const graph={complete:true,purpose:'recycle',nodes:affected.map(n=>({key:'[REDACTED:0123456789abcdef]',type:n.type,id:n.row.id,affected:true,data:structuredClone(n.row),
      path:n.parentId?`/${n.type==='targets'?'upstreams':'consumers'}/${n.parentId}/${n.type==='targets'?'targets':n.type}/${n.row.id}`:`/${n.type}/${n.row.id}`,
      dependencies:n.parentId?[`${n.type==='targets'?'upstreams':'consumers'}:${n.parentId}`]:[]}))};
     archives.set(entryId,{entry:{id:entryId,cluster_id:cid,workspace_id:wid,state:'deleted',root_type:type,original_id:id},nodes,graph});data={entryId,state:'deleted',deleted:affected.map(n=>({type:n.type,id:n.row.id}))};
    }
   }else if(/\/iam\/(users|roles)\/[a-f\d-]{36}$/.test(p)){
    const[type,id]=p.split('/').slice(-2),map=type==='users'?users:roles,row=map.get(id);expect(row).toBeDefined();
    if(method==='GET')data=structuredClone(row);else{
     expect(body).toEqual({revision:row.revision,confirmed:true,confirm_name:type==='users'?row.username:row.name});
     if(id===actors.admin.user.id||id===state.accounts.find(a=>a.label==='admin').role.id)expect(actor.user.id).toBe(actors.bootstrap.user.id);
     row.status='deleted';row.revision++;data=structuredClone(row);
    }
   }else if(/\/workspaces\/[a-f\d-]{36}$/.test(p)){
    const row=workspaces.get(p.split('/').at(-1));if(method==='GET')data=structuredClone(row);else{expect([...native.values()].filter(n=>n.area.wid===row.id&&!n.deleted)).toHaveLength(0);expect(body).toEqual({revision:row.revision,confirmed:true,confirm_name:row.name});row.status='deleted';row.revision++;data={state:'deleted',workspace:structuredClone(row)};}
   }else throw Error(`unexpected synthetic BFF path ${method} ${p}`);
   const result={status,requestId:randomUUID(),payload:error?{success:false,error}:{success:true,data}};
   if(packet){Object.assign(packet,{state:'response_observed',status,requestId:result.requestId});h.save({phase:'request-observed',inFlight:null});keyed.set(packet.key,packet);}
   h.check((options.expected??[200,201]).includes(status),'RAM exact controller response status');return result;
  }};
 return{h,state,actors,calls,metadata,native,archives,users,roles,workspaces,original:JSON.stringify(originalRequest),service,route,plugin};
}

describe('independent SOURCE original M8 BFF cleanup stages',()=>{
 it('deactivates every schedule, owner-archives all scoped/internal snapshots to EOF, recycles exact graphs once and CAS-soft-deletes identities last',async()=>{
  const f=fixture(),events=[];const result=await m8CleanupAcceptance(f.h,f.actors,{pageSize:1,
   beforeCleanup:async()=>events.push('beforeCleanup'),beforeNative:async()=>{expect(f.metadata.every(m=>m.row.state==='deleted')).toBe(true);events.push('beforeNative');},
   beforeIdentity:async()=>{expect([...f.native.values()].every(n=>n.deleted)).toBe(true);expect([...f.users.values()].every(u=>u.status==='active')).toBe(true);events.push('beforeIdentity');},
   beforeFinalIdentity:async()=>events.push('beforeFinalIdentity'),afterIdentity:async()=>events.push('afterIdentity')});
  expect(result).toMatchObject({businessCompleted:true,configurationArchived:true,nativeRecycled:true,identitySoftDeleted:true,archivedMetadata:5,nativeRootsRecycled:5,nativeAffectedObjects:10});
  expect(events).toEqual(['beforeCleanup','beforeNative','beforeIdentity','beforeFinalIdentity','afterIdentity']);
  expect(f.state.cleanupJournal.eofPages.some(p=>p.pages>1)).toBe(true);expect(f.state.cleanupJournal.eofPages.every(p=>p.terminal)).toBe(true);
  const snapshotWrites=f.calls.filter(c=>c.method==='POST'&&c.path.includes('/archive'));
  expect(snapshotWrites).toHaveLength(3);expect(snapshotWrites.some(c=>c.actorId===f.actors.owner.user.id)).toBe(true);expect(snapshotWrites.some(c=>c.body.confirm_name==='internal failed preview')).toBe(true);
  const nativeDeletes=f.calls.filter(c=>c.method==='DELETE'&&c.path.includes('/entities/'));
  expect(nativeDeletes.map(c=>new URL(c.path,'http://source.invalid').pathname.split('/').at(-2))).toEqual(['services','consumers','upstreams','certificates','ca_certificates']);
  expect(nativeDeletes.some(c=>[f.route.id,f.plugin.id].some(id=>c.path.includes(id)))).toBe(false);
  const last=f.calls.filter(c=>c.method==='DELETE').slice(-2);expect(last.every(c=>c.actorId===f.actors.bootstrap.user.id)).toBe(true);
  expect(f.state.requests[0]).toEqual(JSON.parse(f.original));expect(f.state.privateHistoryRefs).toHaveLength(1);
  expect(f.calls.some(c=>/\/purge|\/configuration\/(?:plans|imports|exports).*DELETE/.test(c.path))).toBe(false);
  expect(f.state.cleanupJournal.phase).toBe('complete');const count=f.calls.length;await expect(m8CleanupAcceptance(f.h,f.actors)).rejects.toThrow();expect(f.calls).toHaveLength(count);
 });
 it('preserves a real archive conflict for failed preview rather than declaring success or starting native deletion',async()=>{
  const f=fixture('failedArchive409');await beginM8Cleanup(f.h,f.actors,{pageSize:1});await expect(m8CleanupConfiguration(f.h,f.actors)).rejects.toThrow('STOP_NO_REPLAY');
  expect(f.state.cleanupJournal.phase).toBe('stopped-original-retained');expect(f.calls.some(c=>c.method==='DELETE'&&c.path.includes('/entities/'))).toBe(false);
  expect(f.metadata.find(m=>m.row.state==='failed')).toBeDefined();expect(f.state.cleanup?.businessCompleted).not.toBe(true);
 });
 it('unknown first timer write stops before snapshots/native/IAM and retains its one original packet without replay',async()=>{
  const f=fixture('unknownPause');await expect(m8CleanupAcceptance(f.h,f.actors)).rejects.toThrow('STOP_NO_REPLAY');
  expect(f.state.requests.at(-1).state).toBe('response_unknown');expect(f.state.cleanupJournal.operations.at(-1).state).toBe('response_unknown');
  expect(f.calls.some(c=>c.method==='DELETE')).toBe(false);const count=f.calls.length;await expect(m8CleanupConfiguration(f.h,f.actors)).rejects.toThrow();expect(f.calls).toHaveLength(count);
 });
 it('never treats a current native 404 as success without an actual affected/deleted archive node',async()=>{
  const f=fixture('unproven404');await beginM8Cleanup(f.h,f.actors);await m8CleanupConfiguration(f.h,f.actors);await expect(m8CleanupNative(f.h,f.actors)).rejects.toThrow('STOP_NO_REPLAY');
  expect(f.state.cleanupJournal.archives).toHaveLength(0);expect(f.calls.some(c=>c.method==='DELETE'&&c.path.includes('/entities/'))).toBe(false);
 });
 it('a reference-only child in a purported deletion graph cannot justify cascade 404 or later identity deletion',async()=>{
  const f=fixture('referenceNode');await beginM8Cleanup(f.h,f.actors);await m8CleanupConfiguration(f.h,f.actors);await expect(m8CleanupNative(f.h,f.actors)).rejects.toThrow('STOP_NO_REPLAY');
  expect(f.state.cleanupJournal.affected.some(p=>p.id===f.route.id)).toBe(false);expect(f.calls.filter(c=>c.method==='DELETE'&&c.path.includes('/entities/'))).toHaveLength(1);
  expect(f.calls.some(c=>c.method==='DELETE'&&c.path.includes('/iam/'))).toBe(false);
 });
 it('redacted graph keys never weaken the original credential SQL key, parent dependency or data identity proof',async()=>{
  for(const change of['wrongChildNodeKey','wrongChildDependency','wrongChildDataIdentity']){
   const f=fixture(change);await beginM8Cleanup(f.h,f.actors);await m8CleanupConfiguration(f.h,f.actors);await expect(m8CleanupNative(f.h,f.actors)).rejects.toThrow('STOP_NO_REPLAY');
   expect(f.state.cleanupJournal.phase).toBe('stopped-original-retained');expect(f.calls.some(c=>c.method==='DELETE'&&c.path.includes('/iam/'))).toBe(false);
   const count=f.calls.length;await expect(m8CleanupNative(f.h,f.actors)).rejects.toThrow();expect(f.calls).toHaveLength(count);
  }
 });
 it('cursor cycles and changes to an original packet/history reference stop before another mutation',async()=>{
  const f=fixture('cursorCycle');await beginM8Cleanup(f.h,f.actors);await expect(m8CleanupConfiguration(f.h,f.actors)).rejects.toThrow('STOP_NO_REPLAY');expect(f.state.cleanupJournal.phase).toBe('stopped-original-retained');
  for(const change of['packet','history']){const q=fixture();await beginM8Cleanup(q.h,q.actors);if(change==='packet')q.state.requests[0].sessionId=randomUUID();else q.state.privateHistoryRefs[0].sha256='2'.repeat(64);
   const count=q.calls.length;await expect(m8CleanupConfiguration(q.h,q.actors)).rejects.toThrow('retains every complete');expect(q.calls).toHaveLength(count);}
 });
 it('running stages cannot be restarted after a process boundary and identity removal cannot run before native EOF',async()=>{
  const f=fixture();await beginM8Cleanup(f.h,f.actors);f.state.cleanupJournal.phase='configuration-running';const count=f.calls.length;
  await expect(m8CleanupConfiguration(f.h,f.actors)).rejects.toThrow('exact known previous');await expect(m8CleanupNative(f.h,f.actors)).rejects.toThrow('exact known previous');await expect(m8CleanupIdentity(f.h,f.actors)).rejects.toThrow('exact known previous');expect(f.calls).toHaveLength(count);
 });
});
