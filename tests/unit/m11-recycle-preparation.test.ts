import 'reflect-metadata';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ForbiddenException, NotFoundException } from '@nestjs/common';
import { createHash, randomUUID } from 'node:crypto';
import { RecycleService, recycleName } from '../../apps/console-api/src/modules/recycle-bin/recycle.service';
import type { GraphNode, RecycleGraph } from '../../apps/console-api/src/modules/recycle-bin/graph-capturer.service';
import type { EntityChangeOperation, PreparedEntityChange } from '../../apps/console-api/src/modules/entities/entity-change.types';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { entityForPath } from '../../apps/console-api/src/infrastructure/kong/policy';
import { executionFixture } from './execution-test-fixture';
import { defaultWorkspaceId, payWorkspaceId, workspaceFixture } from './workspace-test-fixture';

const cid=randomUUID(),actor={user:{id:randomUUID(),username:'owner',superAdmin:true},workspaceId:defaultWorkspaceId};
type RecycleChange=Extract<EntityChangeOperation,{kind:'recycle'}>;
function node(type:string,values:any,dependencies:GraphNode[]=[],affected=true):GraphNode{
  const id=values.id??randomUUID(),parent=type==='targets'?dependencies.find(item=>item.type==='upstreams'):
    ['key-auth','basic-auth','jwt','oauth2','hmac-auth','acls'].includes(type)?dependencies.find(item=>item.type==='consumers'):undefined;
  const data={id,...values};
  return {key:`${type}:${id}`,type,id,path:parent?`/${parent.type}/${parent.id}/${type}/${id}`:`/${type}/${id}`,data,affected,dependencies:dependencies.map(item=>item.key),restorable:true,restoreData:structuredClone(data)};
}
function graph(root:GraphNode,children:GraphNode[]=[]):RecycleGraph{return {rootKey:root.key,nodes:[root,...children],purpose:'recycle',complete:true,capturedAt:new Date().toISOString()};}
function fixture(original=graph(node('services',{name:'orders',host:'echo.internal'}))){
  const secrets=new SecretService(),entryId=randomUUID(),root=original.nodes.find(item=>item.key===original.rootKey)!,remote=new Map(original.nodes.map(item=>[item.path,structuredClone(item.data)]));
  let entry:any={id:entryId,cluster_id:cid,workspace_id:defaultWorkspaceId,root_type:root.type,original_id:root.id,root_name:recycleName(root),state:'deleted',
    parent_id:null,credential_kind:null,mutation_id:randomUUID(),node_count:original.nodes.length,created_at:new Date(),expires_at:new Date(Date.now()+86400000),payload_secret:secrets.encrypt(original,`recycle:${entryId}`)};
  const statuses=original.nodes.map(item=>({node_key:item.key,entity_type:item.type,original_id:item.id,affected:item.affected,dependencies:[...item.dependencies],delete_state:item.affected?'deleted':'reference',restore_state:item.affected?'pending':'reference',restored_id:null}));
  let component:any=null,originState='succeeded';
  const db:any={one:vi.fn(async(sql:string,p:any[])=>sql.includes('FROM clusters')?{admin_url:'http://kong:8001',transport_scope:'scope',revision:1,version:'1.5.1',status:'connected'}:
    sql.includes('FROM recycle_entries')?entry?.cluster_id===p[0]&&entry.id===p[1]?structuredClone(entry):null:sql.includes('FROM configuration_recycle_components')?component:null),
    query:vi.fn(async(sql:string)=>sql.includes('FROM recycle_nodes')?structuredClone(statuses).sort((a,b)=>a.node_key.localeCompare(b.node_key)):
      sql.includes("'mutation'::text AS kind")?[{kind:'mutation',id:entry.mutation_id,state:originState,workspace_id:defaultWorkspaceId,workflow_id:null,workflow_state:null,execution_state:null,unresolved_steps:false}]:[]),exec:vi.fn(async()=>{throw new Error('Unexpected business write');}),transaction:vi.fn(async()=>{throw new Error('Unexpected business transaction');})};
  const schema={fields:[{id:{type:'string'}}]},kong:any={
    request:vi.fn(async(_cid:string,method:string,path:string)=>{if(method!=='GET')throw new Error('Unexpected native write');if(!remote.has(path))throw new NotFoundException();return structuredClone(remote.get(path));}),
    list:vi.fn(async(_cid:string,path:string)=>({items:[...remote.entries()].filter(([key,value])=>key.startsWith(path+'/')&&value.weight>0).map(([,value])=>structuredClone(value)),nextCursor:null,size:100})),
    schema:vi.fn(async()=>schema),pluginSchema:vi.fn(async()=>schema),
    prepareSchema:vi.fn(async(_cid:string,path:string,body:any)=>({version:1,clusterId:cid,canonicalPath:path,nativeType:entityForPath(path),kongVersion:'1.5.1',adapter:'kong-oss-1.5-v1',clusterRevision:1,payloadHmac:secrets.fingerprint(body??null),schemaMaterial:{entity:{name:entityForPath(path),canonicalPath:`/schemas/${entityForPath(path)}`,schema}}}))};
  const authz:any={assertEntity:vi.fn(),assertArchivedEntity:vi.fn(),assertNestedParentScope:vi.fn()},capturer:any={capture:vi.fn(async()=>structuredClone(original))},
    mutations:any={execute:vi.fn(),claimGraphImpact:vi.fn()},audit:any={append:vi.fn()},credentials:any={save:vi.fn(),remove:vi.fn(),getRestorePayload:vi.fn()},index:any={upsert:vi.fn(),remove:vi.fn()},workspaces=workspaceFixture(cid);
  const recycle=new RecycleService(db,secrets,kong,mutations,capturer,authz,audit,credentials,index,workspaces.resolver,executionFixture());
  const del:RecycleChange={kind:'recycle',action:'delete',entityType:['basic-auth','key-auth'].includes(root.type)?'credentials':root.type as any,entityId:root.id,
    ...(root.type==='targets'?{parentId:(root.data.upstream as any).id}:{}),confirmed:true,confirm_name:recycleName(root)};
  const restore:RecycleChange={kind:'recycle',action:'restore',entryId,confirmed:true,confirm_name:entry.root_name};
  const clearAffected=()=>{for(const item of original.nodes.filter(item=>item.affected))remote.delete(item.path);};
  const assertNoWrites=()=>{expect(db.exec).not.toHaveBeenCalled();expect(db.transaction).not.toHaveBeenCalled();expect(audit.append).not.toHaveBeenCalled();expect(mutations.execute).not.toHaveBeenCalled();expect(credentials.save).not.toHaveBeenCalled();expect(credentials.remove).not.toHaveBeenCalled();expect(index.upsert).not.toHaveBeenCalled();expect(index.remove).not.toHaveBeenCalled();expect(kong.request.mock.calls.every((call:any[])=>call[1]==='GET')).toBe(true);};
  return {recycle,secrets,db,kong,authz,capturer,audit,credentials,index,mutations,remote,statuses,original,del,restore,entry,clearAffected,assertNoWrites,setComponent:(value:any)=>{component=value;},setOriginState:(value:string)=>{originState=value;}};
}
function material(prepared:any,request:RecycleChange):PreparedEntityChange{return {clusterId:cid,workspaceId:defaultWorkspaceId,request,packets:prepared.packets,schemas:prepared.schemas,prerequisites:prepared.prerequisites,metadataObligations:prepared.metadataObligations} as PreparedEntityChange;}

describe('M11 zero-write recycle preparation (domain facts; authority delegates mocked explicitly)',()=>{
  beforeEach(()=>vi.stubEnv('CONSOLE_ENCRYPTION_KEY','ab'.repeat(32)));afterEach(()=>vi.unstubAllEnvs());
  it('seals a complete graph, child-first DELETE DAG, exact body/before HMACs and real legacy schema GETs without writes',async()=>{
    const service=node('services',{name:'orders',host:'echo.internal'}),route=node('routes',{name:'orders-route',service:{id:service.id},paths:['/orders']},[service]),plugin=node('plugins',{name:'key-auth',route:{id:route.id},config:{}},[route]);
    const f=fixture(graph(service,[route,plugin])),prepared=await f.recycle.prepareEntityChange(cid,f.del,actor);
    expect(prepared.packets.map(item=>item.nativeType)).toEqual(['plugins','routes','services']);expect(prepared.packets[1].dependencies).toEqual([prepared.packets[0].key]);expect(prepared.packets[2].dependencies).toEqual([prepared.packets[1].key]);
    expect(f.kong.prepareSchema).not.toHaveBeenCalled();expect(f.kong.pluginSchema).toHaveBeenCalledWith(cid,'key-auth');expect(prepared.schemas[0].schemaMaterial.plugin?.canonicalPath).toBe('/plugins/schema/key-auth');
    expect(prepared.packets.every(item=>item.bodyHmac===f.secrets.fingerprint(null)&&item.beforeHmac===f.secrets.fingerprint(item.before))).toBe(true);
    expect(prepared.metadataObligations.find(item=>item.kind==='recycle-archive')).toMatchObject({graphHmac:f.secrets.fingerprint(f.original)});f.assertNoWrites();
  });
  it('projects certificate send-time SNI names using only explicit preceding child DELETEs, keeping the original prerequisite',async()=>{
    const cert=node('certificates',{cert:'cert',key:'private',snis:['api.example','keep.example']}),sni=node('snis',{name:'api.example',certificate:{id:cert.id}},[cert]);
    const f=fixture(graph(cert,[sni])),prepared=await f.recycle.prepareEntityChange(cid,f.del,actor),packet=prepared.packets.find(item=>item.nativeType==='certificates')!;
    expect(packet.before).toMatchObject({snis:['keep.example']});expect(packet.dependencies).toEqual([prepared.packets[0].key]);expect(prepared.prerequisites.find(item=>item.type==='certificates')?.before).toMatchObject({snis:['api.example','keep.example']});f.assertNoWrites();
  });
  it('stops on failed secondary confirmation or any affected-child grant before producing a plan',async()=>{
    const f=fixture();await expect(f.recycle.prepareEntityChange(cid,{...f.del,confirm_name:'wrong'},actor)).rejects.toMatchObject({status:400});
    f.authz.assertEntity.mockRejectedValue(new ForbiddenException());await expect(f.recycle.prepareEntityChange(cid,f.del,actor)).rejects.toMatchObject({status:403});f.assertNoWrites();
  });
  it('restores only the immutable Basic plaintext whose Kong SHA1 provenance matches, with exact Consumer dependency',async()=>{
    const consumer=node('consumers',{username:'business'}),password='immutable-password-fixture',basic=node('basic-auth',{username:'api-client',consumer:{id:consumer.id},password:createHash('sha1').update(password+consumer.id).digest('hex')},[consumer]);basic.restoreData={...basic.data,password};
    const f=fixture(graph(consumer,[basic]));f.clearAffected();const prepared=await f.recycle.prepareEntityChange(cid,f.restore,actor);
    expect(prepared.packets.map(item=>item.nativeType)).toEqual(['consumers','basic-auth']);expect(prepared.packets[1].dependencies).toEqual([prepared.packets[0].key]);expect(prepared.packets[1].body?.password).toBe(password);expect(f.credentials.getRestorePayload).not.toHaveBeenCalled();
    const obligation=prepared.metadataObligations.find(item=>item.kind==='recycle-restore')!;expect(obligation).toMatchObject({graph:f.original,sealedEntry:{clusterId:cid,workspaceId:defaultWorkspaceId,entryId:f.entry.id,state:'deleted'}});
    const wrong=structuredClone(f.original);wrong.nodes[1].restoreData.password='replacement';f.entry.payload_secret=f.secrets.encrypt(wrong,`recycle:${f.entry.id}`);
    await expect(f.recycle.prepareEntityChange(cid,f.restore,actor)).rejects.toMatchObject({response:{code:'BASIC_AUTH_RESTORE_PROVENANCE_INVALID'}});f.assertNoWrites();
  });
  it('rejects unbound/foreign/busy/expired/component/incomplete recycle entries without auto-binding or reconciliation',async()=>{
    const f=fixture();f.clearAffected();
    for(const [property,value,code] of [['workspace_id',null,'RECYCLE_WORKSPACE_BINDING_REQUIRED'],['workspace_id',payWorkspaceId,'WORKSPACE_MISMATCH'],['state','deleting','RECYCLE_BUSY'],['expires_at',new Date(0),'RECYCLE_EXPIRED']] as const){const old=f.entry[property];f.entry[property]=value;await expect(f.recycle.prepareEntityChange(cid,f.restore,actor)).rejects.toMatchObject({response:{code}});f.entry[property]=old;}
    f.setComponent({recycle_entry_id:randomUUID()});await expect(f.recycle.prepareEntityChange(cid,f.restore,actor)).rejects.toMatchObject({response:{code:'RECYCLE_COMPONENT_RESTORE_REQUIRED'}});f.setComponent(null);
    f.setOriginState('uncertain');await expect(f.recycle.prepareEntityChange(cid,f.restore,actor)).rejects.toMatchObject({response:{code:'RECYCLE_ORIGIN_UNRESOLVED'}});f.setOriginState('succeeded');
    f.statuses[0].delete_state='uncertain';await expect(f.recycle.prepareEntityChange(cid,f.restore,actor)).rejects.toMatchObject({response:{code:'RECYCLE_MANIFEST_INVALID'}});f.statuses[0].delete_state='deleted';
    f.statuses.pop();await expect(f.recycle.prepareEntityChange(cid,f.restore,actor)).rejects.toMatchObject({response:{code:'RECYCLE_MANIFEST_INVALID'}});f.assertNoWrites();
  });
  it('single Target restoration fixes a new absent UUID; whole absent Upstream restoration preserves the original ID',async()=>{
    for(const whole of [false,true]){
      const upstream=node('upstreams',{name:'pool'},[],whole),target=node('targets',{target:'echo.internal:8080',weight:100,upstream:{id:upstream.id}},[upstream]);
      const f=fixture(graph(whole?upstream:target,whole?[target]:[upstream]));f.clearAffected();
      if(!whole)f.remote.set(target.path,{...target.data}); // old physical history GET is not effective membership
      f.kong.list.mockResolvedValue({items:[],nextCursor:null,size:100});const prepared=await f.recycle.prepareEntityChange(cid,f.restore,actor),packet=prepared.packets.find(item=>item.nativeType==='targets')!;
      expect(packet.before).toBeNull();expect(packet.nativeId===target.id).toBe(whole);expect(packet.originalNativeId).toBe(whole?undefined:target.id);expect(packet.body?.id).toBe(packet.nativeId);
      await f.recycle.assertPreparedEntityChange(cid,f.restore,material(prepared,f.restore),actor);expect(packet.nativeId).toBe(prepared.packets.find(item=>item.nativeType==='targets')!.nativeId);f.assertNoWrites();
    }
  });
  it('fresh approval checks use the actual approver read grants and fail on archive-state/schema/object drift',async()=>{
    const f=fixture();f.clearAffected();const prepared=await f.recycle.prepareEntityChange(cid,f.restore,actor),sealed=material(prepared,f.restore),reviewer={...actor,user:{id:randomUUID(),username:'reviewer',superAdmin:false}};
    f.authz.assertArchivedEntity.mockImplementation(async(user:any,_cid:string,_type:string,action:string)=>{if(user.id===reviewer.user.id&&action!=='read')throw new ForbiddenException();});
    await f.recycle.assertPreparedEntityChange(cid,f.restore,sealed,reviewer,{action:'approve',mode:'fresh'});expect(f.authz.assertArchivedEntity).toHaveBeenCalledWith(reviewer.user,cid,'services','read',expect.anything(),defaultWorkspaceId,expect.anything());
    f.entry.state='partially_deleted';await expect(f.recycle.assertPreparedEntityChange(cid,f.restore,sealed,reviewer,{action:'approve',mode:'fresh'})).rejects.toMatchObject({response:{code:'ENTITY_CHANGE_RECYCLE_SEAL_CHANGED'}});f.entry.state='deleted';
    f.kong.prepareSchema.mockImplementation(async()=>({...prepared.schemas[0],schemaMaterial:{entity:{...prepared.schemas[0].schemaMaterial.entity,schema:{changed:true}}}}));
    await expect(f.recycle.assertPreparedEntityChange(cid,f.restore,sealed,reviewer,{action:'approve',mode:'fresh'})).rejects.toMatchObject({response:{code:'ENTITY_CHANGE_SCHEMA_CHANGED'}});f.assertNoWrites();
  });
});
