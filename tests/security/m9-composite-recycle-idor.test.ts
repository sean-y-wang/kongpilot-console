import { describe, expect, it, vi } from 'vitest';
import { randomUUID } from 'node:crypto';
import { ForbiddenException } from '@nestjs/common';
import { RecycleService } from '../../apps/console-api/src/modules/recycle-bin/recycle.service';

function fixture(){
  const cid=randomUUID(),wid=randomUUID(),actor={id:randomUUID(),username:'synthetic-restricted-user',superAdmin:false};
  const first={key:'',type:'services',id:randomUUID(),path:'',data:{name:'authorized-service',tags:['workspace:synthetic']},affected:true,dependencies:[]};first.key=`services:${first.id}`;first.path=`/services/${first.id}`;
  const other={...first,id:randomUUID(),data:{name:'private-other-service',tags:['workspace:synthetic']}};other.key=`services:${other.id}`;other.path=`/services/${other.id}`;
  const graph:any={rootKey:first.key,nodes:[first,other],complete:true,capturedAt:new Date().toISOString()},entry:any={id:randomUUID(),cluster_id:cid,workspace_id:wid,root_type:'services',original_id:first.id,root_name:'批量回收 · authorized-service 等 2 个根对象',state:'restored',node_count:2,payload_secret:'synthetic-composite-encrypted',created_at:new Date()};
  const db:any={one:vi.fn(async(sql:string)=>sql.includes('FROM configuration_recycle_components')?null:entry),query:vi.fn(async(sql:string)=>sql.includes('FROM recycle_entries')?[entry]:[]),exec:vi.fn(),transaction:vi.fn(async(fn:any)=>fn(db))};
  const authz:any={assertCluster:vi.fn(async()=>undefined),isPlatformAdmin:vi.fn(async()=>false),permissionVersion:vi.fn(async()=> 'synthetic-epoch'),assertArchivedEntity:vi.fn(async(_actor:any,_cid:any,_type:any,_action:any,data:any)=>{if(data.name==='private-other-service')throw new ForbiddenException({code:'ARCHIVED_OBJECT_FORBIDDEN'});})};
  const secrets:any={decrypt:vi.fn(()=>graph),redact:vi.fn((value:any)=>value)},workspaces:any={listScope:vi.fn(async()=>({workspaceId:wid,workspaceRevision:1,binding:'synthetic'})),resolve:vi.fn(async()=>({id:wid,status:'active'})),assertMembership:vi.fn()},kong:any={request:vi.fn()},mutations:any={execute:vi.fn()};
  const service=new RecycleService(db,secrets,kong,mutations,{}as any,authz,{append:vi.fn()}as any,{}as any,{}as any,workspaces,{}as any);
  return{cid,wid,actor,first,other,graph,entry,db,authz,secrets,kong,mutations,service};
}

describe('M9 composite recycle records cannot reveal unauthorized graph members',()=>{
  it('omits an entire batch from the list when only its first root is authorized',async()=>{
    const f=fixture();const result=await f.service.list(f.cid,f.actor,{workspaceId:f.wid});
    expect(result.items).toEqual([]);expect(JSON.stringify(result)).not.toContain('private-other-service');expect(JSON.stringify(result)).not.toContain('2 个根对象');
    expect(f.authz.assertArchivedEntity).toHaveBeenCalledWith(f.actor,f.cid,'services','read',f.other.data,f.wid,f.graph.nodes);expect(f.kong.request).not.toHaveBeenCalled();
  });
  it('does not return restored original IDs through the idempotent restore shortcut without complete graph rights',async()=>{
    const f=fixture();await expect(f.service.restore(f.cid,f.entry.id,f.actor,{confirmed:true,confirm_name:f.entry.root_name},{workspaceId:f.wid})).rejects.toMatchObject({response:{code:'ARCHIVED_OBJECT_FORBIDDEN'}});
    expect(f.db.query.mock.calls.some(([sql]:any[])=>sql.includes('FROM recycle_nodes'))).toBe(false);expect(f.mutations.execute).not.toHaveBeenCalled();expect(f.kong.request).not.toHaveBeenCalled();
  });
  it('rejects an original component restore if its complete graph contains a credential outside current write rights',async()=>{
    const f=fixture(),consumer=randomUUID(),credential=randomUUID(),parentEntryId=randomUUID();
    const parent={key:`consumers:${consumer}`,type:'consumers',id:consumer,path:`/consumers/${consumer}`,data:{id:consumer,username:'ordinary',tags:['workspace:synthetic']},affected:true,dependencies:[]};
    const child={key:`key-auth:${consumer}:${credential}`,type:'key-auth',id:credential,path:`/consumers/${consumer}/key-auth/${credential}`,data:{id:credential,consumer:{id:consumer}},affected:true,dependencies:[parent.key]};
    const leafGraph={...f.graph,rootKey:parent.key,nodes:[parent]},completeGraph={...leafGraph,nodes:[parent,child]},parentEntry={...f.entry,id:parentEntryId,root_type:'consumers',original_id:consumer,root_name:'ordinary',state:'deleted',payload_secret:'synthetic-complete-encrypted'};
    Object.assign(f.entry,{root_type:'consumers',original_id:consumer,root_name:'ordinary',state:'deleted'});
    f.secrets.decrypt.mockImplementation((encrypted:string)=>encrypted===parentEntry.payload_secret?completeGraph:leafGraph);
    f.db.one.mockImplementation(async(sql:string,p:any[])=>sql.includes('FROM configuration_recycle_components')?{recycle_entry_id:parentEntryId}:p[1]===parentEntryId?parentEntry:f.entry);
    f.authz.assertArchivedEntity.mockImplementation(async(_actor:any,_cid:any,type:string,action:string)=>{if(type==='key-auth'&&action==='write')throw new ForbiddenException({code:'CREDENTIAL_WRITE_FORBIDDEN'});});
    await expect(f.service.restore(f.cid,f.entry.id,f.actor,{confirmed:true,confirm_name:'ordinary'},{workspaceId:f.wid})).rejects.toMatchObject({response:{code:'CREDENTIAL_WRITE_FORBIDDEN'}});
    expect(f.mutations.execute).not.toHaveBeenCalled();expect(f.db.exec).not.toHaveBeenCalled();expect(f.kong.request).not.toHaveBeenCalled();
  });
  it('instructs an authorized user to restore the authenticated complete graph instead of replaying the old leaf',async()=>{
    const f=fixture(),parentEntryId=randomUUID(),parentEntry={...f.entry,id:parentEntryId,state:'deleted',payload_secret:'synthetic-parent-encrypted'};f.entry.state='deleted';
    f.db.one.mockImplementation(async(sql:string,p:any[])=>sql.includes('FROM configuration_recycle_components')?{recycle_entry_id:parentEntryId}:p[1]===parentEntryId?parentEntry:f.entry);
    f.authz.assertArchivedEntity.mockResolvedValue(undefined);
    await expect(f.service.restore(f.cid,f.entry.id,f.actor,{confirmed:true,confirm_name:f.entry.root_name},{workspaceId:f.wid})).rejects.toMatchObject({response:{code:'RECYCLE_COMPONENT_RESTORE_REQUIRED',recoveryEntryId:parentEntryId}});
    expect(f.authz.assertArchivedEntity).toHaveBeenCalledWith(f.actor,f.cid,'services','write',f.other.data,f.wid,f.graph.nodes);expect(f.mutations.execute).not.toHaveBeenCalled();expect(f.kong.request).not.toHaveBeenCalled();
  });
  it('fences a list response if permission state changes during graph authorization',async()=>{
    const f=fixture();f.authz.assertArchivedEntity.mockResolvedValue(undefined);f.authz.permissionVersion.mockResolvedValueOnce('before').mockResolvedValueOnce('after');
    await expect(f.service.list(f.cid,f.actor,{workspaceId:f.wid})).rejects.toMatchObject({response:{code:'PERMISSIONS_CHANGED'}});expect(f.kong.request).not.toHaveBeenCalled();
  });
});
