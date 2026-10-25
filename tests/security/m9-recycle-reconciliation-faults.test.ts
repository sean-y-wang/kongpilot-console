import { describe, expect, it, vi } from 'vitest';
import { randomUUID } from 'node:crypto';
import { ForbiddenException } from '@nestjs/common';
import { RecycleService } from '../../apps/console-api/src/modules/recycle-bin/recycle.service';

function fixture(){
  const cid=randomUUID(),wid=randomUUID(),actor={id:randomUUID(),username:'synthetic-requester',superAdmin:false},entry={id:randomUUID(),cluster_id:cid,state:'deleting',root_name:'synthetic-consumer'};
  const consumer=randomUUID(),credential=randomUUID(),root={key:`consumers:${consumer}`,type:'consumers',id:consumer,path:`/consumers/${consumer}`,affected:true,data:{id:consumer,username:entry.root_name},dependencies:[]};
  const child={key:`key-auth:${consumer}:${credential}`,type:'key-auth',id:credential,path:`/consumers/${consumer}/key-auth/${credential}`,affected:true,data:{id:credential,consumer:{id:consumer}},dependencies:[root.key]};
  const graph={rootKey:root.key,nodes:[root,child],complete:true,capturedAt:new Date().toISOString()};
  const receipt={id:randomUUID(),receipt_operation_id:randomUUID(),recycle_entry_id:randomUUID(),root_type:'credentials',credential_kind:'key-auth',parent_id:consumer,original_id:credential};
  const claim={id:randomUUID(),cluster_id:cid,workspace_id:randomUUID(),object_workspace_id:wid,job_id:randomUUID(),execution_id:randomUUID(),actor_id:actor.id,graph_hmac:'authenticated-graph',execution_state:'executing',expires_at:new Date(Date.now()+60000),lease_expires_at:new Date(Date.now()+60000)};
  const effects:any[]=[],tx:any={one:vi.fn(async(sql:string)=>sql.includes('FROM configuration_recycle_graphs')?claim:sql.includes('state IN')?null:sql.includes('count(*)')?{count:1}:null),query:vi.fn(async()=>[receipt]),exec:vi.fn(async(sql:string,parameters:any[])=>{effects.push({sql,parameters});return 1;})};
  const db:any={transaction:vi.fn(async(fn:any)=>fn(tx)),query:vi.fn(async()=>[]),exec:vi.fn(),one:vi.fn()};
  const secrets:any={fingerprint:vi.fn(()=>claim.graph_hmac)},kong:any={request:vi.fn()},audit:any={append:vi.fn(async(event:any)=>{effects.push({audit:event});})},mutations:any={execute:vi.fn()};
  const service=new RecycleService(db,secrets,kong,mutations,{} as any,{} as any,audit,{} as any,{} as any,{} as any,{} as any);
  const reconcile=()=> (service as any).reconcileConfigurationArchive(entry,graph,actor,wid,{requestId:'synthetic-request'});
  return{cid,wid,actor,entry,graph,root,child,receipt,claim,effects,tx,db,secrets,kong,audit,mutations,service,reconcile};
}

describe('M9 interrupted composite archive reconciliation uses authenticated SQL facts',()=>{
  it('keeps active native execution blocked and performs zero metadata writes or gateway calls',async()=>{
    const f=fixture();await f.reconcile();expect(f.entry.state).toBe('deleting');expect(f.tx.query).not.toHaveBeenCalled();expect(f.tx.exec).not.toHaveBeenCalled();expect(f.kong.request).not.toHaveBeenCalled();expect(f.audit.append).not.toHaveBeenCalled();
  });
  it('requires both expired leases plus a five-second grace before treating an interrupted execution as inactive',async()=>{
    const f=fixture();f.claim.expires_at=new Date(Date.now()-10000);f.claim.lease_expires_at=new Date(Date.now()-1000);
    await f.reconcile();expect(f.tx.query).not.toHaveBeenCalled();expect(f.tx.exec).not.toHaveBeenCalled();
    f.claim.lease_expires_at=new Date(Date.now()-10000);await f.reconcile();expect(f.entry.state).toBe('partially_deleted');expect(f.kong.request).not.toHaveBeenCalled();
  });
  it.each(['running','uncertain'])('does not turn an unresolved %s native step into success',async state=>{
    const f=fixture();f.claim.execution_state='failed';f.tx.one.mockImplementation(async(sql:string)=>sql.includes('FROM configuration_recycle_graphs')?f.claim:sql.includes('state IN')?{state}:null);
    await f.reconcile();expect(f.entry.state).toBe('deleting');expect(f.tx.query).not.toHaveBeenCalled();expect(f.tx.exec).not.toHaveBeenCalled();expect(f.kong.request).not.toHaveBeenCalled();
  });
  it('refuses a graph whose authenticated fingerprint no longer matches before changing any deletion fact',async()=>{
    const f=fixture();f.secrets.fingerprint.mockReturnValue('mismatched-fingerprint');await expect(f.reconcile()).rejects.toMatchObject({response:{code:'RECYCLE_GRAPH_INVALID'}});expect(f.tx.exec).not.toHaveBeenCalled();expect(f.kong.request).not.toHaveBeenCalled();
  });
  it('records only the known completed original nested credential and leaves other nodes partially deleted',async()=>{
    const f=fixture();f.claim.execution_state='failed';await f.reconcile();
    const sql=f.tx.query.mock.calls[0][0],parameters=f.tx.query.mock.calls[0][1];
    expect(sql).toContain("s.state='succeeded'");expect(sql).toContain("m.state='succeeded'");expect(sql).toContain('m.remote_completed');expect(sql).toContain("m.action='delete'");
    expect(parameters).toEqual([f.cid,f.claim.workspace_id,f.claim.job_id,f.claim.execution_id,f.wid,f.actor.id]);
    expect(f.effects.find(row=>row.sql?.startsWith('UPDATE recycle_nodes')).parameters).toEqual([f.entry.id,f.child.key]);
    expect(f.entry.state).toBe('partially_deleted');expect(f.kong.request).not.toHaveBeenCalled();expect(f.mutations.execute).not.toHaveBeenCalled();
    expect(f.audit.append).toHaveBeenCalledWith(expect.objectContaining({actorId:f.actor.id,clusterId:f.cid,workspaceId:f.wid,after:{state:'partially_deleted',remainingNodes:1,nativeWrites:0}}),f.tx);
  });
  it('rejects a foreign original object despite a successful receipt before writing metadata',async()=>{
    const f=fixture();f.claim.execution_state='failed';f.receipt.original_id=randomUUID();await expect(f.reconcile()).rejects.toMatchObject({response:{code:'RECYCLE_GRAPH_INVALID'}});expect(f.tx.exec).not.toHaveBeenCalled();expect(f.kong.request).not.toHaveBeenCalled();
  });
  it('propagates a finalization audit failure and never emits a compensating native replay',async()=>{
    const f=fixture();f.claim.execution_state='failed';f.audit.append.mockRejectedValue(new Error('synthetic audit storage unavailable'));
    await expect(f.reconcile()).rejects.toThrow('synthetic audit storage unavailable');expect(f.entry.state).toBe('deleting');expect(f.db.transaction).toHaveBeenCalledTimes(1);expect(f.kong.request).not.toHaveBeenCalled();expect(f.mutations.execute).not.toHaveBeenCalled();
  });
  it('checks every archived node before invoking reconciliation during a public restore request',async()=>{
    const f=fixture(),authorization=vi.fn(async()=>{throw new ForbiddenException({code:'CURRENT_GRANT_REVOKED'});});
    (f.service as any).entry=vi.fn(async()=>({entry:f.entry,graph:f.graph,scope:{workspaceId:f.wid}}));(f.service as any).authorizeGraph=authorization;
    await expect(f.service.restore(f.cid,f.entry.id,f.actor,{confirmed:true,confirm_name:f.entry.root_name},{workspaceId:f.wid})).rejects.toMatchObject({response:{code:'CURRENT_GRANT_REVOKED'}});
    expect(authorization).toHaveBeenCalledWith(f.cid,f.actor,f.graph,'write',{workspaceId:f.wid},true);expect(f.db.transaction).not.toHaveBeenCalled();expect(f.kong.request).not.toHaveBeenCalled();
  });
});
