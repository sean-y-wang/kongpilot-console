import { describe, expect, it, vi } from 'vitest';
import { randomUUID } from 'node:crypto';
import { CacheOperationsService } from '../../apps/console-api/src/modules/toolbox/cache-operations.service';
import { DraftsService } from '../../apps/console-api/src/modules/toolbox/drafts.service';
import { ForbiddenException } from '@nestjs/common';

function fixture(){
  const cid=randomUUID(),wid=randomUUID(),actor:any={user:{id:randomUUID(),username:'synthetic-user',superAdmin:true},workspaceId:wid},id=randomUUID(),key=randomUUID();
  const row:any={id,cluster_id:cid,workspace_id:wid,actor_id:actor.user.id,owner_user_id:actor.user.id,idempotency_key:key,kind:'cache-invalidate',state:'succeeded',remote_started:true,remote_completed:true,before_secret:'synthetic-encrypted-only',request_hmac:'synthetic-fingerprint'};
  const db:any={one:vi.fn(async()=>row),query:vi.fn(async()=>[]),exec:vi.fn()},epoch=vi.fn(async()=> 'epoch-before');
  const authz:any={permissionVersion:epoch,assertWholeCluster:vi.fn(async()=>undefined),assertCluster:vi.fn(async()=>undefined)},ws:any={resolve:vi.fn(async()=>({id:wid,revision:1,status:'active'}))},context:any={runActor:vi.fn(async(_scope:any,fn:any)=>fn())};
  const cache=new CacheOperationsService(db,{}as any,{}as any,{}as any,context,authz,ws,{}as any,{}as any,{}as any);
  const draft=new DraftsService(db,{}as any,{}as any,{}as any,context,authz,ws,{}as any);
  return{cid,wid,actor,id,key,row,db,authz,epoch,cache,draft};
}
describe('M9 private original receipts retain current owner and authorization',()=>{
  it('does not expose another owner’s cache operation even to a platform administrator',async()=>{
    const f=fixture();f.row.actor_id=randomUUID();await expect(f.cache.get(f.cid,f.id,f.actor)).rejects.toMatchObject({response:{code:'TOOLBOX_OPERATION_NOT_FOUND'}});
  });
  it.each(['get','by-key'])('denies a cache receipt when grants change while the %s lookup is pending',async route=>{
    const f=fixture();f.epoch.mockResolvedValueOnce('epoch-before').mockResolvedValueOnce('epoch-after');
    await expect(route==='get'?f.cache.get(f.cid,f.id,f.actor):f.cache.byKey(f.cid,f.key,f.actor)).rejects.toMatchObject({response:{code:'PERMISSIONS_CHANGED'}});
  });
  it('binds a cache by-key lookup to the exact authenticated actor, cluster and workspace',async()=>{
    const f=fixture();const value=await f.cache.byKey(f.cid,f.key,f.actor);
    expect(f.db.one).toHaveBeenCalledWith(expect.stringContaining('actor_id=$3 AND idempotency_key=$4'),[f.cid,f.wid,f.actor.user.id,f.key]);expect(value).not.toHaveProperty('before_secret');expect(value).not.toHaveProperty('request_hmac');
  });
  it('denies an original draft metadata receipt when grants are revoked during the lookup',async()=>{
    const f=fixture();f.epoch.mockResolvedValueOnce('epoch-before').mockResolvedValueOnce('epoch-after');
    await expect(f.draft.byKey(f.cid,f.key,f.actor)).rejects.toMatchObject({response:{code:'PERMISSIONS_CHANGED'}});expect(f.db.one).toHaveBeenCalledWith(expect.stringContaining("action LIKE 'draft.%'"),[f.cid,f.wid,f.actor.user.id,f.key]);
  });
  it('performs no receipt query when the current whole-cluster grant is denied',async()=>{
    const f=fixture();f.authz.assertWholeCluster.mockRejectedValue(new ForbiddenException());await expect(f.cache.byKey(f.cid,f.key,f.actor)).rejects.toThrow();expect(f.db.one).not.toHaveBeenCalled();
  });
});
