import { describe, expect, it, vi } from 'vitest';
import { randomUUID } from 'node:crypto';
import { WorkspaceMigrationsController } from '../../apps/console-api/src/modules/workspaces/workspace-migrations.controller';

function fixture(){
  const user={id:randomUUID(),username:'synthetic-user',superAdmin:false},requestId=randomUUID(),wid=randomUUID(),cid=randomUUID(),id=randomUUID(),key=randomUUID();
  // Express exposes ip through a prototype getter, rather than an own field.
  const req:any=Object.assign(Object.create({get ip(){return '192.0.2.10';}}),{user,requestId,body:{user:{superAdmin:true},ip:'198.51.100.20'},headers:{authorization:'synthetic-private-header'}});
  const migration:any={plan:vi.fn(async()=>({id})),apply:vi.fn()},workflow:any={submit:vi.fn(async()=>({id}))};
  return{controller:new WorkspaceMigrationsController(migration,workflow),migration,workflow,req,user,requestId,wid,cid,id,key};
}
describe('M9 migration HTTP controller preserves authenticated request metadata',()=>{
  it('carries a prototype IP getter and real request ID into sealed workflow submission',async()=>{
    const f=fixture(),body={confirmed:true,confirm_name:'Synthetic target',plan_hash:'a'.repeat(64)};
    await f.controller.submit(f.cid,f.id,body,f.req,f.wid,f.key);
    expect(f.workflow.submit).toHaveBeenCalledWith(f.cid,f.id,body,{user:f.user,requestId:f.requestId,ip:'192.0.2.10',workspaceId:f.wid,idempotencyKey:f.key});
  });
  it('does not transfer request headers, body or forged identity into the actor descriptor',async()=>{
    const f=fixture();await f.controller.submit(f.cid,f.id,{},f.req,f.wid,f.key);const actor=f.workflow.submit.mock.calls[0][3];
    expect(actor.user).toBe(f.user);expect(actor).not.toHaveProperty('body');expect(actor).not.toHaveProperty('headers');expect(actor.ip).not.toBe(f.req.body.ip);
  });
  it('keeps the same request metadata when creating the original M3 preview',async()=>{
    const f=fixture(),input={source_workspace_id:f.wid};await f.controller.plan(f.cid,input,f.req,f.wid);
    expect(f.migration.plan).toHaveBeenCalledWith(f.cid,input,{user:f.user,requestId:f.requestId,ip:'192.0.2.10',workspaceId:f.wid,idempotencyKey:undefined});
  });
});
