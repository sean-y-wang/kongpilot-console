import { describe, expect, it, vi } from 'vitest';
import { randomUUID } from 'node:crypto';
import { ForbiddenException } from '@nestjs/common';
import { KongExecutionContextService, type ToolboxOperationProof } from '../../apps/console-api/src/infrastructure/kong/execution-context.service';

function fixture(){
  const context=new KongExecutionContextService(),cid=randomUUID(),wid=randomUUID(),sid=randomUUID(),actor={id:randomUUID(),username:'synthetic-operator',superAdmin:true},handle=Object.freeze({}),scope='a'.repeat(64),path='/cache/service%3Asynthetic';
  const cluster={id:cid,admin_url:'http://kong:8001',version:'1.5.1',execution_mode:'direct',transport_scope:scope};
  let valid=true;const proof:ToolboxOperationProof={operationId:randomUUID(),actorId:actor.id,sessionId:sid,clusterId:cid,workspaceId:wid,transportScope:scope,canonicalPath:path,permissionVersion:'test-current-grants',expiresAt:Date.now()+60000,executionMode:'direct'};
  const hooks={authorizeRequest:vi.fn(async()=>({})),authorizeResponse:vi.fn(async(_ticket:unknown,result:any)=>result),beforeNativeSend:vi.fn(async()=>{})};context.installPolicy(hooks);
  context.installToolboxOperationPolicy({verifyHandle:async value=>{if(value!==handle||!valid)throw new ForbiddenException();return proof;},beforeSend:async()=>{}});
  const run=<T>(fn:()=>Promise<T>)=>context.runHttp({requestId:randomUUID(),ip:'127.0.0.1'},()=>{context.bindHttpActor(actor,sid);return context.runActor({actor,clusterId:cid,workspaceId:wid,module:'toolbox',action:'write'},fn);});
  return{context,cid,wid,handle,cluster,path,hooks,proof,run,revoke:()=>{valid=false;}};
}
describe('cache invalidation remains a private exact operational capability',()=>{
  it('refuses a plain authenticated DELETE even for a super-admin',async()=>{
    const f=fixture();await expect(f.run(()=>f.context.authorizeRequest(f.cluster,'DELETE',f.path,undefined,{}))).rejects.toThrow();expect(f.hooks.authorizeRequest).not.toHaveBeenCalled();
  });
  it('refuses deserialized or copied operational handles',async()=>{
    const f=fixture();await expect(f.run(()=>f.context.runToolboxOperation({...f.proof},async()=>true))).rejects.toThrow();await expect(f.run(()=>f.context.runToolboxOperation({...f.handle},async()=>true))).rejects.toThrow();
  });
  it('permits only the sealed exact cache DELETE without waiving entity recycle protection',async()=>{
    const f=fixture();await f.run(()=>f.context.runToolboxOperation(f.handle,async()=>{
      await expect(f.context.authorizeRequest(f.cluster,'DELETE','/services/'+randomUUID(),undefined,{})).rejects.toThrow();
      await expect(f.context.authorizeRequest(f.cluster,'DELETE','/cache/different',undefined,{})).rejects.toThrow();
      await expect(f.context.authorizeRequest(f.cluster,'DELETE',f.path,{approved:true},{})).rejects.toThrow();
      await expect(f.context.authorizeRequest(f.cluster,'DELETE',f.path,undefined,{size:1})).rejects.toThrow();
      const ticket=await f.context.authorizeRequest(f.cluster,'DELETE',f.path,undefined,{});await f.context.beforeNativeSend(ticket);expect(await f.context.authorizeResponse(ticket,null)).toBeNull();
    }));expect(f.hooks.authorizeRequest).toHaveBeenCalledTimes(1);
  });
  it('rechecks private authority after authorization and before any send hook',async()=>{
    const f=fixture();await f.run(()=>f.context.runToolboxOperation(f.handle,async()=>{
      const ticket=await f.context.authorizeRequest(f.cluster,'DELETE',f.path,undefined,{});f.revoke();await expect(f.context.beforeNativeSend(ticket)).rejects.toThrow();
    }));expect(f.hooks.beforeNativeSend).not.toHaveBeenCalled();
  });
  it('does not accept direct-mode authority in an approval-mode cluster',async()=>{
    const f=fixture();await expect(f.run(()=>f.context.runToolboxOperation(f.handle,()=>f.context.authorizeRequest({...f.cluster,execution_mode:'approval'},'DELETE',f.path,undefined,{})))).rejects.toThrow();expect(f.hooks.authorizeRequest).not.toHaveBeenCalled();
  });
});
