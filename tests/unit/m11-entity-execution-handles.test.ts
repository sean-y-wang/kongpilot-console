import 'reflect-metadata';
import {describe,it,expect,vi} from 'vitest';
import {KongExecutionContextService} from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import {EntityChangeExecutionService} from '../../apps/console-api/src/modules/workflows/entity-change-execution.service';

/** Real private handle registries, with an explicit SQL/domain adapter. These
 * negatives do not substitute for Root's real HTTP/source/FK native tests. */
function fixture(){
  const context=new KongExecutionContextService(),db={one:vi.fn(),query:vi.fn(),exec:vi.fn()},writer={execute:vi.fn(),installExecutionDelegate:vi.fn()},facts={installFixedDelegate:vi.fn()};
  const kernel=new EntityChangeExecutionService(db as any,{} as any,{} as any,context,{} as any,{} as any,{} as any,{} as any,{} as any,{} as any,facts as any,{} as any,writer as any,{} as any);
  context.installEntityChangePacketPolicy(kernel);
  return{kernel,context,db,writer};
}
describe('M11 dedicated private entity packet handles',()=>{
  it('rejects shaped, copied, array and prototype handles before querying SQL or entering the native writer',async()=>{
    const f=fixture();
    for(const handle of [{},{sourceId:'source',baselineId:'baseline',packetKey:'p',approved:true},[],Object.create({sourceId:'source'})]){
      await expect(f.kernel.verifyHandle(handle)).rejects.toMatchObject({response:{code:'ENTITY_CHANGE_EXECUTION_PROOF_INVALID'}});
    }
    expect(f.db.one).not.toHaveBeenCalled();expect(f.writer.execute).not.toHaveBeenCalled();
  });
  it('requires the original genuine handle inside a real HTTP actor frame; session/actor DTOs cannot replace it',async()=>{
    const f=fixture(),actor={id:'actual-user',username:'owner',superAdmin:false};
    await f.context.runHttp({requestId:'actual-request'},async()=>{
      f.context.bindHttpActor(actor,'actual-session');
      await f.context.runActor({actor,clusterId:'actual-cluster',workspaceId:'actual-workspace',module:'workflows',action:'write'},async()=>{
        await expect(f.context.runEntityChangePacket({actorId:actor.id,sessionId:'actual-session',clusterId:'actual-cluster',workspaceId:'actual-workspace',expiresAt:Date.now()+300000},async()=>f.writer.execute())).rejects.toMatchObject({status:403});
      });
    });
    expect(f.writer.execute).not.toHaveBeenCalled();expect(f.db.one).not.toHaveBeenCalled();
  });
  it('does not let internal read or ordinary HTTP roots enter the dedicated packet namespace',async()=>{
    const f=fixture(),actor={id:'actual-user',username:'owner',superAdmin:false};
    await f.context.runHttp({},async()=>{
      f.context.bindHttpActor(actor,'actual-session');
      await expect(f.context.runEntityChangePacket({},async()=>undefined)).rejects.toMatchObject({response:{code:'ENTITY_CHANGE_PACKET_CONTEXT_INVALID'}});
      await f.context.runActor({actor,clusterId:'actual-cluster',workspaceId:'actual-workspace'},()=>f.context.runInternalRead('actual-cluster','entity-preflight',async()=>{
        await expect(f.context.runEntityChangePacket({},async()=>undefined)).rejects.toMatchObject({response:{code:'ENTITY_CHANGE_PACKET_CONTEXT_INVALID'}});
      }));
    });
    expect(f.db.one).not.toHaveBeenCalled();
  });
  it('rejects a second provider installation instead of replacing the original authority',()=>{
    const f=fixture();expect(()=>f.context.installEntityChangePacketPolicy(f.kernel)).toThrow();
  });
});
