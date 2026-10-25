import { describe, expect, it, vi } from 'vitest';
import { randomUUID } from 'node:crypto';
import { EventsService } from '../../apps/console-api/src/modules/events/events.service';

function fixture(outcome:string|null, options:{write?:boolean;state?:string;attempts?:number;intent?:boolean}={}) {
  const row={id:randomUUID(),cluster_id:randomUUID(),workspace_id:randomUUID(),event_id:randomUUID(),channel_id:randomUUID(),subscription_id:null,
    state:options.state??'paused_authority',revision:4,attempt_count:options.attempts??1,replay_generation:0,error_code:'EVENT_DELIVERY_AUTHORITY_REVOKED',
    delivery_kind:'test',created_at:new Date(),intent_started_at:options.intent?new Date():null};
  const db={one:vi.fn(async()=>outcome===null?null:{outcome})};
  const authz={hasWholeWorkspace:vi.fn(async()=>options.write!==false)},metadata={writableScope:vi.fn(async()=>true)};
  const service=new EventsService(db as any,{} as any,authz as any,{} as any,{} as any,metadata as any,{} as any,{} as any);
  const actor={user:{id:randomUUID(),username:'test',superAdmin:false},workspaceId:row.workspace_id};
  return{row,db,view:()=> (service as any).deliveryView(row,actor)};
}

describe('actual delivery DTO replay capability',()=>{
  for(const state of ['paused_authority','exhausted','cancelled','succeeded']) {
    it(`refuses ${state} when the immutable original send remains uncertain`,async()=>{
      const f=fixture('uncertain',{state}),view=await f.view();
      expect(view.capabilities.replay).toBe(false);expect(view.state).toBe(state);
      expect(f.db.one).toHaveBeenCalledWith(expect.stringContaining('ORDER BY attempt_no DESC LIMIT 1'),[f.row.id,f.row.cluster_id,f.row.workspace_id]);
    });
  }
  for(const outcome of ['succeeded','failed']) it(`permits an authorized deliberate replay after known ${outcome}`,async()=>{
    expect((await fixture(outcome).view()).capabilities.replay).toBe(true);
  });
  for(const outcome of [null,'unrecognized']) it(`fails closed for missing or invalid immutable attempt ${outcome}`,async()=>{
    expect((await fixture(outcome).view()).capabilities.replay).toBe(false);
  });
  for(const options of [{write:false},{state:'uncertain'},{state:'sending'},{intent:true}]) it(`does not advertise replay or inspect attempts for unavailable authority ${JSON.stringify(options)}`,async()=>{
    const f=fixture('succeeded',options);expect((await f.view()).capabilities.replay).toBe(false);expect(f.db.one).not.toHaveBeenCalled();
  });
  it('allows a paused pre-send operation with no original attempt to be explicitly replayed',async()=>{
    const f=fixture(null,{attempts:0});expect((await f.view()).capabilities.replay).toBe(true);expect(f.db.one).not.toHaveBeenCalled();
  });
});
