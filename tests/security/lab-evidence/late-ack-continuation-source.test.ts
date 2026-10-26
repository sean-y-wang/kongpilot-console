// @ts-nocheck -- exact helper methods with RAM-only responses.
import { describe,it,expect,vi } from 'vitest';
import { randomUUID } from 'node:crypto';
import { finishOriginalLateAck,prepareLateAckContinuation,M7_LATE_ACK_FAILURE } from './lib/m7-late-ack-continuation.mjs';
import { readFileSync } from 'node:fs';
function fixture(change={}) {
 const area={cid:randomUUID(),wid:randomUUID()},channel={id:randomUUID()},queued={eventId:randomUUID(),deliveryId:randomUUID()},actors={admin:{user:{id:randomUUID()}},direct:area};
 const delivery={id:queued.deliveryId,eventId:queued.eventId,channelId:channel.id,clusterId:area.cid,workspaceId:area.wid,state:'paused_authority',revision:5,capabilities:{replay:false},...change.delivery};
 const attempts=[{sendStarted:true,outcome:'uncertain',...change.attempt}],record={deliveryId:queued.deliveryId,eventId:queued.eventId,clusterId:area.cid,workspaceId:area.wid};
 const h={state:{},check:(ok,n)=>{if(!ok)throw Error(n)},data:r=>r.payload.data,receiver:vi.fn((_s,v)=>v.action==='stats'?{records:Array.from({length:change.records??1},()=>record)}:{ok:true}),request:vi.fn(async(_a,p,m='GET')=>({status:m==='POST'?409:200,requestId:randomUUID(),payload:m==='POST'?{error:{code:change.replayCode??'DELIVERY_UNRESOLVED'}}:{data:p.includes('/attempts?')?{items:attempts}:{entity:delivery}}}))};
 return {h,actors,queued,channel};
}
describe('original late ACK immutable intent continuation',()=>{
 it('accepts exactly one uncertain attempt under paused authority with current replay disabled',async()=>{const f=fixture();await finishOriginalLateAck(f.h,f.actors,f.queued,f.channel);expect(f.h.request.mock.calls.filter(v=>v[2]==='POST')).toHaveLength(1);expect(f.h.public.lateAckFence.outcome).toBe('uncertain');expect(f.h.receiver.mock.calls.at(-1)[1]).toEqual({action:'fault',fault:{times:0,delayMs:0}});});
 it('rejects succeeded,foreign scope,enabled capability or non-uncertain attempt before replay',async()=>{for(const change of[{delivery:{state:'succeeded'}},{delivery:{clusterId:randomUUID()}},{delivery:{capabilities:{replay:true}}},{attempt:{outcome:'failed'}},{attempt:{sendStarted:false}},{records:2}]){const f=fixture(change);await expect(finishOriginalLateAck(f.h,f.actors,f.queued,f.channel)).rejects.toThrow();expect(f.h.request.mock.calls.every(v=>!v[2]||v[2]==='GET')).toBe(true);}});
 it('the sole expected rejected replay must have the exact server unresolved code',async()=>{const f=fixture({replayCode:'SOME_OTHER_CONFLICT'});await expect(finishOriginalLateAck(f.h,f.actors,f.queued,f.channel)).rejects.toThrow('rejects replay');expect(f.h.receiver.mock.calls.every(v=>v[1].action==='stats')).toBe(true);});
 it('unknown original packets cannot release a new continuation or history writer',()=>{const report=readFileSync(M7_LATE_ACK_FAILURE.path),diagnosis=readFileSync(M7_LATE_ACK_FAILURE.diagnosisPath),h={state:{testTag:JSON.parse(report).testTag,phase:'stopped-failure',inFlight:null,requests:[]},check:(ok,n)=>{if(!ok)throw Error(n)},save:vi.fn()};expect(()=>prepareLateAckContinuation(h,report,diagnosis)).toThrow();expect(h.save).not.toHaveBeenCalled();});
});
