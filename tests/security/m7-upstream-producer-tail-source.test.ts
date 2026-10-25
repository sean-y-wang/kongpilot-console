// @ts-nocheck -- actual helper in RAM with synthetic BFF/sequence adapters.
import { readFileSync } from 'node:fs';
import { describe, expect, it, vi } from 'vitest';
const cid='dff45535-ed8d-4851-b7a6-6376feac7f59',wid='4f2f9544-e3f1-4ff9-93ca-4c3b3e5324e5',certificateId='50675a17-ca7f-4113-8003-08fb8f246c84',upstreamId='138c34c9-bdac-470c-a5fa-64564474aebe',targetId='4c92e70c-a2be-43bb-8b6b-f87f1d52a9bf';
function fixture(){
  const samples=Array.from({length:5},()=>({quality:'verified',observedAt:new Date(Date.now()-100000).toISOString()}));
  const h={state:{testTag:'m7-security-b81047b2',samplingIntents:[{}, {}, {state:'completed',id:certificateId,samples}],fixtures:[]},save:vi.fn(),data:r=>r.data,
    check(v,n){if(!v)throw Error(n)},poll:async(read,predicate,n)=>{const value=await read();if(!predicate(value))throw Error(n);return value}};
  const expiry={id:'expiry-event',actorType:'system',actorId:null,phase:'observation',payload:{quality:'verified',expiry:{bucket:'expired',expiresAt:new Date(Date.now()-1000).toISOString()}}};
  const transition={id:'health-event',actorType:'system',actorId:null,phase:'observation',payload:{quality:'verified',health:{before:'healthy',after:'unhealthy'}}};
  const health={data:[{id:targetId,health:'HEALTHY'}]};
  h.request=vi.fn(async(_actor,path,method='GET')=>{if(path.endsWith('/health'))return{data:health};if(path.includes('entities/certificates/'))return{data:{entity:{id:certificateId}}};if(path.includes('entities/upstreams/'))return{data:{entity:{id:upstreamId}}};if(path.endsWith('/unhealthy')&&method==='POST')return{data:{}};throw Error('UNEXPECTED_PATH')});
  const reads=[],eventRead=vi.fn(async(_h,_actor,_area,_path,q)=>{reads.push(q);return{items:q.nativeType==='certificates'?[expiry]:[transition]}}),eventWrite=vi.fn(async()=>({id:'subscription'}));
  const sequence=vi.fn(async(_h,area,type,id,callback)=>{expect(area).toEqual({cid,wid});expect(type).toBe('upstreams');expect(id).toBe(upstreamId);for(let i=0;i<5;i++)await callback({quality:'verified'},i);return samples});
  const source=readFileSync(new URL('./lib/m7-upstream-producer-tail.mjs',import.meta.url),'utf8').replace(/^import .*;$/gm,'').replace(/export /g,'');
  const helper=new Function('entity','rows','scope','eventRead','eventWrite','observationSequence',source+'\nreturn completeM7ExistingUpstreamProducer;')(v=>v.entity??v,v=>v.items??[],(_c,_w,p)=>p,eventRead,eventWrite,sequence);
  return{h,helper,actors:{admin:{id:'original-admin'},approver:{id:'original-approver'},direct:{cid,wid}},expiry,transition,health,eventWrite,eventRead,sequence,reads};
}
describe('original completed certificate and unused Upstream transition tail',()=>{
  it('does not re-create fixtures or replay healthy and executes the original unhealthy only after sample two',async()=>{
    const f=fixture();const r=await f.helper(f.h,f.actors,{id:'original-channel'});
    expect(r).toMatchObject({certificate:{id:certificateId},upstream:{id:upstreamId},eventIds:['expiry-event','health-event']});
    expect(f.eventWrite).toHaveBeenCalledTimes(1);expect(f.eventWrite.mock.calls[0][6]).toMatchObject({nativeIds:[upstreamId]});expect(f.sequence).toHaveBeenCalledTimes(1);
    expect(f.h.request.mock.calls.filter(c=>c[2]==='POST').map(c=>c[1])).toEqual([`upstreams/${upstreamId}/targets/${targetId}/unhealthy`]);expect(f.h.state.producersComplete).toBe(true);
  });
  it.each(['certificate-state','certificate-id','certificate-samples','prior-upstream-intent','prior-subscription','not-healthy','foreign-target'])('refuses %s before allocating any sampler or subscription',async defect=>{
    const f=fixture();if(defect==='certificate-state')f.h.state.samplingIntents[2].state='unknown';if(defect==='certificate-id')f.h.state.samplingIntents[2].id='foreign';if(defect==='certificate-samples')f.h.state.samplingIntents[2].samples.pop();
    if(defect==='prior-upstream-intent')f.h.state.samplingIntents.push({type:'upstreams'});if(defect==='prior-subscription')f.h.state.fixtures.push({type:'subscriptions',name:f.h.state.testTag+'-health'});if(defect==='not-healthy')f.health.data[0].health='UNHEALTHY';if(defect==='foreign-target')f.health.data[0].id='foreign';
    await expect(f.helper(f.h,f.actors,{id:'channel'})).rejects.toThrow();expect(f.eventWrite).not.toHaveBeenCalled();expect(f.sequence).not.toHaveBeenCalled();expect(f.h.state.producersComplete).toBeUndefined();
  });
  it.each(['user-event','not-expired','no-pre-expiry','unverified-expiry'])('refuses reused certificate proof %s before new writes',async defect=>{
    const f=fixture();if(defect==='user-event')f.expiry.actorType='user';if(defect==='not-expired')f.expiry.payload.expiry.bucket='1d';if(defect==='no-pre-expiry')f.h.state.samplingIntents[2].samples.forEach(s=>s.observedAt=new Date().toISOString());if(defect==='unverified-expiry')f.expiry.payload.quality='partial';
    await expect(f.helper(f.h,f.actors,{id:'channel'})).rejects.toThrow();expect(f.eventWrite).not.toHaveBeenCalled();
  });
  it('unknown subscription outcome stops before starting a sampling sequence',async()=>{
    const f=fixture();f.eventWrite.mockRejectedValue(Error('UNKNOWN_ORIGINAL_PACKET'));await expect(f.helper(f.h,f.actors,{id:'channel'})).rejects.toThrow('UNKNOWN');expect(f.sequence).not.toHaveBeenCalled();expect(f.h.state.producersComplete).toBeUndefined();
  });
  it('unknown unhealthy packet stops original sequence and prevents completion and later event reads',async()=>{
    const f=fixture();const original=f.h.request.getMockImplementation();f.h.request.mockImplementation(async(...args)=>{if(args[1].endsWith('/unhealthy'))throw Error('UNKNOWN_ORIGINAL_PACKET');return original(...args)});
    await expect(f.helper(f.h,f.actors,{id:'channel'})).rejects.toThrow('UNKNOWN');expect(f.eventRead).toHaveBeenCalledTimes(1);expect(f.h.state.producersComplete).toBeUndefined();
  });
});
