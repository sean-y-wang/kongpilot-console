import { describe, expect, it, vi } from 'vitest';
import { randomUUID } from 'node:crypto';
import { createHash } from 'node:crypto';
import { canonicalJson } from '../../apps/console-api/src/infrastructure/secret.service';
import { disabledTargetReadback } from '../../apps/console-api/src/infrastructure/kong/disabled-target-readback';

const cid=randomUUID(),upstream=randomUUID(),newId=randomUUID(),address='echo:8080';
const secrets={fingerprint:(v:unknown)=>createHash('sha256').update(canonicalJson(v)).digest('hex')};
const row=(weight:number,created_at:number,id=randomUUID())=>({id,target:address,weight,created_at,upstream:{id:upstream},tags:['owner:test','team:pay']});
function fixture(){
  const native=row(0,1791927041.513,newId),body={id:newId,target:address,weight:0,tags:['team:pay','owner:test']},history=[row(100,1791927020.123),row(80,1791927030.456),native],effective:any[]=[];
  const kong={list:vi.fn(async(_cid:string,path:string,q:any)=>({items:structuredClone(path.endsWith('/all')?history:effective),size:q.size,nextCursor:null})),request:vi.fn()};
  const run=(options:any={})=>disabledTargetReadback(kong,secrets,{clusterId:cid,upstreamId:upstream,approvedBody:body,nativeResult:native},options);
  return{native,body,history,effective,kong,run};
}
describe('future Target weight0 readback uses exact history and bounded effective EOF',()=>{
  it('keeps the exact native zero row and fractional timestamp, with four parent-scoped read collections and no UUID/address GET',async()=>{
    const f=fixture(),before=structuredClone(f.native),result=await f.run();expect(result.observedTarget).toEqual(before);expect(result.budget).toMatchObject({pages:4,records:6});
    expect(result).toMatchObject({knownOriginalResponse:before,historyRetention:'retained',historyAddressAbsent:false,currentEffectiveAbsent:true,originalResultHmac:secrets.fingerprint(before),observedHistoryHmac:secrets.fingerprint(before)});
    expect(f.kong.list.mock.calls.map(c=>c[1])).toEqual([`/upstreams/${upstream}/targets/all`,`/upstreams/${upstream}/targets`,`/upstreams/${upstream}/targets/all`,`/upstreams/${upstream}/targets`]);
    expect(f.kong.request).not.toHaveBeenCalled();expect(f.native).toEqual(before);
  });
  it('certifies native DAO-pruned disabled history through two stable complete EOFs without fabricating a GET row',async()=>{
    const f=fixture();f.history.length=0;const result=await f.run();expect(result).toMatchObject({observedTarget:null,knownOriginalResponse:f.native,historyRetention:'native-pruned',historyAddressAbsent:true,currentEffectiveAbsent:true,originalResultHmac:secrets.fingerprint(f.native),observedHistoryHmac:null,budget:{pages:4,records:0}});
    expect(result.historySnapshotHmac).toBe(secrets.fingerprint([]));expect(result.effectiveSnapshotHmac).toBe(secrets.fingerprint([]));expect(f.kong.list).toHaveBeenCalledTimes(4);expect(f.kong.request).not.toHaveBeenCalled();
  });
  it('allows other retained addresses while the exact disabled address is natively pruned, using complete stable collections',async()=>{
    const f=fixture(),other={...row(90,1791927030.1),target:'other:8080'};f.history.splice(0,f.history.length,other);f.effective.push(other);const result=await f.run();expect(result.historyRetention).toBe('native-pruned');expect(result.observedTarget).toBeNull();expect(result.budget).toMatchObject({pages:4,records:4});
  });
  it.each(['old-positive-only','other-zero-only','active-address','reused-history-uuid','reused-effective-uuid'] as const)('rejects %s instead of inferring pruning from missing allocated UUID',async shape=>{
    const f=fixture();f.history.length=0;
    if(shape==='old-positive-only')f.history.push(row(80,1791927030.456));
    if(shape==='other-zero-only')f.history.push(row(0,1791927030.456));
    if(shape==='active-address')f.effective.push(row(80,f.native.created_at+1));
    if(shape==='reused-history-uuid')f.history.push({...f.native,id:f.native.id.toUpperCase(),target:'other:8080'});
    if(shape==='reused-effective-uuid')f.effective.push({...f.native,id:f.native.id.toUpperCase(),target:'other:8080',weight:80});
    await expect(f.run()).rejects.toBeDefined();expect(f.kong.request).not.toHaveBeenCalled();
  });
  it('rejects retained-to-pruned or pruned-to-retained changes during the four EOF observations',async()=>{
    for(const firstPruned of [false,true]){const f=fixture();let calls=0;f.kong.list.mockImplementation(async(_c,path,q)=>{calls++;const pruned=calls<3?firstPruned:!firstPruned;return{items:path.endsWith('/all')&&!pruned?f.history:[],size:q.size,nextCursor:null};});await expect(f.run()).rejects.toMatchObject({response:{code:'TARGET_DISABLED_READBACK_CHANGED'}});}
  });
  it('traverses all cursor pages before deciding, retaining one cursor-bound size',async()=>{
    const f=fixture();f.kong.list.mockImplementation(async(_cid,path,q,cursor)=>({items:path.endsWith('/all')?(cursor?[f.native]:f.history.slice(0,2)):[],size:q.size,nextCursor:path.endsWith('/all')&&!cursor?'second':null}));
    expect((await f.run()).budget.pages).toBe(6);expect(f.kong.list.mock.calls.filter(c=>c[3]==='second')).toHaveLength(2);expect(f.kong.list.mock.calls.every(c=>c[2].size===100)).toBe(true);
  });
  it.each([
    ['missing new UUID',(f:any)=>f.history.pop()],
    ['wrong exact raw HMA',(f:any)=>{f.history[2]={...f.native,created_at:f.native.created_at+0.001};}],
    ['foreign parent',(f:any)=>{f.history[0].upstream.id=randomUUID();}],
    ['duplicate UUID',(f:any)=>f.history.push({...f.history[0],id:f.history[0].id.toUpperCase(),target:'other:8080'})],
    ['timestamp tie',(f:any)=>f.history.push({...f.native,id:randomUUID(),weight:80})],
    ['newer history row',(f:any)=>f.history.push(row(0,f.native.created_at+1))],
    ['active same address',(f:any)=>f.effective.push(row(80,f.native.created_at+1))],
    ['zero in effective collection',(f:any)=>f.effective.push(f.native)],
    ['malformed old history',(f:any)=>{f.history[0].weight=-1;}],
    ['wrong approved body',(f:any)=>{f.body.target='foreign:8080';}],
    ['wrong approved tag scope',(f:any)=>{f.body.tags=['owner:foreign'];}],
  ])('rejects %s instead of claiming current zero or silently choosing a historical winner',async(_name,change)=>{
    const f=fixture();change(f);await expect(f.run()).rejects.toBeDefined();expect(f.kong.request).not.toHaveBeenCalled();
  });
  it('rejects permission-projected pages even if the selected UUID is visible',async()=>{
    const f=fixture();f.kong.list.mockImplementation(async(_c,_p,q)=>({items:[f.native],size:q.size,nextCursor:null,console_permission_projection:true}));
    await expect(f.run()).rejects.toMatchObject({response:{code:'TARGET_DISABLED_READBACK_INVALID'}});
  });
  it('rejects history and effective collection drift across repeated full observations',async()=>{
    for(const effectiveDrift of [false,true]){const f=fixture();let calls=0;f.kong.list.mockImplementation(async(_c,path,q)=>{calls++;
      const history=structuredClone(f.history),effective:any[]=[];if(!effectiveDrift&&calls>=3)history.push({...row(100,1),target:'unrelated:8080'});
      if(effectiveDrift&&calls>=4)effective.push({...row(100,1),target:'unrelated:8080'});
      return{items:path.endsWith('/all')?history:effective,size:q.size,nextCursor:null};});
      await expect(f.run()).rejects.toMatchObject({response:{code:'TARGET_DISABLED_READBACK_CHANGED'}});}
  });
  it('snapshots approved/result inputs before awaited reads and does not adopt caller mutations',async()=>{
    const f=fixture(),raw=structuredClone(f.native),body=structuredClone(f.body);let calls=0;
    f.kong.list.mockImplementation(async(_c,path,q)=>{if(++calls===1){body.weight=80;raw.weight=80;}return{items:path.endsWith('/all')?f.history:[],size:q.size,nextCursor:null};});
    expect((await disabledTargetReadback(f.kong,secrets,{clusterId:cid,upstreamId:upstream,approvedBody:body,nativeResult:raw})).observedTarget).toEqual(f.native);
  });
  it('fails at shared page/record/byte ceilings or cursor loops without treating a first match as complete',async()=>{
    const empty=fixture();await expect(empty.run({maxPages:0})).rejects.toMatchObject({response:{code:'TARGET_DISABLED_READBACK_LIMIT'}});expect(empty.kong.list).not.toHaveBeenCalled();
    const pages=fixture();await expect(pages.run({maxPages:3})).rejects.toMatchObject({response:{code:'TARGET_DISABLED_READBACK_LIMIT'}});expect(pages.kong.list).toHaveBeenCalledTimes(3);
    const bytes=fixture();await expect(bytes.run({maxBytes:1})).rejects.toMatchObject({response:{code:'TARGET_DISABLED_READBACK_LIMIT'}});
    const records=fixture();await expect(records.run({maxRecords:3,pageSize:3})).rejects.toMatchObject({response:{code:'TARGET_DISABLED_READBACK_LIMIT'}});expect(records.kong.list).toHaveBeenCalledOnce();
    const loop=fixture();loop.kong.list.mockImplementation(async(_c,_p,q)=>({items:[],size:q.size,nextCursor:'repeated'}));await expect(loop.run()).rejects.toMatchObject({response:{code:'TARGET_DISABLED_READBACK_INVALID'}});expect(loop.kong.list).toHaveBeenCalledTimes(2);
  });
});
