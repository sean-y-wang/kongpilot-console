import {describe,expect,it,vi} from 'vitest';
import {MetricsScopeService,METRICS_PREFETCH_MIN} from '../../apps/console-api/src/modules/vitals/metrics-scope.service';
const id=(n:number,p='0')=>`${p.repeat(8)}-0000-4000-8000-${String(n).padStart(12,'0')}`;
const epochs=(n:number)=>Array.from({length:n},(_,i)=>({entity_type:'routes',entity_id:id(i,'a'),service_id:id(i%3,'b')} as any));
function svc(rows:Record<string,any[]>,fail=false){const list=vi.fn(async(_c:string,path:string,_q:any,cursor?:string)=>{if(fail)throw new Error('budget');const all=rows[path]??[];const start=cursor?Number(cursor):0;return {items:all.slice(start,start+1000),nextCursor:start+1000<all.length?String(start+1000):null,size:1000};});
 const runInternalRead=vi.fn(async(_c:string,_k:string,fn:any,opts:any)=>{expect(opts.paths).toHaveLength(1);return fn();});
 return {list,runInternalRead,s:new MetricsScopeService({} as any,{} as any,{list} as any,{runInternalRead} as any,{} as any)};}
describe('M11 vitals identity prefetch',()=>{
 it('uses one list per type instead of one GET per epoch, only keeping wanted ids',async()=>{
  const routes=[...Array.from({length:40},(_,i)=>({id:id(i,'a'),service:{id:id(i%3,'b')},tags:[]})),{id:id(999,'f')}];
  const {s,list}=svc({'/routes':routes,'/services':[{id:id(0,'b')},{id:id(1,'b')}]});
  const m=await (s as any).prefetchIdentities('c',epochs(40),'w');
  expect(list).toHaveBeenCalledTimes(1);expect(list.mock.calls[0][1]).toBe('/routes'); // only 3 parent services < threshold: point GETs
  expect(m.size).toBe(40);expect(m.has(`routes:${id(999,'f')}`)).toBe(false);
 });
 it('skips small sets, pages at most 3 times, and falls back on failure',async()=>{
  expect((await (svc({}).s as any).prefetchIdentities('c',epochs(METRICS_PREFETCH_MIN-1))).size).toBe(0);
  const many=Array.from({length:5000},(_,i)=>({id:id(i+100000,'e')}));const t=svc({'/routes':many});
  const m=await (t.s as any).prefetchIdentities('c',epochs(20));expect(t.list).toHaveBeenCalledTimes(3);expect(m.size).toBe(0);
  const f=svc({},true);expect((await (f.s as any).prefetchIdentities('c',epochs(20))).size).toBe(0);
 });
 it('stops paging once every wanted id is found',async()=>{
  const rows=[...Array.from({length:20},(_,i)=>({id:id(i,'a')})),...Array.from({length:3000},(_,i)=>({id:id(i+50000,'e')}))];
  const t=svc({'/routes':rows});await (t.s as any).prefetchIdentities('c',epochs(20));expect(t.list).toHaveBeenCalledTimes(1);
 });
});
