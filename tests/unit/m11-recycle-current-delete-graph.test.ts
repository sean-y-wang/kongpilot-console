import 'reflect-metadata';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { randomUUID } from 'node:crypto';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { GraphCapturerService, type RecycleGraph } from '../../apps/console-api/src/modules/recycle-bin/graph-capturer.service';
import { RecycleService } from '../../apps/console-api/src/modules/recycle-bin/recycle.service';
import { assertRecycleDeleteGraphCurrent, expectedRecycleDeleteGraph, recycleDeleteClosureRoot } from '../../apps/console-api/src/modules/recycle-bin/entity-recycle-current-delete-graph';

/** Production projection/capture algorithms, real HMACs; transport and Context
 * are controlled read-only adapters, not original SDK authority or real Kong. */
function fixture(type:'service'|'certificate'|'upstream'='service'){
  const a=randomUUID(),b=randomUUID(),ref=randomUUID(),parentType=type==='service'?'services':type==='certificate'?'certificates':'upstreams',childType=type==='service'?'routes':type==='certificate'?'snis':'targets';
  const data:any=type==='service'?{id:a,name:'service',host:'192.0.2.20'}:type==='certificate'?{id:a,cert:'public',key:'private',snis:['unit.example']}:{id:a,name:'upstream'};
  const child:any=type==='service'?{id:b,service:{id:a},paths:['/unit']}:type==='certificate'?{id:b,name:'unit.example',certificate:{id:a}}:{id:b,upstream:{id:a},target:'192.0.2.20:8080',weight:100};
  const graph:RecycleGraph={complete:true,purpose:'recycle',capturedAt:new Date().toISOString(),rootKey:`${parentType}:${a}`,nodes:[
    {key:`${parentType}:${a}`,type:parentType,id:a,path:`/${parentType}/${a}`,data,affected:true,dependencies:[],restoreData:data,restorable:true},
    {key:childType==='targets'?`targets:${a}:${b}`:`${childType}:${b}`,type:childType,id:b,path:childType==='targets'?`/upstreams/${a}/targets/${b}`:`/${childType}/${b}`,data:child,affected:true,dependencies:[`${parentType}:${a}`],restoreData:child,restorable:true},
  ],...(type==='upstream'?{targetHistory:[{upstreamId:a,items:[child]}]}:{})};
  return{graph,a,b,ref,secrets:new SecretService()};
}

describe('V3 exact current cascade EOF graph closure, read-only source fixtures',()=>{
  beforeEach(()=>vi.stubEnv('CONSOLE_ENCRYPTION_KEY','82'.repeat(32)));afterEach(()=>vi.unstubAllEnvs());
  it('accepts the exact untouched whole graph and requires complete baseline capture',()=>{
    const f=fixture(),expected=expectedRecycleDeleteGraph(f.graph,f.graph.rootKey,[]),actual=structuredClone(expected);
    assertRecycleDeleteGraphCurrent(expected,actual,f.secrets);
    for(const field of ['complete','purpose','rootKey']){const broken:any=structuredClone(actual);broken[field]=field==='complete'?false:'forged';expect(()=>assertRecycleDeleteGraphCurrent(expected,broken,f.secrets)).toThrow();}
  });
  it('checks the complete original cascade before a first leaf DELETE, then only the exact remaining parent subtree',()=>{
    const f=fixture(),child=f.graph.nodes[1];expect(recycleDeleteClosureRoot(f.graph,child.key,[])).toBe(f.graph.rootKey);
    const cert=fixture('certificate');expect(recycleDeleteClosureRoot(cert.graph,cert.graph.nodes[1].key,[])).toBe(cert.graph.rootKey);
    const pluginId=randomUUID(),plugin:any={id:pluginId,name:'cors',route:{id:f.b}};
    f.graph.nodes.push({key:`plugins:${pluginId}`,type:'plugins',id:pluginId,path:`/plugins/${pluginId}`,data:plugin,affected:true,dependencies:[child.key],restoreData:plugin,restorable:true});
    expect(recycleDeleteClosureRoot(f.graph,`plugins:${pluginId}`,[])).toBe(f.graph.rootKey);
    expect(recycleDeleteClosureRoot(f.graph,child.key,[`plugins:${pluginId}`])).toBe(child.key);
    expect(()=>recycleDeleteClosureRoot(f.graph,child.key,[child.key])).toThrow();
  });
  it('projects only genuinely completed children and keeps all remaining nodes and immutable fields',()=>{
    const f=fixture(),expected=expectedRecycleDeleteGraph(f.graph,f.graph.rootKey,[f.graph.nodes[1].key]);expect(expected.nodes.map(n=>n.key)).toEqual([f.graph.rootKey]);
    const actual=structuredClone(expected);actual.nodes[0].data.host='192.0.2.21';expect(()=>assertRecycleDeleteGraphCurrent(expected,actual,f.secrets)).toThrow();
    expect(f.graph.nodes).toHaveLength(2);expect(f.graph.nodes[0].data.host).toBe('192.0.2.20');
  });
  it('rejects extra, missing, duplicate or reparented live children independent of tags',()=>{
    const f=fixture(),expected=expectedRecycleDeleteGraph(f.graph,f.graph.rootKey,[]);
    for(const change of [(g:RecycleGraph)=>g.nodes.pop(),(g:RecycleGraph)=>g.nodes.push(g.nodes[1]),(g:RecycleGraph)=>{g.nodes[1].data.service={id:randomUUID()};},(g:RecycleGraph)=>{const child=structuredClone(g.nodes[1]);child.id=randomUUID();child.key=`routes:${child.id}`;child.path=`/routes/${child.id}`;child.data.id=child.id;child.data.tags=['workspace:other'];g.nodes.push(child);}]){
      const actual=structuredClone(expected);change(actual);expect(()=>assertRecycleDeleteGraphCurrent(expected,actual,f.secrets)).toThrow();
    }
  });
  it('projects Certificate.snis only from its exact completed SNI children, retaining all other data',()=>{
    const f=fixture('certificate'),expected=expectedRecycleDeleteGraph(f.graph,f.graph.rootKey,[f.graph.nodes[1].key]);expect(expected.nodes[0].data.snis).toEqual([]);expect(f.graph.nodes[0].data.snis).toEqual(['unit.example']);
    const actual=structuredClone(expected);actual.nodes[0].data.key='different-private';expect(()=>assertRecycleDeleteGraphCurrent(expected,actual,f.secrets)).toThrow();
    const stillPresent=structuredClone(expected);stillPresent.nodes[0].data.snis=['unit.example'];expect(()=>assertRecycleDeleteGraphCurrent(expected,stillPresent,f.secrets)).toThrow();
  });
  it('does not let completed-node shapes remove unknown, duplicate or current root nodes',()=>{
    const f=fixture();for(const completed of [[randomUUID()],[f.graph.nodes[1].key,f.graph.nodes[1].key],[f.graph.rootKey]])expect(()=>expectedRecycleDeleteGraph(f.graph,f.graph.rootKey,completed)).toThrow();
  });
  it('derives a Route subtree with its Service as a reference without acquiring sibling Route authority',()=>{
    const f=fixture(),pluginId=randomUUID(),plugin:any={id:pluginId,name:'cors',route:{id:f.b}};
    f.graph.nodes.push({key:`plugins:${pluginId}`,type:'plugins',id:pluginId,path:`/plugins/${pluginId}`,data:plugin,affected:true,dependencies:[f.graph.nodes[1].key],restoreData:plugin,restorable:true});
    const expected=expectedRecycleDeleteGraph(f.graph,f.graph.nodes[1].key,[]);
    expect(expected.nodes.find(n=>n.type==='services')!.affected).toBe(false);expect(expected.nodes.filter(n=>n.affected).map(n=>n.type)).toEqual(['routes','plugins']);
    const actual=structuredClone(expected);actual.nodes.find(n=>n.type==='services')!.affected=true;expect(()=>assertRecycleDeleteGraphCurrent(expected,actual,f.secrets)).toThrow();
  });
  it('rejects reference drift and invalid or cyclic dependency graphs',()=>{
    const f=fixture();f.graph.nodes[0].dependencies=[f.graph.nodes[1].key];expect(()=>expectedRecycleDeleteGraph(f.graph,f.graph.rootKey,[])).toThrow();
    f.graph.nodes[0].dependencies=['unknown'];expect(()=>expectedRecycleDeleteGraph(f.graph,f.graph.rootKey,[])).toThrow();
  });
  it('requires exact current full Target history and never attributes an unknown zero row to a DELETE',()=>{
    const f=fixture('upstream'),expected=expectedRecycleDeleteGraph(f.graph,f.graph.rootKey,[f.graph.nodes[1].key]);expect(expected.targetHistory![0].items).toEqual([]);
    const actual=structuredClone(expected);actual.targetHistory![0].items.push({...f.graph.nodes[1].data,id:randomUUID(),weight:0});expect(()=>assertRecycleDeleteGraphCurrent(expected,actual,f.secrets)).toThrow();
    assertRecycleDeleteGraphCurrent(expected,structuredClone(expected),f.secrets);
  });
  it('reads every Consumer credential kind and plugin EOF without workspace tag filtering, rejecting a foreign-tag child on the next page',async()=>{
    const cid=randomUUID(),consumerId=randomUUID(),oldId=randomUUID(),extraId=randomUUID(),consumer={id:consumerId,username:'unit-consumer',tags:['workspace:one']};
    const credential={id:oldId,consumer:{id:consumerId},key:'unit-key'},rootKey=`consumers:${consumerId}`,childKey=`key-auth:${consumerId}:${oldId}`;
    const graph:RecycleGraph={rootKey,complete:true,purpose:'recycle',capturedAt:new Date().toISOString(),nodes:[{key:rootKey,type:'consumers',id:consumerId,path:`/consumers/${consumerId}`,data:consumer,affected:true,dependencies:[],restoreData:consumer,restorable:true},{key:childKey,type:'key-auth',id:oldId,path:`/consumers/${consumerId}/key-auth/${oldId}`,data:credential,affected:true,dependencies:[rootKey],restoreData:credential,restorable:true}]};
    let foreign=false,includeOriginal=false;const calls:any[]=[];
    const kong:any={request:vi.fn(async(_cid:string,method:string,path:string)=>{expect(method).toBe('GET');expect(path).toBe(`/consumers/${consumerId}`);return consumer;}),list:vi.fn(async(_cid:string,path:string,query:any,cursor:any)=>{calls.push({path,query,cursor});expect(query).toEqual({size:100});
      if(path.endsWith('/key-auth')){if(foreign)return cursor?{items:[{id:extraId,consumer:{id:consumerId},key:'foreign-key',tags:['workspace:other']}],nextCursor:null}:{items:includeOriginal?[credential]:[],nextCursor:'opaque-second-page'};return{items:includeOriginal?[credential]:[],nextCursor:null};}
      return{items:[],nextCursor:null};})};
    const context:any={runInternalRead:vi.fn(async(_cid:string,purpose:string,fn:any)=>{expect(purpose).toBe('capture');return fn();})};
    const capturer=new GraphCapturerService(kong,{getRestorePayload:async(_cid:any,_parent:any,_kind:any,_id:any,raw:any)=>raw} as any,context);
    const service=Object.create(RecycleService.prototype) as any;service.capturer=capturer;service.secrets=new SecretService();
    await service.assertPreparedDeleteCurrentGraph(cid,graph,rootKey,[childKey]);expect(calls.map(c=>c.path)).toEqual(expect.arrayContaining(['key-auth','basic-auth','jwt','oauth2','hmac-auth','acls'].map(kind=>`/consumers/${consumerId}/${kind}`).concat(['/plugins'])));
    includeOriginal=true;const firstRoot=recycleDeleteClosureRoot(graph,childKey,[]);expect(firstRoot).toBe(rootKey);await service.assertPreparedDeleteCurrentGraph(cid,graph,firstRoot,[]);
    foreign=true;calls.length=0;await expect(service.assertPreparedDeleteCurrentGraph(cid,graph,firstRoot,[])).rejects.toMatchObject({response:{code:'ENTITY_RECYCLE_CURRENT_GRAPH_CHANGED'}});
    expect(calls.filter(c=>c.path.endsWith('/key-auth'))).toHaveLength(2);
  });
});
