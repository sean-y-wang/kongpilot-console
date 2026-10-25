import { ConflictException } from '@nestjs/common';
import { immutableJson } from '../../infrastructure/kong/immutable-json';
import { SecretService } from '../../infrastructure/secret.service';
import type { GraphNode, RecycleGraph } from './graph-capturer.service';
import { isOrdinaryRecycleRoot } from './ordinary-recycle-contract';

const invalid=()=>new ConflictException({code:'ENTITY_RECYCLE_CURRENT_GRAPH_CHANGED',message:'当前对象关联已变化，网关删除已停止'});
/** KP-004 ordinary five roots — single catalog via ordinary-recycle-contract. */
export const requiresRecycleDeleteClosure=(type:string):boolean=>isOrdinaryRecycleRoot(type);

/** First native of EACH canonical archive must see its whole original cascade,
 * even when that first packet is a leaf. No completed fact is cached here. */
export function recycleDeleteClosureRoot(graph:Readonly<RecycleGraph>,nodeKey:string,completedNodeKeys:readonly string[]):string|null{
  const node=graph.nodes.find(item=>item.key===nodeKey),root=graph.nodes.find(item=>item.key===graph.rootKey);
  if(!node?.affected||!root?.affected||completedNodeKeys.includes(nodeKey))throw invalid();
  if(completedNodeKeys.length===0&&requiresRecycleDeleteClosure(root.type))return root.key;
  return requiresRecycleDeleteClosure(node.type)?node.key:null;
}

/** Pure expected-state projection only. completedNodeKeys must come from the
 * coordinator's original successful packet registry; this shape grants no
 * read or native authority and cannot attest a SQL outcome. */
export function expectedRecycleDeleteGraph(graph:Readonly<RecycleGraph>,rootKey:string,completedNodeKeys:readonly string[]):Readonly<RecycleGraph>{
  if(graph.complete!==true||!Array.isArray(graph.nodes)||!graph.nodes.length||!Array.isArray(completedNodeKeys)||new Set(completedNodeKeys).size!==completedNodeKeys.length)throw invalid();
  const nodes=new Map(graph.nodes.map(node=>[node.key,node]));
  if(nodes.size!==graph.nodes.length||graph.nodes.some(node=>!Array.isArray(node.dependencies)||node.dependencies.some(key=>!nodes.has(key))))throw invalid();
  const root=nodes.get(rootKey),completed=new Set(completedNodeKeys);
  if(!root?.affected||completed.has(rootKey)||completedNodeKeys.some(key=>!nodes.get(key)?.affected))throw invalid();
  const descendants=new Set([rootKey]);let changed=true;
  while(changed){changed=false;for(const node of graph.nodes)if(node.affected&&!completed.has(node.key)&&!descendants.has(node.key)&&node.dependencies.some(key=>descendants.has(key))){descendants.add(node.key);changed=true;}}
  const required=new Set(descendants),visiting=new Set<string>(),visited=new Set<string>();
  const visit=(key:string):void=>{if(visited.has(key))return;if(visiting.has(key)||completed.has(key))throw invalid();visiting.add(key);const node=nodes.get(key);if(!node)throw invalid();
    for(const dependency of node.dependencies){required.add(dependency);visit(dependency);}visiting.delete(key);visited.add(key);};
  for(const key of descendants)visit(key);
  const selected:GraphNode[]=graph.nodes.filter(node=>required.has(node.key)).map(node=>{
    const data=structuredClone(node.data);
    if(node.type==='certificates'){
      if(!Array.isArray(data.snis))throw invalid();
      const removed=new Set(graph.nodes.filter(child=>child.type==='snis'&&child.affected&&completed.has(child.key)&&child.dependencies.includes(node.key)).map(child=>child.data.name));
      data.snis=data.snis.filter((name:string)=>!removed.has(name));
    }
    return{...node,data,affected:descendants.has(node.key),dependencies:[...node.dependencies]};
  });
  const targetHistory=graph.targetHistory?.filter(history=>selected.some(node=>node.type==='upstreams'&&node.id===history.upstreamId&&descendants.has(node.key))).map(history=>({
    upstreamId:history.upstreamId,items:history.items.filter(item=>!graph.nodes.some(node=>node.type==='targets'&&completed.has(node.key)&&node.id===item.id))}));
  return immutableJson({rootKey,nodes:selected,complete:true,purpose:'baseline',capturedAt:graph.capturedAt,...(targetHistory?.length?{targetHistory}:{})});
}

/** Compare actual unfiltered full-collection EOF capture with the exact
 * still-present graph. No broad field elision or historical-as-current view. */
export function assertRecycleDeleteGraphCurrent(expected:Readonly<RecycleGraph>,actual:Readonly<RecycleGraph>,secrets:SecretService):void{
  if(actual.complete!==true||actual.purpose!=='baseline'||actual.rootKey!==expected.rootKey||!Array.isArray(actual.nodes)||new Set(actual.nodes.map(node=>node.key)).size!==actual.nodes.length)throw invalid();
  const normalized=(graph:Readonly<RecycleGraph>)=>graph.nodes.map(node=>({key:node.key,type:node.type,id:node.id,path:node.path,affected:node.affected,dependencies:[...node.dependencies].sort(),data:node.data})).sort((a,b)=>a.key.localeCompare(b.key));
  if(secrets.fingerprint(normalized(actual))!==secrets.fingerprint(normalized(expected)))throw invalid();
  const history=(graph:Readonly<RecycleGraph>)=>(graph.targetHistory??[]).map(item=>({upstreamId:item.upstreamId,items:[...item.items].sort((a,b)=>String(a.id).localeCompare(String(b.id)))})).sort((a,b)=>a.upstreamId.localeCompare(b.upstreamId));
  // An unexplained append-only Target row remains drift. Only removal of the
  // exact completed original UUID is projected; unknown zero-weight records
  // cannot be silently attributed to this execution's DELETE.
  if(secrets.fingerprint(history(actual))!==secrets.fingerprint(history(expected)))throw invalid();
}
