import { ConflictException, HttpException, Injectable, ServiceUnavailableException } from '@nestjs/common';
import { createHash } from 'node:crypto';
import { SecretService } from '../../infrastructure/secret.service';
import { KongService } from '../../infrastructure/kong/kong.service';
import { KongExecutionContextService, type KongExecutionFrame } from '../../infrastructure/kong/execution-context.service';
import { currentEffectiveTarget } from '../../infrastructure/kong/effective-target';
import { immutableJson } from '../../infrastructure/kong/immutable-json';
import { entityReferenceId } from '../entities/entity-reference';
import { CREDENTIAL_KINDS } from '../entities/entities.types';
import { GraphCapturerService, type GraphNode } from './graph-capturer.service';
import { derivePreparedRecyclePackets } from './entity-prepared-recycle-writer.service';
import type { EntityRecycleCurrentDescriptor as Descriptor, EntityRecycleCurrentNode, EntityRecycleCurrentWitness,
 EntityRecycleCurrentWitnessDelegate, EntityRecycleCurrentWitnessHandle as Handle } from './entity-recycle-current-witness.types';
const fail=(code='ENTITY_RECYCLE_CURRENT_GRAPH_CHANGED')=>new ConflictException({code,message:'当前对象图或执行来源已变化，请核验原工单'});
const credential=(type:string)=>(CREDENTIAL_KINDS as readonly string[]).includes(type);
const object=(value:any):value is Record<string,any>=>!!value&&typeof value==='object'&&!Array.isArray(value);
const parent=(node:GraphNode)=>node.type==='targets'?entityReferenceId(node.data.upstream):credential(node.type)?entityReferenceId(node.data.consumer):undefined;
interface Stored {active:boolean;original:object;phase:'before-native'|'after-native';frame:KongExecutionFrame;identityHmac:string;expiresAt:number;value:Readonly<EntityRecycleCurrentWitness>}

/** Fixed private current observation domain. Data-shaped handles/descriptors,
 * archived bytes, copied POST responses and status flags cannot issue a witness. */
@Injectable()
export class EntityRecycleCurrentWitnessService {
 private policy?:Readonly<EntityRecycleCurrentWitnessDelegate>;
 private readonly witnesses=new WeakMap<object,Stored>();
 constructor(private readonly kong:KongService,private readonly graphs:GraphCapturerService,private readonly context:KongExecutionContextService,private readonly secrets:SecretService){}
 installFixedDelegate(delegate:EntityRecycleCurrentWitnessDelegate):void{
  if(this.policy||!delegate||typeof delegate.describe!=='function'||typeof delegate.assertLive!=='function'||Object.keys(delegate).some(k=>!['describe','assertLive'].includes(k)))throw fail('ENTITY_RECYCLE_CURRENT_POLICY_INVALID');
  this.policy=Object.freeze({describe:delegate.describe.bind(delegate),assertLive:delegate.assertLive.bind(delegate)});
 }
 private installed(){if(!this.policy)throw new ServiceUnavailableException({code:'ENTITY_RECYCLE_CURRENT_POLICY_UNAVAILABLE'});return this.policy;}
 private live(original:object,frame:KongExecutionFrame,expiry:number){this.installed().assertLive(original);if(this.context.current()!==frame||!Number.isFinite(expiry)||Date.now()>=expiry)throw fail('ENTITY_RECYCLE_CURRENT_ORIGINAL_EXPIRED');}
 private expected(d:Readonly<Descriptor>){
  const plan=derivePreparedRecyclePackets(d.obligation,d.packets,this.secrets),graph=d.obligation.graph,completions=new Map(d.completed.map(item=>[item.nodeKey,item]));
  if(completions.size!==d.completed.length||!plan.some(item=>item.node.key===d.nodeKey&&this.secrets.fingerprint(item.packet)===this.secrets.fingerprint(d.packet)))throw fail();
  for(const completion of d.completed){const selected=plan.find(item=>item.node.key===completion.nodeKey);if(!selected||this.secrets.fingerprint(selected.packet)!==this.secrets.fingerprint(completion.packet)
    ||this.secrets.fingerprint(completion.response)!==completion.responseHmac)throw fail();
   if(selected.packet.method==='DELETE'){if(completion.response!==null)throw fail();}
   else this.reflection(selected.node,selected.packet,completion.response);
  }
  const expected=new Map<string,{node:GraphNode;id:string;path:string;data:Record<string,any>|null}>();
  for(const node of graph.nodes){const completion=completions.get(node.key),selected=plan.find(item=>item.node.key===node.key);let data:any;
   if(!node.affected)data=node.data;
   else if(d.obligation.kind==='recycle-archive')data=completion?null:node.data;
   else if(completion)data=completion.response;
   else if(d.obligation.partialRestore?.presentNodes.some(item=>item.nodeKey===node.key)){
    const p=d.prepared.prerequisites.find(item=>item.type===node.type&&item.nativeId===node.id&&!item.absent);
    const prior=d.obligation.partialRestore.presentNodes.find(item=>item.nodeKey===node.key)!;
    if(!p?.before||this.secrets.fingerprint(p.before)!==prior.beforeHmac)throw fail();data=p.before;
   }else data=null;
   const id=completion?.packet.nativeId??selected?.packet.nativeId??node.id,path=id===node.id?node.path:node.path.replace(/\/[^/]+$/,`/${id}`);
   if(data&&node.type==='certificates'){
    data=structuredClone(data);if(data.snis===undefined&&d.obligation.kind==='recycle-restore'&&completion)data.snis=[];if(!Array.isArray(data.snis))throw fail();
    const names=graph.nodes.filter(child=>child.type==='snis'&&child.dependencies.includes(node.key));
    if(d.obligation.kind==='recycle-archive'){const removed=new Set(names.filter(child=>completions.has(child.key)).map(child=>child.data.name));data.snis=data.snis.filter((name:string)=>!removed.has(name));}
    else{const restored=names.filter(child=>completions.has(child.key)||d.obligation.kind==='recycle-restore'&&d.obligation.partialRestore?.presentNodes.some(item=>item.nodeKey===child.key)).map(child=>child.data.name);
     if(data.snis.some((name:string)=>!restored.includes(name)))throw fail();data.snis=[...new Set(restored)].sort();}
   }
   expected.set(node.key,{node,id,path,data});
  }
  return expected;
 }
 private reflection(node:GraphNode,packet:Readonly<Descriptor['packet']>,raw:unknown):void{
  if(!object(raw)||raw.id!==packet.nativeId||!object(packet.body))throw fail('ENTITY_RECYCLE_RESTORE_REFLECTION_INVALID');
  if(parent(node)&&entityReferenceId(raw[node.type==='targets'?'upstream':'consumer'])!==packet.parentId)throw fail();
  for(const [key,value]of Object.entries(packet.body)){
   if(key==='password'&&node.type==='basic-auth'){
    if(typeof value!=='string'||typeof raw.password!=='string'||createHash('sha1').update(value+packet.parentId).digest('hex')!==raw.password.toLowerCase())throw fail('ENTITY_RECYCLE_CREDENTIAL_CONFIG_UNVERIFIED');continue;
   }
   if(this.secrets.fingerprint(raw[key]??null)!==this.secrets.fingerprint(value??null))throw fail('ENTITY_RECYCLE_RESTORE_REFLECTION_INVALID');
  }
 }
 private async round(d:Readonly<Descriptor>,original:object,frame:KongExecutionFrame,expiry:number,phase:'before-native'|'after-native'){
  const expected=this.expected(d),nodes:EntityRecycleCurrentNode[]=[],absent:string[]=[];
  for(const [key,item]of expected){this.live(original,frame,expiry);let actual:any=null;
   try{actual=await this.context.runInternalRead(d.source.clusterId,'capture',()=>this.kong.request(d.source.clusterId,'GET',item.path),{paths:[item.path],maxCalls:1,maxPages:1,maxRecords:1,maxBytes:1024*1024,timeoutMs:5000,workspaceId:d.source.workspaceId});}
   catch(error){if(!(error instanceof HttpException)||error.getStatus()!==404)throw error;}
   this.live(original,frame,expiry);
   if(item.data===null){if(actual!==null)throw fail('ENTITY_RECYCLE_EXPECTED_CURRENT_ABSENCE');absent.push(key);continue;}
   if(!object(actual)||actual.id!==item.id)throw fail();
   const normalize=(raw:any)=>item.node.type==='certificates'?{...raw,snis:Array.isArray(raw.snis)?[...raw.snis].sort():raw.snis}:raw;
   if(this.secrets.fingerprint(normalize(actual))!==this.secrets.fingerprint(normalize(item.data)))throw fail();
   nodes.push({key,originalId:item.node.id,type:item.node.type,parentId:parent(item.node)??null,affected:item.node.affected,data:actual});
  }
  const originalRoot=expected.get(d.obligation.graph.rootKey)!,current=expected.get(d.nodeKey)!;
  const cascade=new Set(['services','routes','consumers','certificates','upstreams']);
  const initial=d.completed.length===0,terminal=phase==='after-native'&&d.completed.length===d.packets.length;
  // Complete first graph and final restored graph, then only a parent's
  // remaining cascade when that DELETE can implicitly affect new children.
  // Every packet still independently reads all sealed current points twice.
  const closure=d.obligation.kind==='recycle-archive'?(initial?originalRoot:cascade.has(current.node.type)?current:null)
   :terminal||phase==='before-native'&&d.obligation.partialRestore?originalRoot:null;
  const root=closure??originalRoot;
  let closureHistory:unknown=null;
  if(closure?.data){
   const actual=await this.graphs.observe(d.source.clusterId,root.node.type,root.id,{parentId:parent(root.node),credentialKind:credential(root.node.type)?root.node.type:undefined,budget:{maxPages:100,maxRecords:10000,maxNodes:1000,maxBytes:16*1024*1024}});
   this.live(original,frame,expiry);
   const cascade=new Set([root.node.key]);let added=true;
   while(added){added=false;for(const item of expected.values())if(item.data&&item.node.affected&&!cascade.has(item.node.key)&&item.node.dependencies.some(key=>cascade.has(key))){cascade.add(item.node.key);added=true;}}
   const needed=new Set(cascade),visit=(key:string):void=>{const item=expected.get(key);if(!item?.data)throw fail();for(const dep of item.node.dependencies)if(!needed.has(dep)){needed.add(dep);visit(dep);}};
   for(const key of cascade)visit(key);
   const wanted=[...expected.values()].filter(item=>needed.has(item.node.key)),actualIds=new Set(actual.nodes.map(node=>`${node.type}:${node.id}`));
   if(actual.nodes.length!==wanted.length||actual.nodes.some(node=>!wanted.some(item=>item.node.type===node.type&&item.id===node.id)))throw fail('ENTITY_RECYCLE_CURRENT_COLLECTION_DRIFT');
   for(const node of nodes.filter(node=>needed.has(node.key))){if(!actualIds.has(`${node.type}:${node.data.id}`))throw fail();const reflected=actual.nodes.find(item=>item.type===node.type&&item.id===node.data.id)!;
    const normalize=(raw:any)=>node.type==='certificates'?{...raw,snis:[...raw.snis].sort()}:raw;
    if(this.secrets.fingerprint(normalize(reflected.data))!==this.secrets.fingerprint(normalize(node.data)))throw fail();
   }
   closureHistory=actual.targetHistory??null;
   if(d.obligation.kind==='recycle-restore'&&root.node.type==='upstreams'){
    const restored=d.completed.filter(item=>item.packet.nativeType==='targets'&&item.packet.parentId===root.id).map(item=>item.response);
    const history=(actual.targetHistory??[]).find(item=>item.upstreamId===root.id)?.items??[];
    const normalize=(items:any[])=>[...items].sort((a,b)=>String(a.id).localeCompare(String(b.id)));
    if(this.secrets.fingerprint(normalize(history))!==this.secrets.fingerprint(normalize(restored)))throw fail('ENTITY_RECYCLE_TARGET_HISTORY_UNEXPLAINED');
   }
   // Full history is separately observed. Unexplained appends are rejected;
   // the provider never invents a zero-row UUID from a DELETE204 response.
   if(d.obligation.kind==='recycle-archive'&&root.node.type==='upstreams'){
    const removed=new Set(d.completed.filter(item=>item.packet.nativeType==='targets').map(item=>item.packet.nativeId));
    const desired=(d.obligation.graph.targetHistory??[]).map(history=>({...history,items:history.items.filter(item=>!removed.has(item.id))}));
    const normalize=(value:any[])=>value.map(item=>({upstreamId:item.upstreamId,items:[...item.items].sort((a,b)=>String(a.id).localeCompare(String(b.id)))})).sort((a,b)=>a.upstreamId.localeCompare(b.upstreamId));
    if(this.secrets.fingerprint(normalize(actual.targetHistory??[]))!==this.secrets.fingerprint(normalize(desired)))throw fail('ENTITY_RECYCLE_TARGET_HISTORY_UNEXPLAINED');
   }
  }
  let targetEof:unknown=null;
  const target=current.node.type==='targets'?current:originalRoot.node.type==='targets'?originalRoot:null;
  if(target){
   const parentId=parent(target.node);if(!parentId)throw fail();
   targetEof=await this.context.runInternalRead(d.source.clusterId,'capture',async()=>{
    const active=await currentEffectiveTarget(this.kong,d.source.clusterId,parentId,target.node.data.target);
    if(target.data?active.target?.id!==target.id:active.target!==null)throw fail('ENTITY_RECYCLE_TARGET_EFFECTIVE_CHANGED');
    const history:any[]=[];let cursor:string|undefined;const seen=new Set<string>();
    for(let page=0;page<100;page++){
     const response=await this.kong.list(d.source.clusterId,`/upstreams/${parentId}/targets/all`,{size:100},cursor);
     history.push(...response.items);if(history.length>10000||Buffer.byteLength(JSON.stringify(history))>16*1024*1024)throw fail('ENTITY_RECYCLE_TARGET_OBSERVATION_LIMIT');
     if(!response.nextCursor){
      if(d.obligation.kind==='recycle-restore'&&originalRoot.node.type==='upstreams'){
       const restored=d.completed.filter(item=>item.packet.nativeType==='targets'&&item.packet.parentId===parentId).map(item=>item.response);
       const sorted=(items:any[])=>[...items].sort((a,b)=>String(a.id).localeCompare(String(b.id)));
       if(this.secrets.fingerprint(sorted(history))!==this.secrets.fingerprint(sorted(restored)))throw fail('ENTITY_RECYCLE_TARGET_HISTORY_UNEXPLAINED');
      }
      return{effective:active.target,history};
     }if(seen.has(response.nextCursor))throw fail();seen.add(response.nextCursor);cursor=response.nextCursor;
    }throw fail('ENTITY_RECYCLE_TARGET_OBSERVATION_LIMIT');
   },{paths:[`/upstreams/${parentId}/targets`,`/upstreams/${parentId}/targets/all`],maxPages:100,maxRecords:10000,maxBytes:16*1024*1024,workspaceId:d.source.workspaceId});
   this.live(original,frame,expiry);
  }
  return immutableJson({nodes:nodes.sort((a,b)=>a.key.localeCompare(b.key)),absent:absent.sort(),wholeGraphObserved:!!closure?.data,closureHistory,targetEof});
 }
 async observe(original:object,phase:'before-native'|'after-native'):Promise<Handle>{
  if(phase!=='before-native'&&phase!=='after-native')throw fail('ENTITY_RECYCLE_CURRENT_PHASE_INVALID');
  const policy=this.installed(),frame=this.context.current(),start=new Date().toISOString(),descriptor=await policy.describe(original,phase),expiry=Date.parse(descriptor.source.expiresAt),identity=this.secrets.fingerprint(descriptor);
  this.live(original,frame,expiry);const first=await this.round(descriptor,original,frame,expiry,phase),second=await this.round(descriptor,original,frame,expiry,phase);
  if(this.secrets.fingerprint(first)!==this.secrets.fingerprint(second))throw fail('ENTITY_RECYCLE_CURRENT_ROUNDS_CHANGED');
  const closing=await policy.describe(original,phase);this.live(original,frame,expiry);if(this.secrets.fingerprint(closing)!==identity)throw fail();
  const handle=Object.freeze({}) as Handle,until=new Date().toISOString(),value=immutableJson({descriptor,phase,wholeGraphObserved:second.wholeGraphObserved,monotonicDeadline:performance.now()+5000,nodes:second.nodes,absent:second.absent,observationHmac:this.secrets.fingerprint(second),observedFrom:start,observedUntil:until,
   configurationVerification:'verified' as const,functionalVerification:'pending' as const});
  this.witnesses.set(handle,{active:true,original,phase,frame,identityHmac:identity,expiresAt:Math.min(expiry,Date.now()+5000),value});return handle;
 }
 resolve(handle:Handle):Readonly<EntityRecycleCurrentWitness>{const state=this.witnesses.get(handle);if(!state?.active)throw fail('ENTITY_RECYCLE_CURRENT_WITNESS_REQUIRED');this.live(state.original,state.frame,state.expiresAt);if(performance.now()>=state.value.monotonicDeadline)throw fail('ENTITY_RECYCLE_CURRENT_ORIGINAL_EXPIRED');return state.value;}
 close(handle:Handle):void{const state=this.witnesses.get(handle);if(state)state.active=false;this.witnesses.delete(handle);}
}
