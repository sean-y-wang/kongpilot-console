import { EntityRecycleCurrentWitnessService } from './entity-recycle-current-witness.service';
import type { EntityRecycleCurrentDescriptor, EntityRecycleOriginalCompletion, EntityRecycleCurrentWitnessHandle } from './entity-recycle-current-witness.types';
import { ConflictException, ForbiddenException, Injectable, OnModuleInit, Optional, ServiceUnavailableException } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import { DbService } from '../../infrastructure/db.service';
import { SecretService } from '../../infrastructure/secret.service';
import { immutableJson } from '../../infrastructure/kong/immutable-json';
import { KongExecutionContextService } from '../../infrastructure/kong/execution-context.service';
import { NativeKongPolicyService } from '../authorization/native-kong-policy.service';
import { AuditService } from '../audit/audit.service';
import type { EntityChangeRecycleArchiveInput, EntityChangeRecycleNativeInput } from '../authorization/entity-change-recycle-native-policy.types';
import type { PreparedEntityChange, EntityChangePacket } from '../entities/entity-change.types';
import type { EntityChangeExecutionSource } from '../workflows/entity-change-intent.types';
import { EntityChangeRecycleFactsService } from './entity-change-recycle-facts.service';
import type { EntityChangeRecycleArchiveFactsInput, EntityChangeRecycleCompletionFactsInput, EntityChangeRecycleRestoreFactsInput, EntityChangeRecycleDeleteVerification } from './entity-change-recycle-facts.types';
import { EntityPreparedRecycleWriterService, derivePreparedRecyclePackets, preparedRecycleNodeManifest } from './entity-prepared-recycle-writer.service';
import type { EntityPreparedRecycleArchiveGrant, EntityPreparedRecycleArchiveHandle, EntityPreparedRecycleArchiveReceipt,
  EntityPreparedRecyclePacketGrant, EntityPreparedRecyclePacketHandle, EntityPreparedRecyclePacketReceipt, PreparedRecycleObligation } from './entity-prepared-recycle-writer.types';
import { EntityRecycleOriginReaderService } from './entity-recycle-origin-reader.service';
import { RecycleService } from './recycle.service';
import type { EntityChangeRecycleKernelBridge, EntityRecycleExecutionInspection, EntityRecyclePacketInspection } from './entity-change-recycle-execution.types';

const uuid=/^[a-f\d]{8}-[a-f\d]{4}-[1-8][a-f\d]{3}-[89ab][a-f\d]{3}-[a-f\d]{12}$/i;
const denied=(code='ENTITY_RECYCLE_EXECUTION_INVALID')=>new ForbiddenException({code});
const unavailable=()=>new ServiceUnavailableException({code:'ENTITY_RECYCLE_EXECUTION_UNAVAILABLE'});
type FixedPlan=ReturnType<typeof derivePreparedRecyclePackets>;
interface ArchiveState { execution:ExecutionState; obligation:PreparedRecycleObligation; packets:readonly EntityChangePacket[]; plan:FixedPlan; entryId:string;
  handle?:EntityPreparedRecycleArchiveHandle; grant?:EntityPreparedRecycleArchiveGrant; running:boolean; consumed:boolean; receipt?:EntityPreparedRecycleArchiveReceipt; }
interface ExecutionState { original:object; inspection:Readonly<EntityRecycleExecutionInspection>; hmac:string; archives:ArchiveState[];
  byPacket:Map<string,ArchiveState>; completed:Set<string>; completedOriginals:Map<string,Readonly<EntityRecycleOriginalCompletion>>; status:'preparing'|'ready'|'failed'|'closed'; timer?:ReturnType<typeof setTimeout>; }
interface PacketState { original:object; local:EntityPreparedRecyclePacketHandle; execution:ExecutionState; archive:ArchiveState; grant:Readonly<EntityPreparedRecyclePacketGrant>;
  identityHmac:string; active:boolean; running:boolean; consumed:boolean; deleteEntered:boolean; readEntered:boolean; operationId?:string; verification?:EntityChangeRecycleDeleteVerification; originalCompletion?:Readonly<EntityRecycleOriginalCompletion>; }
type FactProof={kind:'archive';archive:ArchiveState;hmac:string}|{kind:'restore';archive:ArchiveState;hmac:string}|{kind:'completion';packet:PacketState;hmac:string};

/** A fixed server coordinator. Original Root handles never escape into a DTO;
 * local writer/proof handles live only in private WeakMaps. Public supports is
 * structural validation, not SQL readiness or native authority. Repair is
 * deliberately closed until a distinct original-result recovery issuer exists. */
@Injectable()
export class EntityChangeRecycleExecutionService implements OnModuleInit {
  private bridge?:Readonly<EntityChangeRecycleKernelBridge>;
  private ready=false;
  private readonly executions=new WeakMap<object,ExecutionState>();
  private readonly sources=new Map<string,ExecutionState>();
  private readonly archiveHandles=new WeakMap<object,ArchiveState>();
  private readonly packetHandles=new WeakMap<object,PacketState>();
  private readonly originalPackets=new WeakMap<object,PacketState>();
  private readonly usedPackets=new WeakSet<object>();
  private readonly proofs=new WeakMap<object,FactProof>();
  private readonly verifications=new WeakMap<object,{identityHmac:string;proof:EntityChangeRecycleDeleteVerification}>();
  constructor(private readonly writer:EntityPreparedRecycleWriterService,private readonly facts:EntityChangeRecycleFactsService,
    private readonly reader:EntityRecycleOriginReaderService,private readonly native:NativeKongPolicyService,private readonly recycle:RecycleService,
    private readonly db:DbService,private readonly secrets:SecretService,private readonly context:KongExecutionContextService,private readonly audit:AuditService,@Optional() private readonly current?:EntityRecycleCurrentWitnessService){}

  installKernelBridge(bridge:EntityChangeRecycleKernelBridge):void{
    const methods=['execution','packet','verifyExecution','verifyPacket','appendKnownOutcome','observeTargetDeletePoststate','assertCurrentOriginScope','assertFrozenOriginSubject','assertCurrentGraphParties'] as const;
    if(this.bridge||!bridge||methods.some(method=>typeof bridge[method]!=='function')||bridge.activeRestoreRevalidation!==undefined&&typeof bridge.activeRestoreRevalidation!=='function'
      ||bridge.verifyPartialRestoreFacts!==undefined&&typeof bridge.verifyPartialRestoreFacts!=='function'
      ||bridge.verifyPartialRestoreCurrent!==undefined&&typeof bridge.verifyPartialRestoreCurrent!=='function')throw denied('ENTITY_RECYCLE_BRIDGE_INVALID');
    this.bridge=Object.freeze({...Object.fromEntries(methods.map(method=>[method,bridge[method].bind(bridge)])),
      ...(bridge.activeRestoreRevalidation?{activeRestoreRevalidation:bridge.activeRestoreRevalidation.bind(bridge)}:{}),
      ...(bridge.verifyPartialRestoreFacts?{verifyPartialRestoreFacts:bridge.verifyPartialRestoreFacts.bind(bridge)}:{}),
      ...(bridge.verifyPartialRestoreCurrent?{verifyPartialRestoreCurrent:bridge.verifyPartialRestoreCurrent.bind(bridge)}:{})}) as unknown as Readonly<EntityChangeRecycleKernelBridge>;
  }
  onModuleInit():void{
    // Nest/bootstrap ordering may present the coordinator before Root's fixed
    // bridge. Keeping every adapter closed allows Root to initialize it later.
    if(!this.bridge||this.ready||!this.current)return;
    this.current.installFixedDelegate({describe:(original,phase)=>this.currentDescriptor(original,phase),assertLive:original=>this.currentLive(original)});
    this.writer.installExecutionDelegate({runArchive:(handle,store)=>this.runArchive(handle,store),runPacket:(handle,write)=>this.runPacket(handle,write),
      runRepair:async()=>{throw unavailable();},linkArchive:(handle,receipt,tx)=>this.linkArchive(handle,receipt,tx),
      runVerifiedDelete:(handle,operationId,send)=>this.runDelete(handle,operationId,send),runVerificationRead:(handle,operationId,read)=>this.runVerification(handle,operationId,read),
      recordTargetDeletePoststate:(handle,observation)=>{const state=this.packetState(handle);this.kernel().observeTargetDeletePoststate(state.original,observation);},
      linkNodeReceipt:(handle,receipt,tx)=>this.linkNode(handle,receipt,tx),verifyCurrentRestore:(handle,operationId,result)=>this.verifyCurrentRestore(handle,operationId,result)});
    this.facts.installFixedDelegate({verifyArchive:(input,proof,tx)=>this.verifyFact('archive',input,proof,tx),verifyRestore:(input,proof,tx)=>this.verifyFact('restore',input,proof,tx),
      verifyCompletion:(input,proof,tx)=>this.verifyFact('completion',input,proof,tx)});
    this.native.installEntityChangeRecyclePolicy({assertDeleteArchive:input=>this.assertNativeArchive(input,'DELETE'),resolveRestoreArchive:input=>this.resolveRestore(input),
      assertRestoreArchive:input=>this.assertNativeArchive(input,'POST'),assertCurrentBeforeSend:async input=>{
      const state=await this.nativeState(input,input.operation.action==='delete'?'DELETE':'POST');await this.verifyCurrentWitness(state,'before-native');
    }});
    this.reader.installFixedDelegate({assertCurrentScope:(input,tx)=>this.kernel().assertCurrentOriginScope(input,tx),assertFrozenSubject:(input,tx)=>this.kernel().assertFrozenOriginSubject(input,tx),
      activeRestoreRevalidation:(input,tx)=>this.kernel().activeRestoreRevalidation?.(input,tx)??Promise.resolve(null)});
    this.recycle.installEntityOriginLookup({readClosedOrigin:input=>{this.kernel();return this.reader.readClosedOrigin(input);}});
    this.ready=true;
  }
  private kernel():Readonly<EntityChangeRecycleKernelBridge>{if(!this.ready||!this.bridge)throw unavailable();return this.bridge;}
  private same(value:unknown,expected:unknown):void{if(this.secrets.fingerprint(value)!==this.secrets.fingerprint(expected))throw denied();}
  private original(handle:object):void{if(!handle||typeof handle!=='object'||Array.isArray(handle))throw denied();}
  private plans(prepared:PreparedEntityChange):Array<{obligation:PreparedRecycleObligation;packets:readonly EntityChangePacket[];plan:FixedPlan}>{
    if(!prepared||prepared.version!==1||!Array.isArray(prepared.packets)||!prepared.packets.length||!Array.isArray(prepared.metadataObligations))throw denied();
    const seen=new Set<string>(),result:Array<{obligation:PreparedRecycleObligation;packets:readonly EntityChangePacket[];plan:FixedPlan}>=[];
    for(const value of prepared.metadataObligations){if(value.kind!=='recycle-archive'&&value.kind!=='recycle-restore')continue;
      const packets=prepared.packets.filter(packet=>value.packetKeys.includes(packet.key)),plan=derivePreparedRecyclePackets(value,packets,this.secrets);
      if(value.kind==='recycle-restore'&&(!value.sealedEntry||value.sealedEntry.entryId!==value.entryId||value.sealedEntry.payloadHmac!==value.graphHmac))throw denied();
      for(const packet of packets){if(seen.has(packet.key))throw denied();seen.add(packet.key);}
      result.push({obligation:value,packets,plan});}
    if(!result.length||prepared.packets.some(packet=>(packet.method==='DELETE'||packet.mutationAction==='restore')&&!seen.has(packet.key)))throw denied();
    return result;
  }
  supports(prepared:PreparedEntityChange):boolean{try{if(!this.current||!this.bridge?.assertCurrentGraphParties)return false;this.plans(prepared);
    if(prepared.metadataObligations.some(o=>o.kind==='recycle-restore'&&o.partialRestore)&&!this.bridge?.verifyPartialRestoreFacts)return false;
    return true;}catch{return false;}}
  private base(input:EntityRecycleExecutionInspection):EntityRecycleExecutionInspection{return{source:input.source,baseline:input.baseline,actor:input.actor,prepared:input.prepared};}
  private packetIdentity(input:EntityRecyclePacketInspection):unknown{return{...this.base(input),packet:input.packet,binding:input.binding,operationKey:input.operationKey};}
  private async inspectExecution(state:ExecutionState,checkpoint:string,tx?:DbService):Promise<Readonly<EntityRecycleExecutionInspection>>{
    const bridge=this.kernel();await bridge.verifyExecution(state.original,checkpoint,tx);const value=bridge.execution(state.original);
    if(this.secrets.fingerprint(this.base(value))!==state.hmac)throw denied('ENTITY_RECYCLE_EXECUTION_CHANGED');
    await this.partialCurrent(state,'capture',tx);return value;
  }
  private async partialCurrent(state:ExecutionState,checkpoint:'capture'|'packet'|'before-send'|'outcome',tx?:DbService,currentResponse=false):Promise<void>{
    if(!state.inspection.prepared.metadataObligations.some(o=>o.kind==='recycle-restore'&&o.partialRestore))return;
    const verify=this.kernel().verifyPartialRestoreFacts;
    if(!verify)throw unavailable();await verify(state.original,currentResponse&&checkpoint!=='outcome'?'current-response':checkpoint,tx);
  }
  private async inspectPacket(state:PacketState,checkpoint:string,tx?:DbService):Promise<Readonly<EntityRecyclePacketInspection>>{
    if(!state.active)throw denied();const bridge=this.kernel();await bridge.verifyPacket(state.original,checkpoint,tx);const value=bridge.packet(state.original);
    if(this.secrets.fingerprint(this.packetIdentity(value))!==state.identityHmac||value.operationId!==undefined&&state.operationId!==undefined&&value.operationId!==state.operationId)throw denied('ENTITY_RECYCLE_PACKET_CHANGED');
    if(value.operationId!==undefined){if(!uuid.test(value.operationId))throw denied();state.operationId=value.operationId;}
    await this.partialCurrent(state.execution,checkpoint==='before-send'?'before-send':checkpoint==='outcome'?'outcome':'packet',tx,value.wireSpent&&value.transportStatus===201);return value;
  }
  private releaseState(state:ExecutionState):void{if(this.sources.get(state.inspection.source.id)===state)this.sources.delete(state.inspection.source.id);if(state.timer)clearTimeout(state.timer);}
  /** Cleanup only. Removing a private source cannot authorize anything. */
  release(originalExecutionHandle:object):void{const state=this.executions.get(originalExecutionHandle);if(state){state.status='closed';this.releaseState(state);}}
  /** Historical real observation only, retained through metadata rollback for
   * Root's truthful immutable outcome. This neither refreshes a SID nor mints
   * a packet, archive or transport permit. */
  verification(originalPacketHandle:object):EntityChangeRecycleDeleteVerification|undefined{
    const inspection=this.kernel().packet(originalPacketHandle),held=this.verifications.get(originalPacketHandle);if(!held)return undefined;
    if(this.secrets.fingerprint(this.packetIdentity(inspection))!==held.identityHmac||inspection.operationId!==held.proof.operationId
      ||!inspection.sent||!inspection.wireSpent||inspection.transportStatus!==204||inspection.transportHmac!==this.secrets.fingerprint(null)
      ||inspection.responseHmac!==inspection.transportHmac)throw denied();
    if(held.proof.status==='target-poststate'){
      const post=inspection.targetPoststate;
      if(!post||held.proof.kind!=='target-poststate'||post.originalNativeId!==held.proof.nativeId||post.address!==held.proof.address
        ||post.historyRetention!==held.proof.historyRetention||post.observationHmac!==held.proof.observationHmac
        ||post.archiveGraphHmac!==held.proof.archiveGraphHmac||inspection.verificationStatus!==undefined)throw denied();
    }else if(inspection.verificationStatus!==404||inspection.verificationPath!==held.proof.canonicalPath||inspection.targetPoststate)throw denied();
    return held.proof;
  }
  async prepare(originalExecutionHandle:object):Promise<void>{
    this.original(originalExecutionHandle);const bridge=this.kernel();if(this.executions.has(originalExecutionHandle))throw new ConflictException({code:'ENTITY_RECYCLE_PREPARATION_ALREADY_ATTEMPTED'});
    await bridge.verifyExecution(originalExecutionHandle,'capture');const inspection=immutableJson(this.base(bridge.execution(originalExecutionHandle)));
    if(inspection.source.sessionId===null||inspection.baseline.sourceId!==inspection.source.id||inspection.actor.user.id!==inspection.source.executionActorId
      ||inspection.actor.workspaceId!==inspection.source.workspaceId)throw denied();
    if(inspection.prepared.metadataObligations.some(o=>o.kind==='recycle-restore'&&o.partialRestore)&&!this.bridge?.verifyPartialRestoreFacts)throw denied('ENTITY_RECYCLE_PARTIAL_CURRENT_ADAPTER_REQUIRED');
    const plans=this.plans(inspection.prepared),state:ExecutionState={original:originalExecutionHandle,inspection,hmac:this.secrets.fingerprint(inspection),archives:[],byPacket:new Map(),completed:new Set(),completedOriginals:new Map(),status:'preparing'};
    if(this.sources.has(inspection.source.id))throw denied('ENTITY_RECYCLE_SOURCE_ALREADY_BOUND');this.executions.set(originalExecutionHandle,state);this.sources.set(inspection.source.id,state);
    try{
      const days=Number(process.env.RECYCLE_RETENTION_DAYS??30);if(!Number.isInteger(days)||days<1||days>3650)throw unavailable();
      for(const value of plans){await this.inspectExecution(state,'capture');const archive:ArchiveState={...value,execution:state,entryId:value.obligation.kind==='recycle-archive'?randomUUID():value.obligation.entryId,running:false,consumed:false};state.archives.push(archive);
        for(const packet of value.packets)state.byPacket.set(packet.key,archive);
        if(value.obligation.kind==='recycle-archive'){
          const handle=Object.freeze({}) as EntityPreparedRecycleArchiveHandle;archive.handle=handle;archive.grant=immutableJson({source:inspection.source as EntityChangeExecutionSource,baseline:inspection.baseline,actor:inspection.actor,
            entryId:archive.entryId,expiresAt:new Date(Date.now()+days*86400000).toISOString(),obligation:value.obligation,packets:value.packets});this.archiveHandles.set(handle,archive);
          try{archive.receipt=await this.writer.archive(handle);}finally{this.archiveHandles.delete(handle);}
        }else{
          const input:EntityChangeRecycleRestoreFactsInput=immutableJson({source:inspection.source,baseline:inspection.baseline,actor:inspection.actor,entryId:archive.entryId,obligation:value.obligation,packets:value.packets});
          const proof=Object.freeze({});this.proofs.set(proof,{kind:'restore',archive,hmac:this.secrets.fingerprint(input)});
          try{await this.facts.bindRestore(input,proof);}finally{this.proofs.delete(proof);}archive.consumed=true;
        }
        await this.inspectExecution(state,'capture');}
      state.status='ready';const delay=Math.max(1,Date.parse(inspection.source.expiresAt)-Date.now());state.timer=setTimeout(()=>this.releaseState(state),delay);state.timer.unref?.();
    }catch(error){state.status='failed';this.releaseState(state);throw error;}
  }
  private archiveState(handle:object):ArchiveState{this.kernel();const state=this.archiveHandles.get(handle);if(!state||state.execution.status!=='preparing'||!state.grant)throw denied();return state;}
  private packetState(handle:object):PacketState{this.kernel();const state=this.packetHandles.get(handle);if(!state||!state.active)throw denied();return state;}
  private async runArchive<T>(handle:object,store:(grant:Readonly<EntityPreparedRecycleArchiveGrant>)=>Promise<T>):Promise<T>{
    const state=this.archiveState(handle);if(state.running||state.consumed)throw denied();state.running=true;state.consumed=true;
    try{await this.inspectExecution(state.execution,'capture');return await store(state.grant!);}finally{state.running=false;}
  }
  private async linkArchive(handle:object,receipt:Readonly<EntityPreparedRecycleArchiveReceipt>,tx:DbService):Promise<void>{
    const state=this.archiveState(handle);if(!state.running)throw denied();const input:EntityChangeRecycleArchiveFactsInput=immutableJson({grant:state.grant!,receipt});
    const proof=Object.freeze({});this.proofs.set(proof,{kind:'archive',archive:state,hmac:this.secrets.fingerprint(input)});
    try{await this.facts.persistArchive(input,proof,tx);}finally{this.proofs.delete(proof);}
  }
  private async verifyFact(kind:FactProof['kind'],input:EntityChangeRecycleArchiveFactsInput|EntityChangeRecycleRestoreFactsInput|EntityChangeRecycleCompletionFactsInput,proof:object,tx:DbService):Promise<void>{
    const bound=this.proofs.get(proof);if(!bound||bound.kind!==kind||bound.hmac!==this.secrets.fingerprint(input))throw denied('ENTITY_RECYCLE_FACT_PROOF_INVALID');
    if(bound.kind==='completion'){
      const inspection=await this.inspectPacket(bound.packet,'outcome',tx);await this.assertStored(bound.packet.archive,tx);
      if(!inspection.sent||!inspection.wireSpent||inspection.operationId!==(input as EntityChangeRecycleCompletionFactsInput).receipt.operationId
        ||inspection.responseHmac!==this.secrets.fingerprint((input as EntityChangeRecycleCompletionFactsInput).nativeResult)||inspection.transportHmac!==inspection.responseHmac)throw denied();
      if(bound.packet.grant.packet.method==='DELETE')this.same((input as EntityChangeRecycleCompletionFactsInput).deleteVerification,bound.packet.verification);
    }else{await this.inspectExecution(bound.archive.execution,'capture',tx);}
    if(this.proofs.get(proof)!==bound||bound.hmac!==this.secrets.fingerprint(input))throw denied();
  }
  async execute(originalPacketHandle:object):Promise<EntityPreparedRecyclePacketReceipt>{
    this.original(originalPacketHandle);const bridge=this.kernel();if(this.usedPackets.has(originalPacketHandle))throw denied('ENTITY_RECYCLE_PACKET_ALREADY_ATTEMPTED');
    await bridge.verifyPacket(originalPacketHandle,'packet');const inspection=immutableJson(bridge.packet(originalPacketHandle)),execution=this.sources.get(inspection.source.id),archive=execution?.byPacket.get(inspection.packet.key);
    if(!execution||execution.status!=='ready'||!archive||inspection.source.sessionId===null||execution.completed.has(inspection.packet.key)||inspection.operationId!==undefined||inspection.sent||inspection.wireSpent)throw denied();
    this.same(this.base(inspection),execution.inspection);const selected=archive.plan.find(item=>item.packet.key===inspection.packet.key);if(!selected)throw denied();this.same(inspection.packet,selected.packet);
    if(inspection.binding.sourceId!==inspection.source.id||inspection.binding.baselineId!==inspection.baseline.baselineId||inspection.binding.pinId!==inspection.baseline.pinId||inspection.binding.packetKey!==inspection.packet.key
      ||!uuid.test(inspection.binding.attemptId)||inspection.operationKey!==`entity-${inspection.source.workflowExecutionId}-${inspection.packet.order}`)throw denied();
    const local=Object.freeze({}) as EntityPreparedRecyclePacketHandle,grant=immutableJson({source:inspection.source as EntityChangeExecutionSource,baseline:inspection.baseline,actor:inspection.actor,
      entryId:archive.entryId,nodeKey:selected.node.key,operationKey:inspection.operationKey,packet:inspection.packet,obligation:archive.obligation,packets:archive.packets});
    const state:PacketState={original:originalPacketHandle,local,execution,archive,grant,identityHmac:this.secrets.fingerprint(this.packetIdentity(inspection)),active:true,running:false,consumed:false,deleteEntered:false,readEntered:false};
    this.usedPackets.add(originalPacketHandle);this.packetHandles.set(local,state);this.originalPackets.set(originalPacketHandle,state);
    try{const result=await this.context.runEntityChangePacket(originalPacketHandle,()=>this.writer.execute(local));
      if(!state.originalCompletion||state.originalCompletion.packet.key!==inspection.packet.key)throw denied('ENTITY_RECYCLE_ORIGINAL_COMPLETION_REQUIRED');
      execution.completedOriginals.set(`${archive.entryId}:${selected.node.key}`,state.originalCompletion);execution.completed.add(inspection.packet.key);
      if(execution.completed.size===execution.byPacket.size)this.releaseState(execution);return result;
    }catch(error){this.releaseState(execution);throw error;}finally{state.active=false;this.packetHandles.delete(local);this.originalPackets.delete(originalPacketHandle);}
  }
  private async runPacket<T>(handle:object,write:(grant:Readonly<EntityPreparedRecyclePacketGrant>)=>Promise<T>):Promise<T>{
    const state=this.packetState(handle);if(state.running||state.consumed)throw denied();state.running=true;state.consumed=true;
    try{await this.inspectPacket(state,'packet');await this.assertStored(state.archive);return await write(state.grant);}finally{state.running=false;}
  }
  /** Root calls only after the first packet's genuine baseline revalidation
   * and original operation binding, inside the actual mutation INSERT tx.
   * Transitioning a protected archive records metadata, never a send permit. */
  async bindPacketOperation(originalPacketHandle:object,operationId:string,tx:DbService):Promise<void>{
    this.original(originalPacketHandle);if(!tx||!uuid.test(operationId))throw denied();
    const state=this.originalPackets.get(originalPacketHandle);if(!state?.active||!state.running||state.execution.status!=='ready')throw denied();
    const inspection=await this.inspectPacket(state,'before-send',tx),s=inspection.source,p=inspection.packet;
    if(inspection.operationId!==operationId||inspection.sent||inspection.wireSpent||state.operationId!==operationId)throw denied();
    await tx.exec("SELECT pg_advisory_xact_lock(hashtextextended('entity-change-recycle-entry:'||$1,0))",[state.archive.entryId]);
    await this.assertStored(state.archive,tx);
    const operation=await tx.one<any>('SELECT * FROM mutation_operations WHERE id=$1',[operationId]);
    if(!operation||operation.id!==operationId||operation.state!=='running'||operation.remote_started!==false||operation.remote_completed!==false||operation.result_secret!==null
      ||operation.cluster_id!==s.clusterId||operation.workspace_id!==s.workspaceId||operation.actor_id!==s.executionActorId||operation.workflow_id!==s.workflowId
      ||operation.entity_change_source_id!==s.id||operation.entity_change_baseline_id!==inspection.baseline.baselineId||operation.entity_change_attempt_id!==inspection.binding.attemptId
      ||operation.entity_change_packet_key!==p.key||operation.entity_id!==p.nativeId||operation.entity_type!==(p.credentialKind?'credentials':p.nativeType)
      ||operation.action!==p.mutationAction||operation.idempotency_key!==inspection.operationKey||(operation.parent_id??null)!==(p.parentId??null)||(operation.credential_kind??null)!==(p.credentialKind??null)
      ||typeof operation.before_secret!=='string'||typeof operation.payload_secret!=='string'
      ||['workflow_execution_id','workflow_plan_revision','workflow_plan_hash','workflow_step_id','configuration_job_id','configuration_execution_id','configuration_step_id','configuration_plan_revision','configuration_plan_hash'].some(field=>operation[field]!=null))throw denied('ENTITY_RECYCLE_OPERATION_BINDING_INVALID');
    this.same(this.secrets.decrypt(operation.before_secret,`mutation:${operationId}:before`),p.before);
    this.same(this.secrets.decrypt(operation.payload_secret,`mutation:${operationId}:payload`),p.body??null);
    if(state.archive.obligation.kind==='recycle-restore'){
      const entry=await tx.one<any>('SELECT * FROM recycle_entries WHERE cluster_id=$1 AND workspace_id=$2 AND id=$3',[s.clusterId,s.workspaceId,state.archive.entryId]);
      if(!entry||!['deleted','partially_deleted','restoring',...(state.archive.obligation.partialRestore?['partially_restored']:[])].includes(entry.state)||entry.mutation_id!==null)throw denied();
      if(entry.state!=='restoring'){
        const changed=await tx.exec("UPDATE recycle_entries SET state='restoring',updated_at=now() WHERE cluster_id=$1 AND workspace_id=$2 AND id=$3 AND state=$4 AND mutation_id IS NULL",
          [s.clusterId,s.workspaceId,state.archive.entryId,entry.state]);if(changed!==1)throw denied('ENTITY_RECYCLE_STATE_CHANGED');
        await this.audit.append({actorId:s.executionActorId,clusterId:s.clusterId,workspaceId:s.workspaceId,entityType:'recycle_entries',entityId:state.archive.entryId,
          action:'restore.started',before:{state:entry.state},after:{state:'restoring',sourceId:s.id,baselineId:inspection.baseline.baselineId,packetKey:p.key,operationId},
          result:'pending',workflowId:s.workflowId,requestId:inspection.actor.requestId,ip:inspection.actor.ip},tx);
      }
    }else if(p.method!=='DELETE')throw denied();
    const after=await this.inspectPacket(state,'before-send',tx);if(after.operationId!==operationId||after.sent||after.wireSpent)throw denied();
    await this.assertStored(state.archive,tx);
  }
  private async runDelete<T>(handle:object,operationId:string,send:()=>Promise<T>):Promise<T>{
    const state=this.packetState(handle),inspection=await this.inspectPacket(state,'before-send');
    if(!state.running||state.deleteEntered||state.grant.packet.method!=='DELETE'||inspection.operationId!==operationId||inspection.sent||inspection.wireSpent)throw denied();
    state.deleteEntered=true;await this.assertStored(state.archive);const node=state.archive.plan.find(item=>item.packet.key===state.grant.packet.key)!.node;
    return this.context.runArchiveDelete({entryId:state.archive.entryId,operationId,clusterId:inspection.source.clusterId,workspaceId:inspection.source.workspaceId,
      nodes:[{path:node.path,type:node.type,id:node.id}]},send);
  }
  private async runVerification<T>(handle:object,operationId:string,read:()=>Promise<T>):Promise<T>{
    const state=this.packetState(handle),inspection=await this.inspectPacket(state,'outcome');
    if(!state.running||!state.deleteEntered||state.readEntered||state.grant.packet.method!=='DELETE'||inspection.operationId!==operationId||!inspection.sent||!inspection.wireSpent
      ||inspection.transportStatus!==204||inspection.transportHmac!==this.secrets.fingerprint(null)||inspection.responseHmac!==inspection.transportHmac)throw denied();
    state.readEntered=true;const node=state.archive.plan.find(item=>item.packet.key===state.grant.packet.key)!.node;
    const parentId=state.grant.packet.parentId;
    const targetPaths=node.type==='targets'&&typeof parentId==='string'
      ?[node.path,`/upstreams/${parentId}/targets`,`/upstreams/${parentId}/targets/all`]:[node.path];
    const budget=node.type==='targets'
      ?{paths:targetPaths,maxCalls:64,maxPages:40,maxRecords:4000,maxBytes:8*1024*1024,timeoutMs:60000,workspaceId:inspection.source.workspaceId}
      :{paths:[node.path],maxCalls:1,maxPages:1,maxRecords:1,maxBytes:1024*1024,timeoutMs:5000,workspaceId:inspection.source.workspaceId};
    const result=await this.context.runInternalRead(inspection.source.clusterId,'recycle-check',read,budget);
    const observed=await this.inspectPacket(state,'outcome');
    if(observed.operationId!==operationId)throw denied('ENTITY_RECYCLE_GET404_REQUIRED');
    if(node.type==='targets'){
      // Kong 1.5 Target DELETE is certified by archive-sealed dual list EOF
      // poststate, never by bare point GET404 on the historical id.
      const post=observed.targetPoststate;
      if(!post||post.originalNativeId!==node.id||observed.verificationStatus!==undefined)throw denied('ENTITY_RECYCLE_TARGET_POSTSTATE_REQUIRED');
      state.verification=immutableJson({version:1 as const,clusterId:inspection.source.clusterId,workspaceId:inspection.source.workspaceId,entryId:state.archive.entryId,nodeKey:node.key,
        packetKey:inspection.packet.key,attemptId:inspection.binding.attemptId,operationId,canonicalPath:node.path,nativeId:node.id,
        status:'target-poststate' as const,kind:'target-poststate' as const,historyRetention:post.historyRetention,
        observationHmac:post.observationHmac,archiveGraphHmac:post.archiveGraphHmac,address:post.address});
    }else{
      // No callback return/status-shaped DTO qualifies as a real GET404. Only
      // Root's genuine transport ticket observer records this exact point read.
      if(observed.verificationStatus!==404||observed.verificationPath!==node.path||observed.targetPoststate)throw denied('ENTITY_RECYCLE_GET404_REQUIRED');
      state.verification=immutableJson({version:1 as const,clusterId:inspection.source.clusterId,workspaceId:inspection.source.workspaceId,entryId:state.archive.entryId,nodeKey:node.key,
        packetKey:inspection.packet.key,attemptId:inspection.binding.attemptId,operationId,canonicalPath:node.path,nativeId:node.id,status:404 as const});
    }
    this.verifications.set(state.original,{identityHmac:state.identityHmac,proof:state.verification});
    return result;
  }
  private async linkNode(handle:object,receipt:Readonly<EntityPreparedRecyclePacketReceipt>,tx:DbService):Promise<void>{
    const state=this.packetState(handle),inspection=await this.inspectPacket(state,'outcome',tx);
    if(!state.running||!inspection.sent||!inspection.wireSpent||inspection.operationId!==receipt.operationId||inspection.responseHmac===undefined||inspection.transportHmac!==inspection.responseHmac
      ||!Number.isInteger(inspection.transportStatus)||inspection.transportStatus!<200||inspection.transportStatus!>299||state.grant.packet.method==='DELETE'&&!state.verification)throw denied();
    this.same(receipt,{entryId:state.archive.entryId,nodeKey:state.grant.nodeKey,packetKey:inspection.packet.key,operationKey:inspection.operationKey,operationId:inspection.operationId,nativeId:inspection.packet.nativeId,state:'succeeded',metadata:'complete'});
    const mutation=await tx.one<any>('SELECT * FROM mutation_operations WHERE id=$1',[inspection.operationId]);if(!mutation?.result_secret)throw denied();
    const raw=this.secrets.decrypt(mutation.result_secret,`mutation:${inspection.operationId}:result`);if(this.secrets.fingerprint(raw)!==inspection.responseHmac)throw denied();
    // Genuine Root observation and SQL21 outcome become visible in exactly
    // this transaction before SQL23 receipt and writer projection/audit.
    await this.kernel().appendKnownOutcome(state.original,state.verification,tx);
    const input:EntityChangeRecycleCompletionFactsInput=immutableJson({grant:state.grant,attempt:inspection.binding,receipt,nativeResult:raw,...(state.verification?{deleteVerification:state.verification}:{})});
    const proof=Object.freeze({});this.proofs.set(proof,{kind:'completion',packet:state,hmac:this.secrets.fingerprint(input)});
    try{await this.facts.linkNode(input,proof,tx);state.originalCompletion=immutableJson({nodeKey:state.grant.nodeKey,packet:state.grant.packet,operationId:receipt.operationId,responseHmac:inspection.responseHmac,response:raw,source:'committed-original-receipt' as const});}finally{this.proofs.delete(proof);}
  }
  private async assertStored(archive:ArchiveState,tx:DbService=this.db):Promise<void>{
    const execution=archive.execution.inspection,s=execution.source,graph=archive.obligation.graph,manifest=preparedRecycleNodeManifest(graph,this.secrets);
    const entry=await tx.one<any>('SELECT * FROM recycle_entries WHERE cluster_id=$1 AND workspace_id=$2 AND id=$3',[s.clusterId,s.workspaceId,archive.entryId]);
    const origin=await tx.one<any>('SELECT * FROM entity_change_recycle_archives WHERE cluster_id=$1 AND workspace_id=$2 AND entry_id=$3',[s.clusterId,s.workspaceId,archive.entryId]);
    if(!entry||entry.mutation_id!==null||entry.cluster_id!==s.clusterId||entry.workspace_id!==s.workspaceId||!entry.payload_secret||entry.state==='purged'||!origin||origin.cluster_id!==s.clusterId||origin.workspace_id!==s.workspaceId
      ||origin.graph_hmac!==archive.obligation.graphHmac||origin.payload_hmac!==archive.obligation.graphHmac||origin.node_manifest_hmac!==this.secrets.fingerprint(manifest)||origin.node_count!==manifest.length||origin.packet_count!==manifest.filter(node=>node.affected).length
      ||archive.obligation.kind==='recycle-archive'&&(origin.source_id!==s.id||origin.baseline_id!==execution.baseline.baselineId||origin.pin_id!==execution.baseline.pinId||origin.workflow_execution_id!==s.workflowExecutionId)
      ||archive.obligation.kind==='recycle-restore'&&origin.source_id===s.id)throw denied();
    this.same(this.secrets.decrypt(entry.payload_secret,`recycle:${archive.entryId}`),graph);this.same(origin.node_manifest,manifest);
    const nodes=await tx.query<any>('SELECT * FROM entity_change_recycle_nodes WHERE entry_id=$1 ORDER BY node_order',[archive.entryId]);
    if(nodes.some(node=>node.cluster_id!==s.clusterId||node.workspace_id!==s.workspaceId))throw denied();
    this.same(nodes.map(node=>({key:node.node_key,order:node.node_order,nativeType:node.native_type,nativeId:node.native_id,parentId:node.parent_id,credentialKind:node.credential_kind,affected:node.affected,
      dependencies:node.dependencies,pathHmac:node.path_hmac,dataHmac:node.data_hmac,restoreHmac:node.restore_hmac})),manifest);
    const legacy=await tx.query<any>('SELECT * FROM recycle_nodes WHERE entry_id=$1 ORDER BY node_key',[archive.entryId]);
    if(legacy.length!==manifest.length||manifest.some(node=>{const row=legacy.find(row=>row.node_key===node.key);return !row||row.entity_type!==node.nativeType||row.original_id!==node.nativeId||row.affected!==node.affected||this.secrets.fingerprint(row.dependencies)!==this.secrets.fingerprint(node.dependencies);}))throw denied();
    const packets=await tx.query<any>('SELECT * FROM entity_change_recycle_packets WHERE source_id=$1 AND entry_id=$2 ORDER BY packet_order',[s.id,archive.entryId]);
    if(packets.length!==archive.plan.length)throw denied();
    for(const [index,row]of packets.entries()){const {node,packet}=archive.plan[index];this.same({...row,created_at:null},{cluster_id:s.clusterId,workspace_id:s.workspaceId,source_id:s.id,baseline_id:execution.baseline.baselineId,pin_id:execution.baseline.pinId,workflow_execution_id:s.workflowExecutionId,
      entry_id:archive.entryId,node_key:node.key,direction:packet.method==='DELETE'?'delete':'restore',intent_id:s.intentId,intent_revision:s.intentRevision,material_hmac:s.materialHmac,change_digest:s.changeDigest,packet_manifest_hmac:s.packetManifestHmac,
      packet_key:packet.key,packet_order:packet.order,method:packet.method,path_hmac:this.secrets.fingerprint(packet.canonicalPath),native_type:packet.nativeType,native_id:packet.nativeId,parent_id:packet.parentId??null,credential_kind:packet.credentialKind??null,
      original_native_id:packet.originalNativeId??null,permission_action:packet.permissionAction,mutation_action:packet.mutationAction,body_hmac:packet.bodyHmac,before_hmac:packet.beforeHmac,created_at:null});}
    if(archive.obligation.kind==='recycle-restore'&&archive.obligation.partialRestore){
      await this.facts.assertPresentFacts({source:s,baseline:execution.baseline,actor:execution.actor,entryId:archive.entryId,obligation:archive.obligation,packets:archive.packets},tx);
    }
  }
  private async nativeState(input:Readonly<EntityChangeRecycleNativeInput>,method:'DELETE'|'POST'):Promise<PacketState>{
    const original=this.context.requireEntityChangePacketFrame(input.frame),state=this.originalPackets.get(original);if(!state||!state.active||!state.running)throw denied();
    const inspection=await this.inspectPacket(state,'before-send'),p=inspection.packet,m=input.operation;
    if(p.method!==method||p.canonicalPath!==input.canonicalPath||p.nativeType!==input.nativeType||(p.parentId??null)!==(input.parentId??null)||(p.credentialKind??null)!==(input.credentialKind??null)
      ||this.secrets.fingerprint(input.body??null)!==p.bodyHmac||inspection.operationId!==m.id||inspection.source.id!==m.entity_change_source_id||inspection.baseline.baselineId!==m.entity_change_baseline_id
      ||inspection.binding.attemptId!==m.entity_change_attempt_id||p.key!==m.entity_change_packet_key||inspection.source.clusterId!==m.cluster_id||inspection.source.workspaceId!==m.workspace_id
      ||inspection.source.executionActorId!==m.actor_id||inspection.source.workflowId!==m.workflow_id||p.nativeId!==m.entity_id||inspection.operationKey!==m.idempotency_key
      ||p.mutationAction!==m.action||m.state!=='running'||!m.remote_started||m.remote_completed||Object.prototype.hasOwnProperty.call(input.body??{},'entryId'))throw denied();
    this.same(this.secrets.decrypt(m.before_secret,`mutation:${m.id}:before`),p.before);this.same(this.secrets.decrypt(m.payload_secret,`mutation:${m.id}:payload`),p.body??null);
    await this.assertStored(state.archive);
    if(this.context.requireEntityChangePacketFrame(input.frame)!==original)throw denied();return state;
  }
  private currentLive(original:object):PacketState{
    const state=this.originalPackets.get(original);
    if(!state?.active||!state.running||state.execution.status!=='ready'||this.sources.get(state.grant.source.id)!==state.execution
      ||Date.parse(state.grant.source.expiresAt)<=Date.now()||this.context.requireEntityChangePacketFrame(this.context.current())!==original)throw denied('ENTITY_RECYCLE_CURRENT_ORIGINAL_REQUIRED');
    return state;
  }
  private async currentDescriptor(original:object,phase:'before-native'|'after-native'):Promise<Readonly<EntityRecycleCurrentDescriptor>>{
    const state=this.currentLive(original),inspection=await this.inspectPacket(state,phase==='before-native'?'before-send':'packet');
    this.currentLive(original);await this.assertStored(state.archive);this.currentLive(original);
    if(phase==='before-native'&&(inspection.wireSpent||inspection.transportStatus!==undefined)||phase==='after-native'&&(!inspection.sent||!inspection.wireSpent||inspection.transportStatus!==201||!inspection.operationId||inspection.responseHmac!==inspection.transportHmac))throw denied();
    const completed:EntityRecycleOriginalCompletion[]=[];
    for(const {node,packet}of state.archive.plan){
      const originalCompletion=state.execution.completedOriginals.get(`${state.archive.entryId}:${node.key}`);
      if(!state.execution.completed.has(packet.key)){if(originalCompletion)throw denied();continue;}
      if(!originalCompletion||originalCompletion.packet.key!==packet.key)throw denied();
      const receipt=await this.db.one<any>('SELECT * FROM entity_change_recycle_receipts WHERE operation_id=$1 AND source_id=$2 AND packet_key=$3',[originalCompletion.operationId,inspection.source.id,packet.key]);
      const m=await this.db.one<any>('SELECT * FROM mutation_operations WHERE id=$1',[originalCompletion.operationId]);
      if(!receipt||receipt.source_id!==inspection.source.id||receipt.packet_key!==packet.key||receipt.entry_id!==state.archive.entryId||receipt.node_key!==node.key||receipt.native_id!==packet.nativeId||receipt.result_hmac!==originalCompletion.responseHmac
        ||receipt.cluster_id!==inspection.source.clusterId||receipt.workspace_id!==inspection.source.workspaceId||receipt.baseline_id!==inspection.baseline.baselineId||receipt.pin_id!==inspection.baseline.pinId
        ||receipt.workflow_execution_id!==inspection.source.workflowExecutionId||receipt.operation_id!==originalCompletion.operationId||receipt.operation_key!==`entity-${inspection.source.workflowExecutionId}-${packet.order}`
        ||receipt.direction!==(packet.method==='DELETE'?'delete':'restore')||!m||m.state!=='succeeded'||m.remote_started!==true||m.remote_completed!==true
        ||m.cluster_id!==inspection.source.clusterId||m.workspace_id!==inspection.source.workspaceId||m.actor_id!==inspection.source.executionActorId||m.workflow_id!==inspection.source.workflowId
        ||m.entity_change_source_id!==inspection.source.id||m.entity_change_baseline_id!==inspection.baseline.baselineId||m.entity_change_attempt_id!==receipt.attempt_id
        ||m.entity_change_packet_key!==packet.key||m.entity_id!==packet.nativeId||(m.parent_id??null)!==(packet.parentId??null)||(m.credential_kind??null)!==(packet.credentialKind??null)
        ||m.action!==packet.mutationAction||m.entity_type!==(packet.credentialKind?'credentials':packet.nativeType)||m.idempotency_key!==receipt.operation_key
        ||typeof m.before_secret!=='string'||typeof m.payload_secret!=='string'||!m.result_secret)throw denied();
      this.same(this.secrets.decrypt(m.before_secret,`mutation:${m.id}:before`),packet.before);this.same(this.secrets.decrypt(m.payload_secret,`mutation:${m.id}:payload`),packet.body??null);
      const raw=this.secrets.decrypt(m.result_secret,`mutation:${m.id}:result`);if(this.secrets.fingerprint(raw)!==originalCompletion.responseHmac)throw denied();completed.push(originalCompletion);
    }
    if(phase==='after-native'){
      const m=await this.db.one<any>('SELECT * FROM mutation_operations WHERE id=$1',[inspection.operationId]);
      if(!m||m.state!=='succeeded'||!m.remote_started||!m.remote_completed||m.entity_change_source_id!==inspection.source.id||m.entity_change_baseline_id!==inspection.baseline.baselineId
        ||m.entity_change_attempt_id!==inspection.binding.attemptId||m.entity_change_packet_key!==inspection.packet.key||m.entity_id!==inspection.packet.nativeId
        ||m.cluster_id!==inspection.source.clusterId||m.workspace_id!==inspection.source.workspaceId||m.actor_id!==inspection.source.executionActorId||m.workflow_id!==inspection.source.workflowId
        ||(m.parent_id??null)!==(inspection.packet.parentId??null)||(m.credential_kind??null)!==(inspection.packet.credentialKind??null)
        ||m.action!==inspection.packet.mutationAction||m.entity_type!==(inspection.packet.credentialKind?'credentials':inspection.packet.nativeType)||m.idempotency_key!==inspection.operationKey
        ||typeof m.before_secret!=='string'||typeof m.payload_secret!=='string'||!m.result_secret)throw denied();
      this.same(this.secrets.decrypt(m.before_secret,`mutation:${m.id}:before`),inspection.packet.before);this.same(this.secrets.decrypt(m.payload_secret,`mutation:${m.id}:payload`),inspection.packet.body??null);
      const raw=this.secrets.decrypt(m.result_secret,`mutation:${m.id}:result`);if(this.secrets.fingerprint(raw)!==inspection.responseHmac)throw denied();
      completed.push({nodeKey:state.grant.nodeKey,packet:inspection.packet,operationId:m.id,responseHmac:inspection.responseHmac!,response:raw,source:'current-original-response'});
    }
    this.currentLive(original);return immutableJson({source:inspection.source,prepared:inspection.prepared,obligation:state.archive.obligation,packets:state.archive.packets,packet:inspection.packet,nodeKey:state.grant.nodeKey,completed});
  }
  private async verifyCurrentWitness(state:PacketState,phase:'before-native'|'after-native'):Promise<void>{
    if(!this.current)throw unavailable();const witness=await this.current.observe(state.original,phase);
    try{await this.kernel().assertCurrentGraphParties(state.execution.original,witness);this.current.resolve(witness);this.currentLive(state.original);}
    finally{this.current.close(witness);}
  }
  private async verifyCurrentRestore(handle:object,operationId:string,result:unknown):Promise<void>{
    const state=this.packetState(handle);if(state.grant.packet.method!=='POST'||state.operationId!==operationId)throw denied();
    const inspection=await this.inspectPacket(state,'packet');if(this.secrets.fingerprint(result)!==inspection.responseHmac)throw denied();
    await this.verifyCurrentWitness(state,'after-native');
  }
  private async resolveRestore(input:Readonly<EntityChangeRecycleNativeInput>):Promise<Readonly<{entryId:string}>>{
    const state=await this.nativeState(input,'POST');if(state.archive.obligation.kind!=='recycle-restore')throw denied();return Object.freeze({entryId:state.archive.entryId});
  }
  private async assertNativeArchive(input:Readonly<EntityChangeRecycleArchiveInput>,method:'DELETE'|'POST'):Promise<void>{
    const state=await this.nativeState(input,method),node=state.archive.plan.find(item=>item.packet.key===state.grant.packet.key)!.node;
    if(input.entry.id!==state.archive.entryId||input.entry.mutation_id!==null||input.entry.cluster_id!==state.grant.source.clusterId||input.entry.workspace_id!==state.grant.source.workspaceId
      ||input.node.key!==state.grant.nodeKey||method==='DELETE'&&(!state.deleteEntered||state.archive.obligation.kind!=='recycle-archive')||method==='POST'&&state.archive.obligation.kind!=='recycle-restore')throw denied();
    this.same(input.graph,state.archive.obligation.graph);this.same(input.node,node);
  }
}
