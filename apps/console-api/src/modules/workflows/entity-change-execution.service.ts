import {ConflictException,ForbiddenException,HttpException,Injectable,OnModuleInit,Optional,ServiceUnavailableException} from '@nestjs/common';
import {randomBytes,randomUUID} from 'node:crypto';
import {DbService} from '../../infrastructure/db.service';
import {RedisService} from '../../infrastructure/redis.service';
import {SecretService} from '../../infrastructure/secret.service';
import {KongExecutionContextService} from '../../infrastructure/kong/execution-context.service';
import {KongService} from '../../infrastructure/kong/kong.service';
import {immutableJson} from '../../infrastructure/kong/immutable-json';
import {AuthorizationService} from '../authorization/authorization.service';
import {AuditService} from '../audit/audit.service';
import {EntityPreparedWriterService,derivePreparedEntityWrite,type EntityPreparedWriteHandle} from '../entities/entity-prepared-writer.service';
import {EntityChangeBoundaryService} from '../entities/entity-change-boundary.service';
import type {EntityActor} from '../entities/entities.types';
import type {EntityChangePacket} from '../entities/entity-change.types';
import type {MutationContext} from '../mutations/mutation.service';
import type {ApprovedMutationBindingV3,ApprovedNativeRequest,ApprovedNativeStage} from './approved-execution.types';
import type {EntityChangePacketExecutionPolicy,EntityChangePacketExecutionProof} from '../../infrastructure/kong/entity-change-execution-policy';
import {WorkflowPlansService} from './workflow-plans.service';
import {WorkflowApprovalAuthorityService} from './workflow-approval-authority.service';
import {EntityChangeIntentsService} from './entity-change-intents.service';
import {EntityChangeExecutionFactsService} from './entity-change-execution-facts.service';
import {EntityChangeBaselineCapturerService} from './entity-change-baseline-capturer.service';
import {assertEntityChangeWorkflowPlan} from './entity-change-workflow';
import type {EntityChangeExecutionSource,EntityChangeIntentEnvelope} from './entity-change-intent.types';
import type {EntityChangeBaselineCapture,EntityChangeBaselineReceipt,EntityChangePacketAttemptBinding,EntityChangePacketFact,EntityChangeFactsCheckpoint} from './entity-change-execution-facts.types';
import type {WorkflowPlanV1} from './workflow.types';
import {portalConfirm,portalObject,portalRevision,requirePortalCas} from '../portal/portal-input';
import {workflowId,workflowKey} from './workflow-validation';
import {safeDatabaseDiagnostic} from '../../common/http';
import {entityBaselineAad,entityPacketFactAad} from './entity-change-execution-facts.service';
import {decodeTag} from '../../infrastructure/kong/tags';
import {entityReferenceId} from '../entities/entity-reference';
import type {EntityChangeOperation} from '../entities/entity-change.types';
import type {EntityChangeBaselineEnvelope,EntityChangeRecoveryLink} from './entity-change-execution-facts.types';
import {EntityChangeRecycleExecutionService} from '../recycle-bin/entity-change-recycle-execution.service';
import type {EntityRecycleCurrentWitness} from '../recycle-bin/entity-recycle-current-witness.types';
import type {EntityChangeRecycleDeleteVerification} from '../recycle-bin/entity-change-recycle-facts.types';
import type {EntityRecycleOriginReadInput} from '../recycle-bin/entity-recycle-origin-reader.types';
import {EntityScheduledAuthorityService} from './entity-scheduled-authority.service';
import {EntityScheduledNamespaceService} from './entity-scheduled-namespace.service';
import {decodeEntityExecutionSource} from './entity-change-source-codec';
import type {EntityExecutionSourceByOrigin,EntityScheduledExecutionSourceV2,EntityScheduleTerminalOutcome} from './entity-change-schedule.contract';
import {conservativeNativeImpact,validImpact} from '../mutations/mutation-impact';
import type {KongExecutionFrame,KongPolicyCluster} from '../../infrastructure/kong/execution-context.service';
import {transportScopeFor} from '../../infrastructure/kong/transport-scope';
import {certifyTerminalRecycleMetadata} from './entity-change-terminal-metadata-proof';
import {certifyPartialNoSendTerminalMetadata} from './entity-change-partial-no-send-terminal-proof';
import {GraphCapturerService,type RecycleGraph} from '../recycle-bin/graph-capturer.service';
import {CredentialStoreService} from '../credentials/credential-store.service';
import {EntityRecycleOriginReaderService} from '../recycle-bin/entity-recycle-origin-reader.service';
import {partialBasicCustodyHmac,validatePartialRecycleRestoreSelection} from '../recycle-bin/partial-recycle-restore';
import {derivePreparedRecyclePackets} from '../recycle-bin/entity-prepared-recycle-writer.service';
import {TargetResultReconciliationService} from './target-result-reconciliation.service';
import {attestTargetOriginalProducer} from './entity-change-target-producer-contract';
import {assertTargetHealthObservation,type TargetHealthObservation} from '../../infrastructure/kong/target-health-observation';
import {currentEffectiveTarget} from '../../infrastructure/kong/effective-target';
import {disabledTargetReadback} from '../../infrastructure/kong/disabled-target-readback';
import {targetWeightRecoveryOperation} from './target-weight-recovery';
import { NativeKongPolicyService } from '../authorization/native-kong-policy.service';

interface ExecutionClaim {
  active:boolean;actor:EntityActor;sessionId:string|null;permissionVersion:string;source:EntityExecutionSourceByOrigin;scheduledNamespace?:object;
  plan:WorkflowPlanV1;envelope:EntityChangeIntentEnvelope;baseline?:EntityChangeBaselineReceipt;
  completed:Set<string>;packets:Set<PacketClaim>;
}
interface PacketClaim {
  active:boolean;execution:ExecutionClaim;packet:Readonly<EntityChangePacket>;binding:EntityChangePacketAttemptBinding;
  operationKey:string;operationId?:string;sent:boolean;wireSpent?:boolean;responseHmac?:string;transportStatus?:number;transportHmac?:string;outcome?:string;
  verificationStatus?:number;verificationPath?:string;
  targetPoststate?:Readonly<{historyRetention:'weight-zero-overlay'|'native-pruned';observationHmac:string;archiveGraphHmac:string;originalNativeId:string;address:string}>;
  healthBefore?:Readonly<TargetHealthObservation>;
  recycleAuthorityNotAfter?:number;recycleAuthorityOperationId?:string;
  partialCurrentUse?:{frame:KongExecutionFrame;operationId:string;observationHmac:string;notAfter:number;ready:boolean};
}
const healthPacket=(packet:Readonly<EntityChangePacket>)=>packet.nativeType==='targets'&&['mark_healthy','mark_unhealthy'].includes(packet.mutationAction);
const mutationPayload=(packet:Readonly<EntityChangePacket>)=>healthPacket(packet)?{state:packet.mutationAction==='mark_healthy'?'healthy':'unhealthy'}:packet.body??null;
const deny=(code='ENTITY_CHANGE_EXECUTION_PROOF_INVALID')=>new ForbiddenException({code,message:'当前执行授权或封存材料无效，操作已停止'});
const stop=(code:string)=>new ConflictException({code,message:'当前配置、权限或执行事实已变化，请核验原工单'});
/** Native changes use their own exact source/baseline/packet namespace. The
 * legacy zero-native wrapper and configuration V2 never become packet permits.
 * HTTP shapes and copied handles cannot enter either private registry. */
@Injectable()
export class EntityChangeExecutionService implements EntityChangePacketExecutionPolicy,OnModuleInit {
  private readonly sources=new Map<string,ExecutionClaim>();
  private readonly executionHandles=new WeakMap<object,ExecutionClaim>();
  private readonly packetHandles=new WeakMap<object,PacketClaim>();
  private readonly pendingBindingTransactions=new WeakMap<PacketClaim,DbService>();
  private readonly executionOriginals=new WeakMap<ExecutionClaim,object>();
  private readonly partialGraphPhases=new WeakMap<ExecutionClaim,{key:string;graph:Readonly<RecycleGraph>}>();
  private readonly captureProofs=new WeakMap<object,{sourceId:string;hmac:string}>();
  private readonly factProofs=new WeakMap<object,{claim:PacketClaim;hmac:string|null}>();
  private readonly recoveryProofs=new WeakMap<object,{hmac:string;actorId:string;sessionId:string;permissionVersion:string}>();
  private readonly noSendProofs=new WeakMap<object,{sourceId:string;bindingHmac:string;factHmac:string}>();
  private readonly noSendSources=new Map<string,{actorId:string;sessionId:string;clusterId:string;workspaceId:string}>();
  private readonly scheduledCompletions=new WeakMap<object,{authorityHandle:object;claimId:string;sourceId:string|null;workflowId:string;executionId:string|null;outcome:EntityScheduleTerminalOutcome}>();
  private scopeHints(plan:WorkflowPlanV1){return{quality:'verified' as const,module:'workflows',subject:{type:'workflows',id:plan.workflowId},beforeExists:true,afterExists:true,beforeTags:[],afterTags:[],beforeWorkspaceId:plan.workspaceId,afterWorkspaceId:plan.workspaceId};}
  constructor(private readonly db:DbService,private readonly redis:RedisService,private readonly secrets:SecretService,
    private readonly context:KongExecutionContextService,private readonly kong:KongService,private readonly authz:AuthorizationService,
    private readonly audit:AuditService,private readonly plans:WorkflowPlansService,private readonly approval:WorkflowApprovalAuthorityService,
    private readonly intents:EntityChangeIntentsService,private readonly facts:EntityChangeExecutionFactsService,
    private readonly capturer:EntityChangeBaselineCapturerService,private readonly writer:EntityPreparedWriterService,
    private readonly boundary:EntityChangeBoundaryService,private readonly recycleExecutor?:EntityChangeRecycleExecutionService,
    @Optional() private readonly scheduledAuthority?:EntityScheduledAuthorityService,@Optional() private readonly scheduledNamespace?:EntityScheduledNamespaceService,
    @Optional() private readonly recycleOrigins?:EntityRecycleOriginReaderService,@Optional() private readonly recycleGraphs?:GraphCapturerService,
    @Optional() private readonly credentialCustody?:CredentialStoreService,
    @Optional() private readonly targetResults?:TargetResultReconciliationService,
    @Optional() private readonly nativePolicy?:NativeKongPolicyService) {}

  onModuleInit():void{
    this.context.installEntityChangePacketPolicy(this);
    this.targetResults?.installFixedBridge({
      assertNoActiveSource:async sourceId=>{if(this.sources.has(sourceId))throw stop('ENTITY_CHANGE_TARGET_EXECUTION_STILL_ACTIVE');},
      attestProducer:async certificate=>attestTargetOriginalProducer(certificate,this.secrets)
    },'967ee9e56c57ba7be4f4c558c33ed6a5af8a683a316db234443d04375d8c169f');
    if(this.scheduledAuthority&&this.scheduledNamespace){
      this.context.installEntityScheduledNamespacePolicy(this.scheduledNamespace);
      this.context.installEntityScheduleReservationPolicy({assertNativeWrite:(frame,cluster,method,path)=>this.assertScheduledReservation(frame,cluster,method,path)});
      this.scheduledNamespace.installContextRunner({
        assertNoFrame:()=>{if(this.context.peek())throw deny('ENTITY_SCHEDULE_EXISTING_CONTEXT_FORBIDDEN');},
        run:(handle,fn)=>this.context.runEntityScheduledNamespace(handle,fn),
        requireCurrentHandle:()=>this.context.requireEntityScheduledNamespaceHandle()
      });
      this.nativePolicy?.installScheduledTargetAppendBridge({verifyOriginalPacket:async(namespaceHandle,packetHandle,packetKey)=>{
        const claim=this.packet(packetHandle);await this.verifyHandle(packetHandle);
        if(claim.execution.scheduledNamespace!==namespaceHandle||claim.packet.key!==packetKey||claim.packet.nativeType!=='targets'
          ||claim.packet.mutationAction!=='update')throw deny('TARGET_APPEND_SCHEDULED_SOURCE_REQUIRED');
        return this.scheduledNamespace!.verifyTargetWeightPacket(namespaceHandle,packetKey,'packet');
      }});
      this.scheduledAuthority.installExecutor({executeClaim:handle=>this.executeScheduledClaim(handle),
        verifyCompletion:(handle,completion,tx)=>this.verifyScheduledCompletion(handle,completion,tx)});
    }
    if(this.recycleExecutor){
      this.recycleExecutor.installKernelBridge({
        execution:handle=>{const claim=this.execution(handle);if('origin'in claim.source)throw deny('ENTITY_SCHEDULE_RECYCLE_ADAPTER_REQUIRED');if(!claim.baseline)throw deny('ENTITY_CHANGE_BASELINE_REQUIRED');
          return Object.freeze({source:claim.source,baseline:claim.baseline,actor:claim.actor,prepared:claim.envelope.prepared});},
        packet:handle=>{const claim=this.packet(handle),execution=claim.execution;if('origin'in execution.source)throw deny('ENTITY_SCHEDULE_RECYCLE_ADAPTER_REQUIRED');if(!execution.baseline)throw deny('ENTITY_CHANGE_BASELINE_REQUIRED');
          return Object.freeze({source:execution.source,baseline:execution.baseline,actor:execution.actor,prepared:execution.envelope.prepared,
            packet:claim.packet,binding:claim.binding,operationKey:claim.operationKey,operationId:claim.operationId,sent:claim.sent,wireSpent:claim.wireSpent===true,
            transportStatus:claim.transportStatus,transportHmac:claim.transportHmac,responseHmac:claim.responseHmac,
            verificationStatus:claim.verificationStatus,verificationPath:claim.verificationPath,
            targetPoststate:claim.targetPoststate});},
        verifyExecution:(handle,checkpoint,tx)=>this.verifySource(this.execution(handle).source.id,this.recycleCheckpoint(checkpoint),tx),
        verifyPacket:async(handle,checkpoint,tx)=>{const claim=this.packet(handle);await this.verifySource(claim.binding.sourceId,this.recycleCheckpoint(checkpoint),tx);
          if(checkpoint!=='outcome')await this.verifyHandle(handle);},
        assertCurrentGraphParties:async(original,witness,tx=this.db)=>{
          const claim=this.execution(original);await this.verifySource(claim.source.id,'packet',tx);
          const partial=claim.envelope.prepared.metadataObligations.some(o=>o.kind==='recycle-restore'&&o.partialRestore);
          const observed=partial?this.boundary.resolveCurrentRecycleWitness(witness):null;
          if(observed)await this.assertPartialCurrentWitness(original,observed,tx);
          let notAfter=await this.boundary.assertCurrentRecycleSubject(claim.actor.user.id,claim.envelope.prepared,'write',witness,tx);
          const approval=await this.approval.verifyApprovalSet(claim.plan,{executionId:claim.source.workflowExecutionId,checkpoint:'packet'},tx);
          for(const userId of new Set(approval.reviewers.map(reviewer=>reviewer.userId)))
            notAfter=Math.min(notAfter,await this.boundary.assertCurrentRecycleSubject(userId,claim.envelope.prepared,'approve',witness,tx));
          await this.verifySource(claim.source.id,'packet',tx);
          const packet=this.packet(this.context.requireEntityChangePacketFrame(this.context.current()));
          if(packet.execution!==claim||!packet.operationId||!Number.isFinite(notAfter)||performance.now()>=notAfter)throw deny('ENTITY_RECYCLE_CURRENT_AUTHORITY_EXPIRED');
          packet.recycleAuthorityNotAfter=notAfter;packet.recycleAuthorityOperationId=packet.operationId;
          if(observed?.phase==='before-native'&&partial)
            packet.partialCurrentUse={frame:this.context.current(),operationId:packet.operationId,observationHmac:observed.observationHmac,notAfter,ready:true};
        },
        appendKnownOutcome:(handle,verification,tx)=>this.appendKnownRecycleOutcome(handle,verification,tx),
        observeTargetDeletePoststate:(handle,observation)=>this.observeTargetDeletePoststate(handle,observation),
        assertCurrentOriginScope:input=>this.assertCurrentRecycleOriginScope(input),
        activeRestoreRevalidation:input=>this.activeRestoreRevalidation(input),
        verifyPartialRestoreCurrent:(handle,checkpoint,tx)=>this.verifyPartialRestoreCurrent(handle,checkpoint,tx),
        verifyPartialRestoreFacts:async(handle,checkpoint,tx=this.db)=>{
          if(checkpoint==='current-response'){await this.verifySource(this.execution(handle).source.id,'packet',tx);return this.verifyPartialRestoreCurrent(handle,'outcome',tx,false,true);}
          return this.verifyPartialRestoreCurrent(handle,checkpoint,tx,false,true);
        },
        assertFrozenOriginSubject:async input=>{
          await this.assertCurrentRecycleOriginScope(input.request);
          await this.boundary.assertStoredSubject({material:input.material,actor:input.request.actor,action:'read',mode:'historical'});
          await this.assertCurrentRecycleOriginScope(input.request);
        }
      });
      this.recycleExecutor.onModuleInit();
    }
    this.writer.installExecutionDelegate({run:async(handle,write)=>{
      const claim=this.packet(handle);await this.verifyHandle(handle);
      if(healthPacket(claim.packet)){
        const ready=await this.facts.assertReadyForPacket(claim.binding.sourceId,claim.binding.baselineId,claim.packet.key);
        const original=ready.capture.objects.find(object=>object.nativeType==='targets'&&object.nativeId===claim.packet.nativeId&&object.parentId===claim.packet.parentId);
        claim.healthBefore=assertTargetHealthObservation((original?.trustedProvenance as any)?.healthBefore,
          {upstreamId:claim.packet.parentId!,target:claim.packet.before as Record<string,unknown>},this.secrets);
      }
      return this.context.runEntityChangePacket(handle,()=>write({clusterId:claim.execution.source.clusterId,workspaceId:claim.execution.source.workspaceId,
        actor:claim.execution.actor,operationKey:claim.operationKey,packet:claim.packet,
        ...(claim.healthBefore?{targetHealthBefore:claim.healthBefore}:{}),
        obligations:claim.execution.envelope.prepared.metadataObligations.filter(o=>(o.kind==='entity-index'||o.kind==='credential-remember')&&o.packetKey===claim.packet.key) as any}));
    }});
    this.facts.installFixedDelegate({
      verifySource:(id,checkpoint,tx)=>this.verifySource(id,checkpoint,tx),
      verifyCapture:async(id,capture,proof,tx)=>{
        const original=this.captureProofs.get(proof);if(!original||original.sourceId!==id||original.hmac!==this.secrets.fingerprint(capture))throw deny('ENTITY_CHANGE_CAPTURE_PROOF_INVALID');
        await this.verifySource(id,'capture',tx);
      },
      verifyPacketFact:async(binding,fact,proof)=>{
        const repair=this.noSendProofs.get(proof);
        if(repair){
          if(fact?.kind!=='outcome'||fact.outcome!=='rejected-before-send'||repair.sourceId!==binding.sourceId
            ||repair.bindingHmac!==this.secrets.fingerprint(binding)||repair.factHmac!==this.secrets.fingerprint(fact))throw deny('ENTITY_CHANGE_NO_SEND_PROOF_REQUIRED');
          return;
        }
        const original=this.factProofs.get(proof),claim=original?.claim;
        if(!original||!claim||this.secrets.fingerprint(binding)!==this.secrets.fingerprint(claim.binding)
          ||original.hmac!==(fact?this.secrets.fingerprint(fact):null))throw deny('ENTITY_CHANGE_PACKET_FACT_PROOF_INVALID');
        if(fact?.kind==='send-intent'&&(!claim.operationId||claim.sent))throw deny('ENTITY_CHANGE_SEND_FACT_INVALID');
        if(fact?.kind==='outcome'&&claim.outcome!==fact.outcome)throw deny('ENTITY_CHANGE_OUTCOME_FACT_INVALID');
      },
      assertHistoricalRead:async(id,actor,tx)=>{
        const baseline=await tx.one<any>('SELECT cluster_id,workspace_id,workflow_id FROM entity_change_baselines WHERE id=$1',[id]);
        if(!baseline||baseline.workspace_id!==actor.workspaceId)throw deny();
        const {plan}=await this.plans.load(baseline.cluster_id,baseline.workspace_id,baseline.workflow_id,tx);
        await this.intents.assertSubject(plan,actor.user.id,'read',tx);
      },
      verifyRetention:async()=>{throw deny('ENTITY_CHANGE_RETENTION_EXTENSION_UNAVAILABLE');},
      verifyRecovery:async(link,proof,tx)=>{
        const original=this.recoveryProofs.get(proof),frame=this.context.current();
        if(!original||original.hmac!==this.secrets.fingerprint(link)||frame.actor?.id!==original.actorId||frame.sessionId!==original.sessionId
          ||frame.clusterId!==link.clusterId||frame.workspaceId!==link.workspaceId||link.actorId!==original.actorId)throw deny('ENTITY_CHANGE_RECOVERY_PROOF_INVALID');
        if(await this.authz.permissionVersion(frame.actor,tx)!==original.permissionVersion)throw deny('ENTITY_CHANGE_PERMISSIONS_CHANGED');
        await this.intents.get(link.clusterId,link.newIntentId,{user:frame.actor,workspaceId:link.workspaceId});
      }
    });
  }
  private packet(handle:object):PacketClaim{
    const claim=handle&&this.packetHandles.get(handle);
    if(!claim||!claim.active||!claim.execution.active)throw deny();return claim;
  }
  private execution(handle:object):ExecutionClaim{
    const claim=handle&&this.executionHandles.get(handle);if(!claim?.active||this.sources.get(claim.source.id)!==claim)throw deny();return claim;
  }
  private recycleCheckpoint(value:string):EntityChangeFactsCheckpoint{
    if(!['capture','packet','before-send','outcome'].includes(value))throw deny();return value as EntityChangeFactsCheckpoint;
  }
  private async assertCurrentRecycleOriginScope(input:Readonly<EntityRecycleOriginReadInput>):Promise<void>{
    const frame=this.context.current();
    if(!frame.sessionId||frame.actor?.id!==input.actor.user.id||frame.clusterId!==input.clusterId||frame.workspaceId!==input.workspaceId
      ||input.actor.workspaceId!==input.workspaceId)throw deny('RECYCLE_CURRENT_ACTOR_REQUIRED');
    // Always use a fresh authority read, not the Reader's repeatable-read
    // evidence snapshot, which cannot see a concurrent session revocation.
    const current=await this.db.one<any>(`SELECT u.credential_epoch FROM auth_sessions s JOIN users u ON u.id=s.user_id
      WHERE s.id=$1 AND s.user_id=$2 AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp()
      AND s.credential_epoch=u.credential_epoch AND u.status='active' AND u.deleted_at IS NULL AND NOT u.force_password_change`,[frame.sessionId,input.actor.user.id]);
    if(!current)throw deny('ENTITY_CHANGE_SESSION_REVOKED');
    await this.authz.snapshot(input.actor.user);
  }
  private partialRestore(claim:ExecutionClaim){
    const matches=claim.envelope.prepared.metadataObligations.filter(o=>o.kind==='recycle-restore'&&o.partialRestore);
    if(matches.length!==1||matches[0].kind!=='recycle-restore'||!matches[0].partialRestore||claim.envelope.version!==1
      ||'origin'in claim.source||!claim.baseline||claim.envelope.prepared.packets.length!==2)throw deny('ENTITY_RECYCLE_PARTIAL_EXECUTION_REQUIRED');
    const obligation=matches[0],selection=obligation.partialRestore!,partition=validatePartialRecycleRestoreSelection(obligation.graph,selection,this.secrets);
    const source=claim.source,history=selection.history;
    if(history.clusterId!==source.clusterId||history.workspaceId!==source.workspaceId||history.entryId!==obligation.entryId
      ||history.sourceId===source.id||history.graphHmac!==obligation.graphHmac)throw deny('ENTITY_RECYCLE_PARTIAL_EXECUTION_REQUIRED');
    derivePreparedRecyclePackets(obligation,claim.envelope.prepared.packets,this.secrets);
    return{obligation,selection,partition};
  }
  private samePartial(value:unknown,expected:unknown):void{
    if(this.secrets.fingerprint(value)!==this.secrets.fingerprint(expected))throw deny('ENTITY_RECYCLE_PARTIAL_CURRENT_CHANGED');
  }
  /** Read the exact authenticated seven-object baseline, not a safe projection
   * or a new capture. Outcome certification deliberately needs no live grant. */
  private async partialBaseline(claim:ExecutionClaim,tx:DbService):Promise<EntityChangeBaselineCapture>{
    const source=claim.source,receipt=claim.baseline!,{obligation,selection,partition}=this.partialRestore(claim);
    const row=await tx.one<any>('SELECT * FROM entity_change_baselines WHERE id=$1 AND source_id=$2',[receipt.baselineId,source.id]);
    if(!row||row.cluster_id!==source.clusterId||row.workspace_id!==source.workspaceId||row.readiness!=='ready'
      ||row.workflow_execution_id!==source.workflowExecutionId||row.baseline_hmac!==receipt.baselineHmac||row.capture_hmac!==receipt.captureHmac
      ||row.object_manifest_hmac!==receipt.objectManifestHmac||row.object_count!==7||row.graph_count!==1)throw deny('ENTITY_RECYCLE_PARTIAL_BASELINE_INVALID');
    const envelope=this.secrets.decrypt<EntityChangeBaselineEnvelope>(row.material_ciphertext,entityBaselineAad(source.clusterId,source.workspaceId,row.id));
    this.samePartial(envelope.source,source);
    const capture=envelope.capture;
    if(envelope.version!==1||envelope.baselineId!==row.id||this.secrets.fingerprint(envelope)!==row.baseline_hmac
      ||this.secrets.fingerprint(capture)!==row.capture_hmac||capture.version!==1||capture.objects.length!==7||capture.graphs.length!==1
      ||capture.blockerCodes.length||capture.nonreversiblePacketKeys.length)throw deny('ENTITY_RECYCLE_PARTIAL_BASELINE_INVALID');
    const normalized=capture.objects.map(o=>({key:o.key,nativeType:o.nativeType,nativeId:o.nativeId,parentId:o.parentId??null,credentialKind:o.credentialKind??null,
      affected:o.affected,present:o.present,dependencies:o.dependencies,beforeHmac:this.secrets.fingerprint(o.before),restoreHmac:o.restorePayload===undefined?null:this.secrets.fingerprint(o.restorePayload),
      schemaHmac:this.secrets.fingerprint(o.schemaMaterial),provenanceHmac:this.secrets.fingerprint(o.trustedProvenance),recovery:o.recovery}));
    this.samePartial(normalized,row.object_manifest);
    if(this.secrets.fingerprint(normalized)!==receipt.objectManifestHmac)throw deny('ENTITY_RECYCLE_PARTIAL_BASELINE_INVALID');
    const objects=await tx.query<any>('SELECT * FROM entity_change_baseline_objects WHERE baseline_id=$1 ORDER BY object_order',[row.id]);
    if(objects.length!==7||objects.some((o,i)=>o.object_order!==i+1||o.cluster_id!==source.clusterId||o.workspace_id!==source.workspaceId||o.object_manifest_hmac!==receipt.objectManifestHmac))throw deny('ENTITY_RECYCLE_PARTIAL_BASELINE_INVALID');
    this.samePartial(objects.map(o=>({key:o.object_key,nativeType:o.native_type,nativeId:o.native_id,parentId:o.parent_id,credentialKind:o.credential_kind,affected:o.affected,present:o.present,
      dependencies:o.dependencies,beforeHmac:o.before_hmac,restoreHmac:o.restore_hmac,schemaHmac:o.schema_hmac,provenanceHmac:o.provenance_hmac,recovery:o.recovery})),normalized);
    const pin=await tx.one<any>('SELECT * FROM entity_change_baseline_pins WHERE id=$1 AND baseline_id=$2',[receipt.pinId,row.id]);
    if(!pin||pin.source_id!==source.id||pin.workflow_execution_id!==source.workflowExecutionId||pin.cluster_id!==source.clusterId||pin.workspace_id!==source.workspaceId
      ||pin.baseline_hmac!==receipt.baselineHmac||pin.object_manifest_hmac!==receipt.objectManifestHmac||new Date(pin.protected_until).toISOString()!==receipt.protectedUntil)throw deny('ENTITY_RECYCLE_PARTIAL_BASELINE_INVALID');
    const root=obligation.graph.nodes.find(n=>n.key===obligation.graph.rootKey)!;
    for(const node of obligation.graph.nodes){
      const parent=node.type==='consumers'?undefined:root.id;
      const matches=capture.objects.filter(o=>o.nativeType===node.type&&o.nativeId===node.id&&(o.parentId??null)===(parent??null)
        &&(o.credentialKind??null)===(parent?node.type:null));
      if(matches.length!==1)throw deny('ENTITY_RECYCLE_PARTIAL_BASELINE_INVALID');const object=matches[0],present=partition.present.some(n=>n.key===node.key);
      if(object.present!==present||object.affected===present||object.recovery!==(present?'reference':'absent')||object.restorePayload!==undefined
        ||object.schemaMaterial==null||object.key!==(parent?`${node.type}:${parent}:${node.id}`:`${node.type}:${node.id}`))throw deny('ENTITY_RECYCLE_PARTIAL_BASELINE_INVALID');
      this.samePartial(object.dependencies,node.dependencies);
      if(present){const prior=selection.history.presentNodes.find(n=>n.nodeKey===node.key)!,observed=selection.presentNodes.find(n=>n.nodeKey===node.key)!;
        if(this.secrets.fingerprint(object.before)!==observed.beforeHmac||observed.beforeHmac!==prior.resultHmac)throw deny('ENTITY_RECYCLE_PARTIAL_BASELINE_INVALID');
        this.samePartial(object.trustedProvenance,{kind:'closed-restore-current-present',nodeKey:node.key,historyCoverageHmac:selection.history.coverageHmac,
          priorSourceId:selection.history.sourceId,priorAttemptId:prior.attemptId,priorOperationId:prior.operationId,priorResultHmac:prior.resultHmac,beforeHmac:observed.beforeHmac,
          ...(observed.basicCustodyHmac?{basicCustodyHmac:observed.basicCustodyHmac}:{})});
      }else if(object.before!==null)throw deny('ENTITY_RECYCLE_PARTIAL_BASELINE_INVALID');
    }
    const graph=capture.graphs[0];
    if(graph.complete!==true||graph.purpose!=='baseline'||graph.rootKey!==root.key||graph.nodes.length!==5
      ||graph.nodes.some(n=>!partition.present.some(p=>p.type===n.type&&p.id===n.id&&p.path===n.path)))throw deny('ENTITY_RECYCLE_PARTIAL_BASELINE_INVALID');
    for(const node of graph.nodes){const object=capture.objects.find(o=>o.nativeType===node.type&&o.nativeId===node.id)!;
      this.samePartial(node.data,object.before);this.samePartial(node.dependencies,object.dependencies);}
    return capture;
  }
  /** Only original process observations explain progress of the new two-packet
   * source. A reservation is not a wire emission; completed predecessors need
   * both immutable outcome and recycle receipts, plus the original observer. */
  private async partialOwnProgress(claim:ExecutionClaim,checkpoint:'capture'|'packet'|'before-send'|'outcome',tx:DbService):Promise<Map<string,string>>{
    const source=claim.source,baseline=claim.baseline!,{obligation}=this.partialRestore(claim),results=new Map<string,string>();
    const attempts=await tx.query<any>('SELECT * FROM entity_change_packet_attempts WHERE source_id=$1 ORDER BY packet_order',[source.id]);
    const events=await tx.query<any>('SELECT * FROM entity_change_packet_events WHERE source_id=$1 ORDER BY attempt_id,event_kind',[source.id]);
    const receipts=await tx.query<any>('SELECT * FROM entity_change_recycle_receipts WHERE source_id=$1 AND entry_id=$2 ORDER BY packet_key',[source.id,obligation.entryId]);
    const mutations=await tx.query<any>('SELECT * FROM mutation_operations WHERE entity_change_source_id=$1 ORDER BY id',[source.id]);
    if(attempts.length>2||new Set(attempts.map(a=>a.id)).size!==attempts.length||new Set(attempts.map(a=>a.packet_key)).size!==attempts.length
      ||events.some(e=>!attempts.some(a=>a.id===e.attempt_id))||mutations.some(m=>!attempts.some(a=>a.id===m.entity_change_attempt_id))
      ||receipts.some(r=>!attempts.some(a=>a.id===r.attempt_id))||events.some(e=>e.outcome==='sent-unknown')||mutations.some(m=>m.state==='uncertain'))throw deny('ENTITY_RECYCLE_PARTIAL_PROGRESS_INVALID');
    let gap=false;
    for(const packet of claim.envelope.prepared.packets){
      const originals=[...claim.packets].filter(p=>p.packet.key===packet.key),stored=attempts.filter(a=>a.packet_key===packet.key);
      if(originals.length>1||stored.length>1||originals.length!==stored.length)throw deny('ENTITY_RECYCLE_PARTIAL_PROGRESS_INVALID');
      if(!originals.length){gap=true;if(claim.completed.has(packet.key))throw deny('ENTITY_RECYCLE_PARTIAL_PROGRESS_INVALID');continue;}
      const original=originals[0],attempt=stored[0];this.samePartial(original.packet,packet);
      if(gap||original.execution!==claim||attempt.id!==original.binding.attemptId||attempt.source_id!==source.id||attempt.baseline_id!==baseline.baselineId||attempt.pin_id!==baseline.pinId
        ||attempt.cluster_id!==source.clusterId||attempt.workspace_id!==source.workspaceId||attempt.workflow_execution_id!==source.workflowExecutionId||attempt.packet_order!==packet.order
        ||attempt.intent_id!==source.intentId||attempt.intent_revision!==source.intentRevision||attempt.material_hmac!==source.materialHmac||attempt.change_digest!==source.changeDigest
        ||attempt.packet_manifest_hmac!==source.packetManifestHmac||attempt.method!==packet.method||attempt.permission_action!==packet.permissionAction||attempt.mutation_action!==packet.mutationAction||attempt.original_native_id!==null
        ||attempt.native_type!==packet.nativeType||attempt.native_id!==packet.nativeId||attempt.parent_id!==packet.parentId||attempt.credential_kind!==packet.credentialKind
        ||attempt.body_hmac!==packet.bodyHmac||attempt.before_hmac!==packet.beforeHmac||attempt.path_hmac!==this.secrets.fingerprint(packet.canonicalPath))throw deny('ENTITY_RECYCLE_PARTIAL_PROGRESS_INVALID');
      const pair=events.filter(e=>e.attempt_id===attempt.id),ownReceipts=receipts.filter(r=>r.attempt_id===attempt.id),ownMutations=mutations.filter(m=>m.entity_change_attempt_id===attempt.id);
      if(pair.length>2||new Set(pair.map(e=>e.event_kind)).size!==pair.length||ownReceipts.length>1||ownMutations.length>1)throw deny('ENTITY_RECYCLE_PARTIAL_PROGRESS_INVALID');
      const decoded=new Map<string,any>();
      for(const e of pair){if(!['send-intent','outcome'].includes(e.event_kind)||e.source_id!==source.id||e.baseline_id!==baseline.baselineId||e.pin_id!==baseline.pinId
        ||e.workflow_execution_id!==source.workflowExecutionId||e.cluster_id!==source.clusterId||e.workspace_id!==source.workspaceId)throw deny('ENTITY_RECYCLE_PARTIAL_PROGRESS_INVALID');
        const fact=this.secrets.decrypt<any>(e.fact_ciphertext,entityPacketFactAad(source.clusterId,source.workspaceId,attempt.id,e.event_kind));
        if(fact.version!==1||fact.kind!==e.event_kind||this.secrets.fingerprint(fact)!==e.fact_hmac||fact.observedAt!==new Date(e.observed_at).toISOString()
          ||fact.kind==='outcome'&&(fact.outcome!==e.outcome||(fact.nativeStatus??null)!==e.native_status||(fact.errorCode??null)!==e.error_code))throw deny('ENTITY_RECYCLE_PARTIAL_PROGRESS_INVALID');
        this.samePartial(fact.binding,original.binding);decoded.set(e.event_kind,fact);}
      const mutation=ownMutations[0];
      if(mutation){if(mutation.id!==original.operationId||mutation.entity_change_source_id!==source.id||mutation.entity_change_baseline_id!==baseline.baselineId
        ||mutation.entity_change_packet_key!==packet.key||mutation.workflow_id!==source.workflowId||mutation.actor_id!==source.executionActorId||mutation.cluster_id!==source.clusterId
        ||mutation.workspace_id!==source.workspaceId||mutation.parent_id!==packet.parentId||mutation.credential_kind!==packet.credentialKind||mutation.entity_id!==packet.nativeId
        ||mutation.entity_type!=='credentials'||mutation.action!=='restore'||mutation.idempotency_key!==original.operationKey||mutation.transport_scope!==claim.plan.scope.transportScope
        ||['workflow_execution_id','workflow_step_id','workflow_plan_revision','workflow_plan_hash','configuration_job_id','configuration_execution_id','configuration_step_id','configuration_plan_revision','configuration_plan_hash'].some(k=>mutation[k]!=null))throw deny('ENTITY_RECYCLE_PARTIAL_PROGRESS_INVALID');
        this.samePartial(this.secrets.decrypt(mutation.before_secret,`mutation:${mutation.id}:before`),packet.before);
        this.samePartial(this.secrets.decrypt(mutation.payload_secret,`mutation:${mutation.id}:payload`),packet.body);}
      else if(original.operationId||pair.length||ownReceipts.length)throw deny('ENTITY_RECYCLE_PARTIAL_PROGRESS_INVALID');
      const send=decoded.get('send-intent'),outcome=decoded.get('outcome');
      if(send){this.samePartial(send.evidence,{operationId:original.operationId,method:packet.method,pathHmac:this.secrets.fingerprint(packet.canonicalPath),bodyHmac:packet.bodyHmac,beforeHmac:packet.beforeHmac});}
      if(original.sent!==!!send||original.wireSpent&&!original.sent)throw deny('ENTITY_RECYCLE_PARTIAL_PROGRESS_INVALID');
      if(!original.wireSpent){
        if(outcome||ownReceipts.length||claim.completed.has(packet.key)||original.transportStatus!==undefined||original.responseHmac!==undefined
          ||mutation&&(!['pending','running'].includes(mutation.state)||mutation.remote_completed||mutation.result_secret!==null))throw deny('ENTITY_RECYCLE_PARTIAL_PROGRESS_INVALID');
        gap=true;continue;
      }
      if(!mutation||mutation.state!=='succeeded'||mutation.remote_started!==true||mutation.remote_completed!==true||!mutation.result_secret
        ||original.transportStatus!==201||!original.responseHmac||original.transportHmac!==original.responseHmac||!send)throw deny('ENTITY_RECYCLE_PARTIAL_PROGRESS_INVALID');
      const raw=this.secrets.decrypt<any>(mutation.result_secret,`mutation:${mutation.id}:result`);
      if(raw?.id!==packet.nativeId||entityReferenceId(raw?.consumer)!==packet.parentId||this.secrets.fingerprint(raw)!==original.responseHmac)throw deny('ENTITY_RECYCLE_PARTIAL_PROGRESS_INVALID');
      for(const [field,value]of Object.entries(packet.body!))if(field!=='consumer')this.samePartial(raw[field],value);
      if(outcome){if(outcome.outcome!=='succeeded'||outcome.nativeStatus!==201||outcome.errorCode!==undefined)throw deny('ENTITY_RECYCLE_PARTIAL_PROGRESS_INVALID');
        this.samePartial(outcome.evidence,{operationId:mutation.id,mutationState:'succeeded',remoteCompleted:true,responseHmac:original.responseHmac,metadataComplete:true});}
      if(ownReceipts.length){const r=ownReceipts[0],node=obligation.graph.nodes.find(n=>n.type===packet.nativeType&&n.id===packet.nativeId)!;
        this.samePartial({...r,created_at:null},{attempt_id:attempt.id,cluster_id:source.clusterId,workspace_id:source.workspaceId,source_id:source.id,
          baseline_id:baseline.baselineId,pin_id:baseline.pinId,workflow_execution_id:source.workflowExecutionId,entry_id:obligation.entryId,node_key:node.key,
          packet_key:packet.key,operation_id:mutation.id,operation_key:original.operationKey,native_id:packet.nativeId,direction:'restore',result_hmac:original.responseHmac,verification_hmac:null,created_at:null});}
      if(!claim.completed.has(packet.key)){
        if(checkpoint!=='outcome'||!original.active)throw deny('ENTITY_RECYCLE_PARTIAL_PROGRESS_INVALID');
      }else if(!outcome||!ownReceipts.length||original.outcome!=='succeeded')throw deny('ENTITY_RECYCLE_PARTIAL_PROGRESS_INVALID');
      results.set(packet.key,original.responseHmac);
    }
    if(claim.completed.size!==[...claim.envelope.prepared.packets].filter(p=>claim.completed.has(p.key)).length)throw deny('ENTITY_RECYCLE_PARTIAL_PROGRESS_INVALID');
    const legacy=await tx.query<any>('SELECT * FROM recycle_nodes WHERE entry_id=$1 ORDER BY node_key',[obligation.entryId]);
    if(legacy.length!==7||new Set(legacy.map(n=>n.node_key)).size!==7)throw deny('ENTITY_RECYCLE_PARTIAL_PROGRESS_INVALID');
    for(const node of obligation.graph.nodes){const row=legacy.find(n=>n.node_key===node.key),packet=claim.envelope.prepared.packets.find(p=>p.nativeType===node.type&&p.nativeId===node.id);
      if(!row||row.entry_id!==obligation.entryId||row.entity_type!==node.type||row.original_id!==node.id||row.affected!==true||row.delete_state!=='deleted')throw deny('ENTITY_RECYCLE_PARTIAL_PROGRESS_INVALID');
      this.samePartial(row.dependencies,node.dependencies);
      const present=!packet||claim.completed.has(packet.key),priorState=node.type==='hmac-auth'?'failed':'pending';
      if(present){if(row.restore_state!=='restored'||row.restored_id!==node.id)throw deny('ENTITY_RECYCLE_PARTIAL_PROGRESS_INVALID');}
      else if(checkpoint==='outcome'&&results.has(packet!.key)){
        if(!(row.restore_state===priorState&&row.restored_id===null||row.restore_state==='restored'&&row.restored_id===node.id))throw deny('ENTITY_RECYCLE_PARTIAL_PROGRESS_INVALID');
      }else if(row.restore_state!==priorState||row.restored_id!==null)throw deny('ENTITY_RECYCLE_PARTIAL_PROGRESS_INVALID');
    }
    return results;
  }
  /** Consumes this use's real opaque current observation. Historical SQL
   * explains the old five/current response prefix; it never supplies raw
   * current objects or an EOF flag. No phase cache enters this validator. */
  private async assertPartialCurrentWitness(handle:object,witness:Readonly<EntityRecycleCurrentWitness>,tx=this.db):Promise<void>{
    const claim=this.execution(handle),packet=this.packet(this.context.requireEntityChangePacketFrame(this.context.current()));
    const {obligation,selection,partition}=this.partialRestore(claim),d=witness.descriptor;
    if(packet.execution!==claim||d.source.id!==claim.source.id||this.secrets.fingerprint(d.source)!==this.secrets.fingerprint(claim.source)
      ||this.secrets.fingerprint(d.prepared)!==this.secrets.fingerprint(claim.envelope.prepared)||d.packet.key!==packet.packet.key
      ||this.secrets.fingerprint(d.packet)!==this.secrets.fingerprint(packet.packet)||d.obligation.kind!=='recycle-restore'||d.obligation.entryId!==obligation.entryId
      ||this.secrets.fingerprint(d.obligation)!==this.secrets.fingerprint(obligation)
      ||!['before-native','after-native'].includes(witness.phase)||performance.now()>=witness.monotonicDeadline)throw deny('ENTITY_RECYCLE_PARTIAL_CURRENT_USE_REQUIRED');
    const checkpoint=witness.phase==='after-native'?'outcome':'before-send';
    await this.verifyPartialRestoreCurrent(handle,checkpoint,tx,false,true);
    const progress=await this.partialOwnProgress(claim,checkpoint,tx),expected=new Map<string,string>();
    for(const node of partition.present)expected.set(`${node.type}:${node.id}`,selection.presentNodes.find(value=>value.nodeKey===node.key)!.beforeHmac);
    for(const p of claim.envelope.prepared.packets)if(progress.has(p.key))expected.set(`${p.nativeType}:${p.nativeId}`,progress.get(p.key)!);
    const terminal=expected.size===obligation.graph.nodes.length;
    if((witness.phase==='before-native'||terminal)&&witness.wholeGraphObserved!==true)throw deny('ENTITY_RECYCLE_PARTIAL_CURRENT_EOF_REQUIRED');
    if(witness.nodes.length!==expected.size||new Set(witness.nodes.map(node=>`${node.type}:${node.originalId}`)).size!==expected.size)throw deny('ENTITY_RECYCLE_PARTIAL_CURRENT_CHANGED');
    const root=obligation.graph.nodes.find(node=>node.key===obligation.graph.rootKey)!;
    for(const node of witness.nodes){
      const old=obligation.graph.nodes.find(old=>old.key===node.key);
      if(!old||node.type!==old.type||node.originalId!==old.id||node.data.id!==old.id||expected.get(`${node.type}:${node.originalId}`)!==this.secrets.fingerprint(node.data)
        ||node.type!=='consumers'&&entityReferenceId(node.data.consumer)!==root.id)throw deny('ENTITY_RECYCLE_PARTIAL_CURRENT_CHANGED');
      if(node.type==='basic-auth'){
        const custody=await this.credentialCustody!.get(claim.source.clusterId,root.id,'basic-auth',node.originalId),sealed=selection.presentNodes.find(value=>value.nodeKey===old.key)!;
        if(partialBasicCustodyHmac(old,node.data,custody,root.id,this.secrets)!==sealed.basicCustodyHmac)throw deny('ENTITY_RECYCLE_PARTIAL_CURRENT_CHANGED');
      }
    }
    const missing=obligation.graph.nodes.filter(node=>!expected.has(`${node.type}:${node.id}`)).map(node=>node.key).sort();
    this.samePartial([...witness.absent].sort(),missing);
    if(this.execution(handle)!==claim||performance.now()>=witness.monotonicDeadline)throw deny('ENTITY_RECYCLE_PARTIAL_CURRENT_USE_REQUIRED');
    await this.verifySource(claim.source.id,'packet',tx);
  }
  private async verifyPartialRestoreCurrent(handle:object,checkpoint:'capture'|'packet'|'before-send'|'outcome',tx=this.db,forceWholeGraph=false,factsOnly=false):Promise<void>{
    const claim=this.execution(handle);
    try{
    const {obligation,selection,partition}=this.partialRestore(claim),source=claim.source;
    if(!this.recycleOrigins||!this.recycleGraphs||!this.credentialCustody)throw deny('ENTITY_RECYCLE_PARTIAL_VERIFIER_UNAVAILABLE');
    await this.verifySource(source.id,checkpoint,tx);
    const capture=await this.partialBaseline(claim,tx),progress=await this.partialOwnProgress(claim,checkpoint,tx);
    const input:EntityRecycleOriginReadInput={clusterId:source.clusterId,workspaceId:source.workspaceId,entryId:obligation.entryId,actor:claim.actor,subjectAction:'read'};
    await this.recycleOrigins.verifyFrozenRestoreCoverage(input,selection.history,source.id,tx);
    const unresolved=await tx.one<any>(`SELECT EXISTS(SELECT 1 FROM entity_change_recycle_packets p
      LEFT JOIN entity_change_execution_sources s ON s.id=p.source_id LEFT JOIN workflow_executions e ON e.id=s.workflow_execution_id
      LEFT JOIN entity_change_packet_attempts a ON a.source_id=p.source_id AND a.packet_key=p.packet_key
      LEFT JOIN entity_change_packet_events o ON o.attempt_id=a.id AND o.event_kind='outcome'
      WHERE p.entry_id=$1 AND(s.id IS NULL OR e.id IS NULL OR o.outcome='sent-unknown'
        OR p.source_id<>$2 AND(e.state NOT IN('succeeded','partial','failed') OR a.id IS NOT NULL AND o.id IS NULL)))
      OR EXISTS(SELECT 1 FROM mutation_operations m JOIN entity_change_recycle_packets p ON p.source_id=m.entity_change_source_id AND p.packet_key=m.entity_change_packet_key
        WHERE p.entry_id=$1 AND(m.state='uncertain' OR m.entity_change_source_id<>$2 AND m.state IN('pending','running'))) AS unresolved`,[obligation.entryId,source.id]);
    if(unresolved?.unresolved!==false)throw deny('ENTITY_RECYCLE_PARTIAL_FOREIGN_UNRESOLVED');
    // Outcome observes the original transport/SQL chain. Requiring missing
    // objects or fresh SID here would discard a real, already emitted result.
    if(checkpoint==='outcome'){
      // ALS itself may already have expired after the wire observation. The
      // original execution handle and the one still-active private packet
      // retain provenance without reopening a context or issuing a permit.
      const originals=[...claim.packets].filter(p=>p.active&&p.wireSpent);
      if(originals.length!==1)throw deny('ENTITY_RECYCLE_PARTIAL_OBSERVED_OUTCOME_REQUIRED');
      const observed=originals[0];
      if(observed.execution!==claim||observed.transportStatus!==201||!observed.responseHmac
        ||observed.transportHmac!==observed.responseHmac||progress.get(observed.packet.key)!==observed.responseHmac)throw deny('ENTITY_RECYCLE_PARTIAL_OBSERVED_OUTCOME_REQUIRED');
      return;
    }
    if(factsOnly)return;
    const root=obligation.graph.nodes.find(n=>n.key===obligation.graph.rootKey)!,expected=new Map<string,string>();
    for(const node of partition.present)expected.set(`${node.type}:${node.id}`,selection.presentNodes.find(p=>p.nodeKey===node.key)!.beforeHmac);
    for(const packet of claim.envelope.prepared.packets)if(progress.has(packet.key))expected.set(`${packet.nativeType}:${packet.nativeId}`,progress.get(packet.key)!);
    // Repeated coordinator/native-policy checks share only a private graph
    // observation for this exact original phase. Live authority, historical
    // facts, current seven point reads and Basic custody are never cached.
    // Source/baseline/operation/progress changes start a separate phase.
    const phaseKey=this.secrets.fingerprint({source:source.id,baseline:claim.baseline,selection:selection.selectionHmac,
      operations:[...claim.packets].map(p=>({key:p.packet.key,attempt:p.binding.attemptId,operation:p.operationId??null})),progress:[...progress].sort(([a],[b])=>a.localeCompare(b))});
    const prior=this.partialGraphPhases.get(claim);
    if(forceWholeGraph||prior?.key!==phaseKey)this.partialGraphPhases.delete(claim);
    const graph=!forceWholeGraph&&prior?.key===phaseKey?prior.graph:await this.recycleGraphs.capture(source.clusterId,'consumers',root.id,{purpose:'baseline',budget:{maxPages:100,maxRecords:10000,maxNodes:1000,maxBytes:16*1024*1024}});
    if(graph.complete!==true||graph.purpose!=='baseline'||graph.rootKey!==root.key||graph.nodes.length!==expected.size
      ||new Set(graph.nodes.map(n=>`${n.type}:${n.id}`)).size!==expected.size)throw deny('ENTITY_RECYCLE_PARTIAL_CURRENT_CHANGED');
    for(const node of graph.nodes){const native=`${node.type}:${node.id}`,old=obligation.graph.nodes.find(n=>n.type===node.type&&n.id===node.id);
      if(!old||expected.get(native)!==this.secrets.fingerprint(node.data)||node.path!==old.path)throw deny('ENTITY_RECYCLE_PARTIAL_CURRENT_CHANGED');
      this.samePartial(node.dependencies,old.dependencies);
      if(node.type==='basic-auth'){const remembered=await this.credentialCustody.get(source.clusterId,root.id,'basic-auth',node.id),observed=selection.presentNodes.find(n=>n.nodeKey===old.key)!;
        if(partialBasicCustodyHmac(old,node.data,remembered,root.id,this.secrets)!==observed.basicCustodyHmac)throw deny('ENTITY_RECYCLE_PARTIAL_CURRENT_CHANGED');}}
    await this.context.runInternalRead(source.clusterId,'recycle-check',async()=>{
      for(const object of capture.objects){const node=obligation.graph.nodes.find(n=>n.type===object.nativeType&&n.id===object.nativeId)!,wanted=expected.get(`${node.type}:${node.id}`);
        try{const raw=await this.kong.request(source.clusterId,'GET',node.path);if(!wanted||this.secrets.fingerprint(raw)!==wanted)throw deny('ENTITY_RECYCLE_PARTIAL_CURRENT_CHANGED');}
        catch(error){if(!(error instanceof HttpException&&error.getStatus()===404&&!wanted))throw error;}}
    },{paths:obligation.graph.nodes.map(n=>n.path),maxCalls:7,maxPages:1,maxRecords:7,maxBytes:16*1024*1024,timeoutMs:120000,workspaceId:source.workspaceId});
    if(this.execution(handle)!==claim)throw deny('ENTITY_RECYCLE_PARTIAL_EXECUTION_REQUIRED');
    await this.verifySource(source.id,checkpoint);
    this.partialGraphPhases.set(claim,{key:phaseKey,graph:immutableJson(graph)});
    }catch(error){this.partialGraphPhases.delete(claim);throw error;}
  }
  /** Exclude only this process's genuine, current, entirely unsent restore
   * source during the final pre-send graph recapture. Foreign/pending/unknown
   * chains remain blockers. This returns an evidence identity, never a permit. */
  private async activeRestoreRevalidation(input:Readonly<EntityRecycleOriginReadInput>):Promise<string|null>{
    await this.assertCurrentRecycleOriginScope(input);const frame=this.context.current();
    let current:PacketClaim;
    try{current=this.packet(this.context.requireEntityChangePacketFrame(frame));}catch{return null;}
    const claim=current.execution;
    if(claim.envelope.prepared.metadataObligations.some(o=>o.kind==='recycle-restore'&&o.entryId===input.entryId&&o.partialRestore)){
      if(!this.sourceFrameMatches(claim,frame)||claim.source.executionActorId!==input.actor.user.id||claim.source.clusterId!==input.clusterId
        ||claim.source.workspaceId!==input.workspaceId||current.wireSpent||current.transportStatus!==undefined)return null;
      const {obligation}=this.partialRestore(claim);
      const origin=await this.db.one<any>('SELECT source_id,graph_hmac FROM entity_change_recycle_archives WHERE cluster_id=$1 AND workspace_id=$2 AND entry_id=$3',[input.clusterId,input.workspaceId,input.entryId]);
      if(!origin||origin.source_id===claim.source.id||origin.graph_hmac!==obligation.graphHmac)return null;
      await this.verifySource(claim.source.id,'capture');
      // During first recapture only, the original mutation INSERT is visible
      // on Root's privately held binding transaction, not on a fresh pool
      // connection or the Reader's independent evidence snapshot.
      const evidence=this.pendingBindingTransactions.get(current)??this.db;
      await this.partialBaseline(claim,evidence);await this.partialOwnProgress(claim,'before-send',evidence);
      if(this.sources.get(claim.source.id)!==claim||!claim.active||!this.sourceFrameMatches(claim,this.context.current()))return null;
      return claim.source.id;
    }
    if(!claim.active||this.sources.get(claim.source.id)!==claim||claim.envelope.version!==1||claim.source.executionActorId!==input.actor.user.id
      ||claim.source.sessionId!==frame.sessionId||claim.source.clusterId!==input.clusterId||claim.source.workspaceId!==input.workspaceId
      ||!claim.baseline||claim.completed.size!==0||[...claim.packets].some(p=>p.sent||p.wireSpent||p.transportStatus!==undefined)
      ||!claim.envelope.prepared.metadataObligations.some(o=>o.kind==='recycle-restore'&&o.entryId===input.entryId))return null;
    const obligation=claim.envelope.prepared.metadataObligations.find(o=>o.kind==='recycle-restore'&&o.entryId===input.entryId);
    const origin=await this.db.one<any>('SELECT source_id,graph_hmac FROM entity_change_recycle_archives WHERE cluster_id=$1 AND workspace_id=$2 AND entry_id=$3',[input.clusterId,input.workspaceId,input.entryId]);
    if(!origin||origin.source_id===claim.source.id||!obligation||obligation.kind!=='recycle-restore'||origin.graph_hmac!==obligation.graphHmac)return null;
    await this.verifySource(claim.source.id,'capture');
    const sent=await this.db.one<any>(`SELECT EXISTS(SELECT 1 FROM entity_change_packet_events WHERE source_id=$1 AND event_kind='send-intent')
      OR EXISTS(SELECT 1 FROM mutation_operations WHERE entity_change_source_id=$1 AND(remote_started OR remote_completed OR state='uncertain')) AS emitted`,[claim.source.id]);
    if(sent?.emitted!==false||this.sources.get(claim.source.id)!==claim||!claim.active||claim.completed.size
      ||[...claim.packets].some(p=>p.sent||p.wireSpent||p.transportStatus!==undefined))return null;
    return claim.source.id;
  }
  private recyclePacket(claim:ExecutionClaim,packet:Readonly<EntityChangePacket>):boolean{
    return claim.envelope.prepared.metadataObligations.some(o=>(o.kind==='recycle-archive'||o.kind==='recycle-restore')&&o.packetKeys.includes(packet.key));
  }
  private sourceFrameMatches(claim:ExecutionClaim,frame=this.context.current()):boolean{
    const source=claim.source;
    if(frame.actor?.id!==source.executionActorId||frame.clusterId!==source.clusterId||frame.workspaceId!==source.workspaceId)return false;
    if('origin'in source){
      if(frame.sessionId!=null||!claim.scheduledNamespace)return false;
      try{return this.context.requireEntityScheduledNamespaceHandle()===claim.scheduledNamespace;}catch{return false;}
    }
    return frame.sessionId===source.sessionId;
  }
  private async assertScheduledReservation(frame:KongExecutionFrame,cluster:KongPolicyCluster,_method:string,_path:string):Promise<void>{
    if(frame!==this.context.current()||!frame.actor||frame.clusterId!==cluster.id)throw deny('ENTITY_SCHEDULE_RESERVATION_CONTEXT_REQUIRED');
    const transportScope=await this.kong.transportScope(cluster.id),fallback=conservativeNativeImpact();
    let impact=fallback,ownSchedule:string|null=null;
    if(frame.operation){
      const mutation=await this.db.one<any>("SELECT * FROM mutation_operations WHERE id=$1 AND cluster_id=$2 AND actor_id=$3 AND state='running'",[frame.operation.operationId,cluster.id,frame.actor.id]);
      if(!mutation||mutation.transport_scope!==transportScope)throw deny('ENTITY_SCHEDULE_RESERVATION_OPERATION_REQUIRED');
      if(validImpact(mutation.impact)&&mutation.impact.keyId===fallback.keyId)impact=mutation.impact;
      if(this.context.hasEntityScheduledNamespace()){
        const namespace=await this.context.verifyEntityScheduledNamespace('before-send'),packet=this.packet(this.context.requireEntityChangePacketFrame(frame));
        if(!namespace||!('origin'in packet.execution.source)||!this.sourceFrameMatches(packet.execution,frame)
          ||packet.execution.source.claimId!==namespace.claim.id||mutation.entity_change_source_id!==packet.execution.source.id
          ||mutation.entity_change_attempt_id!==packet.binding.attemptId||mutation.id!==packet.operationId)throw deny('ENTITY_SCHEDULE_RESERVATION_SOURCE_REQUIRED');
        ownSchedule=namespace.claim.scheduleId;
      }
    }
    await this.db.transaction(async tx=>{
      await tx.exec("SELECT pg_advisory_xact_lock(hashtextextended('entity-schedule-impact:'||$1,0))",[transportScope]);
      const conflict=await tx.one(`SELECT s.id FROM entity_change_schedules s JOIN entity_change_schedule_progress p ON p.schedule_id=s.id
        JOIN entity_change_schedule_activations a ON a.schedule_id=s.id WHERE s.transport_scope=$1 AND ($3::uuid IS NULL OR s.id<>$3::uuid)
        AND(p.state IN('claimed','running','uncertain') OR p.state='active' AND s.window_start<=clock_timestamp() AND s.window_end>clock_timestamp())
        AND m6_rejected_impact_collision(s.impact,$2::jsonb) LIMIT 1`,[transportScope,JSON.stringify(impact),ownSchedule]);
      if(conflict)throw stop('ENTITY_SCHEDULE_PHYSICAL_IMPACT_CONFLICT');
    });
    await this.redis.assertLeaseOwnership();
  }
  private async appendKnownRecycleOutcome(handle:object,verification:EntityChangeRecycleDeleteVerification|undefined,tx:DbService):Promise<void>{
    const claim=this.packet(handle),source=claim.execution.source;
    if(!this.recyclePacket(claim.execution,claim.packet)||!claim.operationId||!claim.sent||!claim.wireSpent
      ||claim.transportStatus===undefined||claim.transportStatus<200||claim.transportStatus>299||!claim.responseHmac
      ||claim.responseHmac!==claim.transportHmac)throw deny('ENTITY_CHANGE_NATIVE_RECEIPT_REQUIRED');
    const mutation=await tx.one<any>('SELECT * FROM mutation_operations WHERE id=$1',[claim.operationId]);
    if(!mutation||mutation.state!=='succeeded'||!mutation.remote_started||!mutation.remote_completed||!mutation.result_secret
      ||mutation.entity_change_source_id!==source.id||mutation.entity_change_baseline_id!==claim.binding.baselineId
      ||mutation.entity_change_attempt_id!==claim.binding.attemptId||mutation.entity_change_packet_key!==claim.packet.key
      ||mutation.idempotency_key!==claim.operationKey||mutation.actor_id!==source.executionActorId
      ||this.secrets.fingerprint(this.secrets.decrypt(mutation.result_secret,`mutation:${mutation.id}:result`))!==claim.responseHmac)throw deny('ENTITY_CHANGE_NATIVE_RECEIPT_REQUIRED');
    if(claim.packet.method==='DELETE'){
      if(!verification||verification.version!==1||verification.clusterId!==source.clusterId||verification.workspaceId!==source.workspaceId
        ||verification.packetKey!==claim.packet.key||verification.attemptId!==claim.binding.attemptId||verification.operationId!==claim.operationId
        ||verification.canonicalPath!==claim.packet.canonicalPath||verification.nativeId!==claim.packet.nativeId
        ||claim.transportStatus!==204||claim.transportHmac!==this.secrets.fingerprint(null))throw deny('ENTITY_CHANGE_DELETE_VERIFICATION_INVALID');
      if(claim.packet.nativeType==='targets'){
        if(verification.status!=='target-poststate'||verification.kind!=='target-poststate'||!claim.targetPoststate
          ||claim.targetPoststate.originalNativeId!==claim.packet.nativeId||claim.targetPoststate.address!==verification.address
          ||claim.targetPoststate.historyRetention!==verification.historyRetention
          ||claim.targetPoststate.observationHmac!==verification.observationHmac
          ||claim.targetPoststate.archiveGraphHmac!==verification.archiveGraphHmac
          ||claim.verificationStatus!==undefined)throw deny('ENTITY_CHANGE_DELETE_VERIFICATION_INVALID');
      }else if(verification.status!==404||claim.verificationStatus!==404||claim.verificationPath!==verification.canonicalPath||claim.targetPoststate){
        throw deny('ENTITY_CHANGE_DELETE_VERIFICATION_INVALID');
      }
    }else if(verification)throw deny('ENTITY_CHANGE_DELETE_VERIFICATION_INVALID');
    claim.outcome='succeeded';
    const fact:EntityChangePacketFact={version:1,kind:'outcome',binding:claim.binding,observedAt:new Date().toISOString(),outcome:'succeeded',nativeStatus:claim.transportStatus,
      evidence:{operationId:claim.operationId,mutationState:mutation.state,remoteCompleted:true,responseHmac:claim.responseHmac,metadataComplete:true,
        ...(verification?{deleteVerification:verification}:{})}};
    const proof=Object.freeze({});this.factProofs.set(proof,{claim,hmac:this.secrets.fingerprint(fact)});
    try{await this.facts.appendOutcome(fact,proof,tx);}finally{this.factProofs.delete(proof);}
  }
  private async verifySource(id:string,checkpoint:EntityChangeFactsCheckpoint,tx=this.db):Promise<void>{
    const claim=this.sources.get(id);
    if(!claim){
      const repair=this.noSendSources.get(id),frame=this.context.current();
      if(checkpoint==='outcome'&&repair&&frame.actor?.id===repair.actorId&&frame.sessionId===repair.sessionId
        &&frame.clusterId===repair.clusterId&&frame.workspaceId===repair.workspaceId)return;
      throw deny('ENTITY_CHANGE_SOURCE_REQUIRED');
    }
    const row=await tx.one<any>('SELECT * FROM entity_change_execution_sources WHERE id=$1',[id]);
    const source=claim.source;
    if(!row||this.secrets.fingerprint(decodeEntityExecutionSource(row))!==this.secrets.fingerprint(source)||row.cluster_id!==source.clusterId||row.workspace_id!==source.workspaceId||row.intent_id!==source.intentId||row.intent_revision!==source.intentRevision
      ||row.material_hmac!==source.materialHmac||row.change_digest!==source.changeDigest||row.packet_manifest_hmac!==source.packetManifestHmac
      ||row.workflow_id!==source.workflowId||row.workflow_plan_revision!==source.workflowPlanRevision||row.workflow_plan_hash!==source.workflowPlanHash
      ||row.workflow_execution_id!==source.workflowExecutionId||row.execution_actor_id!==source.executionActorId||String(row.credential_epoch)!==source.credentialEpoch
      ||row.session_id!==source.sessionId||row.permission_version_hmac!==source.permissionVersionHmac||new Date(row.expires_at).toISOString()!==source.expiresAt)throw deny('ENTITY_CHANGE_SOURCE_FACT_MISMATCH');
    // Recording an already observed outcome is not a fresh execution grant.
    // It must survive revocation/expiry so that truthful facts are not lost.
    if(checkpoint==='outcome')return;
    const frame=this.context.current();
    if(!claim.active||!this.sourceFrameMatches(claim,frame)
      ||Date.parse(source.expiresAt)<=Date.now())throw deny('ENTITY_CHANGE_SOURCE_EXPIRED');
    if('origin'in source){
      const current=await this.context.verifyEntityScheduledNamespace(checkpoint==='capture'?'capture':checkpoint==='before-send'?'before-send':'packet');
      if(!current||current.claim.id!==source.claimId||current.claim.scheduleId!==source.scheduleId||current.claim.occurrenceId!==source.occurrenceId
        ||current.claim.workerOwnerHmac!==source.workerOwnerHmac||current.intent.materialHmac!==source.materialHmac||current.intent.packetManifestHmac!==source.packetManifestHmac
        ||current.credentialEpoch!==source.credentialEpoch||current.permissionVersion!==claim.permissionVersion)throw deny('ENTITY_SCHEDULE_SOURCE_NAMESPACE_MISMATCH');
    }else{
    const session=await tx.one<any>(`SELECT s.expires_at,s.credential_epoch,u.credential_epoch AS user_epoch FROM auth_sessions s JOIN users u ON u.id=s.user_id
      WHERE s.id=$1 AND s.user_id=$2 AND s.revoked_at IS NULL AND s.expires_at>now() AND u.status='active' AND u.deleted_at IS NULL AND NOT u.force_password_change`,[source.sessionId,source.executionActorId]);
    if(!session||String(session.credential_epoch)!==source.credentialEpoch||String(session.user_epoch)!==source.credentialEpoch)throw deny('ENTITY_CHANGE_SESSION_REVOKED');
    }
    if(await this.authz.permissionVersion(claim.actor.user,tx)!==claim.permissionVersion)throw deny('ENTITY_CHANGE_PERMISSIONS_CHANGED');
    const state=await tx.one<any>(`SELECT e.state,w.state AS workflow_state FROM workflow_executions e JOIN workflows w ON w.id=e.workflow_id
      WHERE e.id=$1 AND e.workflow_id=$2 AND e.plan_hash=$3 AND e.execution_actor_id=$4 FOR SHARE OF e,w`,[source.workflowExecutionId,source.workflowId,source.workflowPlanHash,source.executionActorId]);
    if(!state||state.state!=='executing'||state.workflow_state!=='executing')throw deny('ENTITY_CHANGE_EXECUTION_NOT_ACTIVE');
    if(!('origin'in source))await this.intents.executionMaterial(claim.plan,claim.actor,tx);
    const cluster=await tx.one<any>('SELECT revision,execution_mode FROM clusters WHERE id=$1 AND deleted_at IS NULL',[source.clusterId]),workspace=await tx.one<any>("SELECT revision,status FROM workspaces WHERE id=$1 AND cluster_id=$2 AND deleted_at IS NULL",[source.workspaceId,source.clusterId]);
    if(!cluster||cluster.revision!==claim.plan.scope.clusterRevision||cluster.execution_mode!==claim.plan.executionMode||!workspace||workspace.revision!==claim.plan.scope.workspaceRevision||workspace.status!=='active'
      ||await this.kong.transportScope(source.clusterId)!==claim.plan.scope.transportScope)throw stop('ENTITY_CHANGE_EXECUTION_SCOPE_CHANGED');
    await this.approval.verifyApprovalSet(claim.plan,{executionId:source.workflowExecutionId,checkpoint:checkpoint==='capture'?'snapshot':'packet'},tx);
    await this.redis.assertLeaseOwnership();
  }
  async verifyHandle(handle:object):Promise<EntityChangePacketExecutionProof>{
    const claim=this.packet(handle),execution=claim.execution,source=execution.source;
    await this.verifySource(source.id,'packet');
    if(!execution.baseline||claim.binding.baselineId!==execution.baseline.baselineId||!claim.packet.dependencies.every(key=>execution.completed.has(key)))throw deny('ENTITY_CHANGE_PACKET_BASELINE_OR_DEPENDENCY_MISSING');
    await this.facts.assertReadyForPacket(source.id,execution.baseline.baselineId,claim.packet.key);
    return{sourceId:source.id,baselineId:execution.baseline.baselineId,packetKey:claim.packet.key,workflowId:source.workflowId,executionId:source.workflowExecutionId,
      stepId:assertEntityChangeWorkflowPlan(execution.plan).id,actorId:source.executionActorId,sessionId:source.sessionId,...('origin'in source?{origin:'scheduled-entity' as const}:{}),clusterId:source.clusterId,workspaceId:source.workspaceId,
      transportScope:execution.plan.scope.transportScope,permissionVersion:execution.permissionVersion,expiresAt:Date.parse(source.expiresAt)};
  }
  private matchMutation(claim:PacketClaim,input:Readonly<MutationContext>):void{
    const packet=claim.packet,source=claim.execution.source,recycle=this.recyclePacket(claim.execution,packet);
    const operation=recycle?undefined:derivePreparedEntityWrite(packet);
    const type=recycle?(packet.credentialKind?'credentials':packet.nativeType):operation!.kind==='core'?operation!.entityType:operation!.kind==='credential'?'credentials':'targets';
    const action=recycle?packet.mutationAction:operation!.action;
    const id=recycle?(packet.method==='DELETE'?packet.nativeId:undefined):operation!.action==='create'?undefined:operation!.kind==='target-weight'?operation!.originalNativeId:operation!.nativeId;
    if(input.clusterId!==source.clusterId||input.workspaceId!==source.workspaceId||input.actor.id!==source.executionActorId||input.entityType!==type||input.action!==action||input.entityId!==id
      ||(input.parentId??null)!==(packet.parentId??null)||(input.credentialKind??null)!==(packet.credentialKind??null)||input.idempotencyKey!==claim.operationKey
      ||this.secrets.fingerprint(input.before??null)!==packet.beforeHmac||this.secrets.fingerprint(input.payload??null)!==this.secrets.fingerprint(mutationPayload(packet))
      ||healthPacket(packet)&&(!claim.healthBefore||this.secrets.fingerprint(input.targetHealthBefore)!==this.secrets.fingerprint(claim.healthBefore))
      ||!healthPacket(packet)&&input.targetHealthBefore!==undefined)throw deny('ENTITY_CHANGE_MUTATION_TUPLE_MISMATCH');
  }
  async mutationBinding(handle:object,input:Readonly<MutationContext>):Promise<ApprovedMutationBindingV3>{
    const claim=this.packet(handle);await this.verifyHandle(handle);this.matchMutation(claim,input);
    return{version:3,workflowId:claim.execution.plan.workflowId,executionId:claim.execution.source.workflowExecutionId,planRevision:claim.execution.plan.planRevision,
      planHash:claim.execution.source.workflowPlanHash,stepId:assertEntityChangeWorkflowPlan(claim.execution.plan).id,sourceId:claim.binding.sourceId,
      baselineId:claim.binding.baselineId,attemptId:claim.binding.attemptId,packetKey:claim.packet.key,nativeId:claim.packet.nativeId,beforeHmac:claim.packet.beforeHmac};
  }
  async bindOperation(handle:object,input:Readonly<MutationContext>,binding:ApprovedMutationBindingV3,operationId:string,tx:DbService):Promise<void>{
    const claim=this.packet(handle);await this.verifySource(claim.binding.sourceId,'packet',tx);this.matchMutation(claim,input);
    const expected=await this.mutationBinding(handle,input);
    if(this.secrets.fingerprint(binding)!==this.secrets.fingerprint(expected)||claim.operationId)throw deny('ENTITY_CHANGE_OPERATION_BINDING_INVALID');
    const row=await tx.one<any>('SELECT * FROM mutation_operations WHERE id=$1',[operationId]);
    if(!row||row.entity_change_source_id!==binding.sourceId||row.entity_change_baseline_id!==binding.baselineId||row.entity_change_attempt_id!==binding.attemptId||row.entity_change_packet_key!==binding.packetKey
      ||row.actor_id!==input.actor.id||row.workflow_id!==binding.workflowId||row.state!=='running'||row.workflow_step_id!==null||row.configuration_step_id!==null)throw deny('ENTITY_CHANGE_OPERATION_FACT_MISMATCH');
    claim.operationId=operationId;
    // The first recapture can read this transaction's just-inserted operation.
    // Bind its verified identity before Root's own pending-source check; this
    // still grants neither a native ticket nor a send, and failure rolls back
    // the operation INSERT together with the outer mutation transaction.
    if(claim.packet.order===1){
      const ready=await this.facts.assertReadyForPacket(claim.binding.sourceId,claim.binding.baselineId,claim.packet.key,tx);
      this.pendingBindingTransactions.set(claim,tx);
      try{await this.capturer.assertUnchanged(ready.capture,claim.execution.envelope.prepared,claim.execution.actor);}
      finally{this.pendingBindingTransactions.delete(claim);}
    }
    if(this.recyclePacket(claim.execution,claim.packet)){
      if(!this.recycleExecutor)throw deny('ENTITY_CHANGE_RECYCLE_EXECUTOR_REQUIRED');
      await this.recycleExecutor.bindPacketOperation(handle,operationId,tx);
    }
  }
  async assertNative(handle:object,input:Readonly<ApprovedNativeRequest>,stage:ApprovedNativeStage):Promise<void>{
    const claim=this.packet(handle),packet=claim.packet,source=claim.execution.source;
    await this.verifyHandle(handle);
    if(!claim.operationId||input.operationId!==claim.operationId||input.clusterId!==source.clusterId||input.workspaceId!==source.workspaceId||!this.sourceFrameMatches(claim.execution,input.frame)
      ||input.transportScope!==claim.execution.plan.scope.transportScope||input.method!==packet.method||input.canonicalPath!==packet.canonicalPath
      ||(input.parentId??null)!==(packet.parentId??null)||(input.credentialKind??null)!==(packet.credentialKind??null)||Object.keys(input.query).length
      ||this.secrets.fingerprint(input.body??null)!==packet.bodyHmac||this.secrets.fingerprint(input.before??null)!==packet.beforeHmac||input.mutationAction!==packet.mutationAction)throw deny('ENTITY_CHANGE_NATIVE_PACKET_MISMATCH');
    const row=await this.db.one<any>('SELECT * FROM mutation_operations WHERE id=$1',[claim.operationId]);
    if(!row||row.state!=='running'||!row.remote_started||row.entity_change_attempt_id!==claim.binding.attemptId
      ||this.secrets.fingerprint(this.secrets.decrypt(row.before_secret,`mutation:${row.id}:before`))!==packet.beforeHmac
      ||this.secrets.fingerprint(this.secrets.decrypt(row.payload_secret,`mutation:${row.id}:payload`))!==this.secrets.fingerprint(mutationPayload(packet)))throw deny('ENTITY_CHANGE_NATIVE_LEDGER_INVALID');
    if(stage==='response'){
      const validResult=packet.method==='DELETE'
        ?this.recyclePacket(claim.execution,packet)&&claim.transportStatus===204&&input.result===null
        :healthPacket(packet)?claim.transportStatus===204&&input.result===null
        :!!input.result&&typeof input.result==='object'&&(input.result as any).id===packet.nativeId;
      if(!claim.sent||claim.transportStatus===undefined||claim.transportStatus<200||claim.transportStatus>299||!validResult
        ||packet.nativeType==='targets'&&packet.originalNativeId!==undefined&&claim.transportStatus!==201
        ||this.secrets.fingerprint(input.result)!==claim.transportHmac)throw deny('ENTITY_CHANGE_NATIVE_RESPONSE_INVALID');
      claim.responseHmac=this.secrets.fingerprint(input.result);
    }else await this.boundary.assertPacket({clusterId:source.clusterId,workspaceId:source.workspaceId,transportScope:claim.execution.plan.scope.transportScope,
      packet,actor:claim.execution.actor,phase:'revalidate',action:'write'});
  }
  async beforeNativeSend(handle:object,input:Readonly<ApprovedNativeRequest>):Promise<void>{
    const claim=this.packet(handle);await this.assertNative(handle,input,'before-send');
    if(healthPacket(claim.packet)){
      const current=await this.capturer.observeHealth(claim.execution.source.clusterId,claim.packet.parentId!,claim.packet.before,claim.execution.actor);
      if(!claim.healthBefore||this.secrets.fingerprint(current)!==this.secrets.fingerprint(claim.healthBefore))throw stop('TARGET_HEALTH_BASELINE_CHANGED');
      await this.verifyHandle(handle);await this.redis.assertLeaseOwnership();
    }
    if(claim.execution.envelope.prepared.metadataObligations.some(o=>o.kind==='recycle-restore'&&o.partialRestore)){
      const original=this.executionOriginals.get(claim.execution);if(!original)throw deny('ENTITY_RECYCLE_PARTIAL_EXECUTION_REQUIRED');
      // This is the genuine Context transport guard, invoked before DNS and
      // again after DNS. Each invocation re-enumerates full collection EOF;
      // no cached phase or reservation can bypass final drift validation.
      const use=claim.partialCurrentUse;
      if(!use?.ready||use.frame!==this.context.current()||use.operationId!==claim.operationId||performance.now()>=use.notAfter)throw deny('ENTITY_RECYCLE_PARTIAL_CURRENT_USE_REQUIRED');
      use.ready=false;
      await this.verifyPartialRestoreCurrent(original,'before-send',this.db,false,true);
    }
    // DNS rebinding protection intentionally invokes prepareWrite twice.
    // The same one allocated native ticket may revalidate its reservation;
    // context forbids allocating any second write ticket for this handle.
    if(claim.sent){if(claim.transportStatus!==undefined)throw deny('ENTITY_CHANGE_PACKET_ALREADY_SENT');return;}
    const fact:EntityChangePacketFact={version:1,kind:'send-intent',binding:claim.binding,observedAt:new Date().toISOString(),
      evidence:{operationId:claim.operationId,method:claim.packet.method,pathHmac:this.secrets.fingerprint(claim.packet.canonicalPath),bodyHmac:claim.packet.bodyHmac,beforeHmac:claim.packet.beforeHmac}};
    const proof=Object.freeze({});this.factProofs.set(proof,{claim,hmac:this.secrets.fingerprint(fact)});
    try{await this.facts.appendSendIntent(fact,proof);claim.sent=true;}finally{this.factProofs.delete(proof);}
  }
  observeTransportResponse(handle:object,input:Readonly<ApprovedNativeRequest>,status:number,result:unknown):void{
    const claim=this.packet(handle);
    if(!claim.sent||!claim.wireSpent||claim.operationId!==input.operationId||claim.transportStatus!==undefined||input.method!==claim.packet.method||input.canonicalPath!==claim.packet.canonicalPath||!Number.isInteger(status)||status<100||status>599)throw deny('ENTITY_CHANGE_TRANSPORT_RESPONSE_INVALID');
    claim.transportStatus=status;claim.transportHmac=this.secrets.fingerprint(result);
  }
  observeVerificationResponse(handle:object,input:Readonly<ApprovedNativeRequest>,status:number):void{
    const claim=this.packet(handle),source=claim.execution.source;
    if(this.context.requireEntityChangePacketFrame(input.frame)!==handle)throw deny('ENTITY_CHANGE_DELETE_VERIFICATION_INVALID');
    // Dependency/whole-graph reads of an original POST/PATCH packet inherit
    // its operation frame. They are ordinary reads, never DELETE evidence.
    // Resolve the genuine private handle/frame first; copied inputs cannot
    // enter even this no-op branch or create a verification observation.
    if(input.method==='GET'&&claim.packet.method!=='DELETE')return;
    // Target DELETE poststate lists parent-scoped /targets and /targets/all under
    // the same recycle-check frame. Those collection GETs are ordinary reads —
    // only the exact packet point path may seal GET404 verification. Ordinary
    // entity DELETE still denies any non-point path (must not soft-ignore).
    if(input.method==='GET'&&input.canonicalPath!==claim.packet.canonicalPath){
      if(claim.packet.nativeType==='targets'&&claim.packet.method==='DELETE')return;
    }
    if(claim.packet.method!=='DELETE'||!claim.wireSpent||claim.transportStatus!==204||claim.transportHmac!==this.secrets.fingerprint(null)
      ||input.method!=='GET'||input.canonicalPath!==claim.packet.canonicalPath||input.operationId!==claim.operationId
      ||input.clusterId!==source.clusterId||input.workspaceId!==source.workspaceId||input.frame.actor?.id!==source.executionActorId
      ||input.frame.sessionId!==source.sessionId||Object.keys(input.query).length||!Number.isInteger(status)||status<100||status>599
      ||claim.verificationStatus===404||claim.targetPoststate)throw deny('ENTITY_CHANGE_DELETE_VERIFICATION_INVALID');
    claim.verificationStatus=status;claim.verificationPath=input.canonicalPath;
  }
  observeTargetDeletePoststate(handle:object,observation:Readonly<{historyRetention:'weight-zero-overlay'|'native-pruned';observationHmac:string;archiveGraphHmac:string;originalNativeId:string;address:string}>):void{
    const claim=this.packet(handle);
    if(claim.packet.nativeType!=='targets'||claim.packet.method!=='DELETE'||!claim.wireSpent||claim.transportStatus!==204
      ||claim.transportHmac!==this.secrets.fingerprint(null)||claim.verificationStatus!==undefined||claim.targetPoststate
      ||!observation||observation.originalNativeId!==claim.packet.nativeId||typeof observation.address!=='string'||!observation.address
      ||observation.address.length>1024||!['weight-zero-overlay','native-pruned'].includes(observation.historyRetention)
      ||!/^[a-f\d]{64}$/i.test(observation.observationHmac)||!/^[a-f\d]{64}$/i.test(observation.archiveGraphHmac)){
      throw deny('ENTITY_CHANGE_DELETE_VERIFICATION_INVALID');
    }
    claim.targetPoststate=Object.freeze({...observation});
  }
  spendTransport(handle:object,input:Readonly<ApprovedNativeRequest>):void{
    const claim=this.packet(handle),frame=this.context.current();
    if(!claim.sent||claim.wireSpent||claim.operationId!==input.operationId||input.method!==claim.packet.method||input.canonicalPath!==claim.packet.canonicalPath
      ||this.secrets.fingerprint(input.body??null)!==claim.packet.bodyHmac||!this.sourceFrameMatches(claim.execution,frame)
      ||Date.parse(claim.execution.source.expiresAt)<=Date.now())throw deny('ENTITY_CHANGE_TRANSPORT_ALREADY_SPENT_OR_EXPIRED');
    // Fresh all-party SQL binding/secret windows are issued only by the
    // fixed current-witness bridge for this ORIGINAL operation. Checking the
    // monotonic minimum here closes every intervening async/DNS/rate wait.
    if(this.recyclePacket(claim.execution,claim.packet)&&(claim.recycleAuthorityOperationId!==claim.operationId
      ||!Number.isFinite(claim.recycleAuthorityNotAfter)||performance.now()>=claim.recycleAuthorityNotAfter!))throw deny('ENTITY_RECYCLE_CURRENT_AUTHORITY_EXPIRED');
    this.redis.assertLeaseActive();claim.wireSpent=true;
  }
  async canExecute(plan:WorkflowPlanV1,actor:EntityActor):Promise<boolean>{
    try{const envelope=await this.intents.executionMaterial(plan,actor);if(envelope.version!==1)return false;
      const recycle=envelope.prepared.metadataObligations.filter(o=>o.kind==='recycle-archive'||o.kind==='recycle-restore');
      if(recycle.length&&(!this.recycleExecutor||!this.recycleExecutor.supports(envelope.prepared)))return false;
      for(const packet of envelope.prepared.packets){
      if(recycle.some(o=>o.packetKeys.includes(packet.key)))continue;
      derivePreparedEntityWrite(packet);
    }return true;}
    catch(error){if(error instanceof HttpException&&error.getStatus()<500)return false;throw error;}
  }
  async canPreflight(plan:WorkflowPlanV1,actor:EntityActor):Promise<boolean>{
    try{const envelope=await this.intents.executionMaterial(plan,actor);
      return envelope.prepared.packets.every(packet=>!healthPacket(packet)||derivePreparedEntityWrite(packet).kind==='target-health');
    }catch(error){if(error instanceof HttpException&&error.getStatus()<500)return false;throw error;}
  }
  async canRollback(plan:WorkflowPlanV1,actor:EntityActor):Promise<boolean>{
    try{
      await this.intents.assertSubject(plan,actor.user.id,'write');
      const row=await this.db.one<any>(`SELECT b.id,b.source_id FROM entity_change_baselines b JOIN workflow_executions e ON e.id=b.workflow_execution_id
        WHERE b.cluster_id=$1 AND b.workspace_id=$2 AND b.workflow_id=$3 AND b.workflow_plan_revision=$4 AND b.workflow_plan_hash=$5
        AND e.state IN('succeeded','partial','failed') AND e.execution_actor_id=$6
        AND EXISTS(SELECT 1 FROM entity_change_packet_events done WHERE done.source_id=b.source_id AND done.outcome='succeeded')
        AND NOT EXISTS(SELECT 1 FROM entity_change_packet_attempts a WHERE a.source_id=b.source_id AND NOT EXISTS(SELECT 1 FROM entity_change_packet_events outcome WHERE outcome.attempt_id=a.id AND outcome.event_kind='outcome'))
        AND NOT EXISTS(SELECT 1 FROM entity_change_packet_events unknown WHERE unknown.source_id=b.source_id AND unknown.outcome='sent-unknown')`,
        [plan.clusterId,plan.workspaceId,plan.workflowId,plan.planRevision,this.secrets.fingerprint(plan),actor.user.id]);
      if(!row)return false;
      const unsupported=await this.db.one<any>(`SELECT EXISTS(SELECT 1 FROM entity_change_packet_attempts a JOIN entity_change_packet_events outcome ON outcome.attempt_id=a.id AND outcome.outcome='succeeded'
        WHERE a.source_id=$1 AND(a.mutation_action NOT IN('update') OR a.native_type='targets' AND(a.original_native_id IS NULL OR outcome.native_status IS DISTINCT FROM 201))) AS blocked`,[row.source_id]);
      return unsupported?.blocked===false;
    }catch(error){if(error instanceof HttpException&&error.getStatus()<500)return false;throw error;}
  }
  async historical(plan:WorkflowPlanV1,actor:EntityActor):Promise<Record<string,unknown>>{
    await this.intents.assertSubject(plan,actor.user.id,'read');
    assertEntityChangeWorkflowPlan(plan);const intentId=plan.subject.id;
    const source=await this.db.one<any>('SELECT id,workflow_execution_id FROM entity_change_execution_sources WHERE cluster_id=$1 AND workspace_id=$2 AND workflow_id=$3 AND workflow_plan_revision=$4 AND workflow_plan_hash=$5',
      [plan.clusterId,plan.workspaceId,plan.workflowId,plan.planRevision,this.secrets.fingerprint(plan)]);
    if(!source)return{intentId,executionId:null,baseline:null,packets:[]};
    const baseline=await this.db.one<any>('SELECT id FROM entity_change_baselines WHERE source_id=$1',[source.id]);
    const packets=await this.db.query<any>(`SELECT a.packet_key,a.packet_order,a.native_type,a.native_id,m.id AS operation_id,e.outcome,e.native_status,e.error_code,
      EXISTS(SELECT 1 FROM entity_change_packet_events sent WHERE sent.attempt_id=a.id AND sent.event_kind='send-intent') AS send_intent
      FROM entity_change_packet_attempts a LEFT JOIN mutation_operations m ON m.entity_change_attempt_id=a.id
      LEFT JOIN entity_change_packet_events e ON e.attempt_id=a.id AND e.event_kind='outcome' WHERE a.source_id=$1 ORDER BY a.packet_order`,[source.id]);
    const targetResultObservation=await this.targetResults?.authenticatedHistoricalProjection(plan,actor,source.id)??null;
    if(targetResultObservation&&packets.filter(p=>p.operation_id===targetResultObservation.operationId&&p.native_type==='targets'&&p.outcome==='sent-unknown'&&p.native_status===null).length!==1)throw stop('ENTITY_CHANGE_TARGET_RECONCILIATION_CHANGED');
    return{intentId,executionId:source.workflow_execution_id,targetResultReconciliationAvailable:await this.targetResults?.canReconcile(plan,actor)??false,baseline:baseline?await this.facts.historicalProjection(plan.clusterId,plan.workspaceId,baseline.id,actor):null,packets:packets.map(p=>({key:p.packet_key,order:p.packet_order,entityType:p.native_type,entityId:p.native_id,
      operationId:p.operation_id??null,state:p.outcome??(p.send_intent?'uncertain':'not_sent'),nativeStatus:p.native_status??null,errorCode:p.error_code??null,
      ...(targetResultObservation&&p.operation_id===targetResultObservation.operationId?{targetResultObservation}:{})}))};
  }
  async reconcileTargetResult(plan:WorkflowPlanV1,body:unknown,actor:EntityActor):Promise<Record<string,unknown>>{
    if(!this.targetResults)throw new ServiceUnavailableException({code:'ENTITY_CHANGE_TARGET_RECONCILIATION_UNAVAILABLE'});
    return this.targetResults.reconcile(plan,body,actor);
  }
  async preflight(plan:WorkflowPlanV1,actor:EntityActor):Promise<Record<string,unknown>>{
    const envelope=await this.intents.executionMaterial(plan,actor),capture=await this.capturer.capture(envelope.prepared,actor);
    return{ready:true,nativeRequestsSent:0,baselinePersisted:false,objects:capture.objects.length,graphs:capture.graphs.length,
      recoverable:capture.nonreversiblePacketKeys.length===0,nonreversiblePacketKeys:capture.nonreversiblePacketKeys,
      ...(capture.nonreversiblePacketKeys.length?{rollbackUnavailableReason:'TARGET_HEALTH_OVERRIDE_ROLLBACK_UNAVAILABLE'}:{})};
  }
  async closeUnsent(plan:WorkflowPlanV1,body:unknown,actor:EntityActor):Promise<Record<string,unknown>>{
    const value=portalObject(body,['revision','planHash','executionId','confirmed','confirm_name']);portalConfirm(value,'native-change');portalRevision(value.revision);
    workflowId(value.executionId);
    const key=workflowKey(actor.idempotencyKey),frame=this.context.current();
    if(!frame.sessionId||frame.actor?.id!==actor.user.id||frame.clusterId!==plan.clusterId||frame.workspaceId!==plan.workspaceId)throw deny();
    if(value.planHash!==this.secrets.fingerprint(plan))throw stop('WORKFLOW_PLAN_CHANGED');
    await this.intents.assertSubject(plan,actor.user.id,'write');
    return this.redis.withLock(`workflow:${plan.workflowId}`,()=>this.db.transaction(async tx=>{
      await tx.one('SELECT version FROM iam_epoch WHERE singleton=true FOR SHARE');
      const row=await tx.one<any>(`SELECT e.id,e.execution_actor_id,e.idempotency_key,e.state,e.started_at,w.revision,w.plan_hash,w.state AS workflow_state,s.id AS source_id,s.expires_at<clock_timestamp() AS expired,
        EXISTS(SELECT 1 FROM entity_change_baselines b WHERE b.source_id=s.id) AS baseline,
        EXISTS(SELECT 1 FROM entity_change_packet_attempts a WHERE a.source_id=s.id) AS attempt,
        EXISTS(SELECT 1 FROM mutation_operations m WHERE m.workflow_id=w.id) AS mutation
        FROM workflow_executions e JOIN workflows w ON w.id=e.workflow_id JOIN entity_change_execution_sources s ON s.workflow_execution_id=e.id
        WHERE e.id=$1 AND e.workflow_id=$2 AND e.cluster_id=$3 AND e.workspace_id=$4 AND e.plan_hash=$5 AND e.plan_revision=$6 FOR UPDATE OF e,w`,
        [value.executionId,plan.workflowId,plan.clusterId,plan.workspaceId,value.planHash,plan.planRevision]);
      if(!row||row.execution_actor_id!==actor.user.id||row.idempotency_key!==key||row.revision!==value.revision||row.plan_hash!==value.planHash||row.state!=='executing'||row.workflow_state!=='executing'
        ||!row.expired||row.baseline||row.attempt||row.mutation||this.sources.has(row.source_id))throw stop('ENTITY_CHANGE_NO_SEND_PROOF_REQUIRED');
      // A separate READ COMMITTED statement observes any baseline transaction
      // that finished while the execution/workflow row locks were acquired.
      const arrived=await tx.one<any>(`SELECT EXISTS(SELECT 1 FROM entity_change_baselines WHERE source_id=$1)
        OR EXISTS(SELECT 1 FROM entity_change_packet_attempts WHERE source_id=$1)
        OR EXISTS(SELECT 1 FROM mutation_operations WHERE workflow_id=$2) AS changed`,[row.source_id,plan.workflowId]);
      if(arrived?.changed)throw stop('ENTITY_CHANGE_NO_SEND_PROOF_REQUIRED');
      await this.intents.assertSubject(plan,actor.user.id,'write',tx);
      const step=assertEntityChangeWorkflowPlan(plan);
      requirePortalCas(await tx.exec("UPDATE workflow_steps SET state='failed',error_code='ENTITY_CHANGE_BASELINE_NOT_PREPARED',started_at=COALESCE(started_at,$2),completed_at=now(),revision=revision+1,updated_at=now() WHERE id=$1 AND state='pending'",[step.id,row.started_at]));
      requirePortalCas(await tx.exec("UPDATE workflow_executions SET state='failed',snapshot_state='failed',completed_at=now(),revision=revision+1,updated_at=now() WHERE id=$1 AND state='executing' AND snapshot_state='pending'",[row.id]));
      requirePortalCas(await tx.exec("UPDATE workflows SET state='failed',revision=revision+1,updated_at=now() WHERE id=$1 AND state='executing' AND revision=$2",[plan.workflowId,row.revision]));
      await this.audit.append({actorId:actor.user.id,clusterId:plan.clusterId,workspaceId:plan.workspaceId,entityType:'workflows',entityId:plan.workflowId,workflowId:plan.workflowId,
        action:'workflow.execute.no-send-closed',result:'success',requestId:actor.requestId,ip:actor.ip,after:{executionId:row.id,knownNoNativeSend:true},scopeHints:this.scopeHints(plan)},tx);
      await this.redis.assertLeaseOwnership();return{workflowId:plan.workflowId,executionId:row.id,state:'failed',knownNoNativeSend:true,nativeRequestsSent:0};
    }));
  }
  /** Only closes an expired HTTP attempt whose immutable transport reservation
   * never existed. It cannot create a source, packet handle or native permit. */
  async reconcileNoSend(plan:WorkflowPlanV1,body:unknown,actor:EntityActor):Promise<Record<string,unknown>>{
    const value=portalObject(body,['revision','planHash','executionId','confirmed','confirm_name']);portalConfirm(value,'native-change');portalRevision(value.revision);workflowId(value.executionId);
    const key=workflowKey(actor.idempotencyKey),frame=this.context.current();
    if(!frame.sessionId||frame.actor?.id!==actor.user.id||frame.clusterId!==plan.clusterId||frame.workspaceId!==plan.workspaceId)throw deny();
    if(value.planHash!==this.secrets.fingerprint(plan))throw stop('WORKFLOW_PLAN_CHANGED');
    await this.intents.assertSubject(plan,actor.user.id,'write');
    return this.redis.withLock(`workflow:${plan.workflowId}`,()=>this.db.transaction(async tx=>{
      await tx.one('SELECT version FROM iam_epoch WHERE singleton=true FOR SHARE');
      const source=await tx.one<any>(`SELECT s.id,e.execution_actor_id,e.idempotency_key,e.state,w.state AS workflow_state,w.revision,s.credential_epoch,
        s.expires_at<clock_timestamp() AS expired,s.session_id FROM entity_change_execution_sources s
        JOIN workflow_executions e ON e.id=s.workflow_execution_id JOIN workflows w ON w.id=e.workflow_id
        WHERE e.id=$1 AND e.workflow_id=$2 AND e.plan_revision=$3 AND e.plan_hash=$4 AND s.cluster_id=$5 AND s.workspace_id=$6 FOR UPDATE OF e,w`,
        [value.executionId,plan.workflowId,plan.planRevision,value.planHash,plan.clusterId,plan.workspaceId]);
      if(!source||!source.expired||!source.session_id||source.execution_actor_id!==actor.user.id||source.idempotency_key!==key||source.revision!==value.revision
        ||!['failed','uncertain'].includes(source.state)||source.workflow_state!==source.state||this.sources.has(source.id))throw stop('ENTITY_CHANGE_NO_SEND_PROOF_REQUIRED');
      const user=await tx.one<any>("SELECT credential_epoch FROM users WHERE id=$1 AND status='active' AND deleted_at IS NULL AND NOT force_password_change",[actor.user.id]);
      if(!user||String(user.credential_epoch)!==String(source.credential_epoch))throw deny('ENTITY_CHANGE_REQUESTER_CREDENTIAL_CHANGED');
      const attempts=await tx.query<any>('SELECT * FROM entity_change_packet_attempts WHERE source_id=$1 ORDER BY packet_order',[source.id]);
      if(attempts.length!==1)throw stop('ENTITY_CHANGE_NO_SEND_PROOF_REQUIRED');
      const a=attempts[0];await tx.exec("SELECT pg_advisory_xact_lock(hashtextextended('entity-change-attempt:'||$1,0))",[a.id]);
      const events=await tx.one<any>('SELECT count(*)::integer AS count FROM entity_change_packet_events WHERE source_id=$1',[source.id]);
      if(events?.count!==0)throw stop('ENTITY_CHANGE_NO_SEND_PROOF_REQUIRED');
      const m=await tx.one<any>('SELECT * FROM mutation_operations WHERE entity_change_attempt_id=$1 FOR UPDATE',[a.id]);
      const step=assertEntityChangeWorkflowPlan(plan);
      if(!m||m.actor_id!==actor.user.id||m.cluster_id!==plan.clusterId||m.workspace_id!==plan.workspaceId||m.workflow_id!==plan.workflowId
        ||m.entity_change_source_id!==source.id||m.entity_change_baseline_id!==a.baseline_id||m.entity_change_packet_key!==a.packet_key||m.entity_change_attempt_id!==a.id
        ||m.idempotency_key!==`entity-${value.executionId}-${a.packet_order}`
        ||m.state!=='uncertain'||m.error_code!=='42501'||m.remote_completed||m.result_secret!==null||m.entity_id!==a.native_id
        ||m.action!==a.mutation_action||m.entity_type!==(a.credential_kind?'credentials':a.native_type)||(m.parent_id??null)!==(a.parent_id??null)
        ||(m.credential_kind??null)!==(a.credential_kind??null))throw stop('ENTITY_CHANGE_NO_SEND_PROOF_REQUIRED');
      const sealedBefore=this.secrets.decrypt(m.before_secret,`mutation:${m.id}:before`),sealedPayload=this.secrets.decrypt(m.payload_secret,`mutation:${m.id}:payload`);
      if(this.secrets.fingerprint(sealedBefore)!==a.before_hmac||this.secrets.fingerprint(sealedPayload)!==a.body_hmac)throw deny('ENTITY_CHANGE_NO_SEND_PROOF_REQUIRED');
      await this.intents.assertSubject(plan,actor.user.id,'write',tx);
      const binding:EntityChangePacketAttemptBinding={sourceId:source.id,baselineId:a.baseline_id,pinId:a.pin_id,packetKey:a.packet_key,attemptId:a.id};
      const fact:EntityChangePacketFact={version:1,kind:'outcome',outcome:'rejected-before-send',binding,observedAt:new Date().toISOString(),errorCode:'ENTITY_CHANGE_SEND_RESERVATION_FAILED',
        evidence:{operationId:m.id,knownNoNativeSend:true,transportAuthorizationRecorded:false,metadataReconciled:true}};
      const proof=Object.freeze({});this.noSendProofs.set(proof,{sourceId:source.id,bindingHmac:this.secrets.fingerprint(binding),factHmac:this.secrets.fingerprint(fact)});
      this.noSendSources.set(source.id,{actorId:actor.user.id,sessionId:frame.sessionId!,clusterId:plan.clusterId,workspaceId:plan.workspaceId});
      try{await this.facts.appendOutcome(fact,proof,tx);}finally{this.noSendProofs.delete(proof);this.noSendSources.delete(source.id);}
      requirePortalCas(await tx.exec("UPDATE mutation_operations SET state='failed',error_code='ENTITY_CHANGE_SEND_RESERVATION_FAILED',updated_at=now() WHERE id=$1 AND state='uncertain' AND NOT remote_completed",[m.id]));
      if(source.state==='uncertain'){
        requirePortalCas(await tx.exec("UPDATE workflow_executions SET state='failed',revision=revision+1,updated_at=now() WHERE id=$1 AND state='uncertain'",[value.executionId]));
        requirePortalCas(await tx.exec("UPDATE workflows SET state='failed',revision=revision+1,updated_at=now() WHERE id=$1 AND state='uncertain'",[plan.workflowId]));
        await tx.exec("UPDATE workflow_steps SET state='failed',error_code='ENTITY_CHANGE_SEND_RESERVATION_FAILED',revision=revision+1,updated_at=now() WHERE id=$1 AND state='uncertain'",[step.id]);
      }
      await this.audit.append({actorId:actor.user.id,clusterId:plan.clusterId,workspaceId:plan.workspaceId,entityType:'workflows',entityId:plan.workflowId,workflowId:plan.workflowId,
        action:'workflow.execute.no-send-reconciled',result:'success',requestId:actor.requestId,ip:actor.ip,after:{executionId:value.executionId,operationId:m.id,knownNoNativeSend:true},scopeHints:this.scopeHints(plan)},tx);
      await this.redis.assertLeaseOwnership();return{workflowId:plan.workflowId,executionId:value.executionId,state:'failed',knownNoNativeSend:true,nativeRequestsSent:0,metadataReconciled:true};
    }));
  }
  /** Close only authenticated Consumer/credential restore metadata. The original
   * Root no-send outcome is read, never replaced; this issues no packet permit. */
  async reconcileTerminalMetadata(plan:WorkflowPlanV1,body:unknown,actor:EntityActor):Promise<Record<string,unknown>>{
    const value=portalObject(body,['revision','planHash','executionId','confirmed','confirm_name']);
    portalConfirm(value,'native-change');portalRevision(value.revision);workflowId(value.executionId);
    assertEntityChangeWorkflowPlan(plan);const key=workflowKey(actor.idempotencyKey),frame=this.context.current();
    const actorHmac=this.secrets.fingerprint(actor),planHash=this.secrets.fingerprint(plan);
    if(frame.kind!=='actor'||frame.module!=='workflows'||frame.action!=='write'||frame.operation||frame.archive||frame.purpose
      ||!frame.sessionId||frame.actor?.id!==actor.user.id||this.secrets.fingerprint(frame.actor)!==this.secrets.fingerprint(actor.user)
      ||frame.clusterId!==plan.clusterId||frame.workspaceId!==plan.workspaceId||actor.workspaceId!==plan.workspaceId
      ||frame.idempotencyKey!==key)throw deny('ENTITY_CHANGE_TERMINAL_METADATA_ACTOR_REQUIRED');
    if(value.planHash!==planHash)throw stop('WORKFLOW_PLAN_CHANGED');
    const requestHmac=this.secrets.fingerprint({workflowId:plan.workflowId,actorId:actor.user.id,key,...value});
    await this.intents.assertSubject(plan,actor.user.id,'write');
    return this.redis.withLock(`workflow:${plan.workflowId}`,()=>this.redis.withLock(`mutation:${plan.scope.transportScope}`,()=>this.db.transaction(async tx=>{
      await tx.one('SELECT version FROM iam_epoch WHERE singleton=true FOR SHARE');
      const current=await this.plans.load(plan.clusterId,plan.workspaceId,plan.workflowId,tx);
      if(current.row.revision!==value.revision||current.row.plan_hash!==planHash||this.secrets.fingerprint(current.plan)!==planHash
        ||current.row.state!=='partial')throw stop('WORKFLOW_PLAN_CHANGED');
      const execution=await tx.one<any>(`SELECT e.*,w.state AS workflow_state,w.revision AS workflow_revision FROM workflow_executions e
        JOIN workflows w ON w.id=e.workflow_id WHERE e.id=$1 AND e.workflow_id=$2 AND e.cluster_id=$3 AND e.workspace_id=$4
        AND e.plan_revision=$5 AND e.plan_hash=$6 FOR UPDATE OF e,w`,[value.executionId,plan.workflowId,plan.clusterId,plan.workspaceId,plan.planRevision,planHash]);
      if(!execution||execution.execution_actor_id!==actor.user.id||execution.idempotency_key!==key||execution.state!=='partial'
        ||execution.workflow_state!=='partial'||execution.workflow_revision!==value.revision||execution.snapshot_state!=='ready'||!execution.completed_at)
        throw stop('ENTITY_CHANGE_TERMINAL_METADATA_PROOF_INVALID');
      const sourceRow=await tx.one<any>('SELECT * FROM entity_change_execution_sources WHERE workflow_execution_id=$1 AND cluster_id=$2 AND workspace_id=$3',
        [value.executionId,plan.clusterId,plan.workspaceId]);
      const source=decodeEntityExecutionSource(sourceRow);
      if('origin'in source||source.workflowId!==plan.workflowId||source.workflowPlanHash!==planHash||source.workflowPlanRevision!==plan.planRevision
        ||source.executionActorId!==actor.user.id||source.workflowExecutionId!==value.executionId||Date.parse(source.expiresAt)>Date.now()
        ||this.sources.has(source.id))throw stop('ENTITY_CHANGE_TERMINAL_METADATA_PROOF_INVALID');
      const session=await tx.one<any>(`SELECT s.credential_epoch,u.credential_epoch AS user_epoch FROM auth_sessions s JOIN users u ON u.id=s.user_id
        WHERE s.id=$1 AND s.user_id=$2 AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() AND s.credential_epoch=u.credential_epoch
        AND u.status='active' AND u.deleted_at IS NULL AND NOT u.force_password_change FOR SHARE OF s,u`,[frame.sessionId,actor.user.id]);
      if(!session||String(session.credential_epoch)!==source.credentialEpoch||String(session.user_epoch)!==source.credentialEpoch)
        throw deny('ENTITY_CHANGE_SESSION_REVOKED');
      const permissionVersion=await this.authz.permissionVersion(actor.user,tx);
      if(this.secrets.fingerprint(permissionVersion)!==source.permissionVersionHmac)throw deny('ENTITY_CHANGE_PERMISSIONS_CHANGED');
      const cluster=await tx.one<any>('SELECT revision,execution_mode,admin_url,transport_scope FROM clusters WHERE id=$1 AND deleted_at IS NULL FOR SHARE',[plan.clusterId]);
      const workspace=await tx.one<any>("SELECT revision,status FROM workspaces WHERE id=$1 AND cluster_id=$2 AND deleted_at IS NULL FOR SHARE",[plan.workspaceId,plan.clusterId]);
      if(!cluster||cluster.revision!==plan.scope.clusterRevision||cluster.execution_mode!==plan.executionMode
        ||!workspace||workspace.revision!==plan.scope.workspaceRevision||workspace.status!=='active'
        ||transportScopeFor(cluster.admin_url,cluster.transport_scope)!==plan.scope.transportScope)throw stop('ENTITY_CHANGE_EXECUTION_SCOPE_CHANGED');
      // This verifies current subject, credential epoch and policy against the
      // original sealed intent. It does not refresh the expired native source.
      const envelope=await this.intents.executionMaterial(plan,actor,tx);
      const restore=envelope.prepared.metadataObligations.filter(o=>o.kind==='recycle-restore');
      if(envelope.version!==1||restore.length!==1||restore[0].kind!=='recycle-restore')throw stop('ENTITY_CHANGE_TERMINAL_METADATA_SHAPE_UNSUPPORTED');
      const entryId=workflowId(restore[0].entryId);
      // SQL21 completion takes its attempt lock before SQL23 takes entry lock.
      // Keep that ordering; immutable rows are never updated by this endpoint.
      const attempts=await tx.query<any>('SELECT id FROM entity_change_packet_attempts WHERE source_id=$1 ORDER BY packet_order,id',[source.id]);
      for(const attempt of attempts)await tx.exec("SELECT pg_advisory_xact_lock(hashtextextended('entity-change-attempt:'||$1,0))",[workflowId(attempt.id)]);
      await tx.exec("SELECT pg_advisory_xact_lock(hashtextextended('entity-change-recycle-entry:'||$1,0))",[entryId]);
      await tx.query('SELECT id FROM mutation_operations WHERE entity_change_source_id=$1 ORDER BY id FOR UPDATE',[source.id]);
      await tx.one('SELECT id FROM recycle_entries WHERE cluster_id=$1 AND workspace_id=$2 AND id=$3 FOR UPDATE',[plan.clusterId,plan.workspaceId,entryId]);
      await tx.query('SELECT node_key FROM recycle_nodes WHERE entry_id=$1 ORDER BY node_key FOR UPDATE',[entryId]);
      const certificate=await certifyTerminalRecycleMetadata({tx,secrets:this.secrets,facts:this.facts,plan,envelope,source,actor});
      if(certificate.entryId!==entryId||this.sources.has(source.id))throw stop('ENTITY_CHANGE_TERMINAL_METADATA_PROOF_INVALID');
      const after={executionId:value.executionId,sourceId:source.id,entryId,operationId:certificate.failedOperationId,
        outcomeEventId:certificate.outcomeEventId,outcomeFactHmac:certificate.outcomeFactHmac,proofHmac:certificate.proofHmac,requestHmac,
        workflowState:'partial',executionState:'partial',operationState:'failed',entryState:'partially_restored',nodeRestoreState:'failed',
        nativeSuccesses:5,knownNotSent:1,unattempted:1,nativeRequestsSent:0,metadataReconciled:true};
      const audits=await tx.query<any>(`SELECT id,event_hash,after,result FROM audit_events WHERE cluster_id=$1 AND workspace_id=$2
        AND entity_type='workflows' AND entity_id=$3::text AND workflow_id=$3::uuid AND actor_id=$4 AND action='workflow.execute.terminal-metadata-reconciled'
        AND after->>'requestHmac'=$5 ORDER BY occurred_at,id LIMIT 2`,[plan.clusterId,plan.workspaceId,plan.workflowId,actor.user.id,requestHmac]);
      let auditId:string,eventHash:string;
      if(certificate.alreadyClosed){
        if(audits.length!==1||audits[0].result!=='failed'||this.secrets.fingerprint(audits[0].after)!==this.secrets.fingerprint(after))
          throw stop('ENTITY_CHANGE_TERMINAL_METADATA_PROOF_INVALID');
        auditId=audits[0].id;eventHash=audits[0].event_hash;
      }else{
        if(audits.length)throw stop('ENTITY_CHANGE_TERMINAL_METADATA_PROOF_INVALID');
        requirePortalCas(await tx.exec(`UPDATE mutation_operations SET state='failed',updated_at=now() WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3
          AND entity_change_source_id=$4 AND entity_change_attempt_id=$5 AND state='uncertain' AND remote_started=true AND remote_completed=false AND result_secret IS NULL`,
          [certificate.failedOperationId,plan.clusterId,plan.workspaceId,source.id,certificate.failedAttemptId]));
        requirePortalCas(await tx.exec("UPDATE recycle_nodes SET restore_state='failed',safe_error='原执行已核验未发送；恢复需要新的变更意图',updated_at=now() WHERE entry_id=$1 AND node_key=$2 AND restore_state='pending' AND restored_id IS NULL",[entryId,certificate.failedNodeKey]));
        requirePortalCas(await tx.exec("UPDATE recycle_entries SET state='partially_restored',updated_at=now() WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3 AND state='restoring' AND mutation_id IS NULL",[entryId,plan.clusterId,plan.workspaceId]));
        const receipt=await this.audit.append({actorId:actor.user.id,clusterId:plan.clusterId,workspaceId:plan.workspaceId,entityType:'workflows',entityId:plan.workflowId,
          workflowId:plan.workflowId,action:'workflow.execute.terminal-metadata-reconciled',result:'failed',requestId:actor.requestId,ip:actor.ip,
          before:{operationState:'uncertain',entryState:'restoring',nodeRestoreState:'pending'},after,scopeHints:this.scopeHints(plan)},tx);
        auditId=receipt.id;eventHash=receipt.eventHash;
      }
      await this.intents.assertSubject(plan,actor.user.id,'write',tx);
      if(this.context.current()!==frame||this.secrets.fingerprint(actor)!==actorHmac||this.sources.has(source.id)
        ||await this.authz.permissionVersion(actor.user,tx)!==permissionVersion)throw deny('ENTITY_CHANGE_PERMISSIONS_CHANGED');
      await this.redis.assertLeaseOwnership();
      return{workflowId:plan.workflowId,executionId:value.executionId,entryId,operationId:certificate.failedOperationId,state:'partial',terminal:'partial',
        nativeRequestsSent:0,metadataReconciled:true,alreadyReconciled:certificate.alreadyClosed,auditId,eventHash};
    })));
  }
  async reconcilePartialRestoreNoSend(plan:WorkflowPlanV1,body:unknown,actor:EntityActor):Promise<Record<string,unknown>>{
    const value=portalObject(body,['revision','planHash','executionId','confirmed','confirm_name']);
    portalConfirm(value,'native-change');portalRevision(value.revision);workflowId(value.executionId);
    assertEntityChangeWorkflowPlan(plan);const key=workflowKey(actor.idempotencyKey),frame=this.context.current();
    const actorHmac=this.secrets.fingerprint(actor),planHash=this.secrets.fingerprint(plan);
    if(frame.kind!=='actor'||frame.module!=='workflows'||frame.action!=='write'||frame.operation||frame.archive||frame.purpose
      ||!frame.sessionId||frame.actor?.id!==actor.user.id||this.secrets.fingerprint(frame.actor)!==this.secrets.fingerprint(actor.user)
      ||frame.clusterId!==plan.clusterId||frame.workspaceId!==plan.workspaceId||actor.workspaceId!==plan.workspaceId
      ||frame.idempotencyKey!==key)throw deny('ENTITY_CHANGE_PARTIAL_NO_SEND_TERMINAL_ACTOR_REQUIRED');
    if(value.planHash!==planHash)throw stop('WORKFLOW_PLAN_CHANGED');
    const requestHmac=this.secrets.fingerprint({workflowId:plan.workflowId,actorId:actor.user.id,key,...value});
    await this.intents.assertSubject(plan,actor.user.id,'write');
    return this.redis.withLock(`workflow:${plan.workflowId}`,()=>this.redis.withLock(`mutation:${plan.scope.transportScope}`,()=>this.db.transaction(async tx=>{
      await tx.one('SELECT version FROM iam_epoch WHERE singleton=true FOR SHARE');
      const current=await this.plans.load(plan.clusterId,plan.workspaceId,plan.workflowId,tx);
      if(current.row.revision!==value.revision||current.row.plan_hash!==planHash||this.secrets.fingerprint(current.plan)!==planHash
        ||current.row.state!=='failed')throw stop('WORKFLOW_PLAN_CHANGED');
      const execution=await tx.one<any>(`SELECT e.*,w.state AS workflow_state,w.revision AS workflow_revision FROM workflow_executions e
        JOIN workflows w ON w.id=e.workflow_id WHERE e.id=$1 AND e.workflow_id=$2 AND e.cluster_id=$3 AND e.workspace_id=$4
        AND e.plan_revision=$5 AND e.plan_hash=$6 FOR UPDATE OF e,w`,[value.executionId,plan.workflowId,plan.clusterId,plan.workspaceId,plan.planRevision,planHash]);
      if(!execution||execution.execution_actor_id!==actor.user.id||execution.idempotency_key!==key||execution.state!=='failed'
        ||execution.workflow_state!=='failed'||execution.workflow_revision!==value.revision||execution.snapshot_state!=='ready'||!execution.completed_at)
        throw stop('ENTITY_CHANGE_PARTIAL_NO_SEND_TERMINAL_PROOF_INVALID');
      const sourceRow=await tx.one<any>('SELECT * FROM entity_change_execution_sources WHERE workflow_execution_id=$1 AND cluster_id=$2 AND workspace_id=$3',
        [value.executionId,plan.clusterId,plan.workspaceId]);
      const source=decodeEntityExecutionSource(sourceRow);
      if('origin'in source||source.workflowId!==plan.workflowId||source.workflowPlanHash!==planHash||source.workflowPlanRevision!==plan.planRevision
        ||source.executionActorId!==actor.user.id||source.workflowExecutionId!==value.executionId||Date.parse(source.expiresAt)>Date.now()
        ||this.sources.has(source.id))throw stop('ENTITY_CHANGE_PARTIAL_NO_SEND_TERMINAL_PROOF_INVALID');
      const session=await tx.one<any>(`SELECT s.credential_epoch,u.credential_epoch AS user_epoch FROM auth_sessions s JOIN users u ON u.id=s.user_id
        WHERE s.id=$1 AND s.user_id=$2 AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() AND s.credential_epoch=u.credential_epoch
        AND u.status='active' AND u.deleted_at IS NULL AND NOT u.force_password_change FOR SHARE OF s,u`,[frame.sessionId,actor.user.id]);
      if(!session||String(session.credential_epoch)!==source.credentialEpoch||String(session.user_epoch)!==source.credentialEpoch)
        throw deny('ENTITY_CHANGE_SESSION_REVOKED');
      const permissionVersion=await this.authz.permissionVersion(actor.user,tx);
      // Historical permissionVersion is not reused as current authority. The current
      // complete owner/subject/approval checks and IAM fence below remain mandatory.
      const cluster=await tx.one<any>('SELECT revision,execution_mode,admin_url,transport_scope FROM clusters WHERE id=$1 AND deleted_at IS NULL FOR SHARE',[plan.clusterId]);
      const workspace=await tx.one<any>("SELECT revision,status FROM workspaces WHERE id=$1 AND cluster_id=$2 AND deleted_at IS NULL FOR SHARE",[plan.workspaceId,plan.clusterId]);
      if(!cluster||cluster.revision!==plan.scope.clusterRevision||cluster.execution_mode!==plan.executionMode
        ||!workspace||workspace.revision!==plan.scope.workspaceRevision||workspace.status!=='active'
        ||transportScopeFor(cluster.admin_url,cluster.transport_scope)!==plan.scope.transportScope)throw stop('ENTITY_CHANGE_EXECUTION_SCOPE_CHANGED');
      // This verifies current subject, credential epoch and policy against the
      // original sealed intent. It does not refresh the expired native source.
      const envelope=await this.intents.executionMaterial(plan,actor,tx);
      const restore=envelope.prepared.metadataObligations.filter(o=>o.kind==='recycle-restore');
      if(envelope.version!==1||restore.length!==1||restore[0].kind!=='recycle-restore')throw stop('ENTITY_CHANGE_PARTIAL_NO_SEND_TERMINAL_SHAPE_UNSUPPORTED');
      if(plan.executionMode!=='approval'||!plan.approvalRequired)throw stop('ENTITY_CHANGE_PARTIAL_NO_SEND_TERMINAL_APPROVAL_REQUIRED');
      const approvalSet=await this.approval.verifyApprovalSet(plan,{executionId:value.executionId,checkpoint:'packet'},tx);
      if(!approvalSet.reviewers.length)throw stop('ENTITY_CHANGE_PARTIAL_NO_SEND_TERMINAL_APPROVAL_REQUIRED');
      for(const reviewer of approvalSet.reviewers)await this.boundary.assertReviewer(reviewer.userId,envelope.prepared,tx);
      const entryId=workflowId(restore[0].entryId);
      // SQL21 completion takes its attempt lock before SQL23 takes entry lock.
      // Keep that ordering; immutable rows are never updated by this endpoint.
      const attempts=await tx.query<any>('SELECT id FROM entity_change_packet_attempts WHERE source_id=$1 ORDER BY packet_order,id',[source.id]);
      for(const attempt of attempts)await tx.exec("SELECT pg_advisory_xact_lock(hashtextextended('entity-change-attempt:'||$1,0))",[workflowId(attempt.id)]);
      await tx.exec("SELECT pg_advisory_xact_lock(hashtextextended('entity-change-recycle-entry:'||$1,0))",[entryId]);
      await tx.query('SELECT id FROM mutation_operations WHERE entity_change_source_id=$1 ORDER BY id FOR UPDATE',[source.id]);
      await tx.one('SELECT id FROM recycle_entries WHERE cluster_id=$1 AND workspace_id=$2 AND id=$3 FOR UPDATE',[plan.clusterId,plan.workspaceId,entryId]);
      await tx.query('SELECT node_key FROM recycle_nodes WHERE entry_id=$1 ORDER BY node_key FOR UPDATE',[entryId]);
      if(!this.recycleOrigins)throw stop('ENTITY_CHANGE_PARTIAL_NO_SEND_TERMINAL_READER_REQUIRED');
      const certificate=await certifyPartialNoSendTerminalMetadata({tx,secrets:this.secrets,reader:this.recycleOrigins,plan,envelope,source,actor});
      if(certificate.entryId!==entryId||this.sources.has(source.id))throw stop('ENTITY_CHANGE_PARTIAL_NO_SEND_TERMINAL_PROOF_INVALID');
      const nodeProjection=await tx.one<any>('SELECT restore_state,restored_id FROM recycle_nodes WHERE entry_id=$1 AND node_key=$2',[entryId,certificate.failedNodeKey]);
      if(!nodeProjection||nodeProjection.restored_id!==null||!['pending','failed'].includes(nodeProjection.restore_state))
        throw stop('ENTITY_CHANGE_PARTIAL_NO_SEND_TERMINAL_PROOF_INVALID');
      const after={shape:'partial-no-send',executionId:value.executionId,sourceId:source.id,entryId,operationId:certificate.failedOperationId,
        outcomeEventId:certificate.outcomeEventId,outcomeFactHmac:certificate.outcomeFactHmac,proofHmac:certificate.proofHmac,requestHmac,
        workflowState:'failed',executionState:'failed',operationState:'failed',entryState:'partially_restored',nodeRestoreState:'failed',
        coveredPresent:5,nativeSuccesses:0,knownNotSent:1,unattempted:1,nativeRequestsSent:0,metadataReconciled:true};
      const audits=await tx.query<any>(`SELECT id,event_hash,after,result FROM audit_events WHERE cluster_id=$1 AND workspace_id=$2
        AND entity_type='workflows' AND entity_id=$3::text AND workflow_id=$3::uuid AND actor_id=$4 AND action='workflow.execute.terminal-metadata-reconciled'
        AND after->>'requestHmac'=$5 ORDER BY occurred_at,id LIMIT 2`,[plan.clusterId,plan.workspaceId,plan.workflowId,actor.user.id,requestHmac]);
      let auditId:string,eventHash:string;
      if(certificate.alreadyClosed){
        if(audits.length!==1||audits[0].result!=='failed'||this.secrets.fingerprint(audits[0].after)!==this.secrets.fingerprint(after))
          throw stop('ENTITY_CHANGE_PARTIAL_NO_SEND_TERMINAL_PROOF_INVALID');
        auditId=audits[0].id;eventHash=audits[0].event_hash;
      }else{
        if(audits.length)throw stop('ENTITY_CHANGE_PARTIAL_NO_SEND_TERMINAL_PROOF_INVALID');
        if(nodeProjection.restore_state==='pending')requirePortalCas(await tx.exec("UPDATE recycle_nodes SET restore_state='failed',safe_error='原执行已核验未发送；恢复需要新的变更意图',updated_at=now() WHERE entry_id=$1 AND node_key=$2 AND restore_state='pending' AND restored_id IS NULL",[entryId,certificate.failedNodeKey]));
        requirePortalCas(await tx.exec("UPDATE recycle_entries SET state='partially_restored',updated_at=now() WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3 AND state='restoring' AND mutation_id IS NULL",[entryId,plan.clusterId,plan.workspaceId]));
        const receipt=await this.audit.append({actorId:actor.user.id,clusterId:plan.clusterId,workspaceId:plan.workspaceId,entityType:'workflows',entityId:plan.workflowId,
          workflowId:plan.workflowId,action:'workflow.execute.terminal-metadata-reconciled',result:'failed',requestId:actor.requestId,ip:actor.ip,
          before:{operationState:'failed',entryState:'restoring',nodeRestoreState:nodeProjection.restore_state},after,scopeHints:this.scopeHints(plan)},tx);
        auditId=receipt.id;eventHash=receipt.eventHash;
      }
      await this.intents.assertSubject(plan,actor.user.id,'write',tx);
      await this.approval.verifyApprovalSet(plan,{executionId:value.executionId,checkpoint:'packet'},tx);
      if(this.context.current()!==frame||this.secrets.fingerprint(actor)!==actorHmac||this.sources.has(source.id)
        ||await this.authz.permissionVersion(actor.user,tx)!==permissionVersion)throw deny('ENTITY_CHANGE_PERMISSIONS_CHANGED');
      await this.redis.assertLeaseOwnership();
      return{workflowId:plan.workflowId,executionId:value.executionId,entryId,operationId:certificate.failedOperationId,state:'failed',terminal:'failed',
        nativeRequestsSent:0,metadataReconciled:true,alreadyReconciled:certificate.alreadyClosed,auditId,eventHash};
    })));
  }
  async rollbackPrepare(plan:WorkflowPlanV1,body:unknown,actor:EntityActor):Promise<Record<string,unknown>>{
    const value=portalObject(body,['revision','planHash','executionId','confirmed','confirm_name']);portalConfirm(value,'native-change');portalRevision(value.revision);
    workflowId(value.executionId);
    const key=workflowKey(actor.idempotencyKey),frame=this.context.current();if(!frame.sessionId||frame.actor?.id!==actor.user.id||frame.workspaceId!==plan.workspaceId||frame.clusterId!==plan.clusterId)throw deny();
    await this.intents.assertSubject(plan,actor.user.id,'read');
    const loaded=await this.plans.load(plan.clusterId,plan.workspaceId,plan.workflowId);
    if(value.revision!==loaded.row.revision||value.planHash!==loaded.row.plan_hash)throw stop('WORKFLOW_PLAN_CHANGED');
    const source=await this.db.one<any>(`SELECT s.id,b.id AS baseline_id,e.id AS execution_id,e.state,b.material_ciphertext,b.baseline_hmac,b.capture_hmac
      FROM entity_change_execution_sources s JOIN entity_change_baselines b ON b.source_id=s.id JOIN workflow_executions e ON e.id=s.workflow_execution_id
      WHERE s.cluster_id=$1 AND s.workspace_id=$2 AND s.workflow_id=$3 AND s.workflow_plan_revision=$4 AND s.workflow_plan_hash=$5 AND e.id=$6`,
      [plan.clusterId,plan.workspaceId,plan.workflowId,plan.planRevision,loaded.row.plan_hash,value.executionId]);
    if(!source||!['succeeded','partial','failed'].includes(source.state))throw stop('ENTITY_CHANGE_RECOVERY_OUTCOME_UNRESOLVED');
    await this.facts.historicalProjection(plan.clusterId,plan.workspaceId,source.baseline_id,actor);
    const requestHmac=this.secrets.fingerprint({workflowId:plan.workflowId,baselineId:source.baseline_id,...value});
    const old=await this.db.one<any>('SELECT * FROM entity_change_recovery_links WHERE actor_id=$1 AND idempotency_key=$2',[actor.user.id,key]);
    if(old){if(old.baseline_id!==source.baseline_id||old.request_hmac!==requestHmac)throw stop('IDEMPOTENCY_CONFLICT');return{intent:await this.intents.get(plan.clusterId,old.new_intent_id,actor),linkId:old.id,originalWorkflowId:plan.workflowId,submissionRequired:true};}
    const pending=await this.db.one<any>(`SELECT EXISTS(SELECT 1 FROM entity_change_packet_attempts a WHERE a.source_id=$1 AND NOT EXISTS(SELECT 1 FROM entity_change_packet_events e WHERE e.attempt_id=a.id AND e.event_kind='outcome'))
      OR EXISTS(SELECT 1 FROM entity_change_packet_events WHERE source_id=$1 AND outcome='sent-unknown') AS blocked`,[source.id]);
    if(pending?.blocked)throw stop('ENTITY_CHANGE_RECOVERY_OUTCOME_UNRESOLVED');
    const envelope=this.secrets.decrypt<EntityChangeBaselineEnvelope>(source.material_ciphertext,entityBaselineAad(plan.clusterId,plan.workspaceId,source.baseline_id));
    if(this.secrets.fingerprint(envelope)!==source.baseline_hmac||this.secrets.fingerprint(envelope.capture)!==source.capture_hmac)throw stop('ENTITY_CHANGE_BASELINE_MATERIAL_INVALID');
    const successes=await this.db.query<any>(`SELECT a.packet_key,a.native_type,a.native_id,a.parent_id,a.credential_kind,a.mutation_action,a.packet_order,a.original_native_id,a.body_hmac,a.before_hmac,e.native_status,m.before_secret,m.payload_secret,m.result_secret,m.id AS operation_id
      FROM entity_change_packet_attempts a JOIN entity_change_packet_events e ON e.attempt_id=a.id AND e.event_kind='outcome' AND e.outcome='succeeded'
      JOIN mutation_operations m ON m.entity_change_attempt_id=a.id AND m.state='succeeded' AND m.remote_completed=true
      WHERE a.source_id=$1 ORDER BY a.packet_order DESC`,[source.id]);
    if(!successes.length)throw stop('ENTITY_CHANGE_RECOVERY_NO_ACKNOWLEDGED_CHANGE');
    const created=new Set(successes.filter(p=>p.mutation_action==='create').map(p=>`${p.native_type}:${p.native_id}`)),operations:EntityChangeOperation[]=[];
    for(const p of successes){
      if(p.native_type==='targets'&&['mark_healthy','mark_unhealthy'].includes(p.mutation_action))throw stop('TARGET_HEALTH_OVERRIDE_ROLLBACK_UNAVAILABLE');
      const original=envelope.capture.objects.find(o=>o.nativeType===p.native_type&&o.nativeId===(p.native_type==='targets'?p.original_native_id:p.native_id)&&(o.parentId??null)===p.parent_id);
      if(!original||!original.affected)throw stop('ENTITY_CHANGE_RECOVERY_OBJECT_MISSING');
      if(p.native_type==='targets'){
        const nativeResult=this.secrets.decrypt<any>(p.result_secret,`mutation:${p.operation_id}:result`),approvedBody=this.secrets.decrypt<any>(p.payload_secret,`mutation:${p.operation_id}:payload`),
          before=this.secrets.decrypt<any>(p.before_secret,`mutation:${p.operation_id}:before`);
        if(this.secrets.fingerprint(approvedBody)!==p.body_hmac||this.secrets.fingerprint(before)!==p.before_hmac
          ||this.secrets.fingerprint(original.before)!==p.before_hmac)throw stop('ENTITY_CHANGE_RECOVERY_TARGET_RECEIPT_INVALID');
        const current=await this.context.runInternalRead(plan.clusterId,'capture',async()=>{
          if(nativeResult?.weight===0){await disabledTargetReadback(this.kong,this.secrets,{clusterId:plan.clusterId,upstreamId:p.parent_id,approvedBody,nativeResult});return null;}
          const first=(await currentEffectiveTarget(this.kong,plan.clusterId,p.parent_id,nativeResult?.target)).target,
            second=(await currentEffectiveTarget(this.kong,plan.clusterId,p.parent_id,nativeResult?.target)).target;
          if(this.secrets.fingerprint(first)!==this.secrets.fingerprint(second))throw stop('ENTITY_CHANGE_RECOVERY_TARGET_CHANGED');return second;
        },{paths:[`/upstreams/${p.parent_id}/targets`,`/upstreams/${p.parent_id}/targets/all`],workspaceId:plan.workspaceId,maxCalls:100,maxPages:100,maxRecords:10000,maxBytes:32*1024*1024,timeoutMs:120000});
        operations.push(targetWeightRecoveryOperation(original,{nativeId:p.native_id,originalNativeId:p.original_native_id,parentId:p.parent_id,mutationAction:p.mutation_action,nativeStatus:p.native_status},nativeResult,approvedBody,current,this.secrets));
        continue;
      }
      if(!original.present){
        const remote=this.secrets.decrypt<any>(p.result_secret,`mutation:${p.operation_id}:result`),result=remote?.entity??remote;
        // A created certificate's SNI children are archived with that root.
        if(p.native_type==='snis'&&created.has(`certificates:${entityReferenceId(result.certificate)}`))continue;
        const credential=!!p.credential_kind;
        operations.push({kind:'recycle',action:'delete',entityType:credential?'credentials':p.native_type,entityId:p.native_id,
          ...(credential?{parentId:p.parent_id,credentialKind:p.credential_kind}:{}),confirmed:true,confirm_name:String(result.name??result.username??result.target??p.native_id)});
      }else{
        if(original.recovery!=='complete'||!original.restorePayload)throw stop('ENTITY_CHANGE_RECOVERY_MATERIAL_MISSING');
        const restore={...(original.restorePayload as any)};delete restore.id;delete restore.created_at;delete restore.updated_at;delete restore.ttl;
        if(Array.isArray(restore.tags))restore.tags=restore.tags.map(decodeTag).filter((tag:string)=>!tag.startsWith('workspace:'));
        if(p.credential_kind){delete restore.consumer;operations.push({kind:'credential',action:'update',consumerId:p.parent_id,credentialKind:p.credential_kind,credentialId:p.native_id,body:restore});}
        else{if(p.native_type==='certificates')delete restore.snis;operations.push({kind:'entity',action:'update',entityType:p.native_type,entityId:p.native_id,body:restore});}
      }
    }
    const change=operations.length===1?operations[0]:{kind:'batch',operations,confirmed:true},permissionVersion=await this.authz.permissionVersion(actor.user);
    const prepared=await this.intents.prepare(plan.clusterId,{change},{...actor,idempotencyKey:`recovery-${this.secrets.fingerprint({actor:actor.user.id,key}).slice(0,48)}`});
    if(operations.some(operation=>operation.kind==='target')&&plan.approvalRequired&&prepared.executionMode!=='approval')
      throw stop('ENTITY_CHANGE_RECOVERY_APPROVAL_DOWNGRADE_FORBIDDEN');
    const version=await this.db.one<any>('SELECT material_hmac,change_digest,packet_manifest_hmac FROM entity_change_intent_versions WHERE intent_id=$1 AND intent_revision=$2',[prepared.id,prepared.revision]);
    if(!version||version.material_hmac!==prepared.materialHmac)throw stop('ENTITY_CHANGE_RECOVERY_INTENT_MISMATCH');
    const projection:any=await this.facts.historicalProjection(plan.clusterId,plan.workspaceId,source.baseline_id,actor);
    const link:EntityChangeRecoveryLink={baselineId:source.baseline_id,pinId:projection.baseline.pinId,clusterId:plan.clusterId,workspaceId:plan.workspaceId,newIntentId:prepared.id,newIntentRevision:prepared.revision,
      newMaterialHmac:version.material_hmac,newChangeDigest:version.change_digest,newPacketManifestHmac:version.packet_manifest_hmac,actorId:actor.user.id,idempotencyKey:key,requestHmac};
    const proof=Object.freeze({});this.recoveryProofs.set(proof,{hmac:this.secrets.fingerprint(link),actorId:actor.user.id,sessionId:frame.sessionId,permissionVersion});
    try{
      const result=await this.db.transaction(async tx=>{
        await tx.one('SELECT version FROM iam_epoch WHERE singleton=true FOR SHARE');
        const linked=await this.facts.linkRecovery(link,proof,tx);
        await this.audit.append({actorId:actor.user.id,clusterId:plan.clusterId,workspaceId:plan.workspaceId,entityType:'workflows',entityId:plan.workflowId,
          workflowId:plan.workflowId,action:'entity-change.rollback.prepared',result:'success',requestId:actor.requestId,ip:actor.ip,
          before:{workflowId:plan.workflowId,executionId:source.execution_id,baselineId:source.baseline_id},
          after:{newIntentId:prepared.id,newIntentRevision:prepared.revision,linkId:linked.linkId,executionMode:prepared.executionMode,newNativeRequests:true,originalNativeReplayed:false},scopeHints:this.scopeHints(plan)},tx);
        if(this.context.current()!==frame||await this.authz.permissionVersion(actor.user,tx)!==permissionVersion)throw deny('ENTITY_CHANGE_PERMISSIONS_CHANGED');
        await this.intents.assertSubject(plan,actor.user.id,'read',tx);
        await this.redis.assertLeaseOwnership();return linked;
      });
      return{intent:prepared,linkId:result.linkId,originalWorkflowId:plan.workflowId,submissionRequired:true};
    }
    finally{this.recoveryProofs.delete(proof);}
  }
  private restoredConfiguration(claim:ExecutionClaim):Record<string,unknown>{
    const restored=claim.envelope.prepared.metadataObligations.filter(o=>o.kind==='recycle-restore');
    if(!restored.length||restored.some(o=>o.packetKeys.some(key=>!claim.completed.has(key))))return{};
    // Kernel completion follows the fixed writer's real original-response
    // readback and final current whole-graph/all-party witness. This reports
    // configuration consistency only; it never claims business authentication.
    return{restoration:{graphs:restored.length,configurationVerification:'verified',functionalVerification:'pending'}};
  }
  private async receipt(claim:ExecutionClaim):Promise<Record<string,unknown>>{
    const source=claim.source,row=await this.db.one<any>('SELECT state,revision FROM workflows WHERE id=$1',[source.workflowId]);
    const events=await this.db.query<any>(`SELECT a.packet_key,e.event_kind,e.outcome,e.error_code FROM entity_change_packet_attempts a LEFT JOIN entity_change_packet_events e ON e.attempt_id=a.id WHERE a.source_id=$1 ORDER BY a.packet_order,e.created_at`,[source.id]);
    return{id:source.workflowExecutionId,workflowId:source.workflowId,executionId:source.workflowExecutionId,clusterId:source.clusterId,workspaceId:source.workspaceId,state:row?.state,revision:row?.revision,
      baselineId:claim.baseline?.baselineId??null,steps:events.map(e=>({name:e.packet_key,event:e.event_kind,state:e.outcome??'send-intent',errorCode:e.error_code??null})),propagation:row?.state==='succeeded'?'acknowledged':'pending',...(row?.state==='succeeded'?this.restoredConfiguration(claim):{})};
  }
  private async executeScheduledClaim(authorityHandle:object):Promise<object>{
    if(!this.scheduledAuthority||!this.scheduledNamespace||this.context.peek())throw deny('ENTITY_SCHEDULE_NAMESPACE_REQUIRED');
    const inspection=await this.scheduledAuthority.inspect(authorityHandle);
    let sourceId:string|null=null,executionId:string|null=null,outcome:EntityScheduleTerminalOutcome='failed';
    try{await this.scheduledNamespace.runOriginalClaim(authorityHandle,async()=>{
      const namespace=this.context.requireEntityScheduledNamespaceHandle(),proof=await this.context.verifyEntityScheduledNamespace('claim');
      if(!proof||proof.claim.id!==inspection.claim.id||proof.intent.materialHmac!==this.secrets.fingerprint(inspection.envelope))throw deny('ENTITY_SCHEDULE_NAMESPACE_REQUIRED');
      const {plan,envelope}=inspection,actor:EntityActor={user:proof.actor,workspaceId:proof.workspaceId};
      if(envelope.version!==2||!plan.approvalRequired||plan.executionMode!=='approval'
        ||envelope.prepared.metadataObligations.some(o=>o.kind==='recycle-archive'||o.kind==='recycle-restore')
        ||envelope.prepared.packets.some(p=>['mark_healthy','mark_unhealthy'].includes(p.mutationAction)
          ||p.nativeType==='targets'&&!['target-create','target-weight'].includes(derivePreparedEntityWrite(p).kind)))
        throw deny('ENTITY_SCHEDULE_EXECUTION_ADAPTER_REQUIRED');
      for(const packet of envelope.prepared.packets)derivePreparedEntityWrite(packet);
      const current=await this.plans.load(plan.clusterId,plan.workspaceId,plan.workflowId);
      if(current.row.state!=='approved'||current.row.plan_hash!==proof.claim.workflowPlanHash
        ||this.secrets.fingerprint(current.plan)!==proof.claim.workflowPlanHash)throw stop('WORKFLOW_NOT_EXECUTABLE');
      if(await this.db.one('SELECT id FROM workflow_executions WHERE workflow_id=$1 AND plan_revision=$2',[plan.workflowId,plan.planRevision]))throw stop('WORKFLOW_ALREADY_EXECUTED');
      sourceId=randomUUID();executionId=randomUUID();const issuedAt=new Date().toISOString();
      const source:EntityScheduledExecutionSourceV2=immutableJson({format:2,origin:'scheduled-entity',id:sourceId,clusterId:plan.clusterId,workspaceId:plan.workspaceId,
        intentId:envelope.intentId,intentRevision:envelope.revision,materialHmac:proof.intent.materialHmac,changeDigest:proof.intent.changeDigest,packetManifestHmac:proof.intent.packetManifestHmac,
        workflowId:plan.workflowId,workflowPlanRevision:plan.planRevision,workflowPlanHash:proof.claim.workflowPlanHash,workflowExecutionId:executionId,
        executionActorId:actor.user.id,credentialEpoch:proof.credentialEpoch,sessionId:null,permissionVersionHmac:this.secrets.fingerprint(proof.permissionVersion),issuedAt,
        expiresAt:new Date(Math.min(Date.parse(issuedAt)+300000,Date.parse(proof.expiresAt))).toISOString(),scheduleId:proof.claim.scheduleId,scheduleVersion:1,
        specHmac:proof.claim.specHmac,delegationId:proof.claim.delegationId,delegationVersion:1,delegationHmac:proof.claim.delegationHmac,
        occurrenceId:proof.claim.occurrenceId,claimId:proof.claim.id,claimGeneration:1,workerOwnerHmac:proof.claim.workerOwnerHmac,windowStart:proof.claim.windowStart,windowEnd:proof.claim.windowEnd});
      const claim:ExecutionClaim={active:true,actor,sessionId:null,permissionVersion:proof.permissionVersion,source,plan:current.plan,envelope,
        scheduledNamespace:namespace,completed:new Set(),packets:new Set()};
      try{
        await this.db.transaction(async tx=>{
          await tx.one('SELECT version FROM iam_epoch WHERE singleton=true FOR SHARE');
          const verified=await this.context.verifyEntityScheduledNamespace('claim');
          if(verified!==proof||await this.authz.permissionVersion(actor.user,tx)!==proof.permissionVersion)throw deny('ENTITY_CHANGE_PERMISSIONS_CHANGED');
          const approvals=await this.approval.verifyApprovalSet(plan,{checkpoint:'claim'},tx);
          requirePortalCas(await tx.exec("UPDATE workflows SET state='executing',revision=revision+1,updated_at=now() WHERE id=$1 AND revision=$2 AND state='approved'",[plan.workflowId,current.row.revision]));
          await tx.exec(`INSERT INTO workflow_executions(id,cluster_id,workspace_id,workflow_id,plan_revision,plan_hash,execution_mode,approval_required,approved_by,execution_actor_id,state,claim_token_hash,idempotency_key,expires_at,approval_format,approval_set_id,approval_set_hmac)
            VALUES($1,$2,$3,$4,$5,$6,'approval',true,$7,$8,'executing',$9,$10,$11,$12,$13,$14)`,[executionId,plan.clusterId,plan.workspaceId,plan.workflowId,plan.planRevision,source.workflowPlanHash,current.row.approved_by,actor.user.id,this.secrets.fingerprint(randomBytes(32)),`schedule-${source.claimId}`,plan.expiresAt,approvals.format,approvals.setId,approvals.setHmac]);
          await tx.exec(`INSERT INTO entity_change_execution_sources(id,cluster_id,workspace_id,intent_id,intent_revision,material_hmac,change_digest,packet_manifest_hmac,workflow_id,workflow_plan_revision,workflow_plan_hash,workflow_execution_id,execution_actor_id,credential_epoch,session_id,permission_version_hmac,issued_at,expires_at,origin_type,schedule_id,schedule_version,spec_hmac,delegation_id,delegation_version,delegation_hmac,occurrence_id,claim_id,claim_generation,worker_owner_hmac,window_start,window_end)
            VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,NULL,$15,$16,$17,'scheduled-entity',$18,1,$19,$20,1,$21,$22,$23,1,$24,$25,$26)`,
            [source.id,source.clusterId,source.workspaceId,source.intentId,source.intentRevision,source.materialHmac,source.changeDigest,source.packetManifestHmac,source.workflowId,source.workflowPlanRevision,source.workflowPlanHash,source.workflowExecutionId,source.executionActorId,source.credentialEpoch,source.permissionVersionHmac,source.issuedAt,source.expiresAt,source.scheduleId,source.specHmac,source.delegationId,source.delegationHmac,source.occurrenceId,source.claimId,source.workerOwnerHmac,source.windowStart,source.windowEnd]);
          await this.audit.append({actorId:actor.user.id,clusterId:plan.clusterId,workspaceId:plan.workspaceId,entityType:'workflows',entityId:plan.workflowId,workflowId:plan.workflowId,
            action:'workflow.execute.requested',result:'pending',after:{scheduleId:source.scheduleId,claimId:source.claimId,sourceId:source.id},scopeHints:this.scopeHints(plan)},tx);
        });
        this.sources.set(source.id,claim);const handle=Object.freeze({});this.executionHandles.set(handle,claim);
        await this.runExecution(claim,handle);outcome='succeeded';
      }catch(error){
        const actual=await this.db.one<any>('SELECT state FROM workflow_executions WHERE id=$1',[executionId]);
        if(!actual){sourceId=null;executionId=null;outcome='failed';}
        else if(['partial','failed','uncertain'].includes(actual.state))outcome=actual.state;
        else throw error;
      }
    });}catch(error){
      if(await this.db.one('SELECT id FROM entity_change_execution_sources WHERE claim_id=$1',[inspection.claim.id])
        ||await this.db.one('SELECT id FROM workflow_executions WHERE workflow_id=$1',[inspection.plan.workflowId]))throw error;
      sourceId=null;executionId=null;outcome='failed';
    }
    const completion=Object.freeze({});this.scheduledCompletions.set(completion,{authorityHandle,claimId:inspection.claim.id,sourceId,workflowId:inspection.plan.workflowId,executionId,outcome});return completion;
  }
  private async verifyScheduledCompletion(authorityHandle:object,completion:object,tx:DbService):Promise<EntityScheduleTerminalOutcome>{
    const original=this.scheduledCompletions.get(completion);
    if(!original||original.authorityHandle!==authorityHandle)throw deny('ENTITY_SCHEDULE_GENUINE_COMPLETION_REQUIRED');
    if(!original.sourceId){
      if(original.outcome!=='failed'||await tx.one("SELECT id FROM entity_change_execution_sources WHERE claim_id=$1",[original.claimId])
        ||await tx.one('SELECT id FROM workflow_executions WHERE workflow_id=$1',[original.workflowId]))throw deny('ENTITY_SCHEDULE_COMPLETION_FACTS_INVALID');
    }else{
      const source=await tx.one<any>(`SELECT s.claim_id,s.origin_type,s.session_id,e.state,w.state AS workflow_state FROM entity_change_execution_sources s
        JOIN workflow_executions e ON e.id=s.workflow_execution_id JOIN workflows w ON w.id=s.workflow_id WHERE s.id=$1 AND e.id=$2 AND w.id=$3`,[original.sourceId,original.executionId,original.workflowId]);
      if(!source||source.claim_id!==original.claimId||source.origin_type!=='scheduled-entity'||source.session_id!==null||source.state!==original.outcome||source.workflow_state!==original.outcome)
        throw deny('ENTITY_SCHEDULE_COMPLETION_FACTS_INVALID');
      const unresolved=await tx.one<any>(`SELECT EXISTS(SELECT 1 FROM entity_change_packet_attempts a WHERE a.source_id=$1 AND NOT EXISTS(
        SELECT 1 FROM entity_change_packet_events ev WHERE ev.attempt_id=a.id AND ev.event_kind='outcome')) AS pending`,[original.sourceId]);
      if(unresolved?.pending&&original.outcome!=='uncertain')throw deny('ENTITY_SCHEDULE_COMPLETION_FACTS_INVALID');
    }
    // Authority and the repository independently verify the same original
    // completion inside one transaction. This is read-only outcome evidence;
    // consuming it here would reject the second mandatory verification.
    return original.outcome;
  }
  private async runExecution(claim:ExecutionClaim,executionHandle:object):Promise<Record<string,unknown>>{
    const {plan,envelope,actor,source}=claim,executionId=source.workflowExecutionId,step=assertEntityChangeWorkflowPlan(plan);
    this.executionOriginals.set(claim,executionHandle);
      try{
        await this.redis.withLock(`mutation:${plan.scope.transportScope}`,async()=>{
          const capture=await this.capturer.capture(envelope.prepared,actor),proof=Object.freeze({});this.captureProofs.set(proof,{sourceId:source.id,hmac:this.secrets.fingerprint(capture)});
          try{claim.baseline=await this.facts.persistReady(source.id,capture,proof);}finally{this.captureProofs.delete(proof);}
        });
        const snapshot={version:1,baselineId:claim.baseline!.baselineId,sourceId:source.id,captureHmac:claim.baseline!.captureHmac,objectManifestHmac:claim.baseline!.objectManifestHmac};
        requirePortalCas(await this.db.exec("UPDATE workflow_executions SET snapshot_state='ready',snapshot_secret=$2,snapshot_hash=$3,snapshot_id=$4,revision=revision+1,updated_at=now() WHERE id=$1 AND snapshot_state='pending' AND state='executing'",[executionId,this.secrets.encrypt(snapshot,`workflow:${plan.clusterId}:${plan.workspaceId}:${plan.workflowId}:${executionId}:snapshot`),this.secrets.fingerprint(snapshot),claim.baseline!.baselineId]));
        requirePortalCas(await this.db.exec("UPDATE workflow_steps SET state='running',started_at=now(),revision=revision+1,updated_at=now() WHERE id=$1 AND state='pending'",[step.id]));
        if(envelope.prepared.metadataObligations.some(o=>o.kind==='recycle-archive'||o.kind==='recycle-restore')){
          if(!this.recycleExecutor)throw deny('ENTITY_CHANGE_RECYCLE_EXECUTOR_REQUIRED');
          await this.recycleExecutor.prepare(executionHandle);
        }
        for(const packet of envelope.prepared.packets){
          const binding:EntityChangePacketAttemptBinding={sourceId:source.id,baselineId:claim.baseline!.baselineId,pinId:claim.baseline!.pinId,packetKey:packet.key,attemptId:randomUUID()},handle=Object.freeze({}) as EntityPreparedWriteHandle;
          const item:PacketClaim={active:true,execution:claim,packet:immutableJson(packet),binding,operationKey:`entity-${executionId}-${packet.order}`,sent:false};
          claim.packets.add(item);this.packetHandles.set(handle,item);
          const proof=Object.freeze({});this.factProofs.set(proof,{claim:item,hmac:null});
          try{await this.facts.appendAttempt(binding,proof);}finally{this.factProofs.delete(proof);}
          let failure:unknown;
          try{if(this.recyclePacket(claim,packet))await this.recycleExecutor!.execute(handle);else await this.writer.execute(handle);}catch(error){failure=error;}
          const mutation=item.operationId?await this.db.one<any>('SELECT * FROM mutation_operations WHERE id=$1',[item.operationId]):null;
          const healthMetadata=healthPacket(packet)?this.healthMetadata(item,mutation):undefined;
          const known=!!mutation&&mutation.state==='succeeded'&&mutation.remote_completed&&mutation.result_secret&&item.responseHmac
            &&this.secrets.fingerprint(this.secrets.decrypt(mutation.result_secret,`mutation:${mutation.id}:result`))===item.responseHmac
            &&(!healthPacket(packet)||!!healthMetadata);
          const errorCode=failure instanceof HttpException?(failure.getResponse() as any)?.code:failure?'ENTITY_CHANGE_PACKET_FAILED':undefined;
          const outcome=known?'succeeded':item.wireSpent?item.transportStatus!==undefined&&item.transportStatus>=400&&item.transportStatus<500?'native-rejected':'sent-unknown':'failed-known-not-sent';
          item.outcome=outcome;
          const fact:EntityChangePacketFact={version:1,kind:'outcome',binding,observedAt:new Date().toISOString(),outcome,
            // Preserve an actually observed HTTP status even when later
            // readback/metadata fails. The outcome stays sent-unknown; a 201
            // alone never upgrades completion or authorizes a second write.
            ...(['succeeded','native-rejected','sent-unknown'].includes(outcome)&&item.wireSpent&&item.transportStatus!==undefined?{nativeStatus:item.transportStatus}:{}),...(outcome!=='succeeded'&&typeof errorCode==='string'&&/^[A-Z0-9_]{1,128}$/.test(errorCode)?{errorCode}:{}),
            evidence:{operationId:item.operationId??null,mutationState:mutation?.state??null,remoteCompleted:mutation?.remote_completed===true,responseHmac:item.responseHmac??null,metadataComplete:!failure,
              ...(healthMetadata?{healthObservation:healthMetadata}:{}),
              ...(this.recyclePacket(claim,packet)&&this.recycleExecutor?.verification(handle)?{deleteVerification:this.recycleExecutor.verification(handle)}:{})}};
          const outcomeProof=Object.freeze({});this.factProofs.set(outcomeProof,{claim:item,hmac:this.secrets.fingerprint(fact)});
          try{
            const recorded=this.recyclePacket(claim,packet)?await this.db.one<any>("SELECT outcome,native_status FROM entity_change_packet_events WHERE attempt_id=$1 AND event_kind='outcome'",[binding.attemptId]):null;
            if(recorded){if(!known||recorded.outcome!=='succeeded'||recorded.native_status!==item.transportStatus)throw deny('ENTITY_CHANGE_OUTCOME_FACT_MISMATCH');}
            else await this.facts.appendOutcome(fact,outcomeProof);
          }finally{this.factProofs.delete(outcomeProof);item.active=false;this.packetHandles.delete(handle);}
          if(failure)throw failure;if(!known)throw new ServiceUnavailableException({code:'ENTITY_CHANGE_NATIVE_RECEIPT_UNKNOWN'});
          claim.completed.add(packet.key);
        }
        await this.db.transaction(async tx=>{
          await this.verifySource(source.id,'packet',tx);
          requirePortalCas(await tx.exec("UPDATE workflow_steps SET state='succeeded',safe_result=$2::jsonb,completed_at=now(),revision=revision+1,updated_at=now() WHERE id=$1 AND state='running'",[step.id,JSON.stringify({sourceId:source.id,baselineId:claim.baseline!.baselineId,nativePackets:claim.completed.size,...this.restoredConfiguration(claim)})]));
          requirePortalCas(await tx.exec("UPDATE workflow_executions SET state='succeeded',completed_at=now(),revision=revision+1,updated_at=now() WHERE id=$1 AND state='executing'",[executionId]));
          requirePortalCas(await tx.exec("UPDATE workflows SET state='succeeded',revision=revision+1,updated_at=now() WHERE id=$1 AND state='executing'",[plan.workflowId]));
          await this.audit.append({actorId:actor.user.id,clusterId:plan.clusterId,workspaceId:plan.workspaceId,entityType:'workflows',entityId:plan.workflowId,workflowId:plan.workflowId,action:'workflow.execute',result:'success',requestId:actor.requestId,ip:actor.ip,after:{sourceId:source.id,baselineId:claim.baseline!.baselineId,nativePackets:claim.completed.size},scopeHints:this.scopeHints(plan)},tx);
        });
        return await this.receipt(claim);
      }catch(error){
        if(!(error instanceof HttpException))console.error(JSON.stringify({level:'error',requestId:actor.requestId,phase:claim.baseline?'entity-change-packet':'entity-change-baseline',code:'ENTITY_CHANGE_EXECUTION_FAILED',...safeDatabaseDiagnostic(error)}));
        const unknown=[...claim.packets].some(p=>p.outcome==='sent-unknown'||p.wireSpent&&!p.outcome),state=unknown?'uncertain':claim.completed.size||[...claim.packets].some(p=>p.outcome==='succeeded')?'partial':'failed';
        const original=error instanceof HttpException?error.getResponse():null,code=typeof (original as any)?.code==='string'&&(original as any).code.match(/^[A-Z0-9_]{1,128}$/)?(original as any).code:'ENTITY_CHANGE_EXECUTION_FAILED';
        await this.db.transaction(async tx=>{
          await tx.exec("UPDATE workflow_steps SET state=$2,error_code=$3,started_at=COALESCE(started_at,now()),completed_at=now(),revision=revision+1,updated_at=now() WHERE id=$1 AND state IN('pending','running')",[step.id,unknown?'uncertain':'failed',code]);
          await tx.exec("UPDATE workflow_executions SET state=$2,completed_at=now(),revision=revision+1,updated_at=now() WHERE id=$1 AND state='executing'",[executionId,state]);
          await tx.exec("UPDATE workflows SET state=$2,revision=revision+1,updated_at=now() WHERE id=$1 AND state='executing'",[plan.workflowId,state]);
          await this.audit.append({actorId:actor.user.id,clusterId:plan.clusterId,workspaceId:plan.workspaceId,entityType:'workflows',entityId:plan.workflowId,workflowId:plan.workflowId,action:'workflow.execute',result:unknown?'uncertain':'failed',requestId:actor.requestId,ip:actor.ip,after:{code,state,nativePackets:claim.completed.size},scopeHints:this.scopeHints(plan)},tx);
        });
        throw new HttpException({code,message:'变更未全部完成，请核验原工单回执；不会自动重发',workflowId:plan.workflowId,executionId,state},error instanceof HttpException?error.getStatus():503);
      }finally{this.recycleExecutor?.release(executionHandle);this.executionOriginals.delete(claim);this.partialGraphPhases.delete(claim);this.executionHandles.delete(executionHandle);claim.active=false;for(const packet of claim.packets)packet.active=false;this.sources.delete(source.id);}
  }
  /** Metadata confirms genuine readback, while the private transport response
   * remains 204/null. It neither proves a prior override nor replaces state. */
  private healthMetadata(claim:PacketClaim,mutation:any):Record<string,unknown>|undefined{
    try{
      const value=mutation?.safe_result,packet=claim.packet;
      if(!value||value.kind!=='target-health-acknowledgement'||value.nativeResult!==null||value.nativeStatus!==204||value.responseBytes!==0
        ||value.responseHmac!==claim.responseHmac||value.overrideRecovery!=='unavailable'
        ||value.requestedState!==(packet.mutationAction==='mark_healthy'?'healthy':'unhealthy')||value.nodeScope!=='current_admin_node'
        ||claim.transportStatus!==204||claim.responseHmac!==this.secrets.fingerprint(null)||claim.transportHmac!==this.secrets.fingerprint(null)
        ||!claim.healthBefore||this.secrets.fingerprint(value.healthBefore)!==this.secrets.fingerprint(claim.healthBefore))return undefined;
      const after=assertTargetHealthObservation(value.healthAfter,{upstreamId:packet.parentId!,target:packet.before as Record<string,unknown>},this.secrets);
      if(after.nodeId!==claim.healthBefore.nodeId)return undefined;
      return immutableJson({nativeResult:null,requestedState:value.requestedState,healthBefore:claim.healthBefore,healthAfter:after,nodeScope:'current_admin_node',overrideRecovery:'unavailable'});
    }catch{return undefined;}
  }
  async execute(plan:WorkflowPlanV1,body:unknown,actor:EntityActor):Promise<Record<string,unknown>>{
    const value=portalObject(body,['revision','planHash','confirmed','confirm_name']);portalConfirm(value,'native-change');portalRevision(value.revision);
    const key=workflowKey(actor.idempotencyKey),frame=this.context.current(),step=assertEntityChangeWorkflowPlan(plan);
    if(!frame.sessionId||frame.actor?.id!==actor.user.id||frame.clusterId!==plan.clusterId||frame.workspaceId!==plan.workspaceId)throw deny();
    const sessionId=frame.sessionId;
    return this.redis.withLock(`workflow:${plan.workflowId}`,async()=>{
      const current=await this.plans.load(plan.clusterId,plan.workspaceId,plan.workflowId),envelope=await this.intents.executionMaterial(current.plan,actor);
      if(value.planHash!==current.row.plan_hash)throw stop('WORKFLOW_PLAN_CHANGED');
      const old=await this.db.one<any>('SELECT id,state,execution_actor_id,idempotency_key FROM workflow_executions WHERE workflow_id=$1 AND plan_revision=$2',[plan.workflowId,plan.planRevision]);
      if(old)throw stop(old.execution_actor_id===actor.user.id&&old.idempotency_key===key?'ENTITY_CHANGE_USE_ORIGINAL_RECEIPT':'WORKFLOW_ALREADY_EXECUTED');
      if(value.revision!==current.row.revision||!['approved',...(!plan.approvalRequired?['pending']:[])].includes(current.row.state))throw stop('WORKFLOW_NOT_EXECUTABLE');
      if(!await this.canExecute(current.plan,actor))throw stop('ENTITY_CHANGE_EXECUTION_ADAPTER_REQUIRED');
      for(const packet of envelope.prepared.packets){
        if(!envelope.prepared.metadataObligations.some(o=>(o.kind==='recycle-archive'||o.kind==='recycle-restore')&&o.packetKeys.includes(packet.key)))derivePreparedEntityWrite(packet);
      }
      await this.plans.revalidateEntityChange(plan,actor,'claim');
      const version=await this.authz.permissionVersion(actor.user),sourceId=randomUUID(),executionId=randomUUID(),issuedAt=new Date().toISOString();
      const session=await this.db.one<any>('SELECT expires_at FROM auth_sessions WHERE id=$1 AND user_id=$2 AND revoked_at IS NULL',[sessionId,actor.user.id]);
      if(!session)throw deny('ENTITY_CHANGE_SESSION_REVOKED');
      const expiresAt=new Date(Math.min(Date.parse(issuedAt)+300000,Date.parse(envelope.expiresAt),new Date(session.expires_at).getTime())).toISOString();
      const source:EntityChangeExecutionSource={id:sourceId,clusterId:plan.clusterId,workspaceId:plan.workspaceId,intentId:envelope.intentId,intentRevision:envelope.revision,
        materialHmac:this.secrets.fingerprint(envelope),changeDigest:envelope.prepared.changeDigest,packetManifestHmac:envelope.packetManifestHmac,workflowId:plan.workflowId,
        workflowPlanRevision:plan.planRevision,workflowPlanHash:current.row.plan_hash,workflowExecutionId:executionId,executionActorId:actor.user.id,
        credentialEpoch:envelope.credentialEpoch,sessionId,permissionVersionHmac:this.secrets.fingerprint(version),issuedAt,expiresAt};
      const claim:ExecutionClaim={active:true,actor,sessionId,permissionVersion:version,source:immutableJson(source),plan:current.plan,envelope,completed:new Set(),packets:new Set()};
      await this.db.transaction(async tx=>{
        await tx.one('SELECT version FROM iam_epoch WHERE singleton=true FOR SHARE');
        if(await this.authz.permissionVersion(actor.user,tx)!==version)throw deny('ENTITY_CHANGE_PERMISSIONS_CHANGED');
        const approvals=await this.approval.verifyApprovalSet(plan,{checkpoint:'claim'},tx);
        requirePortalCas(await tx.exec("UPDATE workflows SET state='executing',revision=revision+1,updated_at=now() WHERE id=$1 AND revision=$2 AND state=$3",[plan.workflowId,current.row.revision,current.row.state]));
        await tx.exec(`INSERT INTO workflow_executions(id,cluster_id,workspace_id,workflow_id,plan_revision,plan_hash,execution_mode,approval_required,approved_by,execution_actor_id,state,claim_token_hash,request_id,idempotency_key,expires_at,approval_format,approval_set_id,approval_set_hmac)
          VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'executing',$11,$12,$13,$14,$15,$16,$17)`,[executionId,plan.clusterId,plan.workspaceId,plan.workflowId,plan.planRevision,current.row.plan_hash,plan.executionMode,plan.approvalRequired,plan.approvalRequired?current.row.approved_by:null,actor.user.id,this.secrets.fingerprint(randomBytes(32)),actor.requestId??null,key,plan.expiresAt,approvals.format,approvals.setId,approvals.setHmac]);
        await tx.exec(`INSERT INTO entity_change_execution_sources(id,cluster_id,workspace_id,intent_id,intent_revision,material_hmac,change_digest,packet_manifest_hmac,workflow_id,workflow_plan_revision,workflow_plan_hash,workflow_execution_id,execution_actor_id,credential_epoch,session_id,permission_version_hmac,issued_at,expires_at)
          VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`,[source.id,source.clusterId,source.workspaceId,source.intentId,source.intentRevision,source.materialHmac,source.changeDigest,source.packetManifestHmac,source.workflowId,source.workflowPlanRevision,source.workflowPlanHash,source.workflowExecutionId,source.executionActorId,source.credentialEpoch,source.sessionId,source.permissionVersionHmac,source.issuedAt,source.expiresAt]);
        await this.audit.append({actorId:actor.user.id,clusterId:plan.clusterId,workspaceId:plan.workspaceId,entityType:'workflows',entityId:plan.workflowId,workflowId:plan.workflowId,action:'workflow.execute.requested',requestId:actor.requestId,ip:actor.ip,result:'pending',scopeHints:this.scopeHints(plan)},tx);
      });
      this.sources.set(source.id,claim);
      const executionHandle=Object.freeze({});this.executionHandles.set(executionHandle,claim);
      return this.runExecution(claim,executionHandle);

    });
  }
}
