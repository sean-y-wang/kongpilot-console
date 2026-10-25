import { isPortalCredentialScheduleKind } from '../portal/portal-credential-lifecycle-contract';
import { isPortalCredentialBusinessMaterial } from './workflow-business-material.types';
import { isMetadataScheduledKind } from './metadata-schedule.guard';
import { assertMetadataScheduleProductionHandlers } from './metadata-schedule.production';
import { UnknownResultDispositionService } from './unknown-result-disposition.service';
import {AsyncLocalStorage} from 'node:async_hooks';
import {portalReadbackReceipt} from './workflow-portal-readback-receipt';
import {portalActivationReadPaths,portalEntityParentReadPaths} from './workflow-portal-activation-read';
import type {PortalPartyObservationRoundOriginal,PortalPartyObservationRoundVerifier} from './workflow-portal-party-observation.types';
import { ConflictException, ForbiddenException, HttpException, Injectable, OnModuleInit, Optional } from '@nestjs/common';
import { ModuleRef } from '@nestjs/core';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import {isIP} from 'node:net';
import {isServiceHostReferencePoint} from './workflow-service-host-reference';
import { join } from 'node:path';
import { DbService } from '../../infrastructure/db.service';
import { RedisService } from '../../infrastructure/redis.service';
import { SecretService } from '../../infrastructure/secret.service';
import { KongService } from '../../infrastructure/kong/kong.service';
import { KongExecutionContextService } from '../../infrastructure/kong/execution-context.service';
import { immutableJson } from '../../infrastructure/kong/immutable-json';
import { AuthorizationService } from '../authorization/authorization.service';
import { ConfigurationService } from '../configuration/configuration.service';
import { configurationTargetAppendPacketIncomplete } from '../configuration/configuration-target-append-packet';
import { ConfigurationOriginService } from '../configuration/configuration-origin.service';
import { WorkflowPlansService } from './workflow-plans.service';
import { WorkflowService } from './workflow.service';
import { ApprovedWorkflowExecutionService } from './approved-workflow-execution.service';
import { WorkflowScheduleRepository } from './workflow-schedule.repository';
import { WorkflowScheduledAuthorityService } from './workflow-scheduled-authority.service';
import { WorkflowScheduledNamespaceService } from './workflow-scheduled-namespace.service';
import { WorkflowScheduleCandidateReadService } from './workflow-schedule-candidate-read.service';
import { WorkflowScheduledValidationReadService } from './workflow-scheduled-validation-read.service';
import type { WorkflowScheduledValidationFixedGroup } from './workflow-scheduled-validation-read.types';
import { WorkflowScheduledConfigurationOriginService } from './workflow-scheduled-configuration-origin.service';
import { WorkflowBusinessMaterialService } from './workflow-business-material.service';
import { WorkflowBusinessCurrentIdentityService } from './workflow-business-current-identity.service';
import { WorkflowBusinessScopedReadService } from './workflow-business-scoped-read.service';
import { WorkflowBusinessSchedulesService, type WorkflowBusinessSchedulePrepareInput, type WorkflowBusinessScheduleProposalInput,
  type WorkflowBusinessSchedulePreparedMaterial } from './workflow-business-schedules.service';
import { WorkflowBusinessSchedulesWorker } from './workflow-business-schedules.worker';
import { deriveImpact, mergeImpact } from '../mutations/mutation-impact';
import { assertConfigurationWorkflowPlan, type ConfigurationWorkflowPayload } from './configuration-workflow';
import { validateWorkflowPlan, workflowId } from './workflow-validation';
import type { WorkflowScheduleCandidateReadInput, WorkflowScheduleCandidateReadResource, WorkflowScheduleCandidateFixedGroup } from './workflow-schedule-candidate-read.types';
import type { WorkflowScheduledAuthorityCheckpoint, WorkflowScheduledNamespaceProof } from './workflow-scheduled-authority.types';
import type {ConfigurationNativeBeforeReadHandle,ConfigurationNativeBeforeReadIntent,ConfigurationNativeBeforeReadResult} from './approved-execution.types';
import type { WorkflowScheduledConfigurationRootVerifier } from './workflow-scheduled-configuration-origin.types';
import type { WorkflowScheduledConfigurationInspection } from './workflow-scheduled-configuration-origin.types';
import type { WorkflowScheduledPlanV1, WorkflowScheduleTerminalOutcome, WorkflowScheduleStored } from './workflow-schedule.contract';
import type { EntityActor } from '../entities/entities.types';
import type { WorkflowPlanV1, WorkflowSnapshotV1, WorkflowStep } from './workflow.types';

const deny=(code:string)=>new ForbiddenException({code});
const changed=(code:string)=>new ConflictException({code});
type Usage=Readonly<{calls:number;pages:number;records:number;bytes:number}>;
type Resource=Readonly<WorkflowScheduleCandidateReadResource>;
type Observations=Map<string,{resource:Resource;value:unknown;absence?:'sdk404'|'parent-FK-absence'}>;
type PartyObservationSource=Readonly<{kind:'sdk404'|'parent-FK-absence';witness:object;parentWitness?:object;parentKey?:string}>;
type PartyObservationState={original:Readonly<PortalPartyObservationRoundOriginal>;active:boolean;capturing:boolean;
 sources:Map<string,PartyObservationSource>;scopeHmac?:string;observations?:readonly Readonly<{resource:Resource;value:unknown;absence?:'sdk404'|'parent-FK-absence'}>[]};
/** One scheduled configuration_v2 authority checkpoint (a single
 * scheduledAuthority invocation). The first party captures one immutable SDK
 * observation; later parties of the SAME invocation replay authorizeResponse
 * with their own fresh grants. Never shared across step/packet/before-send
 * checkpoints or invocations: the round dies when the checkpoint returns. */
type ConfigurationLiveObservation=Readonly<{resource:Resource;value:unknown;absence?:'sdk404'|'parent-FK-absence'}>;
type ConfigurationPartyRound={namespace:object;phase:WorkflowScheduledAuthorityCheckpoint;active:boolean;joinable?:boolean;request?:true;planHash?:string;permissionVersion?:string;
 captured:Map<string,readonly ConfigurationLiveObservation[]>};
type ReadCapsule={handle:object;domain?:'scoped-points-v1';provider:WorkflowScheduleCandidateReadService|WorkflowScheduledValidationReadService};
const checksum=(name:string)=>createHash('sha256').update(readFileSync(join(__dirname,'../../infrastructure/migrations',name))).digest('hex');

/** Fixed bootstrap wiring, never a generic Admin API proxy. The providers own
 * original private handles; this class supplies current SQL/material checks and
 * real bounded GET observations. Source registration alone starts no timer. */
@Injectable()
export class WorkflowBusinessRuntimeService implements OnModuleInit {
  #partyObservationVerifier?:Readonly<PortalPartyObservationRoundVerifier>;
  readonly #partyObservationRound=new AsyncLocalStorage<PartyObservationState>();
  readonly #configurationPartyRound=new AsyncLocalStorage<ConfigurationPartyRound>();
  readonly #configurationRequestRound=new AsyncLocalStorage<ConfigurationPartyRound>();
  /** One shared verification round per Kong business request (scheduled configuration_v2 only). */
  async runConfigurationRequestRound<T>(namespace:object,fn:()=>Promise<T>):Promise<T>{
    if(typeof fn!=='function')throw deny('WORKFLOW_BUSINESS_ORIGINAL_CONFIGURATION_REQUIRED');
    const outer=this.#configurationRequestRound.getStore();
    if(outer?.active&&outer.namespace===namespace)return fn();
    const current=this.#configurationPartyRound.getStore();
    let kind:string|undefined;
    try{kind=this.context.requireWorkflowScheduledNamespaceHandle()===namespace?this.context.requireWorkflowScheduledCurrentPrincipal(namespace).namespace.kind:undefined;}catch{kind=undefined;}
    // Not configuration_v2, or already inside a before-send round: no sharing (fresh per-layer path).
    if(kind!=='configuration_v2'||current?.phase==='before-send')return fn();
    const round:ConfigurationPartyRound={namespace,phase:'request' as WorkflowScheduledAuthorityCheckpoint,active:true,joinable:true,request:true,captured:new Map()};
    try{return await this.#configurationRequestRound.run(round,()=>this.#configurationPartyRound.run(round,fn));}finally{round.active=false;round.captured.clear();}
  }
  /** Open one checkpoint-scoped party round for scheduled configuration_v2. */
  async runConfigurationPartyCheckpoint<T>(namespace:object,phase:WorkflowScheduledAuthorityCheckpoint,tx:DbService,fn:()=>Promise<T>,join=false,open=false):Promise<T>{
    // A nested checkpoint opens its own fresh round; it never inherits the outer capture.
    if(typeof fn!=='function'||this.context.requireWorkflowScheduledNamespaceHandle()!==namespace
      ||this.context.requireWorkflowScheduledCurrentPrincipal(namespace).namespace.kind!=='configuration_v2')throw deny('WORKFLOW_BUSINESS_ORIGINAL_CONFIGURATION_REQUIRED');
    // Exception: inside one combined origin checkpoint occurrence, its own
    // eligibility verifier of the SAME phase joins that occurrence's round.
    const outer=this.#configurationPartyRound.getStore();
    if(join&&outer?.active&&outer.joinable&&outer.namespace===namespace&&outer.phase===phase)return fn();
    // Approved 2026-10-25: inside one Kong business request every non-before-send
    // checkpoint layer (job, execution, approved load, claim reviewer) shares the
    // request's single fresh per-party read. Replays still re-authorize each
    // party's observation and re-check current grants; before-send never joins.
    const request=this.#configurationRequestRound.getStore();
    if(phase!=='before-send'&&request?.active&&request.namespace===namespace&&outer?.phase!=='before-send')
      return outer===request?fn():this.#configurationPartyRound.run(request,fn);
    const round:ConfigurationPartyRound={namespace,phase,active:true,joinable:open,captured:new Map()};
    try{return await this.#configurationPartyRound.run(round,fn);}finally{round.active=false;round.captured.clear();}
  }
  #assertPartyRound(state:PartyObservationState):void{
    if(!state.active||this.#partyObservationRound.getStore()!==state||!this.#partyObservationVerifier)throw deny('WORKFLOW_PORTAL_OBSERVATION_ROUND_REQUIRED');
    this.#partyObservationVerifier.assert(state.original);
  }
  #rememberPartyAbsence(resource:Resource,witness:object,parent?:Readonly<{resource:Resource;witness:object}>):void{
    const state=this.#partyObservationRound.getStore();if(!state?.active||!state.capturing)return;
    const key=this.observationKey(resource);if(state.sources.has(key)||!witness||typeof witness!=='object')throw deny('WORKFLOW_PORTAL_OBSERVATION_SOURCE_CHANGED');
    if(parent){const source=state.sources.get(this.observationKey(parent.resource));if(source?.kind!=='sdk404'||source.witness!==parent.witness)
      throw deny('WORKFLOW_PORTAL_OBSERVATION_PARENT_SOURCE_REQUIRED');}
    state.sources.set(key,Object.freeze({kind:parent?'parent-FK-absence':'sdk404',witness,...(parent?{parentWitness:parent.witness,parentKey:this.observationKey(parent.resource)}:{})}));
  }
  private installed=false;
  private configurationBeforeSql?:Readonly<Pick<WorkflowScheduledConfigurationRootVerifier,'openClosedCheckpoint'|'assertClosedCheckpoint'|'assertClosedCheckpointLive'|'releaseClosedCheckpoint'>>;
  private fixedValidationGroup?: WorkflowScheduledValidationFixedGroup;
  private fixedCandidateGroup?: WorkflowScheduleCandidateFixedGroup;
  private readonly claims=new WeakMap<object,{namespace:object;proof:Readonly<WorkflowScheduledNamespaceProof>}>();
  private readonly serviceTlsObservations=new WeakMap<object,{active:boolean;frame:ReturnType<KongExecutionContextService['current']>;before:unknown;beforeHmac:string;references:readonly Readonly<{resource:Resource;entity:unknown}>[];referenceHmacs:string[]}>();
  private readonly serviceHostObservations=new WeakMap<object,{active:boolean;frame:ReturnType<KongExecutionContextService['current']>;read:ConfigurationNativeBeforeReadHandle;parent:Resource;raw:unknown;status:200|404;pages:unknown[];parentHmac:string;pageHmacs:string[];serviceBefore:unknown;serviceBeforeHmac:string;absence?:object}>();
  private readonly candidateObservations=new WeakMap<object,{input:Readonly<WorkflowScheduleCandidateReadInput>;observations:Observations}>();
  constructor(private readonly db:DbService,private readonly redis:RedisService,private readonly secrets:SecretService,
    private readonly context:KongExecutionContextService,private readonly kong:KongService,private readonly authz:AuthorizationService,
    private readonly plans:WorkflowPlansService,private readonly workflows:WorkflowService,private readonly approved:ApprovedWorkflowExecutionService,
    private readonly repository:WorkflowScheduleRepository,private readonly authority:WorkflowScheduledAuthorityService,
    private readonly namespaces:WorkflowScheduledNamespaceService,private readonly candidates:WorkflowScheduleCandidateReadService,
    private readonly validation:WorkflowScheduledValidationReadService,private readonly configuration:WorkflowScheduledConfigurationOriginService,
    private readonly material:WorkflowBusinessMaterialService,private readonly identity:WorkflowBusinessCurrentIdentityService,
    private readonly schedules:WorkflowBusinessSchedulesService,private readonly worker:WorkflowBusinessSchedulesWorker,private readonly modules:ModuleRef,
    private readonly scopedReads:WorkflowBusinessScopedReadService,@Optional() private readonly unknownResults?:UnknownResultDispositionService){}

  onModuleInit():void {
    if(this.installed)return;
    const storage=checksum('026_m11_workflow_schedules.sql');
    this.authority.installRepositoryPolicies(storage);this.candidates.installStorageContract(storage);this.validation.installStorageContract(storage);
    this.context.installWorkflowScheduledNamespacePolicy({verifyHandle:(handle,phase)=>this.namespaces.verifyHandle(handle,phase),verifySqlPreparation:(handle,phase)=>this.namespaces.verifySqlPreparation(handle,phase),assertLive:handle=>this.namespaces.assertLive(handle)});
    if(typeof this.context.installConfigurationRequestRoundRunner==='function')this.context.installConfigurationRequestRoundRunner((namespace,fn)=>this.runConfigurationRequestRound(namespace,fn));
    this.namespaces.installContextRunner({assertNoFrame:()=>this.empty(),run:(handle,fn)=>this.context.runWorkflowScheduledNamespace(handle,fn)});
    this.context.installWorkflowScheduleCandidateReadPolicy(this.candidates);
    this.context.installWorkflowCandidateHttpAdmissionPolicy({verifyParent:async(handle,frame)=>{
      await this.candidates.assertOriginalHttpAcceptance(handle,frame);await this.redis.assertLeaseOwnership();
    }});
    this.candidates.installContextRunner({assertNoFrame:()=>this.context.assertWorkflowScheduleCandidateReadAdmission(),run:(handle,fn)=>this.context.runWorkflowScheduleCandidateRead(handle,fn)});
    this.context.installWorkflowScheduledValidationReadPolicy(this.validation);
    this.validation.installContextRunner({originalNamespaceProof:handle=>this.context.requireWorkflowScheduledCurrentPrincipal(handle).namespace,
      assertNamespaceLive:handle=>this.namespaces.assertLive(handle),run:(handle,namespace,fn)=>this.context.runWorkflowScheduledValidationRead(handle,namespace,fn)});
    this.installFixedValidationReader();
    this.installFixedCandidateReader();
    this.context.installPortalMetadataReadPolicy({run:async(namespace,cid,path,read)=>{
      const current=this.context.currentApprovedStep(),proof=this.context.requireWorkflowScheduledCurrentPrincipal(namespace).namespace;
      let paths:readonly string[]=[];
      return this.withPortalSupportRead(namespace,proof.workflow.id,this.db,input=>{
        paths=portalActivationReadPaths(input.plan,current,cid,path);return paths;
      },async()=>{if(paths.length===2)await this.kong.request(cid,'GET',paths[0]);return read();});
    }});
    this.context.installPortalEntityParentReadPolicy({run:async(namespace,cid,path,read)=>{
      const current=this.context.currentApprovedStep(),proof=this.context.requireWorkflowScheduledCurrentPrincipal(namespace).namespace;
      return this.withPortalSupportRead(namespace,proof.workflow.id,this.db,
        input=>portalEntityParentReadPaths(input.plan,current,cid,path),read);
    }});
    if(typeof this.authority.installConfigurationPartyCheckpointRunner==='function')this.authority.installConfigurationPartyCheckpointRunner((namespace,phase,tx,fn)=>this.runConfigurationPartyCheckpoint(namespace,phase,tx,fn,true));
    if(this.fixedValidationGroup&&typeof this.authority.installPortalPartyObservationRoundRunner==='function')this.#partyObservationVerifier=this.authority.installPortalPartyObservationRoundRunner({run:async(original,fn)=>{
      if(this.#partyObservationRound.getStore())throw deny('WORKFLOW_PORTAL_OBSERVATION_ROUND_REENTRY');
      const state:PartyObservationState={original,active:true,capturing:false,sources:new Map()};
      try{return await this.#partyObservationRound.run(state,async()=>{this.#assertPartyRound(state);const result=await fn();this.#assertPartyRound(state);
        if(!state.observations||!state.scopeHmac)throw deny('WORKFLOW_PORTAL_OBSERVATION_CAPTURE_REQUIRED');return result;});}
      finally{state.active=false;state.capturing=false;state.sources.clear();state.observations=undefined;state.scopeHmac=undefined;}
    }});

    this.context.installScheduledReadAbsentTransportObserver({verifyTransport:(ticket,proof)=>this.kong.verifyScheduledReadAbsentTransport(ticket,proof)});
    const absent={verifyOriginalResponse:(token:object,observation:object)=>this.context.verifyScheduledReadAbsentObservation(token,observation)};
    this.candidates.installAbsentResponseVerifier(absent);this.validation.installAbsentResponseVerifier(absent);
    this.material.installScopedReadBridge(this.scopedReads);
    this.approved.installWorkflowScheduledReviewerReadPolicy({verifyCurrent:(reviewerId,plan,tx)=>this.subject(plan as WorkflowPlanV1,reviewerId,'approve','claim',tx)});
    if(typeof this.approved.installPortalInspectionInvocationVerifier==='function'&&typeof this.authority.installPortalInspectionInvocationVerifier==='function')
      this.authority.installPortalInspectionInvocationVerifier(this.approved.installPortalInspectionInvocationVerifier());
    if(typeof this.approved.installWorkflowScheduledAuthorityInspectionPolicy==='function')this.approved.installWorkflowScheduledAuthorityInspectionPolicy({consume:(handle,proof,checkpoint,tx)=>this.namespaces.consumeFreshPortalInspection(handle,proof,checkpoint,tx),
      loadApprovalSet:(plan,executionId,handle,tx)=>this.namespaces.readPortalOperationApprovalSet(plan,executionId,handle,tx)});
    const parentAbsence={assertChild:(input:WorkflowScheduleCandidateReadInput,child:Resource,parent:Resource)=>this.material.authorizeScopedParentAbsence(input,child,parent)};
    this.candidates.installParentAbsencePolicy(parentAbsence);this.validation.installParentAbsencePolicy(parentAbsence);
    this.authz.installWorkflowScheduledCurrentIdentityBridge({currentPrincipal:(namespace,proof,actorId,tx)=>this.identity.currentPrincipal(namespace,proof,actorId,tx)});
    for(const kind of ['configuration_v2','portal-credential-issue','portal-credential-rotate','portal-credential-revoke','entity-annotation','control-metadata','configuration-metadata','governance-metadata','workflow-policy-metadata','iam-metadata','portal-metadata','portal-developer-review','event-metadata'] as const){
      const policy=this.material.businessReadPolicy(kind,true);this.candidates.installBusinessPolicy(kind,policy);this.validation.installBusinessPolicy(kind,policy);
      this.authority.installBusinessPolicy(kind,{assertDraft:async(plan,draft,actor,tx)=>{
        const material=await this.material.materialForPlan(plan,tx);this.assertConfigurationBeforePlanSupported(material);this.same(material.subjectSeal,draft.binding.subjectSeal);
        const input=await this.material.currentReadInput(plan as WorkflowScheduledPlanV1,draft,actor.user.id,'executor',tx);await this.material.assertCurrent(input);
      },assertRequester:async(plan,draft,tx)=>{const material=await this.material.materialForPlan(plan,tx);this.assertConfigurationBeforePlanSupported(material);this.same(material.subjectSeal,draft.binding.subjectSeal);},
      assertSubject:(plan,userId,action,phase,tx)=>this.subject(plan,userId,action,phase,tx),
      assertReviewer:(plan,userId,phase,tx)=>this.subject(plan,userId,'approve',phase,tx),
      isReceiptRead:()=>this.schedules.receiptReadActive(),
      assertReceiptRead:(stored,actor,tx)=>this.assertReceiptRead(stored,actor,tx)});
    }
    this.approved.installWorkflowScheduledDelegate({readConfigurationNativeBefore:handle=>this.configurationNativeBefore(handle),runConfigurationPartyCheckpoint:(namespace,phase,tx,fn)=>this.runConfigurationPartyCheckpoint(namespace,phase,tx,fn),runValidationRead:(namespace,cid,paths,tx,fn,options)=>{
      const proof=this.context.requireWorkflowScheduledCurrentPrincipal(namespace).namespace;
      const final=this.context.scheduledPortalFinalNativePhase();
      if(proof.kind==='portal-credential-issue'&&final?.stage==='before-send'&&final.namespaceHandle===namespace&&final.namespace===proof
        &&tx===this.db&&(options?.role??'executor')==='executor'&&(options?.userId??proof.actor.id)===proof.actor.id){
        this.context.assertScheduledPortalFinalNativePhase(final);
        return this.withPortalSupportRead(namespace,proof.workflow.id,tx,input=>{
          this.context.assertScheduledPortalFinalNativePhase(final);
          if(input.plan.kind!=='portal-credential-issue'||input.plan.clusterId!==cid||input.plan.prerequisites.length!==1
            ||paths.length!==1||input.plan.prerequisites[0].type!=='services'||input.plan.prerequisites[0].path!==paths[0]
            ||final.execution.workflowId!==input.plan.workflowId||final.namespace.workflow.planHash!==this.secrets.fingerprint(input.plan))
            throw deny('WORKFLOW_BUSINESS_PORTAL_PREREQUISITE_REQUIRED');
          return Object.freeze([input.plan.prerequisites[0].path]);
        },async()=>fn()).then(result=>{this.context.assertScheduledPortalFinalNativePhase(final);return result;});
      }
      return this.withLiveReads(namespace,proof.workflow.id,options?.userId??proof.actor.id,options?.role??'executor',tx,
        async(input)=>{
          const scope=await this.material.resolveAbsenceReadScope(input),resources=this.selectResources(scope.resources,cid,proof.workspaceId,paths);
          return this.validation.runValidationResources(namespace,cid,proof.workspaceId,resources,tx,async()=>fn(),options);
        });
    },assertConfigurationOrigin:async(namespace,plan,userId,action,tx)=>{
      if(plan.kind!=='configuration_v2'||this.context.requireWorkflowScheduledNamespaceHandle()!==namespace)throw deny('WORKFLOW_BUSINESS_CONFIGURATION_ORIGIN_REQUIRED');
      await this.subject(plan,userId,action,'packet',tx);
    }});
    const closedConfigurationSql=this.authority.installScheduledConfigurationOriginSqlVerifier({
      observe:(plan,draft,tx)=>this.material.promoteClosedSqlMaterial(plan,draft,tx),
    });
    this.configurationBeforeSql=closedConfigurationSql;
    this.configuration.installRootVerifier({assertCandidateRead:async(handle,jobId,userId,tx)=>{
      const proof=await this.candidates.verifyHandle(handle),read=this.candidateObservations.get(handle);
      if(!read||proof.actor.id!==userId||read.input.plan.kind!=='configuration_v2'||read.input.plan.subject.id!==jobId)throw deny('WORKFLOW_BUSINESS_ORIGINAL_CANDIDATE_REQUIRED');
      await this.material.assertReadComplete(read.input);
    },assertCandidateMaterial:async(handle,material,userId,tx)=>{
      const read=this.candidateObservations.get(handle);if(!read||read.input.principal.user.id!==userId)throw deny('WORKFLOW_BUSINESS_ORIGINAL_CANDIDATE_REQUIRED');
      this.same((await this.material.configurationMaterial(material.job.id,tx)).subjectSeal,material.subjectSeal);await this.material.assertReadComplete(read.input);
    },assertLedgerCurrent:(namespace,proof,tx)=>this.assertLedgerCurrent(namespace,proof,tx),
    runLiveCheckpoint:(namespace,phase,tx,fn)=>{
      // Outside the exact original configuration namespace there is no round:
      // every party keeps its complete fresh per-call live read.
      let eligible=false;try{eligible=this.context.requireWorkflowScheduledNamespaceHandle()===namespace
        &&this.context.requireWorkflowScheduledCurrentPrincipal(namespace).namespace.kind==='configuration_v2';}catch{eligible=false;}
      return eligible?this.runConfigurationPartyCheckpoint(namespace,phase,tx,fn,false,true):fn();},
    assertLiveMaterial:async(inspection,phase,tx)=>this.assertConfigurationMaterial(inspection,tx,phase),
    openClosedCheckpoint:closedConfigurationSql.openClosedCheckpoint,
    assertClosedCheckpoint:closedConfigurationSql.assertClosedCheckpoint,
    assertClosedCheckpointLive:closedConfigurationSql.assertClosedCheckpointLive,
    releaseClosedCheckpoint:closedConfigurationSql.releaseClosedCheckpoint});
    const core=this.modules.get(ConfigurationService,{strict:false}),origins=this.modules.get(ConfigurationOriginService,{strict:false});
    core.installWorkflowScheduledConfigurationOrigin(this.configuration);
    origins.installWorkflowScheduledOrigin({currentOriginalJobHandle:()=>this.configuration.currentOriginalJobHandle(),
      verifyOriginalJobHandle:(handle,phase,tx)=>this.configuration.verifyJobHandle(handle,phase,tx),
      assertCurrentSourceMaterial:async(input,tx)=>{
        const principal=this.context.requireWorkflowScheduledCurrentPrincipal(input.proof.namespaceHandle),stored=await this.repository.inspectStored(principal.namespace.claim.scheduleId,tx);
        const material=await this.material.materialForPlan(stored.plan,tx);if(material.kind!=='configuration_v2'||!material.promotion)throw deny('WORKFLOW_BUSINESS_PROMOTION_SOURCE_REQUIRED');
        this.same(material.promotion.sourceNativeFingerprints,input.sourceNativeFingerprints);this.same(material.promotion.targetNativeFingerprints,input.targetNativeFingerprints);
        this.same(material.promotion.selection,input.selection);this.same(material.promotion.recovery,input.recovery);
        await this.withLiveReads(input.proof.namespaceHandle,stored.plan.workflowId,input.actorId,'executor',tx,async()=>undefined);
      },assertExecutionBudget:async(input,tx)=>{
        const ns=this.context.requireWorkflowScheduledCurrentPrincipal(input.proof.namespaceHandle).namespace;
        const packets=input.plan.steps.reduce((count,s)=>count+s.nativeRequests.length,0);
        if(input.sourceFenceRounds!==packets*2||input.readRetriesReserved!==3)throw deny('WORKFLOW_BUSINESS_SOURCE_BUDGET_INVALID');
        await this.withLiveReads(input.proof.namespaceHandle,ns.workflow.id,input.actorId,'executor',tx,async(_read,_observations,usage)=>this.material.assertExecutionReadBudget(packets,usage));
      }});
    this.workflows.installBusinessScheduledDelegate({verifyOriginalClaim:async(handle,namespace,phase,tx)=>{
      const original=this.claims.get(handle),proof=this.context.requireWorkflowScheduledCurrentPrincipal(namespace).namespace;
      if(!original||original.namespace!==namespace||original.proof!==proof)throw deny('WORKFLOW_BUSINESS_ORIGINAL_CLAIM_REQUIRED');
      const current=await this.namespaces.inspectOriginalClaim(handle,namespace,phase==='inspect'?'claim':phase);
      if(this.claims.get(handle)!==original||this.context.requireWorkflowScheduledCurrentPrincipal(namespace).namespace!==proof)
        throw deny('WORKFLOW_BUSINESS_ORIGINAL_CLAIM_REQUIRED');
      return current;
    },captureSnapshot:(handle,namespace,plan,eid)=>this.snapshot(handle,namespace,plan,eid),
      readNativeAfter:(handle,namespace,plan,step,eid)=>this.nativeAfter(handle,namespace,plan,step,eid),
      deriveCompletion:(handle,eid,tx)=>this.completion(handle,eid,tx)});
    this.authority.installExecutor({executeClaim:(handle,beginBusinessCallback)=>this.namespaces.runOriginalClaim(handle,async()=>{
      const namespace=this.context.requireWorkflowScheduledNamespaceHandle(),proof=this.context.requireWorkflowScheduledCurrentPrincipal(namespace).namespace;
      beginBusinessCallback(namespace);
      this.claims.set(handle,{namespace,proof});return this.workflows.executeBusinessScheduledClaim(handle,namespace);
    }),verifyCompletion:(handle,completion,tx)=>this.workflows.verifyBusinessScheduledCompletion(handle,completion,tx)});
    this.schedules.installProposalPolicy({prepareRevision:input=>this.prepareProposal(input),assertProposal:input=>this.assertProposal(input)},
      {name:'029_m11_business_schedule_revisions.sql',checksum:checksum('029_m11_business_schedule_revisions.sql')});
    this.schedules.installWorkflowOperationPolicy({assertOperation:async input=>{
      const frame=this.context.current();
      if(frame.actor?.id!==input.actor.user.id||frame.sessionId!==input.acceptance.sessionId||frame.clusterId!==input.plan.clusterId
        ||frame.workspaceId!==input.plan.workspaceId)throw deny('WORKFLOW_BUSINESS_ORIGINAL_HTTP_PROPOSAL_REQUIRED');
      if(this.schedules.receiptReadActive()){
        if(input.action!=='read'||!['read','list','receipt'].includes(input.command)||!input.schedule)
          throw deny('WORKFLOW_SCHEDULE_RECEIPT_READ_ONLY');
        this.same(input.plan,input.schedule.plan);
        await this.assertReceiptRead(input.schedule,input.actor,input.transaction);
      }else{
        if(input.action==='write'&&input.command==='activate')this.assertConfigurationBeforePlanSupported(await this.material.materialForPlan(input.plan,input.transaction));
        await this.approved.assertSubject(input.plan as WorkflowPlanV1,input.actor.user,input.action,input.transaction);
      }
      // GET admission has no mutation lease. Command handlers already hold
      // their original lock before entering write/approval verification.
      if(input.action!=='read')await this.redis.assertLeaseOwnership();this.context.current();
    }});
    this.worker.installFixedDelegate({acquireDueClaim:id=>this.authority.acquireDueClaim(id),executeClaim:handle=>this.authority.executeClaim(handle)});
    // Production apply ports: all 8 metadata kinds must have registry handlers so scheduled claims execute via Authority→ApprovedBusinessExecution.
    assertMetadataScheduleProductionHandlers();
    this.unknownResults?.installStorageChecksum(checksum('044_m11_unknown_result_disposition.sql'));
    this.unknownResults?.installConfigurationStorageChecksum(checksum('049_m11_configuration_unknown_result.sql'));
    this.unknownResults?.installAbandonStorageChecksum(checksum('050_m11_unknown_result_abandon.sql'));
    this.unknownResults?.installUnsentStorageChecksum(checksum('051_m11_configuration_unsent_settle.sql'));
    this.installed=true;
  }
  private empty():void{if(this.context.peek()!==null)throw deny('WORKFLOW_BUSINESS_EMPTY_CONTEXT_REQUIRED');}
  private same(a:unknown,b:unknown):void{if(this.secrets.fingerprint(a)!==this.secrets.fingerprint(b))throw changed('WORKFLOW_BUSINESS_MATERIAL_CHANGED');}
  /** Historical schedule projection, not executable-subject authorization.
   * Repository still authenticates/decrypts its existing sealed draft/plan.
   * This helper adds no decrypt, native observation, secret or permit path. */
  private async assertReceiptRead(stored:Readonly<WorkflowScheduleStored>,actor:EntityActor,tx:DbService):Promise<void>{
    await this.schedules.assertReceiptReadScope(stored,actor,tx);
    const plan=stored.plan,b=stored.draft.binding,hash=this.secrets.fingerprint(plan);
    validateWorkflowPlan(plan as WorkflowPlanV1);
    if(!['configuration_v2','portal-credential-issue','portal-credential-rotate','portal-credential-revoke','entity-annotation','control-metadata','configuration-metadata','governance-metadata','workflow-policy-metadata','iam-metadata','portal-metadata','portal-developer-review','event-metadata'].includes(plan.kind)||!plan.approvalRequired||hash!==b.workflowPlanHash
      ||plan.workflowId!==b.workflowId||plan.planRevision!==b.workflowPlanRevision||plan.subject.type!==b.subjectType||plan.subject.id!==b.subjectId)
      throw deny('WORKFLOW_SCHEDULE_RECEIPT_BINDING_INVALID');
    const read=async()=>{await this.authz.assertWholeWorkspace(actor.user,plan.clusterId,plan.workspaceId,'workflows','read',tx);
      await this.authz.assertWholeWorkspace(actor.user,plan.clusterId,plan.workspaceId,({
      'configuration_v2':'snapshots','portal-credential-issue':'portal','portal-credential-rotate':'portal','portal-credential-revoke':'portal','entity-annotation':'annotations','control-metadata':'clusters',
      'configuration-metadata':'snapshots','governance-metadata':'governance','workflow-policy-metadata':'workflows','iam-metadata':'users',
      'portal-metadata':'portal','portal-developer-review':'developers','event-metadata':'events'} as Record<string,string>)[plan.kind]??'workflows','read',tx);};
    await read();const before=await this.receiptBindings(plan,stored.draft.delegation.ownerId,tx);
    await this.schedules.assertReceiptReadScope(stored,actor,tx);
    await read();this.same(await this.receiptBindings(plan,stored.draft.delegation.ownerId,tx),before);
    // Do not freeze old owner/developer epochs or execution windows into a
    // read grant. A new valid SID may see history, never adopt its delegation.
    await this.schedules.assertReceiptReadScope(stored,actor,tx);
  }
  private async receiptBindings(plan:Readonly<WorkflowScheduledPlanV1>,scheduleAuthorId:string,tx:DbService):Promise<unknown>{
    const hash=this.secrets.fingerprint(plan),keys=[plan.workflowId,plan.clusterId,plan.workspaceId];let subject:unknown;
    const workflow=await tx.one<any>(`SELECT id,cluster_id,workspace_id,kind,subject_type,subject_id,requester_type,requester_user_id,requester_developer_id,
      definition_id,definition_version,plan_revision,plan_hash,execution_mode,approval_required FROM workflows WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3`,keys);
    const version=await tx.one<any>(`SELECT cluster_id,workspace_id,workflow_id,plan_revision,plan_hash,policy_version,execution_mode,approval_required,
      step_count,native_request_count,steps_hash,created_by,created_by_developer_id FROM workflow_versions
      WHERE workflow_id=$1 AND cluster_id=$2 AND workspace_id=$3 AND plan_revision=$4`,[...keys,plan.planRevision]);
    if(!workflow||!version||workflow.id!==plan.workflowId||workflow.cluster_id!==plan.clusterId||workflow.workspace_id!==plan.workspaceId
      ||workflow.kind!==plan.kind||workflow.subject_type!==plan.subject.type||workflow.subject_id!==plan.subject.id||workflow.requester_type!==plan.requester.type
      ||(plan.requester.type==='console'?workflow.requester_user_id:workflow.requester_developer_id)!==plan.requester.id
      ||workflow.definition_id!==plan.definition.id||workflow.definition_version!==plan.definition.version
      ||!Number.isSafeInteger(workflow.plan_revision)||workflow.plan_revision<plan.planRevision
      ||workflow.plan_revision===plan.planRevision&&workflow.plan_hash!==hash||workflow.execution_mode!==plan.executionMode||workflow.approval_required!==true
      ||version.cluster_id!==plan.clusterId||version.workspace_id!==plan.workspaceId||version.workflow_id!==plan.workflowId||version.plan_revision!==plan.planRevision
      ||version.plan_hash!==hash||version.policy_version!==plan.definition.version||version.execution_mode!==plan.executionMode||version.approval_required!==true
      ||version.step_count!==plan.steps.length||version.native_request_count!==plan.steps.reduce((n,s)=>n+s.nativeRequests.length,0)
      ||version.steps_hash!==this.secrets.fingerprint(plan.steps)
      // appendScheduledRevision is authored by the accepting console owner,
      // including Portal schedules whose original requester is a developer.
      ||version.created_by!==scheduleAuthorId||version.created_by_developer_id!==null)
      throw deny('WORKFLOW_SCHEDULE_RECEIPT_BINDING_INVALID');
    if(plan.kind==='configuration_v2'){
      const payload=assertConfigurationWorkflowPlan(plan as WorkflowPlanV1).metadata as ConfigurationWorkflowPayload;
      const job=await tx.one<any>(`SELECT id,cluster_id,workspace_id,actor_id,kind,plan_id,plan_revision,plan_hash,workflow_id,
        transport_scope,execution_mode,approval_required,cluster_revision,workspace_revision FROM configuration_jobs WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3`,[plan.subject.id,plan.clusterId,plan.workspaceId]);
      const configuration=await tx.one<any>(`SELECT cluster_id,workspace_id,plan_id,plan_revision,plan_hash,cluster_revision,workspace_revision
        FROM configuration_plan_versions WHERE plan_id=$1 AND cluster_id=$2 AND workspace_id=$3 AND plan_revision=$4`,[payload.planId,plan.clusterId,plan.workspaceId,payload.planRevision]);
      if(!job||!configuration||job.id!==payload.jobId||job.cluster_id!==plan.clusterId||job.workspace_id!==plan.workspaceId||job.actor_id!==plan.requester.id
        ||!['apply','rollback','reconcile'].includes(job.kind)||job.plan_id!==payload.planId||job.plan_revision!==payload.planRevision||job.plan_hash!==payload.planHash
        ||job.workflow_id!==plan.workflowId||job.transport_scope!==plan.scope.transportScope||job.execution_mode!==plan.executionMode||job.approval_required!==true
        ||job.cluster_revision!==plan.scope.clusterRevision||job.workspace_revision!==plan.scope.workspaceRevision
        ||configuration.cluster_id!==plan.clusterId||configuration.workspace_id!==plan.workspaceId||configuration.plan_id!==payload.planId
        ||configuration.plan_revision!==payload.planRevision||configuration.plan_hash!==payload.planHash
        ||configuration.cluster_revision!==plan.scope.clusterRevision||configuration.workspace_revision!==plan.scope.workspaceRevision)
        throw deny('WORKFLOW_SCHEDULE_RECEIPT_BINDING_INVALID');
      subject={job,configuration};
    }else{
      if(plan.subject.type!=='portal_application_grants'||plan.requester.type!=='developer'||plan.steps.length!==4)
        throw deny('WORKFLOW_SCHEDULE_RECEIPT_BINDING_INVALID');
      const g=await tx.one<any>(`SELECT id,cluster_id,workspace_id,application_id,publication_id,developer_id,consumer_id,acl_id,acl_group,workflow_id,transport_scope
        FROM portal_application_grants WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3`,[plan.subject.id,plan.clusterId,plan.workspaceId]);
      if(!g)throw deny('WORKFLOW_SCHEDULE_RECEIPT_BINDING_INVALID');
      const app=await tx.one<any>('SELECT id,cluster_id,workspace_id,developer_id FROM portal_applications WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3',[g.application_id,plan.clusterId,plan.workspaceId]);
      const developer=await tx.one<any>('SELECT id,cluster_id,workspace_id FROM portal_developers WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3',[g.developer_id,plan.clusterId,plan.workspaceId]);
      const publication=await tx.one<any>('SELECT id,cluster_id,workspace_id,service_id,acl_group,transport_scope FROM portal_publications WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3',[g.publication_id,plan.clusterId,plan.workspaceId]);
      const credential=await tx.one<any>(`SELECT id,cluster_id,workspace_id,grant_id,developer_id,consumer_id,kong_id,credential_kind,generation,previous_credential_id,workflow_id,key_fingerprint
        FROM portal_credentials WHERE grant_id=$1 AND cluster_id=$2 AND workspace_id=$3 AND generation=1`,[g.id,plan.clusterId,plan.workspaceId]);
      const sameScope=(row:any)=>row&&row.cluster_id===plan.clusterId&&row.workspace_id===plan.workspaceId;
      if(!sameScope(g)||!sameScope(app)||!sameScope(developer)||!sameScope(publication)||!sameScope(credential)
        ||g.id!==plan.subject.id||g.workflow_id!==plan.workflowId||g.developer_id!==plan.requester.id||g.transport_scope!==plan.scope.transportScope
        ||app.id!==g.application_id||app.developer_id!==g.developer_id||developer.id!==g.developer_id||publication.id!==g.publication_id
        ||typeof g.acl_group!=='string'||!g.acl_group.length||g.acl_group.length>128||publication.acl_group!==g.acl_group||publication.transport_scope!==plan.scope.transportScope
        ||credential.grant_id!==g.id||credential.developer_id!==g.developer_id||credential.consumer_id!==g.consumer_id||credential.workflow_id!==plan.workflowId
        ||credential.credential_kind!=='key-auth'||credential.generation!==1||credential.previous_credential_id!==null
        ||plan.generated?.consumerId!==g.consumer_id||plan.generated?.aclId!==g.acl_id||plan.generated?.credentialId!==credential.kong_id
        ||typeof plan.generated?.key!=='string'||this.secrets.fingerprint(plan.generated.key)!==credential.key_fingerprint
        ||plan.prerequisites.length!==1||plan.prerequisites[0].type!=='services'||plan.prerequisites[0].id!==publication.service_id
        ||plan.prerequisites[0].path!==`/services/${publication.service_id}`)
        throw deny('WORKFLOW_SCHEDULE_RECEIPT_BINDING_INVALID');
      for(const value of [g.id,g.application_id,g.publication_id,g.developer_id,g.consumer_id,g.acl_id,credential.id,credential.kong_id,publication.service_id])workflowId(value);
      subject={grant:g,application:app,developer,publication,credential};
    }
    return{workflow,version,subject};
  }
  private async proposalPrincipal(input:Readonly<WorkflowBusinessSchedulePrepareInput>,currentPlan:Readonly<WorkflowPlanV1>):Promise<void>{
    const {actor,acceptance,transaction:tx,basePlan:plan}=input,frame=this.context.current();
    if(frame.actor?.id!==actor.user.id||frame.sessionId!==acceptance.sessionId||frame.clusterId!==plan.clusterId||frame.workspaceId!==plan.workspaceId)
      throw deny('WORKFLOW_BUSINESS_ORIGINAL_HTTP_PROPOSAL_REQUIRED');
    const row=await tx.one<any>(`SELECT u.id,u.credential_epoch,u.permissions_epoch,i.version FROM auth_sessions s JOIN users u ON u.id=s.user_id
      CROSS JOIN iam_epoch i WHERE s.id=$1 AND u.id=$2 AND i.singleton=true AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp()
      AND s.credential_epoch=u.credential_epoch AND u.status='active' AND u.deleted_at IS NULL AND NOT u.force_password_change FOR SHARE OF s,u,i`,[acceptance.sessionId,actor.user.id]);
    if(!row||String(row.credential_epoch)!==acceptance.credentialEpoch||`${row.id}:${row.permissions_epoch}:${row.version}`!==acceptance.permissionVersion)
      throw deny('WORKFLOW_BUSINESS_PROPOSAL_IDENTITY_CHANGED');
    // The existing execution policy derives Portal scope from its current
    // publication Service. Configuration retains its original full-scope
    // policy until every handler supports an identical scoped authorization.
    // Coarse admission alone never replaces this actual subject check.
    // SQL029 advances the current workflow pointer before its after-version
    // checkpoint. Authenticate that actual stored revision in the same tx;
    // the durable verifier must keep rejecting an obsolete wrapper.
    await this.approved.assertSubject(currentPlan as WorkflowPlanV1,actor.user,'write',tx);
    await this.redis.assertLeaseOwnership();this.context.current();
  }
  private proposalProjection(plan:Readonly<WorkflowPlanV1>):unknown{
    return{version:1,workflowId:plan.workflowId,planRevision:plan.planRevision,requester:plan.requester,scope:plan.scope,definition:plan.definition,
      prerequisites:plan.prerequisites,steps:plan.steps,generated:plan.generated};
  }
  /** configuration_v2 Target weight append (POST + allocatedNativeId≠nativeId)
   * is schedule-eligible when the sealed packet is complete. Incomplete seals
   * stay fail-closed with the same code at author/revision/activate/preclaim.
   * Entity V3 Target packets keep their independent existing policy. */
  private assertConfigurationBeforePlanSupported(material:Awaited<ReturnType<WorkflowBusinessMaterialService['materialForPlan']>>):void{
    if(material.kind!=='configuration_v2')return;
    if(material.plan.steps.some(step=>configurationTargetAppendPacketIncomplete(step)))
      throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_TARGET_APPEND_UNSUPPORTED');
  }
  private async prepareProposal(input:Readonly<WorkflowBusinessSchedulePrepareInput>):Promise<Readonly<WorkflowBusinessSchedulePreparedMaterial>>{
    await this.proposalPrincipal(input,input.old.plan);const material=await this.material.materialForPlan(input.old.plan,input.transaction),plan=input.basePlan;
    this.assertConfigurationBeforePlanSupported(material);
    if(plan.workflowId!==input.old.plan.workflowId||plan.planRevision!==input.old.plan.planRevision+1||plan.expiresAt!==input.old.plan.expiresAt
      ||Date.parse(input.spec.windowEnd)>Date.parse(plan.expiresAt)||!plan.approvalRequired)throw changed('WORKFLOW_BUSINESS_PROPOSAL_DEADLINE_CHANGED');
    const subjectSeal=isPortalCredentialBusinessMaterial(material)?{...material.subjectSeal,nativeManifestHmac:this.secrets.fingerprint(this.proposalProjection(plan))}:material.subjectSeal;
    const impacts=[deriveImpact({entityType:plan.subject.type,entityId:plan.subject.id,action:'write'})];
    if(material.kind==='configuration_v2')for(const step of material.plan.steps)impacts.push(deriveImpact({entityType:step.entityType,
      entityId:step.nativeId??step.allocatedNativeId,action:step.mutationAction,parentId:step.parentId,credentialKind:step.credentialKind,before:step.before,payload:step.body}));
    else if(isPortalCredentialBusinessMaterial(material))for(const step of plan.steps.filter(s=>s.kind==='native'))impacts.push(deriveImpact({entityType:step.entityType,
      entityId:step.nativeRequests[0]?.nativeId,action:step.mutationAction!,parentId:step.parentId,credentialKind:step.credentialKind,before:step.before,payload:step.mutationPayload}));
    if(material.kind==='configuration_v2'&&material.promotion){
      for(const inv of [material.promotion.source,material.promotion.target])await this.authz.assertWholeWorkspace(input.actor.user,inv.scope.clusterId,inv.scope.workspaceId,'promote','write',input.transaction);
      if(material.promotion.selection.includeCredentials||material.promotion.selection.includeSecrets)for(const inv of [material.promotion.source,material.promotion.target])
        await this.authz.assertWholeWorkspace(input.actor.user,inv.scope.clusterId,inv.scope.workspaceId,'secrets','read',input.transaction);
    }
    return immutableJson({subjectSeal,requesterCredentialEpoch:isPortalCredentialBusinessMaterial(material)?String(material.developer.credential_epoch):material.kind==='entity-annotation'?String(material.intent.credential_epoch):input.acceptance.credentialEpoch,impact:mergeImpact(...impacts)});
  }
  private async assertProposal(input:Readonly<WorkflowBusinessScheduleProposalInput>):Promise<void>{
    const before=input.checkpoint==='before-version';await this.proposalPrincipal(input,before?input.old.plan:input.plan);
    const material=await this.material.materialForPlan(before?input.old.plan:input.plan,input.transaction);
    this.assertConfigurationBeforePlanSupported(material);
    const subjectSeal=isPortalCredentialBusinessMaterial(material)?(before?{...material.subjectSeal,nativeManifestHmac:this.secrets.fingerprint(this.proposalProjection(input.basePlan))}:material.subjectSeal):material.subjectSeal;
    this.same(subjectSeal,input.draft.binding.subjectSeal);
    if(input.plan.scheduling.ownerId!==input.actor.user.id||input.plan.scheduling.executorId!==input.actor.user.id
      ||input.plan.scheduling.ownerCredentialEpoch!==input.acceptance.credentialEpoch||input.plan.expiresAt!==input.old.plan.expiresAt
      ||input.plan.planRevision!==input.old.plan.planRevision+1||Date.parse(input.spec.windowEnd)>Date.parse(input.plan.expiresAt))throw changed('WORKFLOW_BUSINESS_PROPOSAL_CHANGED');
    const impacts=[deriveImpact({entityType:input.plan.subject.type,entityId:input.plan.subject.id,action:'write'})];
    if(material.kind==='configuration_v2')for(const s of material.plan.steps)impacts.push(deriveImpact({entityType:s.entityType,entityId:s.nativeId??s.allocatedNativeId,
      action:s.mutationAction,parentId:s.parentId,credentialKind:s.credentialKind,before:s.before,payload:s.body}));
    else if(isPortalCredentialBusinessMaterial(material))for(const s of input.plan.steps.filter(s=>s.kind==='native'))impacts.push(deriveImpact({entityType:s.entityType,entityId:s.nativeRequests[0]?.nativeId,
      action:s.mutationAction!,parentId:s.parentId,credentialKind:s.credentialKind,before:s.before,payload:s.mutationPayload}));
    this.same(mergeImpact(...impacts),input.draft.impact);
    if(material.kind==='configuration_v2'&&material.promotion)for(const inv of [material.promotion.source,material.promotion.target]){
      await this.authz.assertWholeWorkspace(input.actor.user,inv.scope.clusterId,inv.scope.workspaceId,'promote','write',input.transaction);
      if(material.promotion.selection.includeCredentials||material.promotion.selection.includeSecrets)await this.authz.assertWholeWorkspace(input.actor.user,inv.scope.clusterId,inv.scope.workspaceId,'secrets','read',input.transaction);
    }
  }
  private observationKey(resource:Resource):string{return this.secrets.fingerprint({clusterId:resource.clusterId,workspaceId:resource.workspaceId,path:resource.path,query:resource.query??{}});}
  private observation(observations:Observations,cid:string,wid:string,path:string):Observations extends Map<string,infer V>?V|undefined:never {
    const matches=[...observations.values()].filter(o=>o.resource.clusterId===cid&&o.resource.workspaceId===wid&&o.resource.path===path);
    if(matches.length>1)throw changed('WORKFLOW_BUSINESS_AMBIGUOUS_READ_OBSERVATION');return matches[0];
  }
  private selectResources(resources:readonly Resource[],cid:string,wid:string,paths:readonly string[]):readonly Resource[]{
    return paths.map(path=>{
      const matches=resources.filter(r=>r.clusterId===cid&&r.workspaceId===wid&&r.path===path);
      if(matches.length!==1)throw changed('WORKFLOW_BUSINESS_READBACK_SCOPE_REQUIRED');return matches[0];
    });
  }
  private async readResources(resources:readonly Resource[],observations:Observations,capsule:ReadCapsule):Promise<number>{
    const sdkAbsences=new Map<string,object>();let inferredFacts=0;
    const read=(resource:Resource,query:Readonly<Record<string,string|number>>|undefined=resource.query)=>
      this.context.runWorkflowScheduledReadResource(capsule.handle,resource,()=>this.kong.request(resource.clusterId,'GET',resource.path,undefined,query));
    for(const resource of resources){
      if(resource.required===false)continue;
      if(resource.kind!=='collection'){
        if(capsule.domain==='scoped-points-v1'&&resource.kind==='point'&&resource.allowAbsent===true&&resource.parentId){
          const parent=resources.find(r=>r.clusterId===resource.clusterId&&r.workspaceId===resource.workspaceId&&r.kind==='point'&&r.entityId===resource.parentId&&r.parentId===undefined);
          const witness=parent&&sdkAbsences.get(this.observationKey(parent));
          if(witness){
            const derived=await capsule.provider.observeFutureChildAbsence(capsule.handle,resource,witness);
            if(derived.kind!=='parent-FK-absence'||derived.nativeRequestsSent!==0)throw deny('WORKFLOW_BUSINESS_ORIGINAL_PARENT_ABSENCE_REQUIRED');
            this.#rememberPartyAbsence(resource,derived,{resource:parent!,witness});
            observations.set(this.observationKey(resource),{resource,value:null,absence:'parent-FK-absence'});inferredFacts++;continue;
          }
        }
        try{observations.set(this.observationKey(resource),{resource,value:await read(resource)});}
        catch(error){
          if(capsule.domain!=='scoped-points-v1'||resource.kind!=='point'||resource.allowAbsent!==true||!(error instanceof HttpException)||error.getStatus()!==404)throw error;
          // The original provider must already have observed the SDK's parsed
          // 404. A caught exception or its payload cannot establish absence.
          const witness=await capsule.provider.requireObservedAbsentPoint(capsule.handle,resource);
          this.#rememberPartyAbsence(resource,witness);
          sdkAbsences.set(this.observationKey(resource),witness);observations.set(this.observationKey(resource),{resource,value:null,absence:'sdk404'});
        }
        continue;
      }
      let offset:string|undefined;const rows:unknown[]=[];
      for(let page=0;page<100;page++){
        const result=await read(resource,{...resource.query,...(offset?{offset}:{})});
        if(!Array.isArray(result?.data)||!Object.hasOwn(result,'next'))throw changed('WORKFLOW_BUSINESS_ACTUAL_EOF_REQUIRED');rows.push(...result.data);
        if(result.next===null){observations.set(this.observationKey(resource),{resource,value:{data:rows,next:null}});break;}
        if(typeof result.next!=='string'||page===99)throw changed('WORKFLOW_BUSINESS_ACTUAL_EOF_REQUIRED');
        const next=new URL(result.next,'http://validated-cursor.invalid');offset=next.searchParams.get('offset')??undefined;
        if(!offset)throw changed('WORKFLOW_BUSINESS_ACTUAL_CURSOR_REQUIRED');
      }
    }
    return inferredFacts;
  }
  private installFixedCandidateReader():void {
    if(this.fixedCandidateGroup)throw deny('WORKFLOW_BUSINESS_FIXED_CANDIDATE_READER_ALREADY_INSTALLED');
    this.fixedCandidateGroup=this.candidates.installFixedReader({read:async(handle,proof,input)=>{
      const observations:Observations=new Map();this.candidateObservations.set(handle,{input,observations});
      try{await this.readResources(proof.scope.resources,observations,{handle,domain:proof.scope.domain,provider:this.candidates});
        await this.material.assertReadComplete(input);
      }finally{this.candidateObservations.delete(handle);}
    }});
  }
  private installFixedValidationReader():void {
    if(this.fixedValidationGroup)throw deny('WORKFLOW_BUSINESS_FIXED_READER_ALREADY_INSTALLED');
    this.fixedValidationGroup=this.validation.installFixedReader({frame:(namespace,proof,read)=>{
      const frame=this.context.current(),principal=this.context.requireWorkflowScheduledCurrentPrincipal(namespace);
      if(principal.namespace!==proof||frame.sessionId!=null||proof.sessionId!==null||proof.origin!=='scheduled-workflow')throw deny('WORKFLOW_BUSINESS_FIXED_READER_FRAME_REQUIRED');
      if(read){if(frame.kind!=='workflow-validation-read'||principal.actor!==read.proof.actor||frame.actor!==read.proof.actor
        ||principal.role!==read.proof.role||principal.readOnly!==true||principal.validationReadHandle!==read.handle||read.proof.namespace!==proof)
          throw deny('WORKFLOW_BUSINESS_FIXED_READER_FRAME_REQUIRED');}
      // Genuine scheduled configuration jobs clone their actor when entering
      // their private child frame. Context still binds its actual executor to
      // the original Namespace; the exact parent frame is pinned separately.
      else if(principal.actor!==proof.actor||frame.actor?.id!==proof.actor.id||principal.role!=='executor'||principal.readOnly!==false||principal.validationReadHandle!==undefined)
        throw deny('WORKFLOW_BUSINESS_FIXED_READER_FRAME_REQUIRED');
      return frame;
    },read:async(handle,proof)=>{
      const observations:Observations=new Map(),inferredRecords=await this.readResources(proof.scope.resources,observations,{handle,domain:proof.scope.domain,provider:this.validation});
      return{observations:[...observations.values()],usage:this.context.currentUsage(),inferredRecords};
    }});
  }
  private async withLiveReads<T>(namespace:object,workflowId:string,userId:string,role:'executor'|'reviewer',tx:DbService,
    fn:(input:Readonly<WorkflowScheduleCandidateReadInput>,observations:Observations,usage:Usage)=>Promise<T>):Promise<T>{
    const proof=this.context.requireWorkflowScheduledCurrentPrincipal(namespace).namespace,stored=await this.repository.inspectStored(proof.claim.scheduleId,tx);
    if(stored.plan.workflowId!==workflowId)throw deny('WORKFLOW_BUSINESS_PLAN_CHANGED');
    const input=await this.material.currentReadInput(stored.plan,stored.draft,userId,role,tx),scope=await this.material.resolveAbsenceReadScope(input);
    return this.material.runResponseScope(async()=>{
      const observations:Observations=new Map(),usage={calls:0,pages:0,records:0,bytes:0};
      const groups=new Map<string,Resource[]>();for(const resource of scope.resources){const key=`${resource.clusterId}:${resource.workspaceId}`;groups.set(key,[...(groups.get(key)??[]),resource]);}
      for(const resources of groups.values()){
        const {clusterId:cid,workspaceId:wid}=resources[0];
        if(this.fixedValidationGroup){
          const result=await this.fixedValidationGroup(namespace,cid,wid,resources,tx,{role,userId});
          for(const observation of result.observations)observations.set(this.observationKey(observation.resource),observation);
          for(const key of Object.keys(usage)as Array<keyof typeof usage>)usage[key]+=result.usage[key];
          usage.records+=result.inferredRecords;continue;
        }
        await this.validation.runValidationResources(namespace,cid,wid,resources,tx,async handle=>{
          const inferred=await this.readResources(resources,observations,{handle,domain:scope.domain,provider:this.validation});
          const actual=this.context.currentUsage();for(const key of Object.keys(usage) as Array<keyof typeof usage>)usage[key]+=actual[key];
          // FK facts consume record capacity without inventing SDK calls,
          // response bytes, HTTP pages or Native requests.
          usage.records+=inferred;
        },{role,userId});
      }
      await this.material.assertCurrentReadGrants(input);return fn(input,observations,immutableJson(usage));
    });
  }
  /** A support read is deliberately incomplete. Its actual SDK responses
   * retain the original Validation provider's path, parent, workspace, READ
   * and secret checks. It never certifies the complete business scope and
   * cannot mint a Native permit; final and poststate authority remain separate. */
  private async withPortalSupportRead<T>(namespace:object,workflowId:string,tx:DbService,
    select:(input:Readonly<WorkflowScheduleCandidateReadInput>)=>readonly string[],read:()=>Promise<T>):Promise<T>{
    const frame=this.context.current(),principal=this.context.requireWorkflowScheduledCurrentPrincipal(namespace),proof=principal.namespace;
    const live=()=>{if(this.context.current()!==frame||this.context.requireWorkflowScheduledCurrentPrincipal(namespace).namespace!==proof
      ||!isPortalCredentialScheduleKind(proof.kind)||principal.role!=='executor'||principal.readOnly||principal.validationReadHandle||frame.sessionId!=null
      ||frame.actor?.id!==proof.actor.id||tx!==this.db)throw deny('WORKFLOW_BUSINESS_PORTAL_SUPPORT_ORIGINAL_REQUIRED');this.namespaces.assertLive(namespace);};
    live();const stored=await this.repository.inspectStored(proof.claim.scheduleId,tx);live();
    if(!isPortalCredentialScheduleKind(stored.plan.kind)||stored.plan.workflowId!==workflowId||stored.plan.workflowId!==proof.workflow.id
      ||this.secrets.fingerprint(stored.plan)!==proof.workflow.planHash)throw deny('WORKFLOW_BUSINESS_PORTAL_SUPPORT_PLAN_CHANGED');
    const input=await this.material.currentReadInput(stored.plan,stored.draft,proof.actor.id,'executor',tx);live();
    const paths=Object.freeze([...select(input)]);live();
    if(!paths.length||paths.length>2||new Set(paths).size!==paths.length)throw deny('WORKFLOW_BUSINESS_PORTAL_SUPPORT_PATH_REQUIRED');
    return this.material.runResponseScope(async()=>{
      const scope=await this.material.resolveAbsenceReadScope(input);live();
      const resources=this.selectResources(scope.resources,proof.clusterId,proof.workspaceId,paths);
      if(resources.some(resource=>resource.kind!=='point'))throw deny('WORKFLOW_BUSINESS_PORTAL_SUPPORT_POINT_REQUIRED');
      const result=await this.validation.runValidationResources(namespace,proof.clusterId,proof.workspaceId,resources,tx,async()=>read(),{role:'executor',userId:proof.actor.id});live();
      // No assertReadComplete/complete-grants claim: only the fixed points have
      // been observed. The actual complete authority round follows separately.
      await this.material.assertCurrent(input);live();return result;
    });
  }
  private async subject(plan:Readonly<WorkflowPlanV1>,userId:string,action:'read'|'write'|'approve',phase:WorkflowScheduledAuthorityCheckpoint,tx:DbService):Promise<void>{
    if(!('scheduling'in plan))throw deny('WORKFLOW_BUSINESS_SEALED_SCHEDULE_REQUIRED');
    const scheduled=plan as WorkflowScheduledPlanV1,frame=this.context.peek();
    if(frame?.sessionId&&frame.actor?.id===userId){
      await this.approved.assertSubject(plan as WorkflowPlanV1,frame.actor,action,tx);return;
    }
    const role=action==='approve'?'reviewer':'executor';
    if(frame&&!frame.sessionId){
      const namespace=this.context.requireWorkflowScheduledNamespaceHandle(),round=this.#partyObservationRound.getStore();
      if(round)return this.#subjectFromPartyObservation(round,namespace,plan,userId,role,phase,tx);
      const configurationRound=this.#configurationPartyRound.getStore();
      if(configurationRound)return this.#subjectInConfigurationRound(configurationRound,namespace,plan,userId,role,phase,tx);
      await this.withLiveReads(namespace,plan.workflowId,userId,role,tx,async()=>undefined);return;
    }
    if(action==='read')throw deny('WORKFLOW_BUSINESS_READ_PRINCIPAL_REQUIRED');
    if(this.fixedCandidateGroup){
      await this.material.runResponseScope(()=>this.fixedCandidateGroup!(scheduled,userId,role,tx));return;
    }
    const stored=await this.repository.inspectStored(scheduled.scheduling.scheduleId,tx),input=await this.material.currentReadInput(scheduled,stored.draft,userId,role,tx);
    await this.material.runResponseScope(()=>this.candidates.runOriginalPlan(scheduled,userId,role,async handle=>{
      const proof=await this.candidates.verifyHandle(handle),observations:Observations=new Map();this.candidateObservations.set(handle,{input,observations});
      try{await this.readResources(proof.scope.resources,observations,{handle,domain:proof.scope.domain,provider:this.candidates});await this.material.assertReadComplete(input);}finally{this.candidateObservations.delete(handle);}
    },tx));
  }
  /** Same Kong point (cluster/workspace/path) observed for another party of
   * the SAME checkpoint; each party still authorizes it with its own resource
   * descriptor and fresh grants. */
  #configurationResourceKey(r:Readonly<Resource>):string{return `${r.clusterId}:${r.workspaceId}:${r.path}`;}
  #configurationScopeKey(resources:readonly Readonly<Resource>[]):string{return this.secrets.fingerprint([...resources.map(r=>this.#configurationResourceKey(r))].sort());}
  async #subjectInConfigurationRound(round:ConfigurationPartyRound,namespace:object,plan:Readonly<WorkflowPlanV1>,userId:string,role:'executor'|'reviewer',
    phase:WorkflowScheduledAuthorityCheckpoint,tx:DbService):Promise<void>{
    const proof=this.context.requireWorkflowScheduledCurrentPrincipal(namespace).namespace;
    if(proof.kind!=='configuration_v2'||proof.workflow.id!==plan.workflowId)throw deny('WORKFLOW_BUSINESS_ORIGINAL_CONFIGURATION_REQUIRED');
    // Any mismatch (other namespace, closed round, final before-send) takes
    // the complete fresh per-party live path.
    const eligible=()=>round.active&&round.namespace===namespace&&round.phase!=='before-send'&&phase!=='before-send'&&this.#configurationPartyRound.getStore()===round;
    if(!eligible()){await this.withLiveReads(namespace,plan.workflowId,userId,role,tx,async()=>undefined);return;}
    const planHash=this.secrets.fingerprint(plan);
    if(round.planHash!==undefined&&(round.planHash!==planHash||round.permissionVersion!==proof.permissionVersion))round.captured.clear();
    round.planHash=planHash;round.permissionVersion=proof.permissionVersion;
    if(round.captured.size){
      const stored=await this.repository.inspectStored(proof.claim.scheduleId,tx);
      if(stored.plan.workflowId!==plan.workflowId||this.secrets.fingerprint(stored.plan)!==planHash)throw deny('WORKFLOW_BUSINESS_PLAN_CHANGED');
      const input=await this.material.currentReadInput(stored.plan,stored.draft,userId,role,tx);
      const replayed=await this.material.runResponseScope(async()=>{
        const scope=await this.material.resolveAbsenceReadScope(input),captured=round.captured.get(`${role}:${userId}:${this.#configurationScopeKey(scope.resources)}`);
        if(!captured||!eligible())return false;
        for(const observation of captured){
          const resource=scope.resources.find(r=>this.#configurationResourceKey(r)===this.#configurationResourceKey(observation.resource));
          if(!resource)throw deny('WORKFLOW_PORTAL_OBSERVATION_RESOURCE_REQUIRED');
          if(observation.absence==='parent-FK-absence')throw deny('WORKFLOW_PORTAL_OBSERVATION_PARENT_SOURCE_REQUIRED');
          await this.material.authorizeResponse({...input,resource,response:observation.value,status:observation.absence==='sdk404'?404:200});
        }
        await this.material.assertCurrentReadGrants(input);return true;
      });
      if(replayed)return;
    }
    await this.withLiveReads(namespace,plan.workflowId,userId,role,tx,async(input,observations)=>{
      const scope=await this.material.resolveAbsenceReadScope(input),actual=[...observations.values()];
      const required=scope.resources.filter(r=>r.required!==false);
      if(required.some(resource=>!actual.some(o=>this.secrets.fingerprint(o.resource)===this.secrets.fingerprint(resource)))
        ||actual.some(o=>!scope.resources.some(resource=>this.secrets.fingerprint(o.resource)===this.secrets.fingerprint(resource))))
        throw deny('WORKFLOW_PORTAL_OBSERVATION_INCOMPLETE');
      if(eligible())round.captured.set(`${role}:${userId}:${this.#configurationScopeKey(scope.resources)}`,
        Object.freeze(actual.map(o=>Object.freeze({resource:immutableJson(o.resource),value:immutableJson(o.value),...(o.absence?{absence:o.absence}:{})}))));
    });
  }
  /** One actual SDK observation round, separate fresh authorization for
   * every party. Original opaque absence sources are retained privately; a
   * replay is not a new transport witness, SDK call or shared permission. */
  async #subjectFromPartyObservation(state:PartyObservationState,namespace:object,plan:Readonly<WorkflowPlanV1>,userId:string,role:'executor'|'reviewer',phase:WorkflowScheduledAuthorityCheckpoint,tx:DbService):Promise<void>{
    this.#assertPartyRound(state);const original=state.original;
    if(original.namespaceHandle!==namespace||original.transaction!==tx||original.checkpoint!==phase
      ||this.secrets.fingerprint(original.plan)!==this.secrets.fingerprint(plan)||!original.parties.some(p=>p.userId===userId&&p.role===role))
      throw deny('WORKFLOW_PORTAL_OBSERVATION_PARTY_REQUIRED');
    if(!state.observations){
      if(state.capturing||role!=='executor'||userId!==original.namespace.actor.id)throw deny('WORKFLOW_PORTAL_OBSERVATION_EXECUTOR_FIRST_REQUIRED');
      state.capturing=true;
      try{await this.withLiveReads(namespace,plan.workflowId,userId,role,tx,async(input,observations)=>{
        this.#assertPartyRound(state);const scope=await this.material.resolveAbsenceReadScope(input);this.#assertPartyRound(state);
        if(scope.domain!=='scoped-points-v1'||scope.resources.some(r=>r.kind==='collection'))throw deny('WORKFLOW_PORTAL_OBSERVATION_POINTS_REQUIRED');
        const required=scope.resources.filter(r=>r.required!==false),actual=[...observations.values()];
        if(required.some(resource=>!actual.some(o=>this.secrets.fingerprint(o.resource)===this.secrets.fingerprint(resource)))
          ||actual.some(o=>!scope.resources.some(resource=>this.secrets.fingerprint(o.resource)===this.secrets.fingerprint(resource))))throw deny('WORKFLOW_PORTAL_OBSERVATION_INCOMPLETE');
        for(const observation of actual){const source=state.sources.get(this.observationKey(observation.resource));
          if(observation.absence&&(source?.kind!==observation.absence||observation.value!==null))throw deny('WORKFLOW_PORTAL_OBSERVATION_SOURCE_REQUIRED');}
        state.scopeHmac=this.secrets.fingerprint(scope.resources);
        state.observations=Object.freeze(actual.map(o=>Object.freeze({resource:immutableJson(o.resource),value:immutableJson(o.value),...(o.absence?{absence:o.absence}:{})})));
      });this.#assertPartyRound(state);}finally{state.capturing=false;}
      return;
    }
    const stored=await this.repository.inspectStored(original.namespace.claim.scheduleId,tx);this.#assertPartyRound(state);
    this.same(stored.plan,original.plan);this.same(stored.draft,original.draft);
    const input=await this.material.currentReadInput(stored.plan,stored.draft,userId,role,tx);this.#assertPartyRound(state);
    await this.material.runResponseScope(async()=>{
      const scope=await this.material.resolveAbsenceReadScope(input);this.#assertPartyRound(state);
      if(scope.domain!=='scoped-points-v1'||this.secrets.fingerprint(scope.resources)!==state.scopeHmac)throw deny('WORKFLOW_PORTAL_OBSERVATION_SCOPE_CHANGED');
      for(const observation of state.observations!){
        this.#assertPartyRound(state);const resource=scope.resources.find((d=>(r:any)=>this.secrets.fingerprint(r)===d)(this.secrets.fingerprint(observation.resource)));
        if(!resource)throw deny('WORKFLOW_PORTAL_OBSERVATION_RESOURCE_REQUIRED');
        if(observation.absence==='parent-FK-absence'){
          const source=state.sources.get(this.observationKey(resource)),parent=scope.resources.find(r=>this.observationKey(r)===source?.parentKey),parentSource=parent&&state.sources.get(this.observationKey(parent));
          if(!source||source.kind!=='parent-FK-absence'||!parent||parentSource?.kind!=='sdk404'||source.parentWitness!==parentSource.witness)throw deny('WORKFLOW_PORTAL_OBSERVATION_PARENT_SOURCE_REQUIRED');
          await this.material.authorizeScopedParentAbsence(input,resource,parent);
        }else{
          if(observation.absence==='sdk404'&&state.sources.get(this.observationKey(resource))?.kind!=='sdk404')throw deny('WORKFLOW_PORTAL_OBSERVATION_SOURCE_REQUIRED');
          await this.material.authorizeResponse({...input,resource,response:observation.value,status:observation.absence==='sdk404'?404:200});
        }
        this.#assertPartyRound(state);
      }
      // Rebuild this party's complete parent/absence/action witnesses and
      // independently check every current grant. No seen/complete bit or
      // permission result is copied from any other party.
      await this.material.assertCurrentReadGrants(input);this.#assertPartyRound(state);
    });this.#assertPartyRound(state);
  }
  /** TLS references are the fresh SDK points in this SAME complete
   * CurrentBefore round, never sealed historical certificate DTOs. Per-party
   * SQL/READ/member/secret closures inspect each original raw row independently. */
  private async configurationServiceTlsObservation(handle:ConfigurationNativeBeforeReadHandle,intent:Readonly<ConfigurationNativeBeforeReadIntent>,input:Readonly<WorkflowScheduleCandidateReadInput>,observations:Observations,before:any,body:any):Promise<Pick<ConfigurationNativeBeforeReadResult,'serviceReferences'>>{
    const effective={...before,...body},ids=new Map<string,{type:'certificates'|'ca_certificates';id:string}>(),id=(v:any)=>typeof v==='string'?v:v?.id;
    if(id(effective.client_certificate))ids.set(`certificates:${id(effective.client_certificate)}`,{type:'certificates',id:id(effective.client_certificate)});
    if(Array.isArray(effective.ca_certificates))for(const value of effective.ca_certificates)if(id(value))ids.set(`ca_certificates:${id(value)}`,{type:'ca_certificates',id:id(value)});
    const references=[...ids.values()].sort((a,b)=>a.type.localeCompare(b.type)||a.id.localeCompare(b.id)).map(ref=>{
      const observation=this.observation(observations,intent.clusterId,intent.workspaceId,`/${ref.type}/${ref.id}`);
      if(!observation||observation.resource.kind!=='point'||observation.resource.entityId!==ref.id||observation.resource.entityType!==ref.type||observation.absence
        ||!(observation.value as any)?.id||(observation.value as any).id!==ref.id)throw deny('CONFIGURATION_SERVICE_TLS_CURRENT_POINT_REQUIRED');
      return{resource:observation.resource,entity:observation.value};
    });
    const origin=Object.freeze({}),round={active:true,frame:this.context.current(),before,beforeHmac:this.secrets.fingerprint(before),references,referenceHmacs:references.map(ref=>this.secrets.fingerprint(ref))};this.serviceTlsObservations.set(origin,round);
    const original=()=>{this.approved.assertConfigurationNativeBeforeReadLive(handle,input.transaction);if(this.serviceTlsObservations.get(origin)!==round||!round.active||this.context.current()!==round.frame
      ||this.secrets.fingerprint(round.before)!==round.beforeHmac||round.references.some((ref,i)=>this.secrets.fingerprint(ref)!==round.referenceHmacs[i]))throw deny('CONFIGURATION_SERVICE_TLS_ORIGINAL_OBSERVATION_REQUIRED');};
    try{
      const stored=await this.repository.inspectStored(intent.namespace.claim.scheduleId,input.transaction);original();
      const reviewers=[...new Set(intent.namespace.approvalSet.reviewers.map(r=>r.userId))];if(!reviewers.length)throw deny('CONFIGURATION_SERVICE_REVIEWER_SET_INVALID');
      for(const actorId of reviewers){
        if(actorId===intent.actorId)throw deny('CONFIGURATION_SERVICE_REVIEWER_SET_INVALID');
        const participant=await this.material.currentReadInput(stored.plan,stored.draft,actorId,'reviewer',input.transaction);original();
        await this.material.assertServiceTlsParticipant(participant,{serviceId:intent.nativeId!,before:round.before,references:round.references});original();
      }
      original();return immutableJson({serviceReferences:references.map(ref=>({entityType:ref.resource.entityType as 'certificates'|'ca_certificates',entity:ref.entity}))});
    }finally{round.active=false;this.serviceTlsObservations.delete(origin);}
  }
  /** All principals inspect this same ORIGINAL SDK observation. The private
   * round is neither caller-constructible nor reusable after its continuation;
   * current READ/member/secret/SQL facts are independently checked per party. */
  private async configurationServiceHostObservation(handle:ConfigurationNativeBeforeReadHandle,intent:Readonly<ConfigurationNativeBeforeReadIntent>,input:Readonly<WorkflowScheduleCandidateReadInput>,before:any,body:any):Promise<Pick<ConfigurationNativeBeforeReadResult,'serviceHostUpstream'|'serviceTargets'>>{
    const effective={...before,...body};if(typeof effective.host!=='string')throw deny('CONFIGURATION_SERVICE_HOST_REQUIRED');
    this.context.startConfigurationServiceObservation();
    if(isIP(effective.host.replace(/^\[|\]$/g,'')))return {};
    const scope=await this.material.resolveAbsenceReadScope(input),parents=scope.resources.filter(r=>isServiceHostReferencePoint(r)&&r.clusterId===intent.clusterId&&r.workspaceId===intent.workspaceId
      &&r.serviceHostReference!.host===effective.host&&r.serviceHostReference!.serviceIds.includes(intent.nativeId??intent.allocatedNativeId??''));
    if(parents.length!==1)throw deny('CONFIGURATION_SERVICE_HOST_SCOPE_REQUIRED');
    const parent=parents[0],read=(readHandle:object,resource:Resource,query:Readonly<Record<string,string|number>>={})=>this.context.runWorkflowScheduledReadResource(readHandle,resource,()=>this.kong.request(resource.clusterId,'GET',resource.path,undefined,query));
    let raw:unknown,status:200|404=200,absence:object|undefined;
    await this.validation.runValidationResources(intent.namespaceHandle,intent.clusterId,intent.workspaceId,[parent],input.transaction,async readHandle=>{
      try{raw=await read(readHandle,parent);}catch(error){
        if(!(error instanceof HttpException)||error.getStatus()!==404)throw error;
        const original=await this.validation.observedServiceHostAbsence(readHandle,parent);raw=original.response;absence=original.originalWitness;status=404;
      }
    },{role:'executor',userId:intent.actorId});
    this.context.assertConfigurationServiceObservation();
    const pages:unknown[]=[],targets:unknown[]=[];
    if(status===200&&intent.observation==='service-destination'){
      const resource=await this.material.resolveServiceHostTargetResource(input,parent,raw);this.context.assertConfigurationServiceObservation();
      await this.validation.runValidationResources(intent.namespaceHandle,intent.clusterId,intent.workspaceId,[resource],input.transaction,async readHandle=>{
        let offset:string|undefined;
        for(let page=0;page<5;page++){
          const response=await read(readHandle,resource,{...resource.query,...(offset?{offset}:{})});this.context.assertConfigurationServiceObservation();
          if(!Array.isArray(response?.data)||!Object.hasOwn(response,'next'))throw deny('CONFIGURATION_SERVICE_TARGET_EOF_REQUIRED');
          pages.push(response);targets.push(...response.data);
          if(response.next===null)return;
          if(typeof response.next!=='string')throw deny('CONFIGURATION_SERVICE_TARGET_CURSOR_REQUIRED');
          const next=new URL(response.next,'http://validated-service-target.invalid');offset=next.searchParams.get('offset')??undefined;
          if(!offset)throw deny('CONFIGURATION_SERVICE_TARGET_CURSOR_REQUIRED');
        }
        throw deny('CONFIGURATION_SERVICE_TARGET_PAGE_BUDGET');
      },{role:'executor',userId:intent.actorId});
    }
    this.context.assertConfigurationServiceObservation();
    await this.material.assertServiceHostReadComplete(input,parent,status===200?raw:null,intent.observation==='service-destination');
    const origin=Object.freeze({}),round={active:true,frame:this.context.current(),read:handle,parent,raw,status:status as 200|404,pages,parentHmac:this.secrets.fingerprint(raw),pageHmacs:pages.map(p=>this.secrets.fingerprint(p)),serviceBefore:before,serviceBeforeHmac:this.secrets.fingerprint(before),...(absence?{absence}:{})};
    this.serviceHostObservations.set(origin,round);
    const original=()=>{const current=this.serviceHostObservations.get(origin);this.context.assertConfigurationServiceObservation();this.approved.assertConfigurationNativeBeforeReadLive(handle,input.transaction);
      if(current!==round||!round.active||this.context.current()!==round.frame||round.read!==handle||this.secrets.fingerprint(round.raw)!==round.parentHmac
        ||this.secrets.fingerprint(round.serviceBefore)!==round.serviceBeforeHmac||round.pages.some((page,i)=>this.secrets.fingerprint(page)!==round.pageHmacs[i])||round.status===404&&!round.absence)
        throw deny('CONFIGURATION_SERVICE_ORIGINAL_OBSERVATION_REQUIRED');};
    try{
      const stored=await this.repository.inspectStored(intent.namespace.claim.scheduleId,input.transaction);original();
      const reviewers=[...new Set(intent.namespace.approvalSet.reviewers.map(r=>r.userId))];
      if(!reviewers.length||reviewers.includes(intent.actorId))throw deny('CONFIGURATION_SERVICE_REVIEWER_SET_INVALID');
      for(const actorId of reviewers){
        original();const participant=await this.material.currentReadInput(stored.plan,stored.draft,actorId,'reviewer',input.transaction);original();
        await this.material.assertServiceHostParticipant(participant,parent,round.raw,round.status,round.pages,intent.observation==='service-destination',{serviceId:intent.nativeId!,before:round.serviceBefore});original();
      }
      original();return immutableJson({serviceHostUpstream:status===200?raw:null,...(intent.observation==='service-destination'?{serviceTargets:targets}:{})});
    }finally{round.active=false;this.serviceHostObservations.delete(origin);}
  }
  /** One new complete read round for this original packet. No previous
   * guard, hook, snapshot or caller-provided observation is reused here. */
  private async configurationNativeBefore(handle:ConfigurationNativeBeforeReadHandle):Promise<Readonly<ConfigurationNativeBeforeReadResult>>{
    if(!this.configurationBeforeSql)throw deny('CONFIGURATION_BEFORE_ROOT_PROVIDER_UNAVAILABLE');
    const until=performance.now()+30000,tx=this.db,intent=await this.approved.beginConfigurationNativeBeforeRead(handle,tx),sql=this.configurationBeforeSql;
    const frame=this.context.current();let closing:object|undefined;
    this.approved.limitConfigurationNativeBeforeRead(handle,tx,until);
    const live=()=>{this.approved.assertConfigurationNativeBeforeReadLive(handle,tx);
      if(this.context.current()!==frame||this.context.requireWorkflowScheduledNamespaceHandle()!==intent.namespaceHandle||performance.now()>=until||Date.now()>=intent.expiresAt)
        throw deny('CONFIGURATION_BEFORE_ORIGINAL_READ_EXPIRED');};
    try{
      live();closing=await sql.openClosedCheckpoint(intent.namespaceHandle,intent.namespace,'before-send',tx);live();
      const result=await this.withLiveReads(intent.namespaceHandle,intent.workflowId,intent.actorId,'executor',tx,async(input,observations)=>{
        live();const m=await this.material.configurationMaterial(intent.jobId,tx);live();
        const step=m.plan.steps.find(s=>s.stepId===intent.planStepId),request=step?.nativeRequests[0];
        if(!step||step.nativeRequests.length!==1||!request||m.job.id!==intent.jobId||m.job.cluster_id!==intent.clusterId||m.job.plan_id!==intent.planId
          ||m.job.plan_revision!==intent.planRevision||m.job.plan_hash!==intent.planHash||step.objectWorkspaceId!==intent.workspaceId
          ||step.entityType!==intent.entityType||step.mutationAction!==intent.mutationAction||(step.nativeId??null)!==(intent.nativeId??null)
          ||(step.allocatedNativeId??null)!==(intent.allocatedNativeId??null)||(step.parentId??null)!==(intent.parentId??null)
          ||(step.credentialKind??null)!==(intent.credentialKind??null)||request.method!==intent.method||request.canonicalPath!==intent.canonicalPath
          ||request.bodyHmac!==intent.bodyHmac||request.beforeHmac!==intent.beforeHmac)throw deny('CONFIGURATION_BEFORE_SEALED_STEP_CHANGED');
        const append=step.entityType==='targets'&&step.mutationAction==='update'&&step.allocatedNativeId!==step.nativeId;
        const beforePath=append?`${request.canonicalPath}/${step.nativeId}`:request.method==='POST'?`${request.canonicalPath}/${step.allocatedNativeId??step.nativeId}`:request.canonicalPath;
        if(beforePath!==intent.beforePath||(append?`${request.canonicalPath}/${step.allocatedNativeId}`:undefined)!==intent.allocatedPath)
          throw deny('CONFIGURATION_BEFORE_SEALED_STEP_CHANGED');
        const scope=await this.material.resolveAbsenceReadScope(input);live();
        const point=async(path:string,id:string,mayBeAbsent:boolean):Promise<unknown>=>{
          live();const observation=this.observation(observations,intent.clusterId,intent.workspaceId,path);
          if(observation){if(observation.resource.kind!=='point'||observation.resource.entityId!==id||(observation.resource.parentId??null)!==(intent.parentId??null))throw deny('CONFIGURATION_BEFORE_OBSERVATION_INVALID');
            if(observation.value===null){if(!mayBeAbsent||!['sdk404','parent-FK-absence'].includes(observation.absence??'')||step.entityType==='targets'&&observation.absence!=='sdk404')throw deny('CONFIGURATION_BEFORE_ABSENCE_NOT_OBSERVED');}
            else if(!observation.value||(observation.value as any).id!==id)throw deny('CONFIGURATION_BEFORE_OBSERVATION_INVALID');return observation.value;}
          // Target history may contain a hidden old UUID even when the active
          // collection reaches EOF. Require a genuine point read, never infer
          // a Target's absence from /targets' current active list.
          if(step.entityType==='targets'&&mayBeAbsent){
            const parentPath=`/upstreams/${step.parentId}`,resources=this.selectResources(scope.resources,intent.clusterId,intent.workspaceId,[parentPath,path]);
            const parent=resources[0],child=resources[1];
            if(parent.kind!=='point'||parent.entityId!==step.parentId||child.kind!=='point'||child.entityId!==id||child.parentId!==step.parentId||child.allowAbsent!==true)
              throw deny('CONFIGURATION_BEFORE_ABSENCE_SCOPE_REQUIRED');
            return this.validation.runValidationResources(intent.namespaceHandle,intent.clusterId,intent.workspaceId,resources,tx,async readHandle=>{
              const read=(resource:Resource)=>this.context.runWorkflowScheduledReadResource(readHandle,resource,()=>this.kong.request(resource.clusterId,'GET',resource.path));
              await read(parent);
              try{return await read(child);}catch(error){
                if(!(error instanceof HttpException)||error.getStatus()!==404)throw error;
                // The existing opaque SDK404 witness deliberately supports only
                // compiled required scoped points. Legacy optional allocations
                // remain unsupported rather than manufacturing that witness.
                if(scope.domain!=='scoped-points-v1'||child.required!==true)throw deny('CONFIGURATION_BEFORE_ORIGINAL_SCOPED_ABSENCE_REQUIRED');
                await this.validation.requireObservedAbsentPoint(readHandle,child);return null;
              }
            },{role:'executor',userId:intent.actorId});
          }
          if(!mayBeAbsent)throw deny('CONFIGURATION_BEFORE_POINT_NOT_OBSERVED');
          const collectionPath=path.slice(0,path.lastIndexOf('/')),collection=this.observation(observations,intent.clusterId,intent.workspaceId,collectionPath);
          if(!collection||collection.resource.kind!=='collection'||(collection.resource.parentId??null)!==(intent.parentId??null)
            ||collection.resource.query?.tags!==undefined||!Array.isArray((collection.value as any)?.data)||(collection.value as any).next!==null)
            throw deny('CONFIGURATION_BEFORE_ABSENCE_NOT_OBSERVED');
          return (collection.value as any).data.find((row:any)=>row.id===id)??null;
        };
        const beforeId=append?step.nativeId:request.method==='POST'?step.allocatedNativeId??step.nativeId:step.nativeId;
        if(!beforeId)throw deny('CONFIGURATION_BEFORE_NATIVE_ID_REQUIRED');
        const before=await point(beforePath,beforeId,request.method==='POST'&&!append);live();
        let allocatedAbsent:boolean|undefined;
        if(append){if(!step.allocatedNativeId||!intent.allocatedPath)throw deny('CONFIGURATION_BEFORE_NATIVE_ID_REQUIRED');allocatedAbsent=(await point(intent.allocatedPath,step.allocatedNativeId,true))===null;live();}
        await this.material.assertCurrentReadGrants(input);live();
        const tls=step.entityType==='services'&&request.method==='PATCH'?await this.configurationServiceTlsObservation(handle,intent,input,observations,before,step.body):{};live();
        const service=step.entityType==='services'&&request.method==='PATCH'?await this.configurationServiceHostObservation(handle,intent,input,before,step.body):{};live();
        await this.approved.assertConfigurationNativeBeforeRead(handle,tx);live();
        await sql.assertClosedCheckpoint(closing!,intent.namespaceHandle,intent.namespace,'before-send',tx);live();
        sql.assertClosedCheckpointLive(closing!,intent.namespaceHandle,intent.namespace,'before-send',tx);
        return immutableJson({before,...(append?{allocatedAbsent}:{}),...tls,...service});
      });
      live();sql.assertClosedCheckpointLive(closing!,intent.namespaceHandle,intent.namespace,'before-send',tx);live();return result;
    }finally{if(closing)sql.releaseClosedCheckpoint(closing);}
  }
  private async assertConfigurationMaterial(inspection:Readonly<WorkflowScheduledConfigurationInspection>,tx:DbService,phase?:string):Promise<void>{
    if(this.context.requireWorkflowScheduledNamespaceHandle()!==inspection.originalNamespaceHandle)throw deny('WORKFLOW_BUSINESS_ORIGINAL_CONFIGURATION_REQUIRED');
    const material=await this.material.materialForPlan(inspection.wrapper,tx);if(material.kind!=='configuration_v2')throw deny('WORKFLOW_BUSINESS_ORIGINAL_CONFIGURATION_REQUIRED');
    this.same(material.subjectSeal,inspection.subjectSeal);
    const round=this.#configurationPartyRound.getStore();
    if(round?.active&&round.joinable&&round.namespace===inspection.originalNamespaceHandle&&(round.phase===phase||round.request)&&phase!=='before-send'){
      await this.#subjectInConfigurationRound(round,inspection.originalNamespaceHandle,inspection.wrapper as Readonly<WorkflowPlanV1>,inspection.namespace.actor.id,'executor',round.phase,tx);return;}
    await this.withLiveReads(inspection.originalNamespaceHandle,inspection.wrapper.workflowId,inspection.namespace.actor.id,'executor',tx,async()=>undefined);
  }
  /** Metadata ledger observation only. The original Context and the real
   * SQL identity verifier remain mandatory; explicit execution/Native gates
   * separately retain their full Namespace and current-object observations. */
  private async assertLedgerCurrent(namespaceHandle:object,namespace:Readonly<WorkflowScheduledNamespaceProof>,tx:DbService):Promise<void>{
    const frame=this.context.current();
    const assertOriginal=()=>{
      const principal=this.context.requireWorkflowScheduledCurrentPrincipal(namespaceHandle);
      if(this.context.current()!==frame||principal.namespace!==namespace||principal.actor!==namespace.actor
        ||principal.actor.id!==namespace.actor.id||principal.role!=='executor'||principal.readOnly!==false||principal.validationReadHandle!==undefined
        ||frame.sessionId!=null||frame.actor?.id!==namespace.actor.id||namespace.sessionId!==null||namespace.origin!=='scheduled-workflow'
        ||namespace.kind!=='configuration_v2')throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_LEDGER_PRINCIPAL_REQUIRED');
      this.namespaces.assertLive(namespaceHandle);
    };
    assertOriginal();await this.redis.assertLeaseOwnership();assertOriginal();
    const current=await this.identity.currentPrincipal(namespaceHandle,namespace,namespace.actor.id,tx);
    assertOriginal();
    if(current.actorId!==namespace.actor.id||current.role!=='executor'||current.readOnly!==false
      ||current.permissionVersion!==namespace.permissionVersion||current.credentialEpoch!==namespace.credentialEpoch)
      throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_LEDGER_PERMISSIONS_CHANGED');
    await this.redis.assertLeaseOwnership();assertOriginal();
  }
  private assertOriginal(handle:object,namespace:object,plan:Readonly<WorkflowScheduledPlanV1>):void{
    const original=this.claims.get(handle);if(!original||original.namespace!==namespace||original.proof!==this.context.requireWorkflowScheduledCurrentPrincipal(namespace).namespace
      ||original.proof.workflow.id!==plan.workflowId||original.proof.workflow.planHash!==this.secrets.fingerprint(plan))throw deny('WORKFLOW_BUSINESS_ORIGINAL_CLAIM_REQUIRED');
  }
  private async snapshot(handle:object,namespace:object,plan:Readonly<WorkflowScheduledPlanV1>,executionId:string):Promise<WorkflowSnapshotV1>{
    this.assertOriginal(handle,namespace,plan);
    return this.withLiveReads(namespace,plan.workflowId,plan.scheduling.executorId,'executor',this.db,async(input,observations)=>{
      const paths=new Map<string,{type:string;id:string;fingerprint:string;absent:boolean}>();
      for(const p of plan.prerequisites)paths.set(p.path,{type:p.type,id:p.id,fingerprint:p.fingerprint,absent:false});
      for(const s of plan.steps)for(const r of s.nativeRequests){if(!r.nativeId)throw changed('WORKFLOW_BUSINESS_SNAPSHOT_ID_REQUIRED');
        const path=r.method==='POST'?`${r.canonicalPath}/${r.nativeId}`:r.canonicalPath;
        paths.set(path,{type:r.nativeType,id:r.nativeId,fingerprint:r.method==='POST'?this.secrets.fingerprint(null):r.beforeHmac??s.beforeFingerprint!,absent:r.method==='POST'});}
      const objects:WorkflowSnapshotV1['objects']=[];
      for(const [path,expected]of paths){
        let before:unknown=null;const point=this.observation(observations,plan.clusterId,plan.workspaceId,path);
        if(point)before=point.value;
        else{
          const collectionPath=path.slice(0,path.lastIndexOf('/')),collection=this.observation(observations,plan.clusterId,plan.workspaceId,collectionPath);
          if(collection?.resource.kind==='collection'&&(collection.value as any)?.next===null)before=(collection.value as any).data.find((row:any)=>row.id===expected.id)??null;
          else if(expected.absent){
            const r=plan.steps.flatMap(s=>s.nativeRequests).find(r=>r.nativeId===expected.id),parent=r?.parentId;
            const parentCreate=parent&&plan.steps.flatMap(s=>s.nativeRequests).find(r=>r.method==='POST'&&r.nativeId===parent),parentCollection=parentCreate&&this.observation(observations,plan.clusterId,plan.workspaceId,parentCreate.canonicalPath);
            if(!parentCollection||(parentCollection.value as any)?.next!==null||(parentCollection.value as any).data.some((row:any)=>row.id===parent))throw changed('WORKFLOW_BUSINESS_SNAPSHOT_ABSENCE_NOT_OBSERVED');
          }else throw changed('WORKFLOW_BUSINESS_SNAPSHOT_NOT_OBSERVED');
        }
        if(point&&before===null&&!point.absence||expected.absent&&before!==null||!expected.absent&&!before||this.secrets.fingerprint(before)!==expected.fingerprint)throw changed('WORKFLOW_BUSINESS_SNAPSHOT_CHANGED');
        objects.push({type:expected.type,id:expected.id,path,before,absent:expected.absent,fingerprint:this.secrets.fingerprint(before)});
      }
      return{version:1,workflowId:plan.workflowId,executionId,clusterId:plan.clusterId,workspaceId:plan.workspaceId,planRevision:plan.planRevision,
        planHash:this.secrets.fingerprint(plan),capturedAt:new Date().toISOString(),objects};
    });
  }
  private async nativeAfter(handle:object,namespace:object,plan:Readonly<WorkflowScheduledPlanV1>,step:Readonly<WorkflowStep>,executionId:string):Promise<unknown>{
    this.assertOriginal(handle,namespace,plan);const request=step.nativeRequests[0];if(!request?.nativeId||step.nativeRequests.length!==1)throw changed('WORKFLOW_BUSINESS_READBACK_STEP_INVALID');
    const path=request.method==='POST'?`${request.canonicalPath}/${request.nativeId}`:request.canonicalPath;
    if(isPortalCredentialScheduleKind(plan.kind)&&step.nativeRequests[0]?.method==='POST'){
      const current=this.context.currentApprovedStep(),originalStep=plan.steps.find(s=>s.id===step.id);
      if(current.kind!=='native'||current.stepId!==step.id||current.execution.executionId!==executionId||current.execution.workflowId!==plan.workflowId
        ||current.execution.actorId!==plan.scheduling.executorId
        ||!originalStep||this.secrets.fingerprint(originalStep)!==this.secrets.fingerprint(step)||request.method!=='POST')
        throw deny('WORKFLOW_BUSINESS_PORTAL_READBACK_ORIGINAL_REQUIRED');
      const binding=async()=>{
        const live=()=>{this.assertOriginal(handle,namespace,plan);this.namespaces.assertLive(namespace);
          if(this.context.currentApprovedStep()!==current)throw deny('WORKFLOW_BUSINESS_PORTAL_READBACK_ORIGINAL_REQUIRED');};
        live();const rows=await this.db.query<any>('SELECT * FROM workflow_steps WHERE workflow_id=$1 AND plan_revision=$2 ORDER BY step_order',[plan.workflowId,plan.planRevision]);live();
        const row=rows.find(row=>row.id===step.id),operation=row?.operation_id&&await this.db.one<any>('SELECT * FROM mutation_operations WHERE id=$1',[row.operation_id]);live();
        return portalReadbackReceipt(plan,step,executionId,row,operation,this.secrets);
      };
      const before=await binding(),parentPath=request.parentId?`/consumers/${request.parentId}`:undefined;
      const result=await this.withPortalSupportRead(namespace,plan.workflowId,this.db,input=>{
        this.same(input.plan,plan);return Object.freeze([...(parentPath?[parentPath]:[]),path]);
      },async()=>{if(parentPath)await this.kong.request(plan.clusterId,'GET',parentPath);return this.kong.request(plan.clusterId,'GET',path);});
      this.same(await binding(),before);
      if(this.secrets.fingerprint(result)!==before.result)throw changed('WORKFLOW_BUSINESS_PORTAL_READBACK_RESULT_CHANGED');
      return result;
    }
    return this.withLiveReads(namespace,plan.workflowId,plan.scheduling.executorId,'executor',this.db,async(input)=>{
      const scope=await this.material.resolveAbsenceReadScope(input),parentPath=request.parentId?`/${request.nativeType==='targets'?'upstreams':'consumers'}/${request.parentId}`:undefined;
      const paths=[...(parentPath?[parentPath]:[]),path],resources=this.selectResources(scope.resources,plan.clusterId,plan.workspaceId,paths);
      return this.validation.runValidationResources(namespace,plan.clusterId,plan.workspaceId,resources,this.db,async()=>{if(parentPath)await this.kong.request(plan.clusterId,'GET',parentPath);return this.kong.request(plan.clusterId,'GET',path);},{role:'executor',userId:plan.scheduling.executorId});
    });
  }
  private async completion(handle:object,executionId:string,tx:DbService):Promise<WorkflowScheduleTerminalOutcome>{
    const original=this.claims.get(handle);if(!original)throw deny('WORKFLOW_BUSINESS_ORIGINAL_COMPLETION_REQUIRED');const ns=original.proof;
    const stored=await this.repository.inspectStored(ns.claim.scheduleId,tx),loaded=await this.plans.load(ns.clusterId,ns.workspaceId,ns.workflow.id,tx);
    this.same(stored.plan,loaded.plan);if(stored.claim?.id!==ns.claim.id||stored.progress.claimId!==ns.claim.id)throw changed('WORKFLOW_BUSINESS_COMPLETION_CLAIM_CHANGED');
    const row=await tx.one<any>(`SELECT e.*,w.state AS workflow_state,o.claim_id,o.executor_id FROM workflow_executions e JOIN workflows w ON w.id=e.workflow_id
      JOIN workflow_execution_origins o ON o.execution_id=e.id WHERE e.id=$1 AND e.cluster_id=$2 AND e.workspace_id=$3`,[executionId,ns.clusterId,ns.workspaceId]);
    if(!row||row.workflow_id!==ns.workflow.id||row.plan_revision!==ns.workflow.planRevision||row.plan_hash!==ns.workflow.planHash||row.permission_version!==ns.permissionVersion
      ||row.claim_id!==ns.claim.id||row.executor_id!==ns.actor.id||row.execution_actor_id!==ns.actor.id||row.state!==row.workflow_state||!row.completed_at
      ||!['succeeded','partial','failed','uncertain'].includes(row.state))throw changed('WORKFLOW_BUSINESS_COMPLETION_FACTS_CHANGED');
    const steps=await tx.query<any>('SELECT * FROM workflow_steps WHERE workflow_id=$1 AND plan_revision=$2 ORDER BY step_order',[ns.workflow.id,ns.workflow.planRevision]);
    if(steps.length!==stored.plan.steps.length)throw changed('WORKFLOW_BUSINESS_COMPLETION_STEPS_CHANGED');
    for(const [index,step]of stored.plan.steps.entries()){
      const actual=steps[index];if(actual.id!==step.id||actual.plan_hash!==ns.workflow.planHash)throw changed('WORKFLOW_BUSINESS_COMPLETION_STEPS_CHANGED');
      if(row.state==='succeeded'&&actual.state!=='succeeded')throw changed('WORKFLOW_BUSINESS_COMPLETION_STEPS_CHANGED');
      if(step.kind==='native'&&actual.state==='succeeded'){
        const mutation=await tx.one<any>('SELECT * FROM mutation_operations WHERE id=$1',[actual.operation_id]);
        if(!mutation||mutation.state!=='succeeded'||mutation.cluster_id!==ns.clusterId||mutation.workspace_id!==ns.workspaceId||mutation.workflow_id!==ns.workflow.id
          ||mutation.workflow_plan_revision!==ns.workflow.planRevision||mutation.entity_type!==step.entityType||mutation.action!==step.mutationAction
          ||(mutation.parent_id??null)!==(step.parentId??null)||(mutation.credential_kind??null)!==(step.credentialKind??null)
          ||mutation.entity_id!==step.nativeRequests[0].nativeId||mutation.workflow_execution_id!==executionId||mutation.workflow_step_id!==step.id||mutation.actor_id!==ns.actor.id
          ||mutation.workflow_plan_hash!==ns.workflow.planHash||mutation.remote_started!==true||mutation.remote_completed!==true||!mutation.result_secret
          ||this.secrets.fingerprint(this.secrets.decrypt(mutation.before_secret,`mutation:${mutation.id}:before`))!==step.beforeFingerprint
          ||this.secrets.fingerprint(this.secrets.decrypt(mutation.payload_secret,`mutation:${mutation.id}:payload`))!==step.mutationPayloadHmac)throw changed('WORKFLOW_BUSINESS_COMPLETION_NATIVE_CHANGED');
        const result=this.secrets.decrypt<any>(mutation.result_secret,`mutation:${mutation.id}:result`),entity=result.entity??result;
        if(entity?.id!==step.nativeRequests[0].nativeId||this.secrets.fingerprint(entity)!==actual.after_fingerprint)throw changed('WORKFLOW_BUSINESS_COMPLETION_NATIVE_CHANGED');
      }
    }
    if(row.state==='succeeded'&&stored.plan.kind==='portal-credential-issue'){
      const grant=await tx.one<any>('SELECT * FROM portal_application_grants WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3',[stored.plan.subject.id,ns.clusterId,ns.workspaceId]);
      const metadata=stored.plan.steps[3].metadata as any,credential=await tx.one<any>('SELECT * FROM portal_credentials WHERE id=$1',[metadata.credentialId]);
      if(!grant||grant.state!=='active'||grant.current_generation!==1||grant.current_credential_id!==metadata.credentialId||grant.consumer_id!==metadata.consumerId
        ||!grant.acl_credential_ref_id||!credential||credential.state!=='active'||credential.grant_id!==grant.id||credential.kong_id!==metadata.kongId
        ||credential.key_fingerprint!==metadata.keyFingerprint||credential.workflow_id!==ns.workflow.id||!credential.credential_ref_id)throw changed('WORKFLOW_BUSINESS_COMPLETION_ACTIVATION_CHANGED');
      if(!await tx.one("SELECT id FROM audit_events WHERE workflow_id=$1 AND actor_id=$2 AND action='portal.credential.activate' AND result='success'",[ns.workflow.id,ns.actor.id]))throw changed('WORKFLOW_BUSINESS_COMPLETION_ACTIVATION_AUDIT_REQUIRED');
    }
    if(row.state==='succeeded'&&stored.plan.kind==='portal-credential-rotate'){
      const metaStep=stored.plan.steps.find(s=>s.handler==='portal.credential.rotate');
      const metadata=metaStep?.metadata as any;
      const grant=await tx.one<any>('SELECT * FROM portal_application_grants WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3',[stored.plan.subject.id,ns.clusterId,ns.workspaceId]);
      const neu=metadata&&await tx.one<any>('SELECT * FROM portal_credentials WHERE id=$1',[metadata.credentialId]);
      const old=metadata?.oldCredentialId&&await tx.one<any>('SELECT * FROM portal_credentials WHERE id=$1',[metadata.oldCredentialId]);
      if(!metaStep||!grant||grant.state!=='active'||grant.current_credential_id!==metadata.credentialId||!neu||neu.state!=='active'||neu.workflow_id!==ns.workflow.id
        ||!old||old.state!=='revoked'||!old.recycle_entry_id)throw changed('WORKFLOW_BUSINESS_COMPLETION_ROTATE_CHANGED');
      if(!await tx.one("SELECT id FROM audit_events WHERE workflow_id=$1 AND actor_id=$2 AND action='portal.credential.rotate' AND result='success'",[ns.workflow.id,ns.actor.id]))throw changed('WORKFLOW_BUSINESS_COMPLETION_ROTATE_AUDIT_REQUIRED');
    }
    if(row.state==='succeeded'&&stored.plan.kind==='portal-credential-revoke'){
      const metaStep=stored.plan.steps.find(s=>s.handler==='portal.credential.revoke');
      const metadata=metaStep?.metadata as any;
      const grant=await tx.one<any>('SELECT * FROM portal_application_grants WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3',[stored.plan.subject.id,ns.clusterId,ns.workspaceId]);
      const cred=metadata&&await tx.one<any>('SELECT * FROM portal_credentials WHERE id=$1',[metadata.credentialId]);
      const remaining=await tx.query<any>("SELECT id FROM portal_credentials WHERE grant_id=$1 AND state NOT IN('revoked','deleted')",[stored.plan.subject.id]);
      if(!metaStep||!grant||grant.state!=='revoked'||!cred||cred.state!=='revoked'||!cred.recycle_entry_id||remaining.length)throw changed('WORKFLOW_BUSINESS_COMPLETION_REVOKE_CHANGED');
      if(!await tx.one("SELECT id FROM audit_events WHERE workflow_id=$1 AND actor_id=$2 AND action='portal.credential.revoke' AND result='success'",[ns.workflow.id,ns.actor.id]))throw changed('WORKFLOW_BUSINESS_COMPLETION_REVOKE_AUDIT_REQUIRED');
    }
    const nested=await tx.query<any>(`SELECT e.* FROM workflow_configuration_execution_origins o JOIN configuration_executions e ON e.id=o.configuration_execution_id WHERE o.claim_id=$1`,[ns.claim.id]);
    if(stored.plan.kind==='configuration_v2'&&row.state==='succeeded'&&(nested.length!==1||nested[0].state!=='succeeded'||nested[0].actor_id!==ns.actor.id||!nested[0].completed_at))throw changed('WORKFLOW_BUSINESS_COMPLETION_CONFIGURATION_CHANGED');
    // Authority authenticates this original completion twice in the same
    // transaction. Retain its WeakMap association; an intermediate observer
    // must not consume it before the durable outcome trigger verifies it.
    if(row.state==='failed'&&nested.some(e=>['succeeded','partial'].includes(e.state)))return 'partial';
    return row.state;
  }
}
