import 'reflect-metadata';
import {randomUUID} from 'node:crypto';
import {vi} from 'vitest';
import {workflowScheduledFixture} from './workflow-scheduled-fixture';
import {KongExecutionContextService} from '../../../apps/console-api/src/infrastructure/kong/execution-context.service';
import {WorkflowScheduledAuthorityService} from '../../../apps/console-api/src/modules/workflows/workflow-scheduled-authority.service';
import {WorkflowScheduledNamespaceService} from '../../../apps/console-api/src/modules/workflows/workflow-scheduled-namespace.service';

/** Real Authority, original Namespace and Context. SQL, approval reader and
 * subject scans are controlled source adapters; they make no live SQL/SDK
 * claims. Actual canonical SQL approval-reader has its independent suite. */
export function portalInspectionProducerFixture(){
 const f=workflowScheduledFixture('portal-credential-issue'),context=new KongExecutionContextService();
 const scan={executor:0,reviewer:0},flags={approvalChanged:false,membershipRevoked:false,grantsChanged:false};
 const query=f.db.query.getMockImplementation()!,bindings=new Map<string,{id:string;roleId:string}>();
 f.db.query.mockImplementation(async(sql:string,args:any[])=>{
  if(!sql.includes('FROM iam_effective_grants'))return query(sql,args);
  let bound=bindings.get(args[0]);if(!bound){bound={id:randomUUID(),roleId:randomUUID()};bindings.set(args[0],bound);}
  const grant={user_id:args[0],role_id:bound.roleId,binding_id:bound.id,binding_source:'user',module:'portal',action:flags.grantsChanged?'read':'write',scope_type:'global',scope_values:[],cluster_id:null,workspace_id:null};
  return sql.includes('binding_current')?[{grant,binding:{id:bound.id,role_id:bound.roleId,user_id:args[0],status:'active',expires_at:null},binding_expires_at:null,binding_current:true,observed_at:new Date().toISOString()}]:[grant];
 });
 f.policy.assertSubject.mockImplementation(async()=>{if(!f.state.scopeAllowed)throw Error('CURRENT_OBJECT_SCOPE_DENIED');scan.executor++;});
 f.policy.assertReviewer.mockImplementation(async()=>{if(!f.state.reviewerActive)throw Error('CURRENT_REVIEWER_REVOKED');scan.reviewer++;});
 f.approvals.installScheduledPortalInspectionSqlReader=vi.fn((verifier:any)=>async(token:object,plan:any,input:any,tx:any)=>{
  await verifier.enter(token,plan,input.checkpoint,tx);
  try{if(flags.membershipRevoked||!f.state.reviewerActive)throw Error('CURRENT_CANDIDATE_MEMBERSHIP_REVOKED');
   return flags.approvalChanged?{...f.approvalSet,setHmac:'e'.repeat(64)}:structuredClone(f.approvalSet);
  }finally{await verifier.leave(token,plan,input.checkpoint,tx);}
 });
 const authority=new WorkflowScheduledAuthorityService(f.db,f.secrets,f.redis,context,f.plans,f.approvals,f.repository);
 const namespace=new WorkflowScheduledNamespaceService(authority,f.secrets,f.redis,context);
 context.installWorkflowScheduledNamespacePolicy({verifyHandle:(handle,phase)=>namespace.verifyHandle(handle,phase),assertLive:handle=>namespace.assertLive(handle)});
 namespace.installContextRunner({assertNoFrame(){if(context.peek())throw Error('SOURCE_ORIGINAL_EMPTY_CONTEXT_REQUIRED');},run:(handle,fn)=>context.runWorkflowScheduledNamespace(handle,fn)});
 const executionHandle=Object.freeze({}),executionId=randomUUID(),operationId=randomUUID();let proof:any;
 const approved:any={verifyExecution:vi.fn(async(handle:object)=>{if(handle!==executionHandle)throw Error('ORIGINAL_SOURCE_EXECUTION_REQUIRED');return proof;}),
  verifyWorkflowScheduledExecution:vi.fn(async(p:any,handle:object)=>{if(p!==proof||context.requireWorkflowScheduledNamespaceHandle()!==handle)throw Error('SOURCE_ORIGINAL_NAMESPACE_REQUIRED');}),
  verifyStep:vi.fn(async(p:any,id:string)=>{if(p!==proof||id!==f.plan.steps[0].id)throw Error('SOURCE_ORIGINAL_STEP_REQUIRED');return Object.freeze({execution:proof,stepId:id,kind:'native'});}),
  mutationBinding:vi.fn(),bindOperation:vi.fn(),assertNative:vi.fn(),assertMetadata:vi.fn()};
 context.installApprovedPolicy(approved);
 authority.installBusinessPolicy('portal-credential-issue',f.policy);authority.installRepositoryPolicies('a'.repeat(64));
 let callback:(namespaceHandle:object,proof:any)=>Promise<void>=async()=>{};
 const executor={executeClaim:async(handle:object,begin:(namespace:object)=>void)=>{
  await namespace.runOriginalClaim(handle,async()=>{const original=context.requireWorkflowScheduledNamespaceHandle();begin(original);
   const ns=context.requireWorkflowScheduledCurrentPrincipal(original).namespace;
   proof=Object.freeze({executionId,workflowId:f.plan.workflowId,clusterId:f.cid,workspaceId:f.wid,actorId:f.owner,sessionId:null,
    permissionVersion:ns.permissionVersion,expiresAt:Date.parse(ns.expiresAt),origin:'scheduled-workflow',scheduleClaimId:ns.claim.id,
    workflowOriginId:randomUUID(),approvalFormat:2,approvalSetId:ns.approvalSet.setId,approvalSetHmac:ns.approvalSet.setHmac});
   await context.runApprovedWorkflow(executionHandle as any,()=>context.runApprovedStep(f.plan.steps[0].id,()=>context.runOperation({actor:ns.actor,
    clusterId:f.cid,workspaceId:f.wid,operationId,entityType:'consumers',entityId:f.plan.steps[0].entityId,action:'create'},()=>callback(original,ns))));
  });return f.complete();},verifyCompletion:f.executor.verifyCompletion};
 authority.installExecutor(executor);
 const run=async(fn:typeof callback)=>{callback=fn;const handle=await authority.acquireDueClaim(f.scheduleId);if(!handle)throw Error('SOURCE_DUE_CLAIM_REQUIRED');await authority.executeClaim(handle);};
 return{...f,authority,namespace,context,flags,scan,run,executionId,operationId};
}
