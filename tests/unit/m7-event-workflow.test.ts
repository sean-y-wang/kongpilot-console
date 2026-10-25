import 'reflect-metadata';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { randomUUID } from 'node:crypto';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { validateWorkflowPlan } from '../../apps/console-api/src/modules/workflows/workflow-validation';
import { WorkflowRegistryService } from '../../apps/console-api/src/modules/workflows/workflow-registry.service';
import { WorkflowService } from '../../apps/console-api/src/modules/workflows/workflow.service';
import { eventExecutionAuditProof, eventMetadataProjection, EVENT_WORKFLOW_HANDLERS } from '../../apps/console-api/src/modules/workflows/event-workflow';
import type { WorkflowPlanV1 } from '../../apps/console-api/src/modules/workflows/workflow.types';

function fixture(handler: keyof typeof EVENT_WORKFLOW_HANDLERS = 'event.channel.test') {
  const secrets = new SecretService(), entityId=randomUUID(), before={id:entityId,revision:3,status:'active',endpoint_secret:'Synthetic-encrypted-material'},metadata={revision:3};
  const plan:WorkflowPlanV1={version:1,clusterId:randomUUID(),workspaceId:randomUUID(),workflowId:randomUUID(),planRevision:1,kind:'event-metadata',executionMode:'approval',approvalRequired:true,
    subject:{type:EVENT_WORKFLOW_HANDLERS[handler].subject,id:entityId},requester:{type:'console',id:randomUUID()},definition:{id:randomUUID(),version:1,policyHash:'a'.repeat(64)},issuedAt:new Date().toISOString(),expiresAt:new Date(Date.now()+60000).toISOString(),scope:{transportScope:'b'.repeat(64),clusterRevision:1,workspaceRevision:1},prerequisites:[],steps:[{id:randomUUID(),key:handler,handler,order:1,kind:'metadata',entityType:EVENT_WORKFLOW_HANDLERS[handler].subject,entityId,permissionAction:EVENT_WORKFLOW_HANDLERS[handler].action,dependencies:[],nativeRequests:[],before,metadata,metadataRevision:3,metadataBeforeHmac:secrets.fingerprint(before),metadataPayloadHmac:secrets.fingerprint(metadata)}]};
  return{plan,secrets,before};
}
beforeEach(()=>vi.stubEnv('CONSOLE_ENCRYPTION_KEY','a7'.repeat(32)));afterEach(()=>vi.unstubAllEnvs());
describe('M7 fixed metadata-only workflow boundary',()=>{
  it.each(Object.keys(EVENT_WORKFLOW_HANDLERS) as Array<keyof typeof EVENT_WORKFLOW_HANDLERS>)('accepts server %s subject/action mapping',handler=>{expect(()=>validateWorkflowPlan(fixture(handler).plan)).not.toThrow();});
  it.each(['native','generated','prerequisite','wrong-subject','wrong-action','direct','developer','second-step','mutationPayload','parent'])('refuses %s capability widening',kind=>{
    const {plan}=fixture();const step=plan.steps[0];
    if(kind==='native')step.nativeRequests=[{method:'POST',canonicalPath:'/services',nativeType:'services',nativeId:randomUUID(),bodyHmac:'a'.repeat(64)}];
    if(kind==='generated')plan.generated={consumerId:randomUUID(),aclId:randomUUID(),credentialId:randomUUID(),key:'Synthetic-key'};
    if(kind==='prerequisite')plan.prerequisites=[{type:'services',id:randomUUID(),path:'/services',fingerprint:'a'.repeat(64),before:{}}];
    if(kind==='wrong-subject')plan.subject.type='portal_publications';if(kind==='wrong-action')step.permissionAction='delete';
    if(kind==='direct'){plan.executionMode='direct';plan.approvalRequired=false;}if(kind==='developer')plan.requester.type='developer';
    if(kind==='second-step')plan.steps.push({...step,id:randomUUID(),order:2});if(kind==='mutationPayload')step.mutationPayload={id:randomUUID()};if(kind==='parent')step.parentId=randomUUID();
    expect(()=>validateWorkflowPlan(plan)).toThrow();
  });
  it('rejects event handlers smuggled into a Portal metadata kind',()=>{const {plan}=fixture();plan.kind='portal-metadata';plan.subject.type='portal_content';expect(()=>validateWorkflowPlan(plan)).toThrow();});
  it('does not allow arbitrary registry callbacks or duplicate replacement',()=>{const registry=new WorkflowRegistryService(),handler={authorize:vi.fn(),inspect:vi.fn(),apply:vi.fn()};expect(()=>registry.register('event.inject',handler)).toThrow();registry.register('event.channel.test',handler);expect(()=>registry.register('event.channel.test',handler)).toThrow();});
  it('safe event diff excludes token paths, recipients, raw auth and both ciphertexts',()=>{
    const output=eventMetadataProjection({id:randomUUID(),revision:2,status:'active',endpoint:'https://host/Synthetic-token-path',endpoint_secret:'Synthetic-endpoint-cipher',auth:{password:'Synthetic-password'},auth_secret:'Synthetic-auth-cipher',recipients:['private@example.test'],desiredConfigSecret:{endpoint:'Synthetic-hidden'},maskedDestination:'https://host/***',destinationHost:'host',authConfigured:true});
    expect(JSON.stringify(output)).not.toContain('Synthetic');expect(JSON.stringify(output)).not.toContain('private@example');expect(output).toHaveProperty('authConfigured',true);
  });
  it('review diff shows proposed status/filter/safe destination using consistent SQL and payload names',()=>{
    const before=eventMetadataProjection({credential_generation:2,event_types:['entity.created'],native_type:'services',native_ids:[],physical_tags:['secret-selector'],endpoint_secret:'Synthetic-cipher'});
    const after=eventMetadataProjection({desiredStatus:'disabled',eventTypes:['entity.updated'],nativeType:'services',nativeIds:[],physicalTags:['other-selector'],desiredConfigSecret:{endpoint:{url:'https://host/Synthetic-token-path'},auth:{token:'Synthetic-token'},safeSummary:{destinationHost:'host',maskedDestination:'https://host/***',authConfigured:true}}});
    expect(before).toMatchObject({credentialGeneration:2,eventTypes:['entity.created'],nativeType:'services',tagCount:1,configured:true});expect(after).toMatchObject({status:'disabled',eventTypes:['entity.updated'],destinationHost:'host',authConfigured:true,configured:true});expect(JSON.stringify(after)).not.toContain('Synthetic');expect(JSON.stringify(before)).not.toContain('secret-selector');
  });
  it.each(['old-execution','wrong-before','wrong-payload','wrong-subject','wrong-actor','wrong-hash','missing-row'])('actual business receipt rejects %s while preserving original Portal branch',async(kind)=>{
    const {plan,secrets,before}=fixture('event.channel.save'),step=plan.steps[0],executionId=randomUUID(),actor={user:{id:randomUUID(),username:'actor',superAdmin:false}},result={entity:{id:step.entityId}};
    const receipt={id:randomUUID(),chainScope:`cluster:${plan.clusterId}`,sequence:'12',eventHash:'c'.repeat(64),occurredAt:new Date().toISOString()};
    const row:any={id:receipt.id,event_hash:receipt.eventHash,chain_scope:receipt.chainScope,sequence:'12',occurred_at:receipt.occurredAt,actor_type:'user',actor_id:actor.user.id,cluster_id:plan.clusterId,workspace_id:plan.workspaceId,workflow_id:plan.workflowId,entity_type:step.entityType,entity_id:step.entityId,action:step.handler,result:'success',before:eventMetadataProjection(before),after:{result,operationProof:eventExecutionAuditProof(plan,step,executionId,secrets.fingerprint(plan))}};
    const db:any={one:vi.fn(async()=>kind==='missing-row'?null:row)},engine=new WorkflowService(db,{} as any,secrets,{} as any,{} as any,{} as any,{} as any,{} as any,{} as any,{} as any,{} as any,{} as any,{} as any,{} as any,{} as any);
    if(kind==='old-execution')row.after.operationProof.workflow.executionId=randomUUID();if(kind==='wrong-before')row.before.revision=1;if(kind==='wrong-payload')row.after.operationProof.payloadHmac='e'.repeat(64);if(kind==='wrong-subject')row.entity_id=randomUUID();if(kind==='wrong-actor')row.actor_id=randomUUID();if(kind==='wrong-hash')row.event_hash='f'.repeat(64);
    await expect((engine as any).eventBusinessResult({result,auditReceipt:receipt},plan,step,actor,executionId,before,db)).rejects.toMatchObject({response:{code:'EVENT_BUSINESS_AUDIT_INVALID'}});
  });
  it('verifies actual same-step audit and strips the internal receipt',async()=>{
    const {plan,secrets,before}=fixture('event.channel.save'),step=plan.steps[0],executionId=randomUUID(),actor={user:{id:randomUUID(),username:'actor',superAdmin:false}},result={entity:{id:step.entityId}};
    const receipt={id:randomUUID(),chainScope:`cluster:${plan.clusterId}`,sequence:'12',eventHash:'c'.repeat(64),occurredAt:new Date().toISOString()};
    const row={event_hash:receipt.eventHash,chain_scope:receipt.chainScope,sequence:'12',occurred_at:receipt.occurredAt,actor_type:'user',actor_id:actor.user.id,cluster_id:plan.clusterId,workspace_id:plan.workspaceId,workflow_id:plan.workflowId,entity_type:step.entityType,entity_id:step.entityId,action:step.handler,result:'success',before:eventMetadataProjection(before),after:{result,operationProof:eventExecutionAuditProof(plan,step,executionId,secrets.fingerprint(plan))}};
    const db:any={one:vi.fn(async()=>row)},engine=new WorkflowService(db,{} as any,secrets,{} as any,{} as any,{} as any,{} as any,{} as any,{} as any,{} as any,{} as any,{} as any,{} as any,{} as any,{} as any);
    await expect((engine as any).eventBusinessResult({result,auditReceipt:receipt},plan,step,actor,executionId,before,db)).resolves.toEqual(result);
  });
  it.each(['none','wrong-source','old-execution','foreign-scope','wrong-channel','wrong-replay-source','wrong-generation'])('queue receipt %s verifies actual source and delivery facts instead of queued-looking flags',async(kind)=>{
    const replay=kind==='wrong-replay-source'||kind==='wrong-generation',f=fixture(replay?'event.delivery.replay':'event.channel.test'),{plan,secrets}=f,step=plan.steps[0],executionId=randomUUID(),actor={user:{id:randomUUID(),username:'queue-actor',superAdmin:false}};
    const before={...f.before,event_id:randomUUID(),channel_id:randomUUID(),subscription_id:null};step.before=before;step.metadataBeforeHmac=secrets.fingerprint(before);
    const q={eventId:randomUUID(),deliveryId:randomUUID(),...(replay?{replayGeneration:2}:{})},result={queued:q},receipt={id:randomUUID(),chainScope:`cluster:${plan.clusterId}`,sequence:'12',eventHash:'c'.repeat(64),occurredAt:new Date().toISOString()};
    const audit:any={id:receipt.id,event_hash:receipt.eventHash,chain_scope:receipt.chainScope,sequence:receipt.sequence,occurred_at:receipt.occurredAt,actor_type:'user',actor_id:actor.user.id,cluster_id:plan.clusterId,workspace_id:plan.workspaceId,workflow_id:plan.workflowId,entity_type:step.entityType,entity_id:step.entityId,action:step.handler,result:'success',before:eventMetadataProjection(before),after:{result:{queued:true},operationProof:eventExecutionAuditProof(plan,step,executionId,secrets.fingerprint(plan))}};
    const event:any={id:q.eventId,audit_event_id:receipt.id,actor_id:actor.user.id,cluster_id:plan.clusterId,workspace_id:plan.workspaceId,source_kind:'workflow',source_id:plan.workflowId,iam_operation_id:null,event_type:replay?'delivery.replay':'channel.test',workflow_id:plan.workflowId,workflow_execution_id:executionId,workflow_plan_revision:plan.planRevision,workflow_plan_hash:secrets.fingerprint(plan),workflow_step_id:step.id};
    const delivery:any={id:q.deliveryId,cluster_id:plan.clusterId,workspace_id:plan.workspaceId,creator_id:actor.user.id,state:'pending',intent_started_at:null,channel_id:replay?before.channel_id:step.entityId,subscription_id:null,delivery_kind:'test',event_id:replay?before.event_id:event.id,replay_generation:replay?2:0,parent_delivery_id:replay?step.entityId:null};
    if(kind==='wrong-source')event.source_id=randomUUID();if(kind==='old-execution')event.workflow_execution_id=randomUUID();if(kind==='foreign-scope')delivery.workspace_id=randomUUID();if(kind==='wrong-channel')delivery.channel_id=randomUUID();if(kind==='wrong-replay-source')delivery.event_id=q.eventId;if(kind==='wrong-generation')delivery.replay_generation=1;
    const db:any={one:vi.fn(async(sql:string)=>sql.includes('audit_events')?audit:sql.includes('event_records')?event:delivery)},engine=new WorkflowService(db,{} as any,secrets,{} as any,{} as any,{} as any,{} as any,{} as any,{} as any,{} as any,{} as any,{} as any,{} as any,{} as any,{} as any),call=(engine as any).eventBusinessResult({result,auditReceipt:receipt},plan,step,actor,executionId,before,db);
    if(kind==='none')await expect(call).resolves.toEqual(result);else await expect(call).rejects.toMatchObject({response:{code:'EVENT_BUSINESS_AUDIT_INVALID'}});
  });
});
