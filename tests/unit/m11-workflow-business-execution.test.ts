import 'reflect-metadata';
import { randomUUID } from 'node:crypto';
import { ConflictException, ForbiddenException, Logger } from '@nestjs/common';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { KongExecutionContextService } from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import { WorkflowBusinessExecutionService } from '../../apps/console-api/src/modules/workflows/workflow-business-execution.service';
import { WorkflowService } from '../../apps/console-api/src/modules/workflows/workflow.service';
import { snapshotAad } from '../../apps/console-api/src/modules/workflows/workflow.types';
import { transportScopeFor } from '../../apps/console-api/src/infrastructure/kong/transport-scope';

beforeEach(() => vi.stubEnv('CONSOLE_ENCRYPTION_KEY','e7'.repeat(32)));
afterEach(() => vi.unstubAllEnvs());

/** Real Core/Context and AEAD. In-memory transactional ledger and genuine
 * fixture WeakMap providers model actual durable state; no real SQL or Native
 * send is performed or claimed by these tests. */
function fixture(kind:'configuration_v2'|'portal-credential-issue'|'entity-annotation'='configuration_v2', install=true, mode:'approval'|'direct'='approval'){
  const secrets=new SecretService(),context=new KongExecutionContextService(),authorityHandle=Object.freeze({}),namespaceHandle=Object.freeze({});
  const cid=randomUUID(),wid=randomUUID(),wf=randomUUID(),actor:any=Object.freeze({id:randomUUID(),username:'actual-console-executor',superAdmin:false});
  const subject=randomUUID(),developer=randomUUID(),scope=transportScopeFor('http://kong:8001'),now=Date.now(),expiry=new Date(now+60000).toISOString();
  const metadata:any=kind==='entity-annotation'?{intentId:subject,entityType:'services',entityId:randomUUID(),operation:'set',materialHmac:'e'.repeat(64)}:kind==='configuration_v2'?{jobId:subject,planId:randomUUID(),planRevision:1,planHash:'a'.repeat(64)}:{consumerId:randomUUID(),aclId:randomUUID(),kongId:randomUUID(),credentialId:randomUUID(),action:'issue'};
  const before={id:subject,revision:1,state:'pending'};
  const native=(order:number,type:string,id:string,path:string,body:any,parentId?:string,credentialKind?:string):any=>({id:randomUUID(),key:`native-${order}`,order,kind:'native',entityType:type,entityId:id,parentId,credentialKind,
    permissionAction:'write',dependencies:[],mutationAction:'create',mutationPayload:body,mutationPayloadHmac:secrets.fingerprint(body),mutationIdempotencyKey:`original-${wf}-${order}`,before:null,beforeFingerprint:secrets.fingerprint(null),
    nativeRequests:[{method:'POST',canonicalPath:path,nativeType:type,nativeId:id,parentId,credentialKind,body,bodyHmac:secrets.fingerprint(body)}]});
  const natives:any[]=kind!=='portal-credential-issue'?[]:[native(1,'consumers',metadata.consumerId,'/consumers',{id:metadata.consumerId,username:`app-${wf}`}),
    native(2,'credentials',metadata.aclId,`/consumers/${metadata.consumerId}/acls`,{id:metadata.aclId,group:'portal-test'},metadata.consumerId,'acls'),
    native(3,'credentials',metadata.kongId,`/consumers/${metadata.consumerId}/key-auth`,{id:metadata.kongId,key:'synthetic-key-must-never-be-public'},metadata.consumerId,'key-auth')];
  if(natives.length){natives[1].dependencies=[natives[0].id];natives[2].dependencies=[natives[1].id];}
  const last:any={id:randomUUID(),key:kind==='entity-annotation'?'entity.annotation':'metadata',order:natives.length+1,kind:'metadata',handler:kind==='entity-annotation'?'entity.annotation':kind==='configuration_v2'?'configuration_v2':'portal.credential.activate',
    entityType:kind==='entity-annotation'?'entity_annotation_requests':kind==='configuration_v2'?'configuration_jobs':'portal_application_grants',entityId:subject,permissionAction:'write',dependencies:natives.length?[natives[2].id]:[],nativeRequests:[],
    before,metadata,metadataBeforeHmac:secrets.fingerprint(before),metadataRevision:1,metadataPayloadHmac:secrets.fingerprint(metadata)};
  const claim:any={id:randomUUID(),scheduleId:randomUUID(),occurrenceId:randomUUID(),generation:1,workflowId:wf,workflowPlanRevision:1,issuedAt:new Date(now-1000).toISOString(),authorityExpiresAt:expiry};
  const seal:any={version:1,scheduleId:claim.scheduleId,occurrenceId:claim.occurrenceId,executorId:actor.id};
  const plan:any={version:1,clusterId:cid,workspaceId:wid,workflowId:wf,planRevision:1,kind,executionMode:mode,approvalRequired:true,
    subject:{type:last.entityType,id:subject},requester:{type:kind==='portal-credential-issue'?'developer':'console',id:kind==='portal-credential-issue'?developer:actor.id},
    definition:{id:randomUUID(),version:1,policyHash:'b'.repeat(64)},issuedAt:new Date(now-2000).toISOString(),expiresAt:expiry,
    scope:{transportScope:scope,clusterRevision:1,workspaceRevision:1},prerequisites:[],steps:[...natives,last],scheduling:seal};
  claim.workflowPlanHash=secrets.fingerprint(plan);
  const set:any={format:2,setId:randomUUID(),setHmac:'c'.repeat(64),reviewers:Array.from({length:3},()=>({userId:randomUUID(),approvalId:randomUUID(),level:1,candidateVersion:1}))};
  const ns:any=Object.freeze({version:1,origin:'scheduled-workflow',sessionId:null,actor,clusterId:cid,workspaceId:wid,kind,permissionVersion:'live-pv-1',credentialEpoch:'1',transportScope:scope,
    clusterRevision:1,workspaceRevision:1,expiresAt:expiry,workflow:{id:wf,planRevision:1,planHash:claim.workflowPlanHash},claim,requester:plan.requester,approvalSet:set});
  const inspection:any={version:1,claim,draft:{scheduleId:claim.scheduleId,binding:{workflowId:wf,workflowPlanRevision:1,workflowPlanHash:claim.workflowPlanHash,clusterId:cid,workspaceId:wid}},plan,
    approvalSet:set,principal:actor,permissionVersion:ns.permissionVersion,leaseUntil:expiry,authorityExpiresAt:expiry};
  const stored:any={w:{id:wf,state:'approved',revision:3,plan_revision:1,plan_hash:claim.workflowPlanHash,approval_format:2,approved_by:set.reviewers[2].userId},e:null,origin:null,
    steps:plan.steps.map((s:any)=>({id:s.id,kind:s.kind,step_order:s.order,state:'pending',operation_id:null})),operations:[] as any[],audits:[] as any[],txs:[] as any[]};
  const state={live:true,snapshotMissing:false,snapshotChanged:false,originInsertFail:false,metadataFail:false,receiptMissing:false,readbackChanged:false,deriveLie:false,principalChanged:false};
  const events:string[]=[],objects=new Map<string,any>();let transactionId=0;
  const db:any={
    one:vi.fn(async(sql:string,p:any[]=[])=>{
      if(sql.includes('iam_epoch'))return{version:1};
      if(sql.includes('SELECT id FROM workflow_executions'))return stored.e?{id:stored.e.id}:null;
      if(sql.includes("state='running' ORDER BY step_order"))return stored.steps.find((s:any)=>s.state==='running')??null;
      if(sql.includes('w.state AS workflow_state'))return stored.e&&stored.origin?{...stored.e,workflow_state:stored.w.state,origin_id:stored.origin.id,claim_id:stored.origin.claim_id,schedule_id:stored.origin.schedule_id,executor_id:stored.origin.executor_id}:null;
      throw Error(`UNEXPECTED_SOURCE_QUERY:${sql.slice(0,70)}`);
    }),
    exec:vi.fn(async(sql:string,p:any[])=>{
      stored.txs.push({sql:sql.split(/[\s(]/).slice(0,5).join(' '),tx:transactionId});
      if(sql.startsWith('INSERT INTO workflow_executions')){stored.e={id:p[0],cluster_id:p[1],workspace_id:p[2],workflow_id:p[3],plan_revision:p[4],plan_hash:p[5],approved_by:p[6],execution_actor_id:p[7],idempotency_key:p[9],expires_at:p[10],approval_set_id:p[11],approval_set_hmac:p[12],permission_version:p[13],execution_mode:p[14],state:'executing',snapshot_state:'pending',request_id:null};return 1;}
      if(sql.startsWith('INSERT INTO workflow_execution_origins')){if(state.originInsertFail)throw Error('SOURCE_ORIGIN_INSERT_FAILURE');stored.origin={id:p[0],cluster_id:p[1],workspace_id:p[2],schedule_id:p[3],claim_id:p[4],workflow_id:p[5],workflow_plan_revision:p[6],workflow_plan_hash:p[7],execution_id:p[8],executor_id:p[9]};return 1;}
      if(sql.startsWith("UPDATE workflows SET state='executing'")){if(stored.w.state!=='approved'||stored.w.revision!==p[1])return 0;stored.w.state='executing';stored.w.revision++;return 1;}
      if(sql.startsWith("UPDATE workflow_executions SET snapshot_state='ready'")){Object.assign(stored.e,{snapshot_state:'ready',snapshot_secret:p[1],snapshot_hash:p[2],snapshot_id:p[3]});return 1;}
      if(sql.startsWith("UPDATE workflow_steps SET state='running'")){const s=stored.steps.find((s:any)=>s.id===p[0]);if(!s||s.state!=='pending')return 0;s.state='running';return 1;}
      if(sql.startsWith("UPDATE workflow_steps SET state='succeeded'")){const s=stored.steps.find((s:any)=>s.id===p[0]);if(!s||s.state!=='running')return 0;Object.assign(s,{state:'succeeded',safe_result:JSON.parse(p[1]),...(sql.includes('receipt_secret')?{receipt_secret:p[2],after_fingerprint:p[3]}:{})});return 1;}
      if(sql.startsWith("UPDATE workflow_executions SET state='succeeded'")){if(stored.e.state!=='executing')return 0;stored.e.state='succeeded';return 1;}
      if(sql.startsWith("UPDATE workflows SET state='succeeded'")){if(stored.w.state!=='executing')return 0;stored.w.state='succeeded';return 1;}
      if(sql.startsWith('UPDATE workflow_steps SET state=$2')){Object.assign(stored.steps.find((s:any)=>s.id===p[0]),{state:p[1],error_code:p[2],safe_result:JSON.parse(p[3])});return 1;}
      if(sql.startsWith('UPDATE workflow_executions SET state=$2')){stored.e.state=p[1];return 1;}
      if(sql.startsWith('UPDATE workflows SET state=$2')){stored.w.state=p[1];return 1;}
      throw Error(`UNEXPECTED_SOURCE_WRITE:${sql.slice(0,70)}`);
    }),
    transaction:vi.fn(async(fn:any)=>{const snapshot=structuredClone(stored),old=transactionId;transactionId++;try{return await fn(db);}catch(error){Object.assign(stored,snapshot);throw error;}finally{transactionId=old;}}),
  };
  const nsRegistry=new WeakMap<object,any>([[namespaceHandle,ns]]),authorities=new WeakMap<object,any>([[authorityHandle,inspection]]),executions=new WeakMap<object,any>(),steps=new WeakMap<object,any>();
  context.installWorkflowScheduledNamespacePolicy({assertLive(h){if(!nsRegistry.has(h)||!state.live)throw Error('ORIGINAL_NS_CLOSED');},async verifyHandle(h){if(!nsRegistry.has(h)||!state.live)throw Error('ORIGINAL_NS_CLOSED');return ns;}});
  const approvedPolicy:any={verifyExecution:async(h:object)=>{const p=executions.get(h);if(!p)throw Error('ORIGINAL_APPROVED_REQUIRED');return p;},
    verifyWorkflowScheduledExecution:async(p:any,h:object)=>{if(h!==namespaceHandle||p.executionId!==stored.e?.id||p.workflowOriginId!==stored.origin?.id)throw Error('ACTUAL_PREFIX_REQUIRED');},
    verifyStep:async(p:any,id:string)=>{const row=stored.steps.find((s:any)=>s.id===id),s=plan.steps.find((s:any)=>s.id===id);if(row?.state!=='running')throw Error('ACTUAL_RUNNING_STEP_REQUIRED');const proof=Object.freeze({execution:p,stepId:id,kind:s.kind});steps.set(proof,s);return proof;},
    assertNative:async(proof:any,input:any,stage:string)=>{const s=steps.get(proof),req=s?.nativeRequests[0];if(!req||input.body?.id!==req.nativeId||input.canonicalPath!==req.canonicalPath)throw Error('SEALED_NATIVE_REQUIRED');events.push(`native-policy:${s.order}:${stage}`);},
    async assertMetadata(proof:any){if(steps.get(proof)?.kind!=='metadata')throw Error('ACTUAL_METADATA_STEP_REQUIRED');},async mutationBinding(){throw Error('UNUSED');},async bindOperation(){throw Error('UNUSED');}};
  context.installApprovedPolicy(approvedPolicy);context.installPolicy({async authorizeRequest(){return{};},async authorizeResponse(_ticket,value){return value;}});
  const redis:any={withLock:vi.fn(async(_key:string,fn:any)=>fn()),assertLeaseOwnership:vi.fn(async()=>{if(!state.live)throw Error('LEASE_CLOSED');})};
  const audit:any={append:vi.fn(async(value:any,tx:any)=>{if(tx!==db)throw Error('SAME_TRANSACTION_REQUIRED');stored.audits.push(secrets.redact(value));})};
  const plans:any={load:vi.fn(async()=>({row:structuredClone(stored.w),plan:structuredClone(plan),version:{}}))};
  const receipts=new Map<string,any>();
  const handler={authorize:vi.fn(async()=>undefined),prepare:vi.fn(async()=>{events.push('metadata:prepare');}),inspect:vi.fn(async()=>({before:structuredClone(before),revision:1})),
    apply:vi.fn(async(input:any)=>{if(state.metadataFail)throw new ConflictException({code:'SOURCE_METADATA_CONFLICT'});events.push('metadata:apply');if(input.actor.user.id!==actor.id||context.current().sessionId!=null)throw Error('NO_FAKE_HTTP_ACTOR');return{state:'succeeded',entity:{id:subject}};})};
  const registry:any={get:vi.fn((name:string)=>{if(name!==last.handler)throw Error('FIXED_HANDLER_REQUIRED');return handler;})};
  const approved:any={runApprovedBusinessExecution:vi.fn(async(h:object,id:string,fn:any)=>{if(h!==namespaceHandle||id!==stored.e.id)throw Error('ORIGINAL_NS_REQUIRED');
    const proof=Object.freeze({executionId:id,workflowId:wf,actorId:actor.id,clusterId:cid,workspaceId:wid,sessionId:null,permissionVersion:ns.permissionVersion,expiresAt:Date.parse(expiry),origin:'scheduled-workflow',scheduleClaimId:claim.id,workflowOriginId:stored.origin.id});
    const handle=Object.freeze({});executions.set(handle,proof);try{return await context.runApprovedWorkflow(handle as any,fn);}finally{executions.delete(handle);}}),
    assertStep:vi.fn(async(input:any,tx:any)=>context.assertApprovedMetadataStep(input,tx))};
  const mutations:any={inspectStepReceipt:vi.fn(async(input:any)=>state.receiptMissing?null:receipts.get(input.idempotencyKey)??null)};
  const mutationContext=(p:any,s:any,a:any):any=>({clusterId:cid,workspaceId:wid,actor:a.user,entityType:s.entityType,entityId:s.mutationAction==='create'?undefined:s.entityId,action:s.mutationAction,idempotencyKey:s.mutationIdempotencyKey,payload:s.mutationPayload,before:s.before,parentId:s.parentId,credentialKind:s.credentialKind});
  const dispatch=vi.fn(async(p:any,s:any,a:any)=>{const req=s.nativeRequests[0],operationId=randomUUID();events.push(`dispatch:${s.order}`);
    const result=await context.runOperation({actor:a.user,clusterId:cid,workspaceId:wid,entityType:s.entityType,parentId:s.parentId,credentialKind:s.credentialKind,operationId},async()=>{
      const ticket=await context.authorizeRequest({id:cid,admin_url:'http://kong:8001',version:'1.5.1',execution_mode:mode},req.method,req.canonicalPath,req.body,{});
      await context.beforeNativeSend(ticket);objects.set(`${req.canonicalPath}/${req.nativeId}`,structuredClone(req.body));return context.authorizeResponse(ticket,structuredClone(req.body));
    });receipts.set(s.mutationIdempotencyKey,{operationId,state:'succeeded',remoteStarted:true,remoteCompleted:true,entityId:req.nativeId,safeResult:{}});stored.operations.push({id:operationId,state:'succeeded'});stored.steps.find((r:any)=>r.id===s.id).operation_id=operationId;return result;
  });
  const deps:any={db,redis,secrets,context,authz:{permissionVersion:vi.fn(async()=>ns.permissionVersion)},audit,mutations,plans,registry,approved,dispatch,mutationContext};
  const service=new WorkflowBusinessExecutionService(deps);
  const delegate={verifyOriginalClaim:vi.fn(async(h:object,n:object)=>{if(!authorities.has(h)||n!==namespaceHandle||context.requireWorkflowScheduledNamespaceHandle()!==n)throw new ForbiddenException({code:'ORIGINAL_AUTHORITY_REQUIRED'});
    return state.principalChanged?{...inspection,principal:{...actor,id:randomUUID()}}:inspection;}),
    captureSnapshot:vi.fn(async(_h:object,_n:object,p:any,eid:string)=>{const snapshot:any={version:1,workflowId:wf,executionId:eid,clusterId:cid,workspaceId:wid,planRevision:1,planHash:claim.workflowPlanHash,capturedAt:new Date().toISOString(),
      objects:p.steps.flatMap((s:any)=>s.nativeRequests.map((r:any)=>({type:r.nativeType,id:r.nativeId,path:`${r.canonicalPath}/${r.nativeId}`,before:null,absent:true,fingerprint:secrets.fingerprint(null)})))};
      if(state.snapshotMissing)snapshot.objects.pop();if(state.snapshotChanged&&snapshot.objects.length)snapshot.objects[0].before={id:snapshot.objects[0].id};return snapshot;}),
    readNativeAfter:vi.fn(async(_h:object,_n:object,_p:any,s:any)=>{const req=s.nativeRequests[0],value=structuredClone(objects.get(`${req.canonicalPath}/${req.nativeId}`));return state.readbackChanged?{...value,id:randomUUID()}:value;}),
    deriveCompletion:vi.fn(async(h:object,eid:string)=>{if(!authorities.has(h)||eid!==stored.e?.id||!stored.origin)throw Error('ORIGINAL_COMPLETION_SOURCE_REQUIRED');return state.deriveLie?'succeeded':stored.e.state;})};
  if(install)service.install(delegate as any);
  const run=()=>context.runWorkflowScheduledNamespace(namespaceHandle,()=>service.execute(authorityHandle,namespaceHandle));
  return{service,delegate,run,stored,state,db,handler,dispatch,mutations,context,secrets,plan,ns,claim,inspection,authorityHandle,namespaceHandle,actor,developer,cid,wid,wf,events,deps};
}

describe('business Workflow prefix and original completion use the actual shared execution path',()=>{
  it('initializes configuration wrapper E and SQL026 origin in one transaction and invokes metadata only',async()=>{
    const f=fixture();const completion=await f.run();
    expect(f.dispatch).not.toHaveBeenCalled();expect(f.handler.prepare).toHaveBeenCalledTimes(1);expect(f.handler.apply).toHaveBeenCalledTimes(1);
    expect(f.stored.e).toMatchObject({state:'succeeded',permission_version:'live-pv-1',request_id:null,execution_actor_id:f.actor.id});expect(f.stored.origin.claim_id).toBe(f.claim.id);
    const inserts=f.stored.txs.filter((r:any)=>r.sql.startsWith('INSERT INTO workflow_'));expect(inserts).toHaveLength(2);expect(inserts[0].tx).toBe(inserts[1].tx);expect(inserts[0].tx).toBeGreaterThan(0);
    const snapshot=f.secrets.decrypt<any>(f.stored.e.snapshot_secret,snapshotAad(f.cid,f.wid,f.wf,f.stored.e.id));expect(snapshot.objects).toEqual([]);
    await expect(f.service.verifyCompletion(f.authorityHandle,completion,f.db)).resolves.toBe('succeeded');
  });
  it('executes a sealed entity-annotation schedule through the single metadata handler only',async()=>{
    const f=fixture('entity-annotation');const completion=await f.run();
    expect(f.dispatch).not.toHaveBeenCalled();expect(f.handler.apply).toHaveBeenCalledTimes(1);expect(f.stored.e).toMatchObject({state:'succeeded',execution_mode:'approval'});
    await expect(f.service.verifyCompletion(f.authorityHandle,completion,f.db)).resolves.toBe('succeeded');
    const direct=fixture('entity-annotation',true,'direct');await expect(direct.run()).rejects.toMatchObject({response:{code:'WORKFLOW_SCHEDULE_BUSINESS_FACTS_CHANGED'}});expect(direct.db.exec).not.toHaveBeenCalled();
    const tampered=fixture('entity-annotation');tampered.plan.steps[0].metadata.operation='drop';tampered.plan.steps[0].metadataPayloadHmac=tampered.secrets.fingerprint(tampered.plan.steps[0].metadata);
    const hash=tampered.secrets.fingerprint(tampered.plan);Object.assign(tampered.claim,{workflowPlanHash:hash});Object.assign(tampered.inspection.draft.binding,{workflowPlanHash:hash});
    await expect(tampered.run()).rejects.toBeDefined();expect(tampered.handler.apply).not.toHaveBeenCalled();
  });
  it('dispatches Consumer→ACL→Key→activate through real Context and stores raw readback HMA',async()=>{
    const f=fixture('portal-credential-issue');const completion=await f.run();
    expect(f.events.filter(e=>e.startsWith('dispatch:')||e==='metadata:apply')).toEqual(['dispatch:1','dispatch:2','dispatch:3','metadata:apply']);
    expect(f.handler.apply.mock.calls[0][0].actor.user.id).toBe(f.actor.id);expect(f.actor.id).not.toBe(f.developer);expect(f.stored.steps.every((s:any)=>s.state==='succeeded')).toBe(true);
    expect(f.stored.steps.slice(0,3).every((s:any)=>/^[a-f\d]{64}$/.test(s.after_fingerprint)&&s.receipt_secret)).toBe(true);
    expect(JSON.stringify(f.stored.audits)).not.toContain('synthetic-key-must-never-be-public');expect(JSON.stringify(f.stored.steps.map((s:any)=>s.safe_result))).not.toContain('synthetic-key-must-never-be-public');
    await expect(f.service.verifyCompletion(f.authorityHandle,completion,f.db)).resolves.toBe('succeeded');
  });
  it('preserves direct-cluster Portal mode while still using the genuine complete approval set',async()=>{
    const f=fixture('portal-credential-issue',true,'direct');const completion=await f.run();
    expect(f.stored.e.execution_mode).toBe('direct');expect(f.stored.e.approval_set_id).toBe(f.inspection.approvalSet.setId);
    expect(f.dispatch).toHaveBeenCalledTimes(3);await expect(f.service.verifyCompletion(f.authorityHandle,completion,f.db)).resolves.toBe('succeeded');
    const configuration=fixture('configuration_v2',true,'direct');await expect(configuration.run()).rejects.toMatchObject({response:{code:'WORKFLOW_SCHEDULE_BUSINESS_FACTS_CHANGED'}});
    expect(configuration.db.exec).not.toHaveBeenCalled();
  });
  it('keeps a missing actual Native receipt uncertain instead of calling it known unsent',async()=>{
    const f=fixture('portal-credential-issue');f.state.receiptMissing=true;const completion=await f.run();
    expect(f.dispatch).toHaveBeenCalledTimes(1);expect(f.stored.e.state).toBe('uncertain');expect(f.stored.steps[0].state).toBe('uncertain');
    await expect(f.service.verifyCompletion(f.authorityHandle,completion,f.db)).resolves.toBe('uncertain');
  });
  it('rejects copied completion and foreign authority handles instead of accepting a terminal string or DTO',async()=>{
    const f=fixture();const completion=await f.run();
    for(const value of [{...completion},{state:'succeeded'},'succeeded'])await expect(f.service.verifyCompletion(f.authorityHandle,value as any,f.db)).rejects.toMatchObject({response:{code:'WORKFLOW_SCHEDULE_ORIGINAL_COMPLETION_REQUIRED'}});
    await expect(f.service.verifyCompletion({...f.authorityHandle},completion,f.db)).rejects.toMatchObject({response:{code:'WORKFLOW_SCHEDULE_ORIGINAL_COMPLETION_REQUIRED'}});
  });
  it('rejects missing fixed provider, copied namespace and a copied original authority before writes',async()=>{
    const absent=fixture('configuration_v2',false);await expect(absent.run()).rejects.toMatchObject({response:{code:'WORKFLOW_SCHEDULE_BUSINESS_POLICY_UNAVAILABLE'}});expect(absent.db.exec).not.toHaveBeenCalled();
    const f=fixture();await f.context.runWorkflowScheduledNamespace(f.namespaceHandle,async()=>{
      await expect(f.service.execute({...f.authorityHandle},f.namespaceHandle)).rejects.toMatchObject({response:{code:'ORIGINAL_AUTHORITY_REQUIRED'}});
      await expect(f.service.execute(f.authorityHandle,{...f.namespaceHandle})).rejects.toMatchObject({response:{code:'WORKFLOW_SCHEDULE_ORIGINAL_BUSINESS_EXECUTION_REQUIRED'}});
    });expect(f.db.exec).not.toHaveBeenCalled();
  });
  it('rolls back W/E/origin when actual origin INSERT fails, and never dispatches a native step',async()=>{
    const f=fixture('portal-credential-issue');f.state.originInsertFail=true;await expect(f.run()).rejects.toThrow('SOURCE_ORIGIN_INSERT_FAILURE');
    expect(f.stored.w.state).toBe('approved');expect(f.stored.e).toBeNull();expect(f.stored.origin).toBeNull();expect(f.stored.audits).toEqual([]);expect(f.dispatch).not.toHaveBeenCalled();
  });
  it.each(['missing','changed'])('does not execute Native when captureSnapshot has a %s object proof',async mode=>{
    const f=fixture('portal-credential-issue');if(mode==='missing')f.state.snapshotMissing=true;else f.state.snapshotChanged=true;
    const completion=await f.run();expect(f.dispatch).not.toHaveBeenCalled();expect(f.stored.e.state).toBe('failed');
    await expect(f.service.verifyCompletion(f.authorityHandle,completion,f.db)).resolves.toBe('failed');
  });
  it('preserves partial actual Native completion when subsequent activation fails',async()=>{
    const logger=vi.spyOn(Logger.prototype,'warn').mockImplementation(()=>undefined);
    const f=fixture('portal-credential-issue');f.state.metadataFail=true;const completion=await f.run();
    expect(f.dispatch).toHaveBeenCalledTimes(3);expect(f.stored.steps.slice(0,3).every((s:any)=>s.state==='succeeded')).toBe(true);expect(f.stored.steps[3].state).toBe('failed');
    expect(f.stored.e.state).toBe('partial');await expect(f.service.verifyCompletion(f.authorityHandle,completion,f.db)).resolves.toBe('partial');
    const entry=logger.mock.calls.map(args=>args[0]).find(value=>value?.event==='workflow_execution_observation');
    expect(entry).toMatchObject({workflowId:f.wf,outcome:'partial',errorCode:'SOURCE_METADATA_CONFLICT',omitted:0});
    expect(entry.samples.find((s:any)=>s.phase==='native-complete'&&s.step===3).calls).toBe(3);
    expect(entry.samples.at(-1)).toMatchObject({phase:'failed',step:4,calls:3});
    expect(JSON.stringify(entry)).not.toContain('synthetic-key-must-never-be-public');
  });
  it('keeps the original business failure when the observation log sink fails',async()=>{
    vi.spyOn(Logger.prototype,'warn').mockImplementation(()=>{throw Error('LOG_SINK_FAILED');});
    const f=fixture('portal-credential-issue');f.state.metadataFail=true;
    await f.run();expect(f.stored.e.state).toBe('partial');expect(f.stored.steps[3].error_code).toBe('SOURCE_METADATA_CONFLICT');
  });
  it('opens Portal support only inside the original metadata execution and closes its frame afterwards',async()=>{
    const f=fixture('portal-credential-issue'),reads:any[]=[],callback=vi.fn(async()=>({observed:true}));
    f.context.installPortalMetadataReadPolicy({run:async(namespace,cid,path,read)=>{
      expect(namespace).toBe(f.namespaceHandle);expect(cid).toBe(f.cid);
      expect(f.context.currentApprovedStep().kind).toBe('metadata');reads.push(path);return read();
    }});
    expect(()=>f.context.installPortalMetadataReadPolicy({run:async(_ns,_cid,_path,read)=>read()})).toThrow();
    f.handler.prepare.mockImplementation(async()=>{
      expect(await f.context.runPortalMetadataRead(f.cid,'/consumers/source',callback)).toEqual({observed:true});
      await expect(f.context.runPortalMetadataRead(randomUUID(),'/consumers/source',callback)).rejects.toBeDefined();
    });
    await f.run();expect(f.stored.e.state).toBe('succeeded');expect(callback).toHaveBeenCalledOnce();expect(reads).toHaveLength(1);
    await expect(f.context.runPortalMetadataRead(f.cid,'/consumers/source',callback)).rejects.toBeDefined();expect(callback).toHaveBeenCalledOnce();
  });
  it('does not lend metadata support reads to a running Native step',async()=>{
    const f=fixture('portal-credential-issue'),read=vi.fn(async()=>true),original=f.deps.dispatch;
    f.context.installPortalMetadataReadPolicy({run:async(_ns,_cid,_path,callback)=>callback()});
    f.deps.dispatch=async(...args:any[])=>{
      await expect(f.context.runPortalMetadataRead(f.cid,'/consumers/source',read)).rejects.toBeDefined();
      return original(...args);
    };
    await f.run();expect(f.stored.e.state).toBe('succeeded');expect(read).not.toHaveBeenCalled();
  });
  it('refuses completion when actual durable W/E/origin facts change, even if Root returned success',async()=>{
    const f=fixture();const completion=await f.run();f.stored.origin.claim_id=randomUUID();
    await expect(f.service.verifyCompletion(f.authorityHandle,completion,f.db)).rejects.toMatchObject({response:{code:'WORKFLOW_SCHEDULE_COMPLETION_FACTS_CHANGED'}});
  });
  it('does not let a returned completion string override actual known failed SQL state',async()=>{
    const f=fixture();f.state.metadataFail=true;f.state.deriveLie=true;
    await expect(f.run()).rejects.toMatchObject({response:{code:'WORKFLOW_SCHEDULE_COMPLETION_FACTS_CHANGED'}});expect(f.stored.e.state).toBe('failed');
  });
  it('rejects a changed current principal and never adopts developer or author HTTP identity',async()=>{
    const f=fixture('portal-credential-issue');f.state.principalChanged=true;
    await expect(f.run()).rejects.toMatchObject({response:{code:'WORKFLOW_SCHEDULE_BUSINESS_FACTS_CHANGED'}});expect(f.db.exec).not.toHaveBeenCalled();
  });
  it('is once-installed and once-executed; genuine SQL execution facts cannot be replayed',async()=>{
    const f=fixture();expect(()=>f.service.install(f.delegate as any)).toThrow();await f.run();
    await expect(f.service.execute(f.authorityHandle,f.namespaceHandle)).rejects.toMatchObject({response:{code:'WORKFLOW_SCHEDULE_BUSINESS_EXECUTION_REPLAY_FORBIDDEN'}});expect(f.handler.apply).toHaveBeenCalledTimes(1);
  });
  it('the actual WorkflowService HTTP execute path cannot bypass a sealed scheduled plan',async()=>{
    const f=fixture('portal-credential-issue'),original=f.db.one.getMockImplementation()!;
    f.db.one.mockImplementation(async(sql:string,p:any[])=>{
      if(sql==='SELECT kind FROM workflows WHERE id=$1 AND cluster_id=$2'||sql==='SELECT kind,workspace_id FROM workflows WHERE id=$1 AND cluster_id=$2'){
        expect(p).toEqual([f.wf,f.cid]);return{kind:f.plan.kind,workspace_id:f.plan.workspaceId};
      }
      return original(sql,p);
    });
    const workflows=new WorkflowService(f.db,f.deps.redis,f.secrets,{} as any,f.context,f.deps.authz,f.deps.audit,{} as any,f.mutations,{} as any,
      {resolve:async()=>({id:f.wid,revision:1})} as any,f.deps.plans,f.deps.registry,f.deps.approved,{} as any);
    await f.context.runHttp({},async()=>{f.context.bindHttpActor(f.actor,randomUUID());
      await expect(workflows.execute(f.cid,f.wf,{revision:3,planHash:f.claim.workflowPlanHash,confirmed:true,confirm_name:f.plan.kind},
        {user:f.actor,workspaceId:f.wid,idempotencyKey:'http-no-scheduled-bypass'})).rejects.toMatchObject({response:{code:'WORKFLOW_SCHEDULE_BACKGROUND_EXECUTION_REQUIRED'}});
    });expect(f.handler.authorize).not.toHaveBeenCalled();expect(f.dispatch).not.toHaveBeenCalled();expect(f.db.exec).not.toHaveBeenCalled();
  });
});
