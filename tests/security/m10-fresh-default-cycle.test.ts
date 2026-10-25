import { describe, expect, it } from 'vitest';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { FRESH_DEFAULT_CYCLE_LABELS, preserveM10TimerFixtures, validateFreshDefaultCycle } from './lib/m10-fresh-default-cycle.mjs';
import { assertOptinDefaultApplyGate } from './lib/m10-native-optin-helper.mjs';

const id=(n:number)=>`${n.toString(16).padStart(8,'0')}-0000-4000-8000-000000000000`,sha=(v:any)=>createHash('sha256').update(typeof v==='string'||Buffer.isBuffer(v)?v:JSON.stringify(v)).digest('hex');
const fixture=()=>{
  const actorId=id(1),sourceClusterId=id(2),sourceWorkspaceId=id(3),targetClusterId=id(4),targetWorkspaceId=id(5),inputPlanId=id(6),copiedPlanId=id(7),failedJobId=id(8),executionId=id(9),originalRequestId=id(10),originalKey=id(11),failedRuntimeSourceSha256='a'.repeat(64),currentRuntimeSourceSha256='b'.repeat(64);
  const scope={actorId,sourceClusterId,sourceWorkspaceId,targetClusterId,targetWorkspaceId};
  const originalBody={planHash:'c'.repeat(64),planRevision:1,confirmed:true,confirm_name:`配置计划 ${inputPlanId}`};
  const originalPacket={requestId:originalRequestId,key:originalKey,actorId,method:'POST',path:`/clusters/${targetClusterId}/configuration/plans/${inputPlanId}/apply?workspaceId=${targetWorkspaceId}`,status:403,errorCode:'KONG_EXECUTION_CONTEXT_REQUIRED',state:'response_observed',body:originalBody,bodyHash:sha(originalBody)};
  const failedDeploymentBytes=Buffer.from(JSON.stringify({phase:'m10-candidate-v5',apiSourceSha256:failedRuntimeSourceSha256,apiBuildExit:0,copyExit:0,apiRestartExit:0,readinessStatus:200}));
  const inputPlanExpiresAt='2026-10-13T06:13:22.999Z',observedAt='2026-10-13T06:30:00.000Z';
  const tuple={...scope,originalRequestId,originalKey,originalBodyHash:originalPacket.bodyHash,inputPlanId,copiedPlanId,failedJobId,executionId,failedRuntimeSourceSha256,failedDeploymentSha256:sha(failedDeploymentBytes)};
  const proof:any={version:1,kind:'failed-default-promote-origin',...tuple,originalStatus:403,originalErrorCode:originalPacket.errorCode,originalState:'failed',originalResponseRewritten:false,nativeReplayed:false,planRenewed:false,inputPlanExpired:true,inputPlanExpiresAt,observedAt,
    actualZeroNative:{passed:true,mode:'failed-no-native',consoleReadOnly:true,requestId:originalRequestId,actorId,clusterId:targetClusterId,workspaceId:targetWorkspaceId,sourceClusterId,sourceWorkspaceId,failedJobId,inputPlanId,copiedPlanId,executionId,
      runtimeSourceSha256:currentRuntimeSourceSha256,configurationJobCount:1,jobState:'failed',jobErrorCode:originalPacket.errorCode,mutationCount:0,nativeStartedCount:0,nativeCompletedCount:0,jobRemoteStarted:false,jobRemoteCompleted:false,inputPlanExpired:true,inputPlanExpiresAt,
      immutableOriginMatched:true,runtimeDistMatched:true,migrationChecksumsMatched:true,kongDatabaseAccess:false,independentWireLogClaim:false,initialDigest:'d'.repeat(64),finalDigest:'d'.repeat(64),transactionSnapshotDigestMatched:true}};
  const proofBytes=Buffer.from(JSON.stringify(proof)),intent:any={version:1,...tuple,...FRESH_DEFAULT_CYCLE_LABELS,proofSha256:sha(proofBytes)};
  return {proof,intent,proofBytes,failedDeploymentBytes,originalPacket,...scope,currentRuntimeSourceSha256};
};
const reseal=(f:any)=>{f.proofBytes=Buffer.from(JSON.stringify(f.proof));f.intent.proofSha256=sha(f.proofBytes);return f;};

describe('fresh M10 default cycle follows registered but unsent expired execution',()=>{
  it('retains the actual timer observation manifest and timestamps while rejecting different schedule, scope or owner identities',()=>{
    const f=fixture(),current={sourceClusterId:f.sourceClusterId,sourceWorkspaceId:f.sourceWorkspaceId,targetClusterId:f.targetClusterId,targetWorkspaceId:f.targetWorkspaceId,inspectionScheduleId:id(71),driftScheduleId:id(72),registeredAt:'2026-10-13T00:00:00.000Z'};
    const previous={...current,dueAt:'2026-10-13T06:33:00.000Z',observationManifest:{actorId:f.actorId,sourceClusterId:f.sourceClusterId,sourceWorkspaceId:f.sourceWorkspaceId,targetClusterId:f.targetClusterId,targetWorkspaceId:f.targetWorkspaceId,schedules:[{kind:'inspection',id:id(71),nextRunAt:'2026-10-13T06:32:00.000Z'},{kind:'drift',id:id(72),nextRunAt:'2026-10-13T06:33:00.000Z'}]}};
    expect(preserveM10TimerFixtures(previous,current,f.actorId)).toEqual(previous);
    for(const patch of [{inspectionScheduleId:id(73)},{targetClusterId:id(74)},{registeredAt:'2026-10-13T01:00:00.000Z'}])expect(()=>preserveM10TimerFixtures(previous,{...current,...patch},f.actorId)).toThrow();
    expect(()=>preserveM10TimerFixtures(previous,current,id(75))).toThrow();
  });
  it('requires the one failed job fact and distinguishes V5 failure code from actual V6 observer source',()=>{
    const f=fixture(),before=JSON.stringify(f);const result=validateFreshDefaultCycle(f);expect(result.applyLabel).toBe(FRESH_DEFAULT_CYCLE_LABELS.applyLabel);expect(result.failedJobId).toBe(f.intent.failedJobId);expect(JSON.stringify(f)).toBe(before);
    expect(f.proof.actualZeroNative.configurationJobCount).toBe(1);expect(f.proof.actualZeroNative.runtimeSourceSha256).not.toBe(f.intent.failedRuntimeSourceSha256);
  });
  it.each(['wrong-label','changed-proof-bytes','zero-jobs','two-jobs','native-started','mutation-present','changed-current-origin','expired-false','future-expiry','renewed-plan','rewritten-response','replayed-key','unknown-original','wrong-actor','failed-runtime-as-current','unproved-failed-deployment','changed-digest'])('rejects insufficient proof before any new intent: %s',failure=>{
    const f:any=fixture();
    if(failure==='wrong-label')f.intent.applyLabel='m10-default-cycle-after-frame-free-verifier-apply-again';
    if(failure==='changed-proof-bytes')f.proofBytes=Buffer.concat([f.proofBytes,Buffer.from(' ')]);
    if(failure==='zero-jobs')f.proof.actualZeroNative.configurationJobCount=0;if(failure==='two-jobs')f.proof.actualZeroNative.configurationJobCount=2;
    if(failure==='native-started')f.proof.actualZeroNative.nativeStartedCount=1;if(failure==='mutation-present')f.proof.actualZeroNative.mutationCount=1;
    if(failure==='changed-current-origin')f.proof.actualZeroNative.immutableOriginMatched=false;if(failure==='expired-false')f.proof.inputPlanExpired=false;
    if(failure==='future-expiry')f.proof.inputPlanExpiresAt='2026-10-13T07:30:00.000Z';if(failure==='renewed-plan')f.proof.planRenewed=true;
    if(failure==='rewritten-response')f.proof.originalResponseRewritten=true;if(failure==='replayed-key')f.proof.nativeReplayed=true;
    if(failure==='unknown-original')f.originalPacket.state='response_unknown';if(failure==='wrong-actor')f.originalPacket.actorId=id(95);
    if(failure==='failed-runtime-as-current')f.proof.actualZeroNative.runtimeSourceSha256=f.intent.failedRuntimeSourceSha256;
    if(failure==='unproved-failed-deployment')f.failedDeploymentBytes=Buffer.from(JSON.stringify({apiSourceSha256:f.intent.failedRuntimeSourceSha256}));
    if(failure==='changed-digest')f.proof.actualZeroNative.finalDigest='e'.repeat(64);
    if(failure!=='changed-proof-bytes')reseal(f);expect(()=>validateFreshDefaultCycle(f)).toThrow();
  });
});

describe('opt-in gate binds the complete fresh default cycle receipts',()=>{
  const accepted=()=>{
    const f=fixture(),labels=FRESH_DEFAULT_CYCLE_LABELS,comparisonId=id(20),planId=id(21),sourceJobId=id(22),promotionId=id(23),applyJobId=id(24),applyExecutionId=id(25),planHash='f'.repeat(64);
    const comparisonEntity={id:comparisonId,quality:'complete',source:{clusterId:f.sourceClusterId,workspaceId:f.sourceWorkspaceId},target:{clusterId:f.targetClusterId,workspaceId:f.targetWorkspaceId}};
    const packet=(label:string,path:string,key:string,body:any,responseData:any)=>({label,path,key,body,bodyHash:sha(body),responseData,actorId:f.actorId,method:'POST',state:'response_observed',status:201,requestId:id(50+Number(key.slice(0,8)))});
    const comparison=packet(labels.comparisonLabel,`/clusters/${f.sourceClusterId}/governance/comparisons?workspaceId=${f.sourceWorkspaceId}`,id(30),{scope:'workspace'},{entity:comparisonEntity});
    const promotion=packet(labels.planLabel,`/clusters/${f.sourceClusterId}/governance/comparisons/${comparisonId}/promote-plan?workspaceId=${f.sourceWorkspaceId}`,id(31),{includeEnvironmentFields:false,includeSecrets:false,includeCredentials:false,confirmed:true,confirm_name:`PROMOTE ${comparisonId}`},{planId,jobId:sourceJobId});
    const summary={id:planId,name:`配置计划 ${planId}`,clusterId:f.targetClusterId,workspaceId:f.targetWorkspaceId,executionMode:'direct',planRevision:1,planHash};
    const apply=packet(labels.applyLabel,`/clusters/${f.targetClusterId}/configuration/plans/${planId}/apply?workspaceId=${f.targetWorkspaceId}`,id(32),{confirmed:true,confirm_name:summary.name,planHash,planRevision:1},{domain:'configuration',kind:'apply',actorId:f.actorId,clusterId:f.targetClusterId,workspaceId:f.targetWorkspaceId,idempotencyKey:id(32),state:'succeeded',executionCompleted:true,registrationCompleted:true,executionId:applyExecutionId,jobId:applyJobId});
    const comparisonReceipt={idempotencyKey:comparison.key,actorId:f.actorId,clusterId:f.sourceClusterId,workspaceId:f.sourceWorkspaceId,kind:'comparison',state:'succeeded',entity:comparisonEntity,nativeExecutionRequested:false};
    const promotionReceipt={id:promotionId,idempotencyKey:promotion.key,actorId:f.actorId,clusterId:f.sourceClusterId,workspaceId:f.sourceWorkspaceId,kind:'promotion-plan',state:'ready',nativeExecutionRequested:false,targetClusterId:f.targetClusterId,targetWorkspaceId:f.targetWorkspaceId,planId,jobId:sourceJobId};
    const successfulDeploymentBytes=Buffer.from(JSON.stringify({phase:'m10-candidate-v6',apiSourceSha256:f.currentRuntimeSourceSha256,apiBuildExit:0,copyExit:0,apiRestartExit:0,readinessStatus:200}));
    const state:any={freshDefaultCycleIntent:f.intent,requests:[f.originalPacket,comparison,promotion,apply],acceptancePlanSummaries:{[labels.applyLabel]:summary},governanceFixtures:{promoteApplyLabel:labels.applyLabel,promoteApplyJobId:applyJobId,
      defaultCycle:{proofSha256:f.intent.proofSha256,runtimeSourceSha256:f.currentRuntimeSourceSha256,successfulDeploymentSha256:sha(successfulDeploymentBytes),previousComparisonId:id(26),comparisonId,comparisonReceipt,promotionReceipt,promotionId,sourceJobId,planId,applyLabel:labels.applyLabel,applyJobId}}};
    const args={actorId:f.actorId,clusterId:f.targetClusterId,workspaceId:f.targetWorkspaceId,sourceClusterId:f.sourceClusterId,sourceWorkspaceId:f.sourceWorkspaceId,proofBytes:f.proofBytes,failedDeploymentBytes:f.failedDeploymentBytes,successfulDeploymentBytes,currentRuntimeSourceSha256:f.currentRuntimeSourceSha256};
    return {f,state,args};
  };
  it('requires distinct actual comparison, promotion and succeeded apply receipts before opt-in',()=>{
    const a=accepted(),before=JSON.stringify(a.state);expect(assertOptinDefaultApplyGate(a.state,a.args).label).toBe(FRESH_DEFAULT_CYCLE_LABELS.applyLabel);expect(JSON.stringify(a.state)).toBe(before);expect(a.state.requests[0].status).toBe(403);
  });
  it('retains the actual V6 success under an independently verified current V7 rather than replacing or replaying its default apply',()=>{
    const a=accepted(),before=JSON.stringify(a.state);a.args.currentRuntimeSourceSha256='7'.repeat(64);
    expect(assertOptinDefaultApplyGate(a.state,a.args).label).toBe(FRESH_DEFAULT_CYCLE_LABELS.applyLabel);expect(JSON.stringify(a.state)).toBe(before);
    expect(a.state.governanceFixtures.defaultCycle.runtimeSourceSha256).toBe(a.f.currentRuntimeSourceSha256);
  });
  it.each(['missing-archive','altered-archive','wrong-version','unready','missing-private-seal'])('refuses an unbound archived successful default runtime: %s',failure=>{
    const a:any=accepted();if(failure==='missing-archive')a.args.successfulDeploymentBytes=undefined;
    if(failure==='altered-archive')a.args.successfulDeploymentBytes=Buffer.concat([a.args.successfulDeploymentBytes,Buffer.from(' ')]);
    if(['wrong-version','unready'].includes(failure)){const d=JSON.parse(a.args.successfulDeploymentBytes.toString());if(failure==='wrong-version')d.phase='m10-candidate-v7';else d.readinessStatus=503;a.args.successfulDeploymentBytes=Buffer.from(JSON.stringify(d));a.state.governanceFixtures.defaultCycle.successfulDeploymentSha256=sha(a.args.successfulDeploymentBytes);}
    if(failure==='missing-private-seal')delete a.state.governanceFixtures.defaultCycle.successfulDeploymentSha256;
    expect(()=>assertOptinDefaultApplyGate(a.state,a.args)).toThrow();
  });
  it.each(['proof-absent','old-plan-reuse','old-comparison-reuse','wrong-comparison-source','plan-receipt-mismatch','shared-key','secret-default','wrong-runtime','apply-suffix','apply403'])('rejects a handoff that does not prove this fresh cycle: %s',failure=>{
    const a:any=accepted(),t=a.state.governanceFixtures.defaultCycle;
    if(failure==='proof-absent')a.args.proofBytes=undefined;
    if(failure==='old-plan-reuse')t.planId=a.f.intent.inputPlanId;if(failure==='old-comparison-reuse')t.previousComparisonId=t.comparisonId;
    if(failure==='wrong-comparison-source')a.state.requests[1].responseData.entity.source.clusterId=id(90);
    if(failure==='plan-receipt-mismatch')t.promotionReceipt.planId=id(91);if(failure==='shared-key')a.state.requests[2].key=a.state.requests[1].key;
    if(failure==='secret-default'){a.state.requests[2].body.includeSecrets=true;a.state.requests[2].bodyHash=sha(a.state.requests[2].body);}
    if(failure==='wrong-runtime')t.runtimeSourceSha256='9'.repeat(64);if(failure==='apply-suffix')a.state.governanceFixtures.promoteApplyLabel+='-again';if(failure==='apply403')a.state.requests[3].status=403;
    expect(()=>assertOptinDefaultApplyGate(a.state,a.args)).toThrow();
  });
  it('the prepared core tool allocates only the three fixed labels and retains failed fresh packets before returning',()=>{
    const core=readFileSync('tests/security/m10-native-actual.mjs','utf8');expect(core).toContain('async function freshCycleOnce');expect(core).toContain('rows[0].label=label;h.save()');
    expect(core).toContain('ORIGINAL_NEGATIVE_RECEIPT_REQUIRED_NO_NEW_NEGATIVE');expect(core).toContain('freshCycleOnce(freshDefaultCycle.comparisonLabel');expect(core).toContain('freshCycleOnce(freshDefaultCycle.planLabel');
  });
});
