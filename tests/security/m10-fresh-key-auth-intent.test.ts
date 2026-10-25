import { describe, expect, it } from 'vitest';
import { createHash } from 'node:crypto';
import { FRESH_KEY_AUTH_PREFIX, validateFreshKeyAuthIntent } from './lib/m10-fresh-key-auth-intent.mjs';

const id=(n:number)=>`${n.toString(16).padStart(8,'0')}-0000-4000-8000-000000000000`,sha=(v:any)=>createHash('sha256').update(typeof v==='string'||Buffer.isBuffer(v)?v:JSON.stringify(v)).digest('hex');
const fixture=()=>{
  const actorId=id(1),sourceClusterId=id(2),sourceWorkspaceId=id(3),targetClusterId=id(4),targetWorkspaceId=id(5),originalRequestId=id(6),originalKey=id(7),originalComparisonId=id(8),originalParentId=id(9),sourceSnapshotId=id(10),failedRuntimeSourceSha256='6'.repeat(64),currentRuntimeSourceSha256='7'.repeat(64);
  const sourceRoots=[['services',id(11)],['routes',id(12)],['routes',id(13)],['consumers',id(14)],['plugins',id(15)],['plugins',id(16)]].map(([entityType,nativeId])=>({entityType,nativeId}));
  const scope={actorId,sourceClusterId,sourceWorkspaceId,targetClusterId,targetWorkspaceId};
  const body={selectedObjectKeys:[`consumers:${id(14)}`],includeEnvironmentFields:false,includeSecrets:true,includeCredentials:true,credentialKinds:['key-auth'],confirmed:true,confirm_name:`PROMOTE ${originalComparisonId}`};
  const originalPacket={label:'m10-optin-key-auth-plan',requestId:originalRequestId,key:originalKey,actorId,method:'POST',path:`/clusters/${sourceClusterId}/governance/comparisons/${originalComparisonId}/promote-plan?workspaceId=${sourceWorkspaceId}`,status:409,errorCode:'CONFIGURATION_ORIGIN_PRIVATE_SOURCE_CHANGED',state:'response_observed',body,bodyHash:sha(body)};
  const comparisonBody={scope:'workspace',target:{clusterId:targetClusterId,workspaceId:targetWorkspaceId,scope:'workspace',serviceIds:[]},threshold:0,includeEnvironmentFields:false};
  const originalComparisonPacket={label:'m10-optin-key-auth-comparison',requestId:id(17),key:id(18),actorId,method:'POST',path:`/clusters/${sourceClusterId}/governance/comparisons?workspaceId=${sourceWorkspaceId}`,state:'response_observed',status:201,body:comparisonBody,bodyHash:sha(comparisonBody),responseData:{entity:{id:originalComparisonId}}};
  const diagnostic:any={milestone:'M10',...scope,originalRequestId,originalKey,originalStatus:409,errorCode:originalPacket.errorCode,runtimeSourceSha256:failedRuntimeSourceSha256,originalResponseRewritten:false,nativeReplayed:false,passed:true,consoleReadOnly:true,parentId:originalParentId,parentState:'blocked',comparisonId:originalComparisonId,sourceSnapshotId,
    graphAdapterVersion:'kong-oss-1.5-v1',inventoryAdapterVersion:null,originFallbackAdapter:'kong-1.5',scopeEqual:true,kongVersionEqual:true,graphKongVersion:'1.5.1',completeness:'complete',consistency:'console_fenced_best_effort',manifestMatched:true,
    rootChecks:sourceRoots.map(row=>({...row,present:true,beforeHmacMatches:true,payloadMatches:true})),actualTargetMutationCounters:{count:0,started:0,completed:0}};
  const diagnosticBytes=Buffer.from(JSON.stringify(diagnostic)),failedDeploymentBytes=Buffer.from(JSON.stringify({phase:'m10-candidate-v6',apiSourceSha256:failedRuntimeSourceSha256,apiBuildExit:0,copyExit:0,apiRestartExit:0,readinessStatus:200}));
  const tuple={...scope,originalRequestId,originalKey,originalBodyHash:sha(body),originalComparisonId,originalParentId,sourceSnapshotId,failedRuntimeSourceSha256,candidateRuntimeSourceSha256:currentRuntimeSourceSha256,zeroNativeRuntimeSourceSha256:failedRuntimeSourceSha256,diagnosticSha256:sha(diagnosticBytes),failedDeploymentSha256:sha(failedDeploymentBytes)};
  const proof:any={version:1,kind:'key-auth-adapter-label-failure',prefix:FRESH_KEY_AUTH_PREFIX,...tuple,originalStatus:409,originalErrorCode:originalPacket.errorCode,originalPhase:'stopped',parentState:'blocked',originalResponseRewritten:false,nativeReplayed:false,
    actualZeroNative:{passed:true,mode:'no-native',consoleReadOnly:true,requestId:originalRequestId,actorId,clusterId:targetClusterId,workspaceId:targetWorkspaceId,runtimeSourceSha256:failedRuntimeSourceSha256,configurationJobCount:0,mutationCount:0,nativeStartedCount:0,nativeCompletedCount:0,runtimeDistMatched:true,migrationChecksumsMatched:true,kongDatabaseAccess:false,independentWireLogClaim:false}};
  const proofBytes=Buffer.from(JSON.stringify(proof)),intent:any={version:1,prefix:FRESH_KEY_AUTH_PREFIX,...tuple,proofSha256:sha(proofBytes)};
  return {intent,proof,proofBytes,diagnostic,diagnosticBytes,failedDeploymentBytes,phaseState:{state:'stopped',nativeVerified:false},originalPacket,originalComparisonPacket,...scope,currentRuntimeSourceSha256,sourceRoots};
};
const reseal=(f:any)=>{f.proofBytes=Buffer.from(JSON.stringify(f.proof));f.intent.proofSha256=sha(f.proofBytes);return f;};

describe('fixed explicitly authorized key-auth opt-in after actual adapter-label diagnosis',()=>{
  it('permits one fixed new prefix while retaining the original 409, blocked parent, exact six-root proof and original deployment bytes',()=>{
    const f=fixture(),before=JSON.stringify(f);expect(validateFreshKeyAuthIntent(f).prefix).toBe(FRESH_KEY_AUTH_PREFIX);expect(JSON.stringify(f)).toBe(before);expect(f.originalPacket.status).toBe(409);
  });
  it('records actual zero-native observation under V7 separately from the failure observed under V6',()=>{
    const f=fixture();f.intent.zeroNativeRuntimeSourceSha256=f.currentRuntimeSourceSha256;f.proof.zeroNativeRuntimeSourceSha256=f.currentRuntimeSourceSha256;f.proof.actualZeroNative.runtimeSourceSha256=f.currentRuntimeSourceSha256;
    expect(validateFreshKeyAuthIntent(reseal(f)).prefix).toBe(FRESH_KEY_AUTH_PREFIX);expect(f.diagnostic.runtimeSourceSha256).toBe(f.intent.failedRuntimeSourceSha256);
  });
  it.each(['no-intent','prefix-suffix','changed-proof-bytes','unknown-packet','changed-old-status','running-phase','unknown-phase','already-native-verified','no-zero-native','wrong-zero-scope','jobs-present','native-started','native-completed','unknown-runtime','old-source-candidate','changed-diagnostic-bytes','changed-root','root-hmac-false','missing-root','unfenced-graph','renewed-failure-deployment','old-comparison-changed','broader-credential-copy'])('refuses a fresh native cycle without all actual original evidence: %s',failure=>{
    const f:any=fixture();
    if(failure==='no-intent')f.intent=null;if(failure==='prefix-suffix')f.intent.prefix+='-retry';if(failure==='changed-proof-bytes')f.proofBytes=Buffer.concat([f.proofBytes,Buffer.from(' ')]);
    if(failure==='unknown-packet')f.originalPacket.state='response_unknown';if(failure==='changed-old-status')f.originalPacket.status=201;
    if(failure==='running-phase')f.phaseState.state='running';if(failure==='unknown-phase')f.phaseState.state='uncertain';if(failure==='already-native-verified')f.phaseState.nativeVerified=true;
    if(failure==='no-zero-native')delete f.proof.actualZeroNative;if(failure==='wrong-zero-scope')f.proof.actualZeroNative.workspaceId=id(90);
    if(failure==='jobs-present')f.proof.actualZeroNative.configurationJobCount=1;if(failure==='native-started')f.proof.actualZeroNative.nativeStartedCount=1;if(failure==='native-completed')f.proof.actualZeroNative.nativeCompletedCount=1;
    if(failure==='unknown-runtime'){f.intent.zeroNativeRuntimeSourceSha256='8'.repeat(64);f.proof.zeroNativeRuntimeSourceSha256='8'.repeat(64);f.proof.actualZeroNative.runtimeSourceSha256='8'.repeat(64);}
    if(failure==='old-source-candidate'){f.currentRuntimeSourceSha256=f.intent.failedRuntimeSourceSha256;f.intent.candidateRuntimeSourceSha256=f.currentRuntimeSourceSha256;f.proof.candidateRuntimeSourceSha256=f.currentRuntimeSourceSha256;}
    if(failure==='changed-diagnostic-bytes')f.diagnosticBytes=Buffer.concat([f.diagnosticBytes,Buffer.from(' ')]);
    if(['changed-root','root-hmac-false','missing-root','unfenced-graph'].includes(failure)){if(failure==='changed-root')f.diagnostic.rootChecks[0].nativeId=id(91);if(failure==='root-hmac-false')f.diagnostic.rootChecks[0].beforeHmacMatches=false;if(failure==='missing-root')f.diagnostic.rootChecks.pop();if(failure==='unfenced-graph')f.diagnostic.consistency='complete-but-unfenced';f.diagnosticBytes=Buffer.from(JSON.stringify(f.diagnostic));f.intent.diagnosticSha256=sha(f.diagnosticBytes);f.proof.diagnosticSha256=sha(f.diagnosticBytes);}
    if(failure==='renewed-failure-deployment')f.failedDeploymentBytes=Buffer.from(JSON.stringify({phase:'m10-candidate-v7',apiSourceSha256:f.intent.failedRuntimeSourceSha256}));
    if(failure==='old-comparison-changed')f.originalComparisonPacket.responseData.entity.id=id(92);
    if(failure==='broader-credential-copy'){f.originalPacket.body.credentialKinds=['key-auth','oauth2'];f.originalPacket.bodyHash=sha(f.originalPacket.body);f.intent.originalBodyHash=f.originalPacket.bodyHash;f.proof.originalBodyHash=f.originalPacket.bodyHash;}
    if(failure!=='changed-proof-bytes'&&f.intent)reseal(f);expect(()=>validateFreshKeyAuthIntent(f)).toThrow();
  });
});
