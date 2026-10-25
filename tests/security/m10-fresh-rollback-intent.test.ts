import { describe, expect, it } from 'vitest';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { FRESH_ROLLBACK_PREFIX, validateFreshRollbackIntent } from './lib/m10-fresh-rollback-intent.mjs';

const id=(n:number)=>`${n.toString(16).padStart(8,'0')}-0000-4000-8000-000000000000`,sha=(v:any)=>createHash('sha256').update(typeof v==='string'||Buffer.isBuffer(v)?v:JSON.stringify(v)).digest('hex');
const fixture=()=>{
  const actorId=id(1),targetClusterId=id(2),targetWorkspaceId=id(3),originalRequestId=id(4),originalKey=id(5),snapshotId=id(6),snapshotVersion=1,failedCompareJobId=id(7),baselineCaptureJobId=id(8),baselineSnapshotId=id(9),baselineSnapshotVersion=1,failedRuntimeSourceSha256='7'.repeat(64),currentRuntimeSourceSha256='8'.repeat(64);
  const body={revision:2,confirmed:true,confirm_name:'original preexecution target snapshot',confirm_deletes:true};
  const originalPacket={label:'m10-optin-rollback-preview',requestId:originalRequestId,key:originalKey,actorId,method:'POST',path:`/clusters/${targetClusterId}/snapshots/${snapshotId}/rollback-plan?workspaceId=${targetWorkspaceId}`,status:409,errorCode:'CONFIGURATION_DIFF_SCOPE_MISMATCH',state:'response_observed',body,bodyHash:sha(body)};
  const exactBaselineProof={passed:true,mode:'origin',consoleReadOnly:true,immutableOriginMatched:true,actorId,clusterId:targetClusterId,workspaceId:targetWorkspaceId,actualBaselineSnapshotId:snapshotId,actualBaselineVersion:snapshotVersion,actualExecutionId:id(10),kongDatabaseAccess:false};
  const priorKeyAuth={exactBaselineProof,executed:{baselineSnapshotId:snapshotId,baselineVersion:snapshotVersion,proof:{executionId:id(10),state:'succeeded',executionCompleted:true}}};
  const diagnostic:any={milestone:'M10',originalRequestId,originalKey,actorId,targetClusterId,targetWorkspaceId,originalStatus:409,originalErrorCode:originalPacket.errorCode,originalResponseRewritten:false,nativeReplayed:false,runtimeSourceSha256:failedRuntimeSourceSha256,consoleReadOnly:true,
    oldSnapshotId:snapshotId,oldVersion:snapshotVersion,newBaselineSnapshotId:baselineSnapshotId,newBaselineVersion:baselineSnapshotVersion,scopeEqual:true,kongVersionEqual:true,oldKongVersion:'1.5.1',adapterEqual:true,oldAdapterVersion:'kong-oss-1.5-v1',enabledPluginSetEqual:true,oldComplete:'complete',newComplete:'complete',oldFenced:'console_fenced_best_effort',newFenced:'console_fenced_best_effort',oldManifestVerified:true,newManifestVerified:true,
    entitySchemas:['acls','basicauth_credentials','ca_certificates','certificates','consumers','hmacauth_credentials','jwt_secrets','keyauth_credentials','oauth2_credentials','plugins','routes','services','snis','targets','upstreams'].map(name=>({name,inOld:true,inFresh:true,sameRawDefinition:true})),
    pluginSchemas:[{name:'aws-lambda',inOld:false,inFresh:true,sameRawDefinition:false},{name:'key-auth',inOld:true,inFresh:true,sameRawDefinition:true},{name:'request-termination',inOld:true,inFresh:true,sameRawDefinition:true}],
    compareJobs:[{id:failedCompareJobId,kind:'compare',state:'failed',errorCode:originalPacket.errorCode,nativeStarted:false,nativeCompleted:false},{id:baselineCaptureJobId,kind:'capture',state:'succeeded',errorCode:null,nativeStarted:false,nativeCompleted:false}],actualNativeCounters:{count:0,started:0,completed:0}};
  const diagnosticBytes=Buffer.from(JSON.stringify(diagnostic)),failedDeploymentBytes=Buffer.from(JSON.stringify({phase:'m10-candidate-v7',apiSourceSha256:failedRuntimeSourceSha256,apiBuildExit:0,copyExit:0,apiRestartExit:0,readinessStatus:200}));
  const tuple={actorId,targetClusterId,targetWorkspaceId,originalRequestId,originalKey,originalBodyHash:sha(body),snapshotId,snapshotVersion,failedCompareJobId,baselineCaptureJobId,baselineSnapshotId,baselineSnapshotVersion,failedRuntimeSourceSha256,candidateRuntimeSourceSha256:currentRuntimeSourceSha256,
    diagnosticSha256:sha(diagnosticBytes),failedDeploymentSha256:sha(failedDeploymentBytes),keyAuthBaselineProofSha256:sha(JSON.stringify(exactBaselineProof))};
  const proof:any={version:1,kind:'rollback-schema-union-failure',prefix:FRESH_ROLLBACK_PREFIX,...tuple,originalStatus:409,originalErrorCode:originalPacket.errorCode,originalResponseRewritten:false,nativeReplayed:false,snapshotMaterialChanged:false};
  const proofBytes=Buffer.from(JSON.stringify(proof)),intent:any={version:1,prefix:FRESH_ROLLBACK_PREFIX,...tuple,proofSha256:sha(proofBytes)};
  return {intent,proof,proofBytes,diagnostic,diagnosticBytes,failedDeploymentBytes,phaseState:{state:'stopped',nativeVerified:false},originalPacket,priorKeyAuth,actorId,targetClusterId,targetWorkspaceId,currentRuntimeSourceSha256};
};
const reseal=(f:any)=>{f.proofBytes=Buffer.from(JSON.stringify(f.proof));f.intent.proofSha256=sha(f.proofBytes);return f;};
const resealDiagnostic=(f:any)=>{f.diagnosticBytes=Buffer.from(JSON.stringify(f.diagnostic));f.intent.diagnosticSha256=sha(f.diagnosticBytes);f.proof.diagnosticSha256=sha(f.diagnosticBytes);return reseal(f);};

describe('fixed fresh rollback after actual schema-union preview failure',()=>{
  it('requires the original failed compare and successful capture with zero native mutation, and preserves the precise key-auth baseline proof',()=>{
    const f=fixture(),before=JSON.stringify(f);const result=validateFreshRollbackIntent(f);expect(result.prefix).toBe(FRESH_ROLLBACK_PREFIX);expect(result.snapshotVersion).toBe(1);expect(JSON.stringify(f)).toBe(before);
    expect(f.diagnostic.compareJobs).toHaveLength(2);expect(f.originalPacket.status).toBe(409);
  });
  it.each(['no-intent','prefix-suffix','changed-proof-bytes','unknown-packet','changed-original-response','unknown-phase','native-already-verified','same-candidate','wrong-deployment','unbound-baseline','different-snapshot','different-execution','changed-version','changed-target-scope','modified-ciphertext-claim','entity-schema-drift','shared-plugin-drift','extra-unproved-plugin','missing-compare-job','capture-native-started','native-mutation-present'])('rejects unproved rollback recovery before any new preview: %s',failure=>{
    const f:any=fixture();
    if(failure==='no-intent')f.intent=null;if(failure==='prefix-suffix')f.intent.prefix+='-retry';if(failure==='changed-proof-bytes')f.proofBytes=Buffer.concat([f.proofBytes,Buffer.from(' ')]);
    if(failure==='unknown-packet')f.originalPacket.state='response_unknown';if(failure==='changed-original-response')f.originalPacket.status=201;if(failure==='unknown-phase')f.phaseState.state='uncertain';if(failure==='native-already-verified')f.phaseState.nativeVerified=true;
    if(failure==='same-candidate'){f.currentRuntimeSourceSha256=f.intent.failedRuntimeSourceSha256;f.intent.candidateRuntimeSourceSha256=f.currentRuntimeSourceSha256;f.proof.candidateRuntimeSourceSha256=f.currentRuntimeSourceSha256;}
    if(failure==='wrong-deployment')f.failedDeploymentBytes=Buffer.from(JSON.stringify({phase:'m10-candidate-v8',apiSourceSha256:f.intent.failedRuntimeSourceSha256}));
    if(failure==='unbound-baseline')f.priorKeyAuth.exactBaselineProof.immutableOriginMatched=false;if(failure==='different-snapshot')f.priorKeyAuth.executed.baselineSnapshotId=id(90);if(failure==='different-execution')f.priorKeyAuth.executed.proof.executionId=id(91);
    if(failure==='changed-version')f.priorKeyAuth.exactBaselineProof.actualBaselineVersion=2;if(failure==='changed-target-scope')f.priorKeyAuth.exactBaselineProof.workspaceId=id(92);if(failure==='modified-ciphertext-claim')f.proof.snapshotMaterialChanged=true;
    if(failure==='entity-schema-drift')f.diagnostic.entitySchemas[0].sameRawDefinition=false;if(failure==='shared-plugin-drift')f.diagnostic.pluginSchemas[1].sameRawDefinition=false;
    if(failure==='extra-unproved-plugin')f.diagnostic.pluginSchemas.push({name:'another-plugin',inOld:false,inFresh:true,sameRawDefinition:false});
    if(failure==='missing-compare-job')f.diagnostic.compareJobs.shift();if(failure==='capture-native-started')f.diagnostic.compareJobs[1].nativeStarted=true;if(failure==='native-mutation-present')f.diagnostic.actualNativeCounters.count=1;
    if(['entity-schema-drift','shared-plugin-drift','extra-unproved-plugin','missing-compare-job','capture-native-started','native-mutation-present'].includes(failure))resealDiagnostic(f);
    else if(failure!=='changed-proof-bytes'&&f.intent)reseal(f);
    expect(()=>validateFreshRollbackIntent(f)).toThrow();
  });
  it('uses a separately frozen fresh GET revision and new labels, leaving the original preview label and key out of the recovery sends',()=>{
    const source=readFileSync('tests/security/m10-native-optin-actual.mjs','utf8');
    expect(source).toContain('freshRollback=validateFreshRollbackIntent');expect(source).toContain('prefix=freshRollback.prefix');expect(source).toContain('revision: snapshot.entity.revision');
    expect(source).toContain('FRESH_ROLLBACK_PREVIEW_MUST_NOT_REPLAY_ORIGINAL');expect(source).toContain('FRESH_ROLLBACK_APPLY_MUST_NOT_REPLAY_ORIGINAL');
    expect(source).toContain("flag: 'wx'");expect(source).not.toContain('snapshot.material=');
  });
});
