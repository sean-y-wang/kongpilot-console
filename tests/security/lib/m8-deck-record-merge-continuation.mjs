import {randomUUID} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {parse,stringify} from 'yaml';
import {entity,scope,sha256} from './m8-harness.mjs';
import {configurationRead,configurationWrite,assertConfigurationReceipt} from './m8-configuration-acceptance.mjs';
import {assertM8DeckSession,submitM8DeckApply} from './m8-deck-acceptance.mjs';
import {assertM8DeckPoolRelease,runM8FixedDeckPrivateStderr} from './m8-deck-pool-continuation.mjs';
import {nativeRead,sixCredentialProxyAcceptance} from './m8-native-acceptance.mjs';

export const M8_DECK_RECORD_MERGE_CONTINUATION=Object.freeze({
 packetCount:142,prefix:'aa96960f027859d138fb8c309b9e1d4422209bc07f1440876d1d9d3f419ea593',
 failurePath:'artifacts/M8/security-live-deck-pool-transaction.json',failureSha256:'e9cb06daab60aa77e69ab665d9cad2bdfe7e499b8bb34037da5cd081b9cd079a',
 diagnosisPath:'artifacts/M8/import-sync-second-change-readonly-diagnosis-continuation.json',diagnosisSha256:'d7518ead985ef529fc54e19d1bdadfa539b48101f94f692f47bda5000fcc8feb',
 nullProofPath:'artifacts/M8/import-sync-optional-null-readonly-proof.json',nullProofSha256:'75d5af94b03ecd05bb1afe150bb9a9f198b37c1d2bd2ceaa3d9f9caf5ba118c6',
 priorReadonlyFailurePath:'artifacts/M8/import-sync-second-change-readonly-diagnosis.json',priorReadonlyFailureSha256:'354a9dc5b72ad4d08221a9350a99a657a00e376c5d65aece80ece58f7be1fb3d',
 importJobId:'d04994bd-e3a6-49c7-b95b-e670353c5a00',importKey:'e8823efd-4e22-4189-927c-a6c63f292b59',importRequestId:'7174d39e-c003-434b-90ef-4ff57b1bc62c',
 importBodySha256:'58e3b879c7e426e044d774e611f4b986702a5b89d2e34b656c25bbc943b8155e',
 planId:'e82be558-030f-48ca-a446-b7d958eb1fd3',planRevision:1,planHash:'8e33b4f360912fe2d0874baf0c978eab5d4e14c7baf67e581aad75dcd25a25a5',
 serviceId:'9e5adb4a-0964-4e77-a01b-a6a4347138d7',upstreamId:'6b62af2b-d262-44df-af82-4783a19e4372',
 captureJobId:'701ecba3-7559-40ce-9388-8ee6c6051eb4',
 successPath:'artifacts/M8/security-live-deck-record-merge.json',
 // Filled only from Root's new source freeze and actual continuity evidence.
 sourceFreezePath:'artifacts/M8/root-deck-record-merge-fix-freeze.json',sourceFreezeSha256:'789d22d72cd7ca11fce9eb9a19a5e5de7d1d8ce6edb7f982dc1d652e4088fe87',
 continuityPath:'artifacts/M8/deck-record-merge-api-repair-continuity.json',continuitySha256:'ec8c727cc50388fb76ff65d02cd59ffcbebc79cd62ad84e4d64716c9004e5570',
});
const c=M8_DECK_RECORD_MERGE_CONTINUATION,hex=v=>typeof v==='string'&&/^[a-f\d]{64}$/.test(v);
export function assertM8DeckRecordMergeCheckpoint(r,failedBytes,diagnosisBytes,nullBytes,priorFailureBytes){
 const failed=JSON.parse(failedBytes),diagnosis=JSON.parse(diagnosisBytes),proof=JSON.parse(nullBytes),prior=JSON.parse(priorFailureBytes),p=r.requests?.[141],cli=r.cliIntents?.[3];
 if(r.version!==1||r.milestone!=='M8'||r.phase!=='stopped-failure'||r.inFlight!==null||r.requests?.length!==c.packetCount||sha256(JSON.stringify(r.requests))!==c.prefix
  ||r.requests.some(v=>v.state!=='response_observed')||(r.proxyChecks??[]).some(v=>['prepared','response_unknown'].includes(v.state))
  ||r.cliIntents?.length!==4||r.cliIntents.some(v=>v.state!=='response_observed')||r.deckAcceptance||r.rbacJournal||r.deckRecordMergeContinuation
  ||sha256(failedBytes)!==c.failureSha256||failed.allPassed!==false||failed.passed!==1797||failed.failed!==1||failed.successfulWrites!==130||failed.unknownWrites!==0
  ||sha256(diagnosisBytes)!==c.diagnosisSha256||diagnosis.allPassed!==true||diagnosis.original142PrefixUnchanged!==true||diagnosis.newAuthWrites!==0||diagnosis.newBusinessWrites!==0||diagnosis.newNativeWrites!==0
  ||sha256(nullBytes)!==c.nullProofSha256||proof.allPassed!==true||proof.original142PrefixUnchanged!==true||proof.fieldPath!=='/healthchecks/active/https_sni'
  ||sha256(priorFailureBytes)!==c.priorReadonlyFailureSha256||prior.allPassed!==false
  ||r.deckPoolContinuation?.state!=='unused-standard-diff-sync'||r.deckPoolContinuation.selectedCaptureJobId!==c.captureJobId
  ||!r.c2ModeRestored||r.expiredExecutionRecovery?.state!=='completed'||r.approvalTransfer?.nativeSteps!==17||r.finalHttpUnusedTail?.state!=='fixed-cli-unused')throw Error('M8_EXACT_142_KNOWN_IMPORT_CHECKPOINT_REQUIRED');
 const actor=r.sessions.admin,area=r.scopes.direct,j=p?.responseData,d=r.importSyncSecondChangeDiagnosisContinuation,n=r.importSyncOptionalNullProof;
 if(p.key!==c.importKey||p.requestId!==c.importRequestId||p.status!==201||p.method!=='POST'||p.path!==`/api/v1/clusters/${area.cid}/configuration/imports`
  ||p.bodySha256!==c.importBodySha256||sha256(JSON.stringify(p.body))!==c.importBodySha256||p.actorId!==actor.user.id||p.sessionId!==actor.sid||p.clusterId!==area.cid||p.workspaceId!==area.wid
  ||j?.jobId!==c.importJobId||j.planId!==c.planId||j.planRevision!==c.planRevision||j.planHash!==c.planHash||j.state!=='succeeded'||j.counts?.update!==2||j.counts.create!==0||j.counts.delete!==0
  ||d?.state!=='completed'||n?.state!=='completed'||[d,n].some(v=>v.actorId!==p.actorId||v.sessionId!==p.sessionId||v.clusterId!==p.clusterId||v.workspaceId!==p.workspaceId)
  ||d.originalPrefixSha256!==c.prefix||d.jobId!==c.importJobId||d.planId!==c.planId||d.planHash!==c.planHash||d.planRevision!==1||d.reads?.length!==2||d.reads.some(v=>v.state!=='response_observed'||v.status!==200)
  ||n.upstreamId!==c.upstreamId||n.facts?.actualCurrentHttpsSniOwn!==true||n.facts.actualCurrentHttpsSniNull!==true||n.facts.baselineYamlHttpsSniOwn!==false||n.facts.importYamlHttpsSniOwn!==false||n.facts.upstreamYamlUnchangedByHelper!==true||n.facts.planHasSingleRemoveHttpsSni!==true
  ||cli?.command!=='diff'||cli.fixedOrigin!=='http://console-web:8080'||cli.observer!==false||cli.dockerExitCode!==0||cli.rawStderrPrivatelyFsyncedBeforeDispose!==true
  ||cli.safeResult?.stderrBytes!==0||cli.rawCliStderr!==''||cli.rawCliStderrSha256!==sha256('')||cli.inputSha256!==sha256(JSON.stringify(cli.input))
  ||cli.safeResult?.exitCode!==0||cli.safeResult.possibleUnknown!==false||cli.safeResult.timedOut!==false||cli.safeResult.outputLimitReached!==false||cli.safeResult.consoleJobSuccessProved!==false
  ||cli.safeResult.toolVersion!=='1.2.4'||cli.safeResult.toolCommit!=='8e68931'||cli.safeResult.toolBinarySha256!=='642f49fd64e83aff867939705dbd927c5e750b241a99e8539ab22d18930427ed'
  ||cli.actorId!==actor.user.id||cli.sessionId!==actor.sid||cli.clusterId!==area.cid||cli.workspaceId!==area.wid||cli.jobId!==c.captureJobId||cli.input.stateYaml!==r.baseline.yaml
  ||r.deckSessions?.length!==3||r.deckSessions[2].revoked!==true||r.deckSessions[2].id!==cli.input.sessionId
  ||r.nativeFixture.service.id!==c.serviceId||r.nativeFixture.service.retries!==0)throw Error('M8_ORIGINAL_142_FULL_SCOPE_AND_SUCCESSFUL_DIFF_REQUIRED');
 const body=parse(p.body.yaml),original=parse(r.baseline.yaml),service=body.services?.find(v=>v.id===c.serviceId),upstream=body.upstreams?.find(v=>v.id===c.upstreamId);
 if(p.body.scope!=='workspace'||p.body.mode!=='merge'||service?.retries!==2||!upstream||JSON.stringify(upstream)!==JSON.stringify(original.upstreams?.find(v=>v.id===c.upstreamId)))throw Error('M8_ORIGINAL_ONE_SERVICE_INTENT_REQUIRED');
 return{failed,diagnosis,proof,packet:p,diff:cli,readSession:r.deckSessions[2]};
}
export function assertM8DeckRecordMergeRelease(h){
 for(const [path,digest]of[[c.sourceFreezePath,c.sourceFreezeSha256],[c.continuityPath,c.continuitySha256]]){
  h.check(path.startsWith('artifacts/M8/')&&hex(digest),'new record-merge source and actual runtime evidence must be sealed before release');
  const b=readFileSync(path),v=JSON.parse(b);h.check(sha256(b)===digest&&(path===c.sourceFreezePath?v.sourceOnly===true&&v.stage==='SOURCE_READY_DECK_SCHEMA_RECORD_MERGE_ROUNDTRIP'&&v.validation?.apiTypecheckExitCode===0&&v.validation.apiBuildExitCode===0&&v.validation.gitDiffCheckExitCode===0:v.allPassed===true&&v.businessWrites===0&&v.nativeWrites===0&&v.authRequests===0&&v.cliExecutions===0),'new record-merge repair proof has its fixed exact SHA');
 }
 assertM8DeckPoolRelease(h);
}
export function assertM8SingleServiceRetryPlan(value,imported,area){
 const p=entity(value),items=value?.items;
 if(p.id!==imported.planId||p.planHash!==imported.planHash||p.planRevision!==imported.planRevision||p.clusterId!==area.cid||p.workspaceId!==area.wid
  ||p.counts?.create!==0||p.counts.update!==1||p.counts.delete!==0||p.counts.conflict!==0||p.deleteCount!==0||!Array.isArray(items)||items.length!==1||value.nextCursor!==null
  ||items[0].entityType!=='services'||items[0].nativeId!==c.serviceId||items[0].objectWorkspaceId!==area.wid||items[0].action!=='update'||items[0].referenceOnly===true
  ||items[0].patch?.length!==1||items[0].patch[0].op!=='replace'||items[0].patch[0].path!=='/retries'||items[0].patch[0].value!==2||(items[0].blockerCodes??[]).length)throw Error('M8_EXACT_SINGLE_SERVICE_RETRIES_PLAN_REQUIRED');
 return p;
}
/** Only the still-unused NEW preview/apply/sync intents. Successful validate,
 * standard diff and the original two-step import remain immutable history. */
export async function m8DeckRecordMergeUnusedAcceptance(h,actors){
 h.assertWritable();assertM8DeckRecordMergeRelease(h);h.check(h.state.deckRecordMergeContinuation?.state==='prepared','the original 142 checkpoint may continue once');
 const actor=actors.admin,area=actors.direct,old=h.state.requests[141],marker=h.state.deckRecordMergeContinuation;
 const previous=await configurationRead(h,actor,area,`configuration/jobs/by-key/${c.importKey}`);assertConfigurationReceipt(h,previous,{actor,area,key:c.importKey,jobId:c.importJobId,kind:'import'});
 h.check(previous.state==='succeeded'&&previous.planId===c.planId&&previous.planRevision===1&&previous.planHash===c.planHash&&previous.counts?.update===2,'old committed two-step preview is preserved and never applied or rewritten');
 const body=structuredClone(old.body),newKey=randomUUID();h.check(newKey!==c.importKey&&sha256(JSON.stringify(body))===c.importBodySha256,'new preview is an independent key with the exact original intended payload');
 Object.assign(marker,{state:'new-independent-import-preview',newImportKey:newKey,newImportBodySha256:sha256(JSON.stringify(body)),originalImportReplayed:false,successfulDiffReplayed:false});h.save();
 const imported=await configurationWrite(h,actor,area,'configuration/imports',body,{kind:'import',key:newKey});
 h.check(imported.jobId!==c.importJobId&&imported.planId!==c.planId&&imported.counts?.update===1&&imported.counts.create===0&&imported.counts.delete===0&&imported.counts.conflict===0,'new preview freezes exactly one Service update with no unrelated mutations');
 const changes=await configurationRead(h,actor,area,`configuration/plans/${imported.planId}/changes`,{size:100});assertM8SingleServiceRetryPlan(changes,imported,area);
 Object.assign(marker,{newImportJobId:imported.jobId,newPlanId:imported.planId,state:'unused-direct-deck-apply'});h.save();
 const execution=await submitM8DeckApply(h,actor,area,imported),session=assertM8DeckSession(h,h.data(await h.request(actor,scope(area.cid,area.wid,'configuration/deck-sessions'),'POST',
  {jobId:execution.receipt.jobId,purpose:'write',planId:execution.plan.id,planRevision:execution.plan.planRevision,planHash:execution.plan.planHash})),{purpose:'write',jobId:execution.receipt.jobId,actor,area});
 h.state.deckSessions.push(session);h.state.fixtures.push({...area,type:'configuration_deck_sessions',id:session.id,name:session.id});marker.state='unused-standard-sync';h.save();
 const desired=parse(h.state.baseline.yaml);desired.services.find(s=>s.id===c.serviceId).retries=2;
 await runM8FixedDeckPrivateStderr(h,actor,area,{command:'sync',sessionId:session.id,tokenSecret:session.tokenSecret,stateYaml:stringify(desired)},{jobId:execution.receipt.jobId});
 const terminal=await configurationRead(h,actor,area,`configuration/jobs/by-key/${execution.receipt.idempotencyKey}`);assertConfigurationReceipt(h,terminal,{actor,area,key:execution.receipt.idempotencyKey,jobId:execution.receipt.jobId,kind:'apply'});
 h.check(terminal.state==='succeeded'&&terminal.executionCompleted===true&&terminal.driver==='deck'&&terminal.completedSteps===1,'standard CLI sync has an independently succeeded one-step job');
 const steps=await configurationRead(h,actor,area,`configuration/jobs/${terminal.jobId}/steps`,{size:100});
 h.check(steps.items?.length===1&&steps.items[0].state==='succeeded'&&steps.items[0].verified===true&&/^[a-f\d]{8}-[a-f\d]{4}-[1-8][a-f\d]{3}-[89ab][a-f\d]{3}-[a-f\d]{12}$/.test(steps.items[0].operationId??'')&&steps.items[0].objectWorkspaceId===area.wid,'CLI completion has the exact single verified Native receipt');
 const actual=await nativeRead(h,actor,area,'services',c.serviceId);h.check(actual.retries===2,'current Kong independently matches the single Service retries intent');await sixCredentialProxyAcceptance(h,h.state.nativeFixture,'actual-deck-sync');
 Object.assign(execution.operation,{state:'succeeded',receipt:terminal});h.save();
 const revoked=h.data(await h.request(actor,scope(area.cid,area.wid,`configuration/deck-sessions/${session.id}`),'DELETE',{revision:session.revision,confirmed:true,confirm_name:session.id}));h.check(revoked.revoked===true,'new write session is revoked through its current authorized scope');session.revoked=true;
 h.state.deckAcceptance={captureJobId:c.captureJobId,importJobId:imported.jobId,applyJobId:terminal.jobId,readSessionId:h.state.deckSessions[2].id,writeSessionId:session.id,nativeOperationId:steps.items[0].operationId,actualProxyCredentialKinds:6};
 marker.state='cli-completed';h.public??={};h.public.deckAcceptance={...h.state.deckAcceptance,toolVersion:'1.2.4',toolBinarySha256:'642f49fd64e83aff867939705dbd927c5e750b241a99e8539ab22d18930427ed',formatVersion:'1.1',actualDiff:true,actualSync:true,successfulDiffReplayed:false,originalTwoStepPlanRetained:true,CLIExitAloneAccepted:false,nativeAdminBypassRequests:0};h.save();return h.state.deckAcceptance;
}
