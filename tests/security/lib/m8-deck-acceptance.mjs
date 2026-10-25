import { spawn, execFileSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { parse, stringify } from 'yaml';
import { M8_COMPOSE, entity, scope, sha256 } from './m8-harness.mjs';
import { configurationWrite, configurationRead, assertConfigurationReceipt } from './m8-configuration-acceptance.mjs';
import { nativeRead, sixCredentialProxyAcceptance } from './m8-native-acceptance.mjs';

const toolHash='642f49fd64e83aff867939705dbd927c5e750b241a99e8539ab22d18930427ed';
const uuid=v=>typeof v==='string'&&/^[a-f\d]{8}-[a-f\d]{4}-[1-8][a-f\d]{3}-[89ab][a-f\d]{3}-[a-f\d]{12}$/i.test(v);
export function assertM8DeckSession(h,value,{purpose,jobId,actor,area}) {
  h.check(uuid(value?.id)&&value.revision===1&&value.purpose===purpose&&value.basePath===`/api/v1/deck/${value.id}`
    &&value.authorizationScheme==='KongOS-Deck'&&/^[A-Za-z\d_-]{43}$/.test(value.tokenSecret??'')
    &&Date.parse(value.expiresAt)>Date.now()&&Date.parse(value.expiresAt)<=Date.now()+301000,'actual decK session has its fixed namespace, real expiry and server opaque credential');
  return {...value,jobId,actorId:actor.user.id,sessionId:actor.sid,area:{...area}};
}
/** The caller must use the genuinely running direct-driver apply receipt,
 * never wait for job completion before the actual CLI is allowed to execute. */
export async function submitM8DeckApply(h,actor,area,imported) {
  const plan=entity(await configurationRead(h,actor,area,`configuration/plans/${imported.planId}`));
  h.check(plan.id===imported.planId&&plan.planHash===imported.planHash&&plan.planRevision===imported.planRevision
    &&plan.capabilities?.apply===true&&plan.executionMode==='direct'&&plan.deleteCount===0,'direct decK driver consumes the exact current immutable no-delete plan');
  const key=randomUUID(),body={planRevision:plan.planRevision,planHash:plan.planHash,revision:plan.revision,driver:'deck',confirmed:true,confirm_name:plan.name};
  const op={key,area:{...area},path:`configuration/plans/${plan.id}/apply`,method:'POST',bodySha256:sha256(JSON.stringify(body)),actorId:actor.user.id,sessionId:actor.sid,state:'prepared'};
  h.state.configurationOperations.push(op);h.save();
  const initial=h.data(await h.request(actor,scope(area.cid,area.wid,op.path),'POST',body,{key,expected:[200,201,202]}));
  assertConfigurationReceipt(h,initial,{actor,area,key,kind:'apply'});
  h.check(initial.state==='running'&&initial.driver==='deck'&&uuid(initial.planId)&&initial.planId!==plan.id&&initial.planHash===plan.planHash
    &&initial.planRevision===plan.planRevision&&initial.executionCompleted===false&&uuid(initial.executionId),'actual direct decK apply reserves its genuine job-local cloned plan and running execution without claiming Native completion');
  Object.assign(op,{jobId:initial.jobId,state:'submitted',receipt:initial});h.save();
  const changes=await configurationRead(h,actor,area,`configuration/plans/${initial.planId}/changes`,{size:100}),local=entity(changes);
  h.check(local.id===initial.planId&&local.clusterId===area.cid&&local.workspaceId===area.wid&&local.planHash===plan.planHash&&local.planRevision===plan.planRevision
    &&local.executionMode==='direct'&&local.deleteCount===0&&Number.isSafeInteger(local.stepCount)&&local.stepCount>=1&&local.stepCount<=100
    &&Array.isArray(changes.items)&&changes.items.length===local.stepCount&&changes.nextCursor===null&&changes.items.every(s=>uuid(s.stepId)&&s.objectWorkspaceId===area.wid),
    'the actual current cloned plan has its original immutable HMAC, revision and complete bounded typed changes');
  const steps=await configurationRead(h,actor,area,`configuration/jobs/${initial.jobId}/steps`,{size:100});
  h.check(Array.isArray(steps.items)&&steps.items.length===local.stepCount&&steps.nextCursor===null&&new Set(steps.items.map(s=>s.id)).size===local.stepCount
    &&steps.items.every(s=>uuid(s.id)&&s.executionId===initial.executionId&&s.state==='pending'&&s.operationId===null&&s.verified===false
      &&s.objectWorkspaceId===area.wid&&changes.items.some(p=>p.stepId===s.planStepId&&p.entityType===s.type&&p.action===s.action&&p.nativeId===s.originalId)),
    'the real pending job steps bind the receipt execution to every exact typed cloned-plan step before any write session');
  return{receipt:initial,plan:local,operation:op,sourcePlan:plan};
}
/** Only the fixed, reviewed compose runner can receive this private stdin.
 * An unknown child result freezes the original intent; it is never rerun. */
export async function runM8FixedDeck(h,actor,area,input,{jobId=null}={}) {
  h.assertWritable();
  h.check(['validate','diff','sync'].includes(input.command)&&typeof input.stateYaml==='string'&&Buffer.byteLength(input.stateYaml)<=8*1024*1024,'actual CLI has a bounded fixed command and original private state');
  if(input.command!=='validate')h.check(uuid(input.sessionId)&&/^[A-Za-z\d_-]{43}$/.test(input.tokenSecret??''),'actual network CLI uses an issued current decK session');
  const serialized=JSON.stringify(input),frozen=JSON.parse(serialized),key=randomUUID(),containerName=`kongos-m8-deck-${key}`;
  h.remember({tokenSecret:frozen.tokenSecret});
  const intent={key,command:frozen.command,jobId,actorId:actor.user.id,sessionId:actor.sid,clusterId:area.cid,workspaceId:area.wid,containerName,input:frozen,inputSha256:sha256(serialized),state:'prepared',startedAt:new Date().toISOString()};
  h.state.cliIntents.push(intent);h.save();
  const env={...process.env};for(const k of ['DOCKER_HOST','DOCKER_CONTEXT','DOCKER_TLS','DOCKER_TLS_VERIFY','DOCKER_CERT_PATH'])delete env[k];
  let child,exit,signal,transportFailure=false,timedOut=false;
  const out=[],err=[];let outBytes=0,errBytes=0;
  await new Promise(resolve=>{
    let settled=false,timer,killTimer,closeTimer;
    const settle=(code,sig)=>{if(settled)return;settled=true;exit=code;signal=sig;clearTimeout(timer);clearTimeout(killTimer);clearTimeout(closeTimer);resolve();};
    const stop=()=>{
      transportFailure=true;
      if(settled||killTimer)return;
      try{child?.kill('SIGTERM');}catch{}
      killTimer=setTimeout(()=>{try{child?.kill('SIGKILL');}catch{}},1000);
      // Even an uncooperative transport cannot keep an unresolved original
      // intent alive forever. No second child, command, or sync is attempted.
      closeTimer=setTimeout(()=>settle(undefined,undefined),3000);
    };
    try{
      child=spawn('docker',['--host=unix:///var/run/docker.sock',...M8_COMPOSE,'-f','deploy/compose.gitops.yml','-f','tests/security/fixtures/m8-deck-runtime-no-build.yml','--profile','gitops-runner','run','--rm','--no-deps','--pull','never','-T','--name',containerName,'console-deck-runner'],{env,shell:false,stdio:['pipe','pipe','pipe']});
      child.once('error',stop);child.once('close',(code,sig)=>settle(code,sig));
      for(const stream of [child.stdout,child.stderr,child.stdin])stream.on('error',stop);
      child.stdout.on('data',b=>{outBytes+=b.length;if(outBytes>65536)stop();else out.push(b);});
      child.stderr.on('data',b=>{errBytes+=b.length;if(errBytes>4*1024*1024)stop();else err.push(b);});
      timer=setTimeout(()=>{timedOut=true;stop();},150000);
      child.stdin.end(serialized);
    }catch{transportFailure=true;if(child)stop();else settle(undefined,undefined);}
  });
  const stdout=Buffer.concat(out),stderr=Buffer.concat(err);let result;
  try{const lines=stdout.toString('utf8').trim().split('\n');if(lines.length===1)result=JSON.parse(lines[0]);}catch{}
  // Error detail remains exclusively inside the private journal for narrow
  // diagnosis. No CLI YAML/token/body/error message enters public evidence.
  Object.assign(intent,{dockerExitCode:exit??null,signal:signal??null,stdoutSha256:sha256(stdout),stderrSha256:sha256(stderr),rawStdout:stdout.toString('utf8'),rawStderr:stderr.toString('utf8')});
  if(transportFailure||timedOut||!result||result.command!==frozen.command||result.toolBinarySha256!==toolHash||result.possibleUnknown===true){intent.state='response_unknown';h.save({phase:'stopped-cli-unknown'});throw Error('M8_ORIGINAL_CLI_UNKNOWN_NO_REPLAY');}
  intent.state='response_observed';intent.safeResult=result;h.save();
  h.check(exit===0&&result.exitCode===0&&result.toolVersion==='1.2.4'&&result.toolCommit==='8e68931'&&!result.timedOut&&!result.outputLimitReached&&result.consoleJobSuccessProved===false,'fixed official CLI succeeds without pretending the BFF job or proxy result succeeded');
  return result;
}
async function issue(h,actor,area,jobId,purpose,plan) {
  const body={jobId,purpose,...(plan?{planId:plan.id,planRevision:plan.planRevision,planHash:plan.planHash}:{})};
  const session=assertM8DeckSession(h,h.data(await h.request(actor,scope(area.cid,area.wid,'configuration/deck-sessions'),'POST',body)),{purpose,jobId,actor,area});
  h.state.deckSessions??=[];h.state.deckSessions.push(session);h.state.fixtures.push({...area,type:'configuration_deck_sessions',id:session.id,name:session.id});h.save();return session;
}
async function revoke(h,actor,area,session) {
  const result=h.data(await h.request(actor,scope(area.cid,area.wid,`configuration/deck-sessions/${session.id}`),'DELETE',{revision:session.revision,confirmed:true,confirm_name:session.id}));
  h.check(result.revoked===true,'actual CLI session is revoked through its original current-authorized BFF');session.revoked=true;h.save();
}
/** Requires a preceding, independent validate for the selected fixed tool.
 * It sends only the original scenario's still-unused diff/sync and BFF writes. */
export async function m8DeckReadSyncUnusedTail(h,actors,captured,{run=runM8FixedDeck,validatedIntentIndex}={}) {
  const actor=actors.admin,area=actors.direct,f=h.state.nativeFixture,b=h.state.baseline;
  const validation=validatedIntentIndex===undefined?h.state.cliIntents.at(-1):h.state.cliIntents[validatedIntentIndex];
  assertConfigurationReceipt(h,captured,{actor,area,key:captured.idempotencyKey,jobId:captured.jobId,kind:'capture'});
  h.check(captured.state==='succeeded'
    &&validation?.safeResult?.exitCode===0&&validation?.safeResult?.toolBinarySha256===toolHash
    &&validation?.command==='validate'&&!h.state.deckAcceptance,'unused CLI tail requires current successful capture authority and the independent new fixed tool validation');
  const readSession=await issue(h,actor,area,captured.jobId,'read');
  await run(h,actor,area,{command:'diff',sessionId:readSession.id,tokenSecret:readSession.tokenSecret,stateYaml:b.yaml},{jobId:captured.jobId});
  await revoke(h,actor,area,readSession);
  const desired=parse(b.yaml),service=desired.services.find(s=>s.id===f.service.id);h.check(service?.retries===f.service.retries,'original private deployment state matches the actual post-rollback Service');service.retries=2;
  const importedDocument=structuredClone(desired),keep={};
  for(const consumer of importedDocument.consumers??[])for(const credential of consumer.basicauth_credentials??[]){delete credential.password;keep[`credentials:basic-auth:${consumer.id}:${credential.id}`]='keep';}
  const imported=await configurationWrite(h,actor,area,'configuration/imports',{scope:'workspace',mode:'merge',yaml:stringify(importedDocument),basicPasswordIntents:keep},{kind:'import'});
  h.check(imported.counts?.update===1&&imported.counts?.create===0&&imported.counts?.delete===0,'CLI sync receives exactly one genuinely frozen update');
  const execution=await submitM8DeckApply(h,actor,area,imported),writeSession=await issue(h,actor,area,execution.receipt.jobId,'write',execution.plan);
  await run(h,actor,area,{command:'sync',sessionId:writeSession.id,tokenSecret:writeSession.tokenSecret,stateYaml:stringify(desired)},{jobId:execution.receipt.jobId});
  const terminal=await configurationRead(h,actor,area,`configuration/jobs/by-key/${execution.receipt.idempotencyKey}`);
  assertConfigurationReceipt(h,terminal,{actor,area,key:execution.receipt.idempotencyKey,jobId:execution.receipt.jobId,kind:'apply'});
  h.check(terminal.state==='succeeded'&&terminal.executionCompleted===true&&terminal.driver==='deck'&&terminal.completedSteps===1,'CLI exit is independently joined to the original successful one-step configuration job');
  const steps=await configurationRead(h,actor,area,`configuration/jobs/${terminal.jobId}/steps`,{size:100});
  h.check(steps.items?.length===1&&steps.items[0].state==='succeeded'&&steps.items[0].verified===true&&uuid(steps.items[0].operationId)&&steps.items[0].objectWorkspaceId===area.wid,'actual CLI step has one verified Native receipt in the exact object workspace');
  const actual=await nativeRead(h,actor,area,'services',f.service.id);h.check(actual.retries===2,'actual Kong readback independently proves CLI sync applied the original Service');
  await sixCredentialProxyAcceptance(h,f,'actual-deck-sync');
  Object.assign(execution.operation,{state:'succeeded',receipt:terminal});h.save();await revoke(h,actor,area,writeSession);
  h.state.deckAcceptance={captureJobId:captured.jobId,importJobId:imported.jobId,applyJobId:terminal.jobId,readSessionId:readSession.id,writeSessionId:writeSession.id,nativeOperationId:steps.items[0].operationId,actualProxyCredentialKinds:6};
  h.public??={};h.public.deckAcceptance={...h.state.deckAcceptance,toolVersion:'1.2.4',toolBinarySha256:toolHash,formatVersion:'1.1',actualDiff:true,actualSync:true,CLIExitAloneAccepted:false,nativeAdminBypassRequests:0};h.save();return h.state.deckAcceptance;
}
export async function m8DeckAcceptance(h,actors) {
  h.assertWritable();h.check(!h.state.deckAcceptance&&h.state.cliIntents.length===0,'the original fixed CLI scenario cannot be replayed');
  const {assertM8Deck124Runtime}=await import('./m8-deck124-continuation.mjs');
  assertM8Deck124Runtime(h);
  const actor=actors.admin,area=actors.direct;
  const captured=await configurationWrite(h,actor,area,'snapshots',{scope:'workspace',name:`${h.state.testTag} decK current read`,description:'Actual fixed decK1.2.4 protocol verification'},{kind:'capture'});
  await runM8FixedDeck(h,actor,area,{command:'validate',stateYaml:h.state.baseline.yaml});
  return m8DeckReadSyncUnusedTail(h,actors,captured);
}
