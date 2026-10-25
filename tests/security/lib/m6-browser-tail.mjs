import {FIRST_BROWSER_FAILURE_SHA,FIRST_BROWSER_LOGIN_REQUEST,browserSha,originalCookieJar} from './m6-browser-remaining.mjs';
export const REMAINING_BROWSER_STOP_SHA='3d9aabe34efba4c6db16c262d4f18e5022b84b22f2e69fa6c38a58dd44835639';
const uuid=v=>typeof v==='string'&&/^[a-f\d]{8}-[a-f\d]{4}-[1-8][a-f\d]{3}-[89ab][a-f\d]{3}-[a-f\d]{12}$/i.test(v);
const canonicalNames=['kongos_portal_access','kongos_portal_refresh','kongos_portal_csrf'];

/** No I/O and no reference mutation: both real stop records and all completed
 * packets must agree before restoring the current original-session cookie jar. */
export function browserTailCheckpoint(r,live,firstBytes,stopBytes){
 const stop=JSON.parse(stopBytes),f=live?.fixturesForBrowser,owner=r.portalUsers?.find(v=>v.label==='developer-a'),b=r.browserRemaining,writes=r.browserWriteEvidence,app=r.browserApplication,lost=r.browserUnknown;
 const attempts=(r.writeAttempts??[]).filter(v=>v.source==='browser-remaining'),create=attempts.filter(v=>v.method==='POST'&&v.path==='/api/v1/portal/applications'),refresh=attempts.filter(v=>v.method==='POST'&&v.path==='/api/v1/portal/auth/refresh'),reveals=attempts.filter(v=>v.method==='POST'&&v.path?.endsWith('/reveal'));
 const valid=browserSha(firstBytes)===FIRST_BROWSER_FAILURE_SHA&&browserSha(stopBytes)===REMAINING_BROWSER_STOP_SHA&&stop.failed===1&&stop.stage==='single-new-application-lost-response'&&stop.packetGuardClass===null&&
  live.failed===0&&live.passed===1057&&live.auditCoverage?.distinctRequestIds===145&&live.auditCoverage?.auditedRequestIds===145&&r.phase==='HTTP-complete'&&r.testTag===live.testTag&&!r.browserTail&&!r.browserWorkflowId&&!r.browserKeyScan&&b?.phase==='stopped-without-replay'&&b.originalLoginRequestId===FIRST_BROWSER_LOGIN_REQUEST&&uuid(b.originalSessionId)&&
  writes?.length===5&&browserSha(writes)===browserSha(stop.successfulWrites)&&writes.filter(v=>v.method==='POST'&&v.path==='/api/v1/portal/auth/login'&&v.requestId===FIRST_BROWSER_LOGIN_REQUEST).length===1&&new Set(writes.map(v=>v.requestId)).size===5&&writes.every(v=>uuid(v.requestId))&&
  owner&&uuid(owner.id)&&owner.tenant?.clusterId===f?.clusterId&&owner.tenant?.workspaceId===f?.workspaceId&&r.browser?.activeCredentialId===f?.activeCredentialId&&r.portalTestTargets?.primary?.id===f?.clusterId&&r.portalTestTargets.primary.adminUrl==='http://kong-portal-admin-endpoint:8001'&&r.portalTestTargets.primary.proxyOrigin==='http://127.0.0.1:10000'&&
  uuid(app?.id)&&app.ownerId===owner.id&&app.tenant?.clusterId===f.clusterId&&app.tenant?.workspaceId===f.workspaceId&&lost?.state==='succeeded-original-key-receipt'&&uuid(lost.key)&&uuid(lost.operationId)&&lost.actorId===owner.id&&lost.clusterId===f.clusterId&&lost.workspaceId===f.workspaceId&&
  create.length===1&&create[0].key===lost.key&&create[0].body?.name===app.name&&(create[0].responseData?.entity?.id??create[0].responseData?.id)===app.id&&refresh.length===2&&reveals.length===1&&reveals[0].path===`/api/v1/portal/applications/${f.applicationId}/grants/${f.activeGrantId}/credentials/${f.activeCredentialId}/reveal`&&attempts.length===4&&new Set(attempts.map(v=>v.key)).size===4&&attempts.every(v=>v.state==='response_observed'&&v.httpStatus>=200&&v.httpStatus<300&&v.actorId===owner.id&&v.clusterId===f.clusterId&&v.workspaceId===f.workspaceId&&v.body?.clusterId===f.clusterId&&v.body.workspaceId===f.workspaceId&&uuid(v.key)&&uuid(v.requestId)&&writes.some(w=>w.requestId===v.requestId&&w.path===v.path&&w.method===v.method))&&
  r.abandonmentAcknowledgment?.totalFormalPosts===2&&r.abandonmentAcknowledgment.phase==='certificate-verified';
 if(!valid)throw new Error('Browser tail requires the exact two immutable stops and completed original-key application receipt; no earlier packets can be replayed');
 const jars=(b.latestNamedJars??[]).filter(j=>Array.isArray(j)&&j.some(v=>v.name===canonicalNames[0]));
 if(jars.length!==1||jars[0].length!==3||canonicalNames.some(n=>jars[0].filter(v=>v.name===n).length!==1)||jars[0].some(v=>v.domain!=='127.0.0.1'||v.path!=='/api/v1/portal'||typeof v.value!=='string'||v.value.length>16384))throw new Error('Browser tail original latest named jar is missing or ambiguous');
 const candidates=canonicalNames.map(n=>jars[0].find(v=>v.name===n).value);let claim;try{claim=JSON.parse(Buffer.from(candidates[0].split('.')[1],'base64url'));}catch{throw new Error('Browser tail access identity is malformed');}
 if(claim.kind!=='portal_developer'||claim.iss!=='kongos-portal'||claim.aud!=='kongos-portal'||claim.sub!==owner.id||claim.cid!==f.clusterId||claim.wid!==f.workspaceId||claim.sid!==b.originalSessionId||!Number.isSafeInteger(claim.iat))throw new Error('Browser tail original developer/session/tenant identity changed');
 return{fixture:f,ownerId:owner.id,applicationId:app.id,applicationName:app.name,originalApplicationKey:lost.key,sessionId:claim.sid,candidates,expected:{ownerId:owner.id,clusterId:f.clusterId,workspaceId:f.workspaceId,loginRequestId:FIRST_BROWSER_LOGIN_REQUEST,issuedAt:claim.iat},before:{firstFailureSha256:FIRST_BROWSER_FAILURE_SHA,remainingStopSha256:REMAINING_BROWSER_STOP_SHA,referenceSha256:browserSha(r),writeAttemptsSha256:browserSha(r.writeAttempts),writeEvidenceSha256:browserSha(r.writeEvidence),browserWritesSha256:browserSha(writes),remainingSha256:browserSha(b),originalApplicationKey:lost.key},beforeNamedJars:structuredClone(b.latestNamedJars)};
}

export function originalTailCookieJar(context,proof){
 const jar=originalCookieJar(context,proof);
 if(proof.sessionId!==context.sessionId||proof.accessIndex!==0||proof.refreshIndex!==1||proof.csrfIndex!==2)throw new Error('Browser tail cookie proof is not the exact latest original session');
 return jar;
}

export function proveTailApplicationReceipt(r,receipt,c){
 if(receipt?.state!=='succeeded'||receipt.remoteCompleted!==true||receipt.id!==r.browserUnknown.operationId||receipt.module!=='applications'||receipt.action!=='create'||receipt.clusterId!==c.fixture.clusterId||receipt.workspaceId!==c.fixture.workspaceId||receipt.safeResult?.entity?.id!==c.applicationId)throw new Error('Browser tail original interrupted application is not fully proved by its original key');
 return{applicationId:c.applicationId,operationId:receipt.id,originalKeyVerified:true};
}

/** Synchronous fsync callback must finish before caller continues the packet.
 * Tail cannot create another app, reveal another Key, or replay prior refresh. */
export function journalBrowserTailMutation(r,request,c,sent,persist){
 const u=new URL(request.url()),method=request.method(),key=request.headers()['x-idempotency-key'],body=request.postDataJSON(),f=c.fixture;
 const portal=u.origin==='http://127.0.0.1:8082',console=u.origin==='http://127.0.0.1:8080',refresh=u.pathname==='/api/v1/portal/auth/refresh',credentialRequest=u.pathname==='/api/v1/portal/requests';
 const consoleLogin=console&&u.pathname==='/api/v1/auth/login',workflowAction=console&&uuid(r.browserWorkflowId)&&['approve','execute'].some(a=>u.pathname===`/api/v1/clusters/${f.clusterId}/workflows/${r.browserWorkflowId}/${a}`);
 const allowed=portal&&(credentialRequest||refresh&&c.accessExpired===true)||consoleLogin||workflowAction;
 const counter=method+':'+u.pathname;
 if(method!=='POST'||!allowed||!uuid(key)||(sent.get(counter)??0)!==0||r.browserTail?.phase==='stopped-without-replay'||(r.writeAttempts??[]).some(a=>a.key===key))throw new Error('Browser tail write is outside its single remaining packet budget');
 if(portal&&(body?.clusterId!==f.clusterId||body.workspaceId!==f.workspaceId))throw new Error('Browser tail tenant changed');
 if(credentialRequest&&(r.browserTail?.originalApplicationReceiptVerified!==true||body?.applicationId!==c.applicationId||body.publicationId!==f.publicationId))throw new Error('Browser tail request requires the original verified new application');
 if(workflowAction&&(u.searchParams.get('workspaceId')!==f.workspaceId||body?.confirmed!==true||body.confirm_name!=='portal-credential-issue'||!Number.isInteger(body.revision)||body.revision<1||!/^[a-f\d]{64}$/.test(body.planHash??'')))throw new Error('Browser tail current workflow confirmation changed');
 const attempt={method,path:u.pathname,key,body,query:u.search.slice(1),actorId:portal?c.ownerId:r.consoleAdministrator?.user?.id,clusterId:f.clusterId,workspaceId:f.workspaceId,state:'before-single-send',source:'browser-remaining',continuation:'tail-only',startedAt:new Date().toISOString()};
 if(!uuid(attempt.actorId)||r.browserTail?.phase!=='tail-actions-started')throw new Error('Browser tail actor/checkpoint is not ready');
 r.writeAttempts.push(attempt);persist();sent.set(counter,1);return attempt;
}

/** A transport interruption is never evidence of rollback. Lock the whole tail
 * synchronously and retain its original attempt before any later packet. */
export function markTailInterrupted(r,request,persist){
 if(['GET','HEAD','OPTIONS'].includes(request.method()))return false;
 const u=new URL(request.url()),key=request.headers()['x-idempotency-key'];
 const attempt=(r.writeAttempts??[]).findLast(a=>a.continuation==='tail-only'&&a.key===key&&a.method===request.method()&&a.path===u.pathname);
 if(attempt){attempt.state='response-uncertain';attempt.transportInterrupted=true;}
 if(!r.browserTail)throw new Error('Browser tail interruption has no durable checkpoint');
 r.browserTail.phase='stopped-without-replay';r.browserTail.packetGuardClass='InterruptedTailWrite';persist();return true;
}
