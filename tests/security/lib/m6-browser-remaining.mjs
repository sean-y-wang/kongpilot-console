import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';

export const FIRST_BROWSER_FAILURE_SHA='32d764adf1a66bf4f152b7873c9eba688ecfbf830ce5371188a43ad50f2931f1';
export const FIRST_BROWSER_LOGIN_REQUEST='6c4af633-12f7-4c5a-a6c7-28bf1dee1f55';
export const FIRST_BROWSER_LOGIN_IAT=Date.parse('2026-10-11T01:20:07.000Z')/1000;
export const browserSha=value=>createHash('sha256').update(typeof value==='string'||Buffer.isBuffer(value)?value:JSON.stringify(value)).digest('hex');
const uuid=value=>typeof value==='string'&&/^[a-f\d]{8}-[a-f\d]{4}-[1-8][a-f\d]{3}-[89ab][a-f\d]{3}-[a-f\d]{12}$/i.test(value);

export function browserRemainingCheckpoint(reference,live,failureBytes){
 const failure=JSON.parse(failureBytes),writes=reference.browserWriteEvidence,owner=reference.portalUsers?.find(v=>v.label==='developer-a'),f=live.fixturesForBrowser,target=reference.portalTestTargets?.primary;
 const valid=browserSha(failureBytes)===FIRST_BROWSER_FAILURE_SHA&&failure.failed===1&&failure.passed===0&&failure.stage==='existing-application-masked-credential'&&failure.line===83&&failure.explicitRevealStarted===false&&failure.newApplicationRecorded===false&&failure.newApplicationOriginalKeyRecorded===false&&failure.newWorkflowRecorded===false&&
  failure.capturedSuccessfulWrites?.length===1&&failure.capturedSuccessfulWrites[0].requestId===FIRST_BROWSER_LOGIN_REQUEST&&writes?.length===1&&writes[0].requestId===FIRST_BROWSER_LOGIN_REQUEST&&writes[0].method==='POST'&&writes[0].path==='/api/v1/portal/auth/login'&&
  live.failed===0&&live.passed===1057&&live.auditCoverage?.distinctRequestIds===145&&live.auditCoverage.auditedRequestIds===145&&reference.phase==='HTTP-complete'&&reference.testTag===live.testTag&&
  !reference.browserRemaining&&!reference.browserApplication&&!reference.browserUnknown&&!reference.browserWorkflowId&&owner&&uuid(owner.id)&&f&&uuid(f.applicationId)&&uuid(f.activeGrantId)&&uuid(f.activeCredentialId)&&owner.tenant?.clusterId===f.clusterId&&owner.tenant?.workspaceId===f.workspaceId&&
  target?.id===f.clusterId&&target.adminUrl==='http://kong-portal-admin-endpoint:8001'&&target.proxyOrigin==='http://127.0.0.1:10000'&&reference.fixtures[0].workspace.id===f.workspaceId&&reference.browser.activeGrantId===f.activeGrantId&&reference.browser.activeCredentialId===f.activeCredentialId&&
  reference.grants.some(v=>v.grant.id===f.activeGrantId&&v.credential.id===f.activeCredentialId)&&reference.abandonmentAcknowledgment?.totalFormalPosts===2&&reference.abandonmentAcknowledgment.phase==='certificate-verified';
 if(!valid)throw new Error('Browser remaining requires the immutable first stop and exact untouched successful-login checkpoint');
 const candidates=[...new Set((reference.secrets??[]).filter(v=>typeof v==='string'&&v.length))];
 if(candidates.length>4096||JSON.stringify(candidates).length>4*1024*1024)throw new Error('Browser cookie recovery candidate budget exceeded');
 return{fixture:f,ownerId:owner.id,candidates,expected:{ownerId:owner.id,clusterId:f.clusterId,workspaceId:f.workspaceId,loginRequestId:FIRST_BROWSER_LOGIN_REQUEST,issuedAt:FIRST_BROWSER_LOGIN_IAT},before:{failureSha256:FIRST_BROWSER_FAILURE_SHA,referenceSha256:browserSha(reference),writeAttemptsSha256:browserSha(reference.writeAttempts),writeEvidenceSha256:browserSha(reference.writeEvidence),browserWritesSha256:browserSha(writes),grantsSha256:browserSha(reference.grants)}};
}

export const BROWSER_COOKIE_SESSION_SQL=`SELECT s.id,s.refresh_token_hash,s.csrf_token_hash,s.expires_at,s.credential_epoch,
 EXISTS(SELECT 1 FROM audit_events a WHERE a.request_id=$5 AND a.action='portal.login' AND a.result='success'
   AND a.actor_type='developer' AND a.entity_id=d.id::text AND a.cluster_id=s.cluster_id AND a.workspace_id=s.workspace_id
   AND a.occurred_at BETWEEN s.created_at-interval '2 seconds' AND s.created_at+interval '5 seconds') AS original_login_audited
 FROM portal_sessions s JOIN portal_developers d ON d.cluster_id=s.cluster_id AND d.workspace_id=s.workspace_id AND d.id=s.developer_id
 JOIN portal_settings p ON p.cluster_id=s.cluster_id AND p.workspace_id=s.workspace_id
 JOIN workspaces w ON w.cluster_id=s.cluster_id AND w.id=s.workspace_id JOIN clusters c ON c.id=s.cluster_id
 WHERE s.id=$1 AND s.developer_id=$2 AND s.cluster_id=$3 AND s.workspace_id=$4 AND s.revoked_at IS NULL AND s.expires_at>now()
 AND d.status='active' AND d.deleted_at IS NULL AND d.credential_epoch=s.credential_epoch AND p.status='active' AND p.published=true AND p.deleted_at IS NULL
 AND w.status='active' AND w.deleted_at IS NULL AND c.status<>'disabled' AND c.deleted_at IS NULL`;

// Raw candidates enter only STDIN and remain in API process RAM. Output contains
// candidate indices, session identity and booleans, never a token/hash/query row.
export const BROWSER_COOKIE_READER_PROGRAM=`const pg=require('pg'),jwt=require('jsonwebtoken'),{createHash}=require('node:crypto');let input='';process.stdin.on('data',v=>{input+=v;if(Buffer.byteLength(input)>4*1024*1024)process.exitCode=2;});process.stdin.on('end',async()=>{let pool,client;try{if(process.exitCode)throw Error();const q=JSON.parse(input),e=q.expected,t=q.candidates;if(!Array.isArray(t)||t.length>4096||t.some(v=>typeof v!=='string'||v.length>16384)||!e||!Number.isSafeInteger(e.issuedAt))throw Error();const matches=[];for(let i=0;i<t.length;i++){try{const c=jwt.verify(t[i],process.env.PORTAL_SECRET,{algorithms:['HS256'],issuer:'kongos-portal',audience:'kongos-portal',ignoreExpiration:true});if(c.kind==='portal_developer'&&c.sub===e.ownerId&&c.cid===e.clusterId&&c.wid===e.workspaceId&&c.iat===e.issuedAt&&Number.isSafeInteger(c.credential_epoch)&&c.exp===c.iat+900&&typeof c.sid==='string')matches.push({i,c});}catch{}}if(matches.length!==1)throw Error();const access=matches[0];pool=new pg.Pool({connectionString:process.env.DATABASE_URL??process.env.CONSOLE_DATABASE_URL});client=await pool.connect();await client.query('BEGIN READ ONLY');const rows=(await client.query(${JSON.stringify(BROWSER_COOKIE_SESSION_SQL)},[access.c.sid,e.ownerId,e.clusterId,e.workspaceId,e.loginRequestId])).rows;await client.query('ROLLBACK');if(rows.length!==1||rows[0].original_login_audited!==true||Number(rows[0].credential_epoch)!==access.c.credential_epoch)throw Error();const row=rows[0],hash=s=>createHash('sha256').update(s).digest('hex'),refresh=[],csrf=[];for(let i=0;i<t.length;i++){const parts=t[i].split('.');if(parts.length===2&&parts[0]===row.id&&/^[A-Za-z0-9_-]{43,128}$/.test(parts[1])&&hash(parts[1])===row.refresh_token_hash)refresh.push(i);if(/^[A-Za-z0-9_-]{43,128}$/.test(t[i])&&hash(t[i])===row.csrf_token_hash)csrf.push(i);}if(refresh.length!==1||csrf.length!==1)throw Error();process.stdout.write(JSON.stringify({accessIndex:access.i,refreshIndex:refresh[0],csrfIndex:csrf[0],sessionId:row.id,expiresAt:new Date(row.expires_at).toISOString(),credentialEpoch:access.c.credential_epoch,accessExpired:access.c.exp<=Date.now()/1000,originalLoginAudited:true,currentSessionVerified:true}));}catch{if(client)await client.query('ROLLBACK').catch(()=>{});process.exitCode=2;}finally{client?.release();await pool?.end();}});`;

export function readOriginalBrowserCookies(context,execute=execFileSync){
 try{return JSON.parse(execute('docker',['compose','exec','-T','console-api','node','-e',BROWSER_COOKIE_READER_PROGRAM],{input:JSON.stringify({expected:context.expected,candidates:context.candidates}),encoding:'utf8',stdio:['pipe','pipe','pipe'],maxBuffer:1024*1024}));}
 catch{throw new Error('Original browser cookie recovery failed; private diagnostics withheld');}
}
export function originalCookieJar(context,proof){
 const names=['kongos_portal_access','kongos_portal_refresh','kongos_portal_csrf'],indices=[proof?.accessIndex,proof?.refreshIndex,proof?.csrfIndex];
 if(proof?.originalLoginAudited!==true||proof.currentSessionVerified!==true||!uuid(proof.sessionId)||!Number.isSafeInteger(proof.credentialEpoch)||proof.credentialEpoch<1||!Number.isFinite(Date.parse(proof.expiresAt))||Date.parse(proof.expiresAt)<=Date.now()||indices.some(i=>!Number.isInteger(i)||i<0||i>=context.candidates.length)||new Set(indices).size!==3)throw new Error('Original browser cookie proof is incomplete or ambiguous');
 const values=indices.map(i=>context.candidates[i]),claim=JSON.parse(Buffer.from(values[0].split('.')[1],'base64url'));
 if(claim.sid!==proof.sessionId||claim.sub!==context.expected.ownerId||claim.cid!==context.expected.clusterId||claim.wid!==context.expected.workspaceId||claim.iat!==context.expected.issuedAt||values[1].split('.')[0]!==proof.sessionId)throw new Error('Original browser cookie identity changed');
 return names.map((name,i)=>({name,value:values[i],domain:'127.0.0.1',path:'/api/v1/portal',httpOnly:true,secure:false,sameSite:'Strict'}));
}

/** The durable callback runs before the caller may continue/fetch the packet.
 * Every remaining endpoint has one packet budget, with the two independently
 * authorized refresh occasions sharing the original session. */
export function journalBrowserMutation(reference,request,context,sent,persist){
 const url=new URL(request.url()),method=request.method(),headers=request.headers(),f=context.fixture;
 const portal=url.origin==='http://127.0.0.1:8082',console=url.origin==='http://127.0.0.1:8080';
 const portalAllowed=portal&&['/api/v1/portal/auth/refresh','/api/v1/portal/applications','/api/v1/portal/requests',`/api/v1/portal/applications/${f.applicationId}/grants/${f.activeGrantId}/credentials/${f.activeCredentialId}/reveal`].includes(url.pathname);
 const consoleAllowed=console&&(url.pathname==='/api/v1/auth/login'||uuid(reference.browserWorkflowId)&&['approve','execute'].some(action=>url.pathname===`/api/v1/clusters/${f.clusterId}/workflows/${reference.browserWorkflowId}/${action}`));
 const key=headers['x-idempotency-key'],counter=method+':'+url.pathname,count=(sent.get(counter)??0)+1,max=url.pathname==='/api/v1/portal/auth/refresh'?(context.accessExpired?2:1):1;
 if(method!=='POST'||!(portalAllowed||consoleAllowed)||!uuid(key)||count>max||reference.browserRemaining?.phase==='stopped-without-replay')throw new Error('Browser mutation is outside the untouched remaining flow');
 const body=request.postDataJSON();
 if(portal&&(body?.clusterId!==f.clusterId||body?.workspaceId!==f.workspaceId))throw new Error('Browser mutation tenant changed');
 if(url.pathname==='/api/v1/portal/requests'&&reference.browserUnknown?.state!=='succeeded-original-key-receipt')throw new Error('Interrupted browser application must be verified before any new intent');
 if(url.pathname==='/api/v1/portal/requests'&&(!uuid(reference.browserApplication?.id)||body?.applicationId!==reference.browserApplication.id||body?.publicationId!==f.publicationId))throw new Error('Browser request is not the genuinely new browser application');
 if((reference.writeAttempts??[]).some(a=>a.key===key))throw new Error('Browser mutation cannot reuse any completed or unknown original key');
 const actorId=portal?context.ownerId:reference.consoleAdministrator?.user?.id;
 if(!uuid(actorId))throw new Error('Browser mutation actor is not the original current identity');
 const attempt={method,path:url.pathname,key,body,query:url.search.slice(1),actorId,clusterId:f.clusterId,workspaceId:f.workspaceId,state:'before-single-send',source:'browser-remaining',startedAt:new Date().toISOString()};
 reference.writeAttempts.push(attempt);reference.browserRemaining.phase='remaining-actions-started';persist();sent.set(counter,count);return attempt;
}
export function proveRemainingApplicationReceipt(reference,receipt,fixture){
 const saved=reference.browserUnknown,app=reference.browserApplication;
 if(!saved||!uuid(saved.key)||saved.clusterId!==fixture.clusterId||saved.workspaceId!==fixture.workspaceId||saved.actorId!==reference.portalUsers.find(v=>v.label==='developer-a')?.id||!app?.id||receipt?.clusterId!==fixture.clusterId||receipt.workspaceId!==fixture.workspaceId||receipt.state!=='succeeded'||receipt.remoteCompleted!==true||receipt.module!=='applications'||receipt.action!=='create'||receipt.safeResult?.entity?.id!==app.id)throw new Error('Interrupted browser application is not terminal on its original receipt');
 saved.state='succeeded-original-key-receipt';saved.operationId=receipt.id;return saved;
}
