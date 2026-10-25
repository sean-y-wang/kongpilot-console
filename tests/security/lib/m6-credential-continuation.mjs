import {randomUUID} from 'node:crypto';
import {M6_C1,M6_C2,cookieMerge,entity,portalScope,scope} from './m6-harness.mjs';
import {originalConsoleSession} from './m6-publication-continuation.mjs';
import {canonical} from './m4-harness.mjs';

const cookieValue=(cookie,name)=>cookie.split('; ').find(pair=>pair.startsWith(`${name}=`))?.slice(name.length+1);
export async function originalPortalSession(h,developer){
  const session=developer.session,tenant=developer.tenant;
  let response=await h.portal(session,portalScope('/auth/me',tenant));
  if(response.status===401){
    const oldSid=cookieValue(session.cookie,'kongos_portal_refresh')?.split('.')[0],oldCookie=session.cookie;
    h.check(/^[\da-f-]{36}$/.test(oldSid??''),'CredentialContinuation/Refresh','original portal refresh session UUID is retained');
    const csrf=h.ok(await h.portal(session,portalScope('/auth/csrf',tenant)),'CredentialContinuation/Refresh','same tenant supplies valid original-session CSRF');
    h.check(typeof csrf.csrfToken==='string'&&csrf.csrfToken.length>=16,'CredentialContinuation/Refresh','portal refresh CSRF is present');
    session.csrf=csrf.csrfToken;
    h.saveReference({originalPortalRefreshes:[...(h.referenceData.originalPortalRefreshes??[]),{actorId:developer.id,tenant,sessionId:oldSid,previousCookie:oldCookie,phase:'before-single-refresh',startedAt:new Date().toISOString()}]});
    const refreshed=await h.portal(session,'/auth/refresh','POST',tenant);
    const value=h.ok(refreshed,'CredentialContinuation/Refresh','one standard refresh renews the original developer session');
    const nextCookie=cookieMerge(session.cookie,refreshed.response.headers.getSetCookie()),nextSid=cookieValue(nextCookie,'kongos_portal_refresh')?.split('.')[0];
    let jwtSid;try{jwtSid=JSON.parse(Buffer.from(cookieValue(nextCookie,'kongos_portal_access').split('.')[1],'base64url').toString()).sid;}catch{jwtSid=undefined;}
    h.check(value.developer?.id===developer.id&&value.developer.clusterId===tenant.clusterId&&value.developer.workspaceId===tenant.workspaceId&&oldSid===nextSid&&jwtSid===oldSid,'CredentialContinuation/Refresh','refresh keeps exact developer, tenant and original server SID');
    h.check(typeof value.csrfToken==='string'&&value.csrfToken.length>=16,'CredentialContinuation/Refresh','refreshed portal CSRF is valid before the next write');
    session.cookie=nextCookie;session.developer=value.developer;session.csrf=value.csrfToken;h.rememberCookies(nextCookie);h.secrets?.push(value.csrfToken);h.saveReference();
    response=await h.portal(session,portalScope('/auth/me',tenant));
  }
  const me=h.ok(response,'CredentialContinuation/Actor','original developer session is currently authenticated');
  h.check(me.id===developer.id&&me.clusterId===tenant.clusterId&&me.workspaceId===tenant.workspaceId,'CredentialContinuation/Actor','current developer UUID and tenant are unchanged');
  return session;
}
export function credentialContinuationCheckpoint(reference,diagnostic=reference.isolatedPublicationRequestFailure){
  const primary=reference.fixtures?.[0],secondary=reference.fixtures?.[1],otherFixture=reference.fixtures?.[2],failure=diagnostic;
  const owned=new Set((reference.fixtures??[]).map(row=>`${row.cluster.id}:${row.workspace.id}`));
  const attempts=(reference.writeAttempts??[]).filter(row=>row.path==='/api/v1/portal/requests'&&owned.has(`${row.body?.clusterId}:${row.body?.workspaceId}`));
  const attempt=attempts[0];
  const developer=reference.portalUsers?.find(row=>row.label==='developer-a'&&row.tenant.clusterId===primary?.cluster.id&&row.tenant.workspaceId===primary?.workspace.id);
  const other=reference.portalUsers?.find(row=>row.label==='developer-b'&&row.tenant.clusterId===primary?.cluster.id&&row.tenant.workspaceId===primary?.workspace.id);
  const c2Developer=reference.portalUsers?.find(row=>row.label==='developer-c2'&&row.tenant.clusterId===secondary?.cluster.id&&row.tenant.workspaceId===secondary?.workspace.id);
  const appAttempt=reference.writeAttempts?.find(row=>row.path==='/api/v1/portal/applications'&&row.actorId===developer?.id&&row.body?.name===`${reference.testTag} Application A`&&row.state==='response_observed'&&row.httpStatus===201);
  const c2Attempt=reference.writeAttempts?.find(row=>row.path==='/api/v1/portal/applications'&&row.actorId===c2Developer?.id&&row.body?.name===`${reference.testTag} Application C2`&&row.state==='response_observed'&&row.httpStatus===201);
  const app=entity(appAttempt?.responseData),c2App=entity(c2Attempt?.responseData);
  const proof=failure?.currentProofComparison,facts=failure?.facts?.[0];
  const tokens=reference.tokens??[],purposes={native_scrape:'bff',collector_catalog:'bff',collector_scrape:'collector',collector_ingest:'collector'};
  const materialValid=tokens.length===8&&new Set(tokens.map(row=>row.token)).size===8&&[[M6_C1,2],[M6_C2,1]].every(([cid,generation])=>Object.entries(purposes).every(([purpose,audience])=>tokens.filter(row=>row.clusterId===cid&&row.generation===generation&&row.purpose===purpose&&row.audience===audience&&typeof row.token==='string'&&/^[A-Za-z0-9_-]{43,128}$/.test(row.token)).length===1));
  const valid=reference.phase==='portal-publications-published'&&reference.isolatedStart&&!(reference.grants?.length)&&!reference.credentialContinuation&&reference.portalUsers?.length===3&&
    reference.portalTestTargets?.primary.id===primary?.cluster.id&&primary.cluster.id!==M6_C1&&primary.cluster.id!==M6_C2&&secondary.cluster.id===M6_C2&&owned.size===3&&
    reference.portalTestTargets.primary.adminUrl==='http://kong-portal-admin-endpoint:8001'&&reference.portalTestTargets.primary.proxyOrigin==='http://127.0.0.1:10000'&&reference.portalTestTargets.secondary.id===M6_C2&&reference.portalTestTargets.secondary.proxyOrigin==='http://127.0.0.1:9000'&&materialValid&&
    reference.consoleAdministrator?.user?.id&&reference.accounts?.['approver-only']?.session&&reference.accounts?.['approver-c2']?.session&&developer&&other&&c2Developer&&app?.id&&c2App?.id&&
    attempts.length===1&&attempt.state==='response_observed'&&attempt.httpStatus===409&&attempt.errorCode==='PORTAL_PUBLICATION_REVALIDATION_REQUIRED'&&attempt.actorId===developer.id&&
    attempt.key===failure?.originalRequest?.key&&attempt.key===reference.isolatedPublicationRequestFailure?.originalRequest?.key&&attempt.requestId===failure.originalRequest.requestId&&attempt.body.applicationId===app.id&&attempt.body.publicationId===primary.publications?.[0]?.id&&
    Object.keys(attempt.body).sort().join(',')==='applicationId,clusterId,publicationId,reason,workspaceId'&&attempt.body.clusterId===primary.cluster.id&&attempt.body.workspaceId===primary.workspace.id&&
    failure.originalReceipt.status===200&&failure.originalReceipt.state==='failed'&&failure.originalReceipt.safeResultKeys?.length===0&&facts?.grants===0&&facts.credentials===0&&facts.unresolved===0&&
    proof?.effectiveComputedMatchesPublishedProof===true&&proof.publicationMatchesPublishedProof===true&&proof.clusterRevisionMatches===true&&proof.workspaceRevisionMatches===true&&proof.workspaceActive===true;
  if(!valid)throw new Error('M6 credential continuation requires the exact known failed DB-only checkpoint');
  return{admin:reference.consoleAdministrator,fixtures:reference.fixtures,primary,secondary,otherFixture,approver:reference.accounts['approver-only'],secondaryApprover:reference.accounts['approver-c2'],developer,other,c2Developer,app,c2App,attempt};
}
const nativeComparable=value=>canonical(Object.fromEntries(Object.entries(value).filter(([key])=>!key.startsWith('console_')&&!key.startsWith('_console'))));
export async function guardCredentialContinuation(h,diagnostic){
  h.requireLive();const p=h.referenceData,state=credentialContinuationCheckpoint(p,diagnostic);
  await originalConsoleSession(h,state.admin);await originalConsoleSession(h,state.approver.session);await originalConsoleSession(h,state.secondaryApprover.session);
  for(const developer of[state.developer,state.other,state.c2Developer])await originalPortalSession(h,developer);
  for(const f of state.fixtures){
    const read=async path=>h.ok(await h.request(state.admin,scope(`/clusters/${f.cluster.id}/${path}`,f.workspace)),'CredentialContinuation/Current','read-only current owned fixture proof');
    const workspace=h.ok(await h.request(state.admin,`/clusters/${f.cluster.id}/workspaces/${f.workspace.id}`),'CredentialContinuation/Scope','original workspace metadata');
    h.check(workspace.id===f.workspace.id&&workspace.code===f.workspace.code&&workspace.revision===f.workspace.revision&&workspace.status==='active','CredentialContinuation/Scope','original workspace identity/revision remain unchanged');
    const settings=(await read('portal/settings')).settings;h.check(settings.id===f.settings.id&&settings.revision===f.settings.revision&&settings.published===true,'CredentialContinuation/Settings','tenant settings remain at their original published revision');
    for(const type of['services','routes'])for(const saved of f[type]){const actual=entity(await read(`entities/${type}/${saved.id}`));h.check(JSON.stringify(nativeComparable(actual))===JSON.stringify(nativeComparable(saved)),'CredentialContinuation/Native','saved native configuration has not changed');}
    for(const saved of f.publications){const actual=entity(await read(`portal/publications/${saved.id}`));h.check(actual.id===saved.id&&actual.serviceId===saved.serviceId&&actual.revision===saved.revision&&actual.documentRevision===saved.documentRevision&&actual.status==='published','CredentialContinuation/Publication','all original publication proofs remain published and unchanged');}
  }
  const receipt=h.ok(await h.portal(state.developer.session,portalScope(`/operations/by-key/${state.attempt.key}`,state.developer.tenant)),'CredentialContinuation/Receipt','original failed request remains its own terminal receipt');
  h.check(receipt.state==='failed'&&receipt.errorCode==='PORTAL_PUBLICATION_REVALIDATION_REQUIRED'&&Object.keys(receipt.safeResult??{}).length===0,'CredentialContinuation/Receipt','old key remains failed, with no submitted workflow result');
  const wids=state.fixtures.map(row=>row.workspace.id),cids=[M6_C1,M6_C2,state.primary.cluster.id];
  const counts=h.consoleRead(`SELECT(SELECT count(*)::int FROM portal_application_grants WHERE workspace_id=ANY($1::uuid[]))AS grants,(SELECT count(*)::int FROM portal_credentials WHERE workspace_id=ANY($1::uuid[]))AS credentials,(SELECT count(*)::int FROM workflows WHERE requester_developer_id=ANY($2::uuid[]))AS developer_workflows,(SELECT count(*)::int FROM mutation_operations WHERE cluster_id=ANY($3::uuid[])AND state IN('running','uncertain'))AS native_unresolved,(SELECT count(*)::int FROM portal_operations WHERE workspace_id=ANY($1::uuid[])AND state IN('running','uncertain'))AS portal_unresolved`,[wids,[state.developer.id,state.other.id,state.c2Developer.id],cids])[0];
  const original=h.consoleRead('SELECT state,error_code,workflow_id,result_secret IS NULL AS no_result,safe_result,remote_started,remote_completed FROM portal_operations WHERE developer_id=$1 AND idempotency_key=$2',[state.developer.id,state.attempt.key]);
  h.check(Object.values(counts??{}).length===5&&Object.values(counts).every(value=>value===0)&&original.length===1&&original[0].state==='failed'&&original[0].error_code==='PORTAL_PUBLICATION_REVALIDATION_REQUIRED'&&original[0].workflow_id===null&&original[0].no_result===true&&Object.keys(original[0].safe_result).length===0,'CredentialContinuation/ZeroEffect','fresh independent DB proof confirms no issued, submitted or unresolved effect; terminal DB receipt is distinct from native completion');
  const plugins=p.writeAttempts.filter(row=>row.path===`/api/v1/clusters/${state.primary.cluster.id}/entities/plugins`&&new URLSearchParams(row.query).get('workspaceId')===state.primary.workspace.id&&row.state==='response_observed'&&row.httpStatus===201).map(row=>entity(row.responseData));
  const legacyKeyAuth=plugins.find(row=>row.name==='key-auth'),legacyAcl=plugins.find(row=>row.name==='acl');
  h.check(Boolean(legacyKeyAuth&&legacyAcl),'CredentialContinuation/Legacy','original independent legacy key-auth and ACL IDs are captured');
  for(const saved of[legacyKeyAuth,legacyAcl]){const actual=entity(h.ok(await h.request(state.admin,scope(`/clusters/${state.primary.cluster.id}/entities/plugins/${saved.id}`,state.primary.workspace)),'CredentialContinuation/Native','read-only legacy plugin proof'));h.check(JSON.stringify(nativeComparable(actual))===JSON.stringify(nativeComparable(saved)),'CredentialContinuation/Native','legacy plugin configuration is unchanged');}
  for(const[developer,app]of[[state.developer,state.app],[state.c2Developer,state.c2App]]){const actual=entity(h.ok(await h.portal(developer.session,portalScope(`/applications/${app.id}`,developer.tenant)),'CredentialContinuation/Application','original owned application still exists'));h.check(actual.id===app.id&&actual.revision===app.revision&&actual.name===app.name,'CredentialContinuation/Application','existing application identity and revision are unchanged');}
  const initialRequest={key:randomUUID(),body:structuredClone(state.attempt.body)};
  h.check(!p.writeAttempts.some(row=>row.key===initialRequest.key),'CredentialContinuation/Key','explicit remediation uses one fresh key while the failed key remains immutable');
  h.saveReference({credentialContinuation:{phase:'before-single-new-request',originalFailedKey:state.attempt.key,newKey:initialRequest.key,body:initialRequest.body,counts,originalReceiptState:receipt.state,guardedAt:new Date().toISOString()}});
  return{...state,legacyKeyAuth,legacyAcl,initialRequest};
}
