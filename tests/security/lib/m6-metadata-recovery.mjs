import {M6_C1,M6_C2,entity,scope} from './m6-harness.mjs';
import {canonical} from './m4-harness.mjs';
import {originalConsoleSession} from './m6-publication-continuation.mjs';
import {originalPortalSession} from './m6-credential-continuation.mjs';
import {PENDING_KEY_TUPLE as T,pendingReferenceGuard} from './m6-pending-key-capture.mjs';

const nativeComparable=value=>canonical(Object.fromEntries(Object.entries(value).filter(([key])=>!key.startsWith('console_')&&!key.startsWith('_console'))));
const receiptPath=()=>scope(`/clusters/${T.clusterId}/workflows/receipts/by-key/${T.executionKey}`,T.workspaceId);
const viewPath=()=>scope(`/clusters/${T.clusterId}/workflows/${T.workflowId}`,T.workspaceId);
const opIds=[T.consumerOperationId,T.aclOperationId,T.keyOperationId];
const tupleIds=[T.consumerId,T.aclId,T.nativeId];
const sessionId=(cookie,portal=false)=>cookie?.split('; ').find(p=>p.startsWith(portal?'kongos_portal_refresh=':'kongos_refresh='))?.split('=')[1]?.split('.')[0];

export function metadataRecoveryCheckpoint(reference,diagnostic=reference.credentialExecutionFailure){
  pendingReferenceGuard(reference);
  const primary=reference.fixtures?.[0],secondary=reference.fixtures?.[1],otherFixture=reference.fixtures?.[2],admin=reference.consoleAdministrator;
  const developer=reference.portalUsers?.find(p=>p.label==='developer-a'&&p.tenant.clusterId===T.clusterId&&p.tenant.workspaceId===T.workspaceId);
  const other=reference.portalUsers?.find(p=>p.label==='developer-b'&&p.tenant.clusterId===T.clusterId&&p.tenant.workspaceId===T.workspaceId);
  const c2Developer=reference.portalUsers?.find(p=>p.label==='developer-c2'&&p.tenant.clusterId===M6_C2&&p.tenant.workspaceId===secondary?.workspace.id);
  const appAttempt=reference.writeAttempts?.find(a=>a.path==='/api/v1/portal/applications'&&a.actorId===developer?.id&&a.body?.name===`${reference.testTag} Application A`&&a.httpStatus===201);
  const c2AppAttempt=reference.writeAttempts?.find(a=>a.path==='/api/v1/portal/applications'&&a.actorId===c2Developer?.id&&a.body?.name===`${reference.testTag} Application C2`&&a.httpStatus===201);
  const app=entity(appAttempt?.responseData),c2App=entity(c2AppAttempt?.responseData),executeAttempt=reference.writeAttempts.find(a=>a.key===T.executionKey&&a.path.endsWith(`/workflows/${T.workflowId}/execute`));
  const request=reference.writeAttempts.find(a=>a.path==='/api/v1/portal/requests'&&a.httpStatus===201&&a.responseData?.workflowId===T.workflowId&&a.responseData?.grant?.id===T.grantId);
  const scopedPlugins=reference.writeAttempts.filter(a=>a.path===`/api/v1/clusters/${T.clusterId}/entities/plugins`&&new URLSearchParams(a.query).get('workspaceId')===T.workspaceId&&a.httpStatus===201).map(a=>entity(a.responseData));
  const legacyKeyAuth=scopedPlugins.find(p=>p.name==='key-auth'),legacyAcl=scopedPlugins.find(p=>p.name==='acl');
  const tokens=reference.tokens??[],purposes={native_scrape:'bff',collector_scrape:'collector',collector_catalog:'bff',collector_ingest:'collector'};
  const materials=tokens.length===8&&new Set(tokens.map(t=>t.token)).size===8&&[[M6_C1,2],[M6_C2,1]].every(([cid,generation])=>Object.entries(purposes).every(([purpose,audience])=>tokens.filter(t=>t.clusterId===cid&&t.generation===generation&&t.purpose===purpose&&t.audience===audience&&typeof t.token==='string'&&/^[A-Za-z0-9_-]{43,128}$/.test(t.token)).length===1));
  const capture=reference.pendingCredentialScanCaptures?.find(c=>c.credentialId===T.credentialId&&c.executionId===T.executionId&&c.scannerOnly===true);
  const proof=diagnostic?.originalExecution;
  const valid=reference.phase==='portal-publications-published'&&reference.isolatedStart&&reference.priorFixtureRuns?.length>0&&!reference.metadataRecovery&&!(reference.grants?.length)&&primary?.cluster.id===T.clusterId&&primary.workspace.id===T.workspaceId&&secondary?.cluster.id===M6_C2&&otherFixture?.cluster.id===T.clusterId&&reference.fixtures.length===3&&
    reference.portalTestTargets?.primary.adminUrl==='http://kong-portal-admin-endpoint:8001'&&reference.portalTestTargets.primary.proxyOrigin==='http://127.0.0.1:10000'&&reference.portalTestTargets.secondary.proxyOrigin==='http://127.0.0.1:9000'&&materials&&
    developer&&other&&c2Developer&&app?.id&&c2App?.id&&admin?.user.id===executeAttempt.actorId&&reference.accounts?.['approver-only']?.session&&reference.accounts?.['approver-c2']?.session&&legacyKeyAuth&&legacyAcl&&capture&&
    request?.actorId===developer.id&&request.body.applicationId===app.id&&request.body.publicationId===primary.publications[0].id&&request.body.clusterId===T.clusterId&&request.body.workspaceId===T.workspaceId&&
    reference.credentialContinuation?.newKey===request.key&&reference.credentialContinuation.body.applicationId===app.id&&executeAttempt.body?.confirm_name==='portal-credential-issue'&&executeAttempt.body.confirmed===true&&/^[a-f0-9]{64}$/.test(executeAttempt.body.planHash)&&
    proof?.key===T.executionKey&&proof.workflowId===T.workflowId&&proof.clusterId===T.clusterId&&proof.workspaceId===T.workspaceId&&proof.status===503&&proof.errorCode==='WORKFLOW_EXECUTION_FAILED'&&diagnostic.receipt?.state==='uncertain'&&diagnostic.receipt.executionId===T.executionId&&
    diagnostic.native?.length===3&&diagnostic.native.every((n,index)=>n.id===opIds[index]&&n.entity_id===tupleIds[index]&&n.state==='succeeded'&&n.remote_completed===true)&&diagnostic.grant?.[0]?.id===T.grantId&&diagnostic.grant[0].credential_id===T.credentialId&&diagnostic.grant[0].credential_state==='pending';
  if(!valid)throw new Error('M6 metadata recovery requires the exact original uncertain execution checkpoint');
  return{admin,fixtures:reference.fixtures,primary,secondary,otherFixture,developer,other,c2Developer,app,c2App,approver:reference.accounts['approver-only'],secondaryApprover:reference.accounts['approver-c2'],legacyKeyAuth,legacyAcl,executeAttempt,request};
}

export function assertRecoveryReceipt(h,receipt,state){
  h.check(receipt?.executionId===T.executionId&&receipt.workflowId===T.workflowId&&receipt.state===state&&receipt.steps?.length===4,'MetadataRecovery/Receipt','original receipt identifies the same execution and complete four-step plan');
  for(let index=0;index<3;index++)h.check(receipt.steps[index].state==='succeeded'&&receipt.steps[index].operationId===opIds[index]&&receipt.steps[index].remoteCompleted===true,'MetadataRecovery/Native','all three original native receipts retain their successful operation IDs');
  const last=receipt.steps[3];h.check(last.id===T.metadataStepId&&last.name==='portal.credential.activate'&&last.state===state&&last.operationId===null&&last.remoteCompleted===(state==='succeeded'),'MetadataRecovery/Metadata','only the original final metadata step changes outcome');
}

// pg_catalog.sha256(bytea) is built into PostgreSQL 16. pgcrypto's optional
// digest() is deliberately not required, and ciphertext never leaves the DB.
export const METADATA_RECOVERY_DATABASE_SQL=`SELECT c.id,c.state AS credential_state,c.generation,c.consumer_id,c.kong_id,c.credential_ref_id,c.issue_operation_id,c.key_fingerprint,encode(sha256(convert_to(c.key_secret,'UTF8')),'hex') AS immutable_key_cipher_sha,g.id AS grant_id,g.state AS grant_state,g.current_generation,g.current_credential_id,g.acl_credential_ref_id,w.state AS workflow_state,w.plan_hash,w.revision AS workflow_revision,e.id AS execution_id,e.state AS execution_state,e.execution_actor_id,e.idempotency_key,
    (SELECT count(*)::int FROM mutation_operations WHERE workflow_execution_id=e.id) AS native_operation_count,
    (SELECT count(*)::int FROM mutation_operations WHERE cluster_id=ANY($5::uuid[])AND state IN('running','uncertain')) AS native_unresolved,
    (SELECT count(*)::int FROM portal_operations WHERE workspace_id=ANY($6::uuid[])AND state IN('running','uncertain')) AS portal_unresolved
    FROM portal_credentials c JOIN portal_application_grants g ON g.id=c.grant_id JOIN workflows w ON w.id=c.workflow_id JOIN workflow_executions e ON e.workflow_id=w.id AND e.plan_revision=w.plan_revision AND e.plan_hash=w.plan_hash
    WHERE c.id=$1 AND c.grant_id=$2 AND c.cluster_id=$3 AND c.workspace_id=$4 AND e.id=$7 AND e.idempotency_key=$8`;
function databaseProof(h){
  const rows=h.consoleRead(METADATA_RECOVERY_DATABASE_SQL,[T.credentialId,T.grantId,T.clusterId,T.workspaceId,[M6_C1,M6_C2,T.clusterId],h.referenceData.fixtures.map(f=>f.workspace.id),T.executionId,T.executionKey]);
  h.check(rows.length===1,'MetadataRecovery/Database','one exact pending credential/grant/original execution tuple exists');return rows[0];
}

export async function guardMetadataRecovery(h,diagnostic){
  h.requireLive();const state=metadataRecoveryCheckpoint(h.referenceData,diagnostic);
  const sessions=[[state.admin,false],[state.approver.session,false],[state.secondaryApprover.session,false],[state.developer.session,true],[state.other.session,true],[state.c2Developer.session,true]];
  const sessionIds=sessions.map(([session,portal])=>sessionId(session.cookie,portal));
  h.check(sessionIds.every(id=>/^[a-f\d]{8}-[a-f\d]{4}-[1-8][a-f\d]{3}-[89ab][a-f\d]{3}-[a-f\d]{12}$/i.test(id??'')),'MetadataRecovery/Session','every original actor retains its exact refresh SID before permitted standard renewal');
  await originalConsoleSession(h,state.admin);await originalConsoleSession(h,state.approver.session);await originalConsoleSession(h,state.secondaryApprover.session);
  for(const user of[state.developer,state.other,state.c2Developer])await originalPortalSession(h,user);
  h.check(sessions.every(([session,portal],index)=>sessionId(session.cookie,portal)===sessionIds[index]),'MetadataRecovery/Session','fresh console/developer authorization preserves every original SID');
  for(const f of state.fixtures){
    const read=async path=>h.ok(await h.request(state.admin,scope(`/clusters/${f.cluster.id}/${path}`,f.workspace)),'MetadataRecovery/Current','current owned fixture proof');
    const workspace=h.ok(await h.request(state.admin,`/clusters/${f.cluster.id}/workspaces/${f.workspace.id}`),'MetadataRecovery/Workspace','current original workspace');
    h.check(workspace.id===f.workspace.id&&workspace.revision===f.workspace.revision&&workspace.code===f.workspace.code&&workspace.status==='active','MetadataRecovery/Workspace','workspace identity/revision remain unchanged');
    const settings=(await read('portal/settings')).settings;h.check(settings.id===f.settings.id&&settings.revision===f.settings.revision&&settings.published===true,'MetadataRecovery/Settings','original published tenant settings remain unchanged');
    for(const type of['services','routes'])for(const saved of f[type]){const actual=entity(await read(`entities/${type}/${saved.id}`));h.check(JSON.stringify(nativeComparable(actual))===JSON.stringify(nativeComparable(saved)),'MetadataRecovery/Native','existing Service/Route configuration is unchanged');}
    for(const saved of f.publications){const actual=entity(await read(`portal/publications/${saved.id}`));h.check(actual.id===saved.id&&actual.serviceId===saved.serviceId&&actual.revision===saved.revision&&actual.documentRevision===saved.documentRevision&&actual.status==='published','MetadataRecovery/Publication','current publication retains its immutable published identity');}
  }
  for(const saved of[state.legacyKeyAuth,state.legacyAcl]){const actual=entity(h.ok(await h.request(state.admin,scope(`/clusters/${T.clusterId}/entities/plugins/${saved.id}`,T.workspaceId)),'MetadataRecovery/Legacy','existing unrelated controlled legacy plugin'));h.check(JSON.stringify(nativeComparable(actual))===JSON.stringify(nativeComparable(saved)),'MetadataRecovery/Legacy','legacy fixture configuration is unchanged');}
  const receipt=h.ok(await h.request(state.admin,receiptPath()),'MetadataRecovery/Receipt','original execution receipt before recovery');assertRecoveryReceipt(h,receipt,'uncertain');
  h.check(receipt.metadataRecovery?.eligible===true&&receipt.metadataRecovery.executionId===T.executionId&&receipt.metadataRecovery.originalExecutionKeyRequired===true,'MetadataRecovery/Eligibility','current server proof independently admits only this metadata recovery');
  const view=entity(h.ok(await h.request(state.admin,viewPath()),'MetadataRecovery/View','current original workflow'));
  h.check(view.id===T.workflowId&&view.kind==='portal-credential-issue'&&view.state==='uncertain'&&view.planHash===state.executeAttempt.body.planHash,'MetadataRecovery/Plan','original immutable approved plan remains uncertain');
  const before=databaseProof(h);
  h.check(before.credential_state==='pending'&&before.grant_state==='pending'&&before.generation===1&&before.current_generation===0&&before.current_credential_id===null&&before.credential_ref_id===null&&before.issue_operation_id===null&&before.workflow_state==='uncertain'&&before.execution_state==='uncertain'&&before.execution_actor_id===state.admin.user.id&&before.plan_hash===view.planHash&&before.workflow_revision===view.revision&&before.native_operation_count===3&&before.native_unresolved===0&&before.portal_unresolved===0&&/^[a-f0-9]{64}$/.test(before.immutable_key_cipher_sha),'MetadataRecovery/Database','fresh independent DB proof retains exactly three native completions and pending immutable key metadata');
  for(const [type,id,parent]of[['consumers',T.consumerId,null],['acls',T.aclId,T.consumerId],['key-auth',T.nativeId,T.consumerId]]){
    const path=parent?`consumers/${parent}/credentials/${type}/${id}`:`entities/${type}/${id}`;
    const native=entity(h.ok(await h.request(state.admin,scope(`/clusters/${T.clusterId}/${path}`,T.workspaceId)),'MetadataRecovery/Native','fresh actual previously-created native identity'));
    h.check(native.id===id&&(!parent||native.consumer?.id===parent),'MetadataRecovery/Native','original Consumer/ACL/key-auth tuple is still present with the same parent');
    if(type==='key-auth')h.check(typeof native.key==='string'&&native.key.startsWith('[REDACTED'),'MetadataRecovery/Secret','default BFF read still masks the pending native Key');
  }
  const body={revision:view.revision,planHash:view.planHash,executionId:T.executionId,confirmed:true,confirm_name:'portal-credential-issue'};
  h.saveReference({metadataRecovery:{phase:'before-single-reconcile',originalKey:T.executionKey,workflowId:T.workflowId,executionId:T.executionId,grantId:T.grantId,credentialId:T.credentialId,body,before,guardedAt:new Date().toISOString()}});
  return{...state,recoveryBody:body,before};
}

export async function reconcileOriginalMetadata(h,context){
  const saved=h.referenceData.metadataRecovery;
  h.check(saved?.phase==='before-single-reconcile'&&saved.originalKey===T.executionKey&&JSON.stringify(canonical(saved.body))===JSON.stringify(canonical(context.recoveryBody)),'MetadataRecovery/Journal','the single original-key recovery request is saved before its POST');
  h.saveReference({metadataRecovery:{...saved,phase:'reconcile-request-started'}});
  const response=await h.request(context.admin,scope(`/clusters/${T.clusterId}/workflows/${T.workflowId}/reconcile-metadata`,T.workspaceId),'POST',context.recoveryBody,{key:T.executionKey});
  const completed=h.ok(response,'MetadataRecovery/Complete','formal recovery completes only the original last metadata step');assertRecoveryReceipt(h,completed,'succeeded');
  const original=h.ok(await h.request(context.admin,receiptPath()),'MetadataRecovery/Receipt','original execution key now resolves its successful receipt');assertRecoveryReceipt(h,original,'succeeded');
  const after=databaseProof(h);
  h.check(after.credential_state==='active'&&after.grant_state==='active'&&after.current_generation===1&&after.current_credential_id===T.credentialId&&after.credential_ref_id===T.keyReferenceId&&after.acl_credential_ref_id===T.aclReferenceId&&after.issue_operation_id===T.keyOperationId&&after.workflow_state==='succeeded'&&after.execution_state==='succeeded'&&after.native_operation_count===3&&after.immutable_key_cipher_sha===context.before.immutable_key_cipher_sha&&after.key_fingerprint===context.before.key_fingerprint&&after.native_unresolved===0&&after.portal_unresolved===0,'MetadataRecovery/NoReplay','exact original metadata activates without changing key ciphertext/fingerprint or creating any additional native operation');
  h.saveReference({metadataRecovery:{...saved,phase:'metadata-succeeded-original-execution',receiptState:original.state,after,requestId:response.payload?.meta?.requestId,completedAt:new Date().toISOString()}});
  return original;
}
