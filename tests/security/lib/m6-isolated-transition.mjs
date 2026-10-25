import { createHash, randomUUID } from 'node:crypto';
import { M6_C1,M6_C2,entity,scope } from './m6-harness.mjs';
import { originalConsoleSession } from './m6-publication-continuation.mjs';

export const checkpointSha = checkpoint => createHash('sha256').update(JSON.stringify(checkpoint)).digest('hex');
export async function registerIsolatedCluster(h,tag){
  h.requireLive();
  if(h.referenceData.isolatedRegistration||h.referenceData.isolatedStart||!/^m6-isolated-[a-z0-9-]+$/.test(tag))throw new Error('M6 isolated registration already attempted or invalid; use original receipts');
  const key=randomUUID(),adminUrl='http://kong-portal-admin-endpoint:8001';
  h.saveReference({isolatedRegistration:{key,plannedTag:tag,adminUrl,state:'before-single-registration',startedAt:new Date().toISOString()}});
  const cluster=h.ok(await h.request(h.referenceData.consoleAdministrator,'/clusters','POST',{name:`${tag}-primary`,environment:'portal-security-acceptance',admin_url:adminUrl,labels:[tag],execution_mode:'direct'},{key}),'Isolation/Register','one audited registration of the genuinely new dedicated Kong');
  h.saveReference({isolatedRegistration:{...h.referenceData.isolatedRegistration,state:'response-observed',clusterId:cluster.id}});
  const probeKey=randomUUID();
  h.saveReference({isolatedRegistration:{...h.referenceData.isolatedRegistration,probe:{key:probeKey,state:'before-single-probe',startedAt:new Date().toISOString()}}});
  h.ok(await h.request(h.referenceData.consoleAdministrator,`/clusters/${cluster.id}/probe`,'POST',undefined,{key:probeKey}),'Isolation/Probe','one explicit audited probe populates version and capabilities after registration');
  h.saveReference({isolatedRegistration:{...h.referenceData.isolatedRegistration,probe:{...h.referenceData.isolatedRegistration.probe,state:'response-observed'}}});
  return cluster;
}
const zeroFields=['grants','issuedCredentials','credentialRefs','completedNative','unresolvedNative','metadataApplied'];
export function validateIsolatedTransition(reference,evidence,targets){
  const owned=(reference.fixtures??[]).map(row=>`${row.cluster.id}:${row.workspace.id}`).sort();
  const proved=(evidence?.ownedScopes??[]).map(row=>`${row.clusterId}:${row.workspaceId}`).sort();
  const failure=reference.boundaryRefusalProof;
  const acl=(reference.writeAttempts??[]).find(row=>row.key===evidence?.aclKey);
  const tokenPurposes={native_scrape:'bff',collector_catalog:'bff',collector_scrape:'collector',collector_ingest:'collector'};
  const tokens=reference.tokens??[];
  const families=tokens.length===8&&new Set(tokens.map(row=>row.token)).size===8&&[[M6_C1,2],[M6_C2,1]].every(([cid,generation])=>Object.entries(tokenPurposes).every(([purpose,audience])=>tokens.filter(row=>row.clusterId===cid&&row.generation===generation&&row.purpose===purpose&&row.audience===audience&&typeof row.token==='string'&&/^[A-Za-z0-9_-]{43,128}$/.test(row.token)).length===1));
  const valid=reference.phase==='bootstrap'&&reference.liveStartedAt&&owned.length===3&&JSON.stringify(owned)===JSON.stringify(proved)&&!(reference.grants?.length)&&!(reference.portalUsers?.length)&&
    failure?.workflowId===evidence?.publicationReceipt?.workflowId&&failure.originalKey===evidence.publicationKey&&
    evidence.publicationReceipt.state==='failed'&&evidence.publicationReceipt.steps.length===3&&evidence.publicationReceipt.steps.every(step=>step.remoteCompleted===false&&['failed','pending'].includes(step.state))&&
    acl?.state==='response_observed'&&acl.httpStatus===403&&acl.errorCode==='PORTAL_UNMANAGED_AUTH_BOUNDARY'&&
    evidence.aclReceipt?.state==='failed'&&evidence.aclReceipt.remoteCompleted===false&&evidence.aclReceipt.entityId===null&&
    zeroFields.every(field=>evidence.oldFacts?.[field]===0)&&families&&
    /^[\da-f]{8}-[\da-f]{4}-[\da-f]{4}-[\da-f]{4}-[\da-f]{12}$/i.test(targets?.primary?.id??'')&&!([M6_C1,M6_C2].includes(targets.primary.id))&&targets.secondary?.id===M6_C2&&
    targets.primary.adminUrl==='http://kong-portal-admin-endpoint:8001'&&targets.secondary.adminUrl==='http://kong-secondary:8001'&&
    targets.primary.proxyOrigin==='http://127.0.0.1:10000'&&targets.secondary.proxyOrigin==='http://127.0.0.1:9000';
  if(!valid)throw new Error('M6 isolated transition lacks exact terminal/zero-issued/tenant/material proof');
  return true;
}
export function isolatedReference(reference,evidence,targets,newTag){
  validateIsolatedTransition(reference,evidence,targets);
  if(typeof newTag!=='string'||!/^m6-isolated-[a-z0-9-]+$/.test(newTag)||newTag===reference.testTag)throw new Error('M6 isolated fixture tag must be new and explicit');
  const prior=structuredClone(reference),digest=checkpointSha(prior);
  return{...reference,priorFixtureRuns:[...(reference.priorFixtureRuns??[]),{testTag:reference.testTag,checkpoint:prior,checkpointSha256:digest}],
    testTag:newTag,phase:'isolatedFixtureStart',liveStartedAt:null,fixtures:[],grants:[],portalUsers:[],accounts:{},browser:null,continuation:null,releasedReservations:[],physicalAliases:[],legacyPlugins:[],boundaryRefusalProof:null,
    portalTestTargets:structuredClone(targets),isolatedStart:{authorizedEvidence:evidence,previousCheckpointSha256:digest,preparedAt:new Date().toISOString()},
    // Global evidence/material arrays remain intact, including failed attempts.
    fixtureJournal:reference.fixtureJournal??[],writeAttempts:reference.writeAttempts??[],writeEvidence:reference.writeEvidence??[],users:reference.users??[],secrets:reference.secrets??[],tokens:reference.tokens??[],portalSessions:reference.portalSessions??[]};
}
export async function guardOldIsolatedFacts(h){
  h.requireLive();const p=h.referenceData,admin=p.consoleAdministrator;
  if(p.phase!=='bootstrap'||!p.boundaryRefusalProof?.workflowId||p.grants?.length||p.portalUsers?.length)throw new Error('M6 old fixture checkpoint is not the known unissued failed phase');
  await originalConsoleSession(h,admin);
  const primary=p.fixtures[0],aclAttempt=p.writeAttempts.findLast(row=>row.method==='POST'&&row.path.endsWith('/entities/plugins')&&row.errorCode==='PORTAL_UNMANAGED_AUTH_BOUNDARY');
  if(!aclAttempt)throw new Error('M6 original failed ACL request is missing');
  const receipt=h.ok(await h.request(admin,scope(`/clusters/${primary.cluster.id}/workflows/receipts/by-key/${p.boundaryRefusalProof.originalKey}`,primary.workspace)),'Isolation/Receipt','original failed publication receipt remains terminal');
  const aclReceipt=h.ok(await h.request(admin,scope(`/clusters/${primary.cluster.id}/mutations/by-key/${aclAttempt.key}`,primary.workspace)),'Isolation/Receipt','original failed ACL mutation receipt remains terminal');
  const ownedScopes=p.fixtures.map(row=>({clusterId:row.cluster.id,workspaceId:row.workspace.id}));
  for(const f of p.fixtures){
    const ws=h.ok(await h.request(admin,`/clusters/${f.cluster.id}/workspaces/${f.workspace.id}`),'Isolation/Ownership','old fixture workspace still has its exact test identity');
    h.check(ws.code.startsWith(p.testTag)&&ws.id===f.workspace.id,'Isolation/Ownership','old cleanup scope uses only explicitly saved test workspace and tag');
    for(const pub of f.publications){const current=entity(h.ok(await h.request(admin,scope(`/clusters/${f.cluster.id}/portal/publications/${pub.id}`,f.workspace)),'Isolation/Publication','old publication detail remains readable after the source repair'));h.check(current.id===pub.id&&current.serviceId===pub.serviceId&&!['published','disabled'].includes(current.status),'Isolation/Publication','no old publication became active');}
  }
  const workspaceIds=ownedScopes.map(row=>row.workspaceId);
  const facts=h.consoleRead(`SELECT
    (SELECT count(*)::int FROM portal_application_grants WHERE workspace_id=ANY($1::uuid[])) AS grants,
    (SELECT count(*)::int FROM portal_credentials WHERE workspace_id=ANY($1::uuid[]) AND(state<>'pending' OR credential_ref_id IS NOT NULL OR issue_operation_id IS NOT NULL)) AS "issuedCredentials",
    (SELECT count(*)::int FROM credential_refs WHERE consumer_id IN(SELECT consumer_id FROM portal_application_grants WHERE workspace_id=ANY($1::uuid[]))) AS "credentialRefs",
    (SELECT count(*)::int FROM mutation_operations WHERE(workflow_id=$2 OR request_id=$3) AND(remote_completed OR state='succeeded')) AS "completedNative",
    (SELECT count(*)::int FROM mutation_operations WHERE cluster_id=ANY($4::uuid[]) AND state IN('running','uncertain')) AS "unresolvedNative",
    (SELECT count(*)::int FROM workflow_steps WHERE workflow_id=$2 AND kind='metadata' AND(state<>'pending' OR safe_result<>'{}'::jsonb OR started_at IS NOT NULL OR completed_at IS NOT NULL)) AS "metadataApplied"`,[workspaceIds,receipt.workflowId,aclAttempt.requestId,[M6_C1,M6_C2]])[0];
  const aclNative=h.consoleRead('SELECT state,remote_started,remote_completed,entity_id FROM mutation_operations WHERE cluster_id=$1 AND request_id=$2',[primary.cluster.id,aclAttempt.requestId]);
  h.check(aclReceipt.state==='failed'&&aclNative.length===1&&aclNative[0].state==='failed'&&aclNative[0].remote_completed===false&&aclNative[0].entity_id===null,'Isolation/Receipt','failed ACL is known terminal without native completion, not inferred unsent');
  h.check(zeroFields.every(field=>facts?.[field]===0),'Isolation/ZeroIssued','old exact scopes have no grants, issued references, completed boundary changes or unresolved operations');
  const evidence={performedAt:new Date().toISOString(),ownedScopes,publicationKey:p.boundaryRefusalProof.originalKey,publicationReceipt:{workflowId:receipt.workflowId,state:receipt.state,steps:receipt.steps.map(row=>({state:row.state,remoteCompleted:row.remoteCompleted,errorCode:row.errorCode}))},aclKey:aclAttempt.key,aclReceipt:{state:aclNative[0].state,remoteStarted:aclNative[0].remote_started,remoteCompleted:aclNative[0].remote_completed,entityId:aclNative[0].entity_id},oldFacts:facts};
  h.saveReference({isolatedTransitionOldProof:evidence});return evidence;
}
export async function guardIsolatedTransition(h,evidence,targets){
  validateIsolatedTransition(h.referenceData,evidence,targets);
  const fresh=await guardOldIsolatedFacts(h);
  for(const target of [targets.primary,targets.secondary]){const current=h.ok(await h.request(h.referenceData.consoleAdministrator,`/clusters/${target.id}`),'Isolation/Cluster','registered isolated target has current identity');h.check(current.id===target.id&&current.admin_url===target.adminUrl&&current.version?.startsWith('1.5.'),'Isolation/Cluster','isolated target is the exact registered Kong1.5 endpoint');}
  validateIsolatedTransition(h.referenceData,fresh,targets);return fresh;
}
