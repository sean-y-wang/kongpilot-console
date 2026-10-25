import { createHmac, randomBytes, randomUUID, X509Certificate, createPrivateKey } from 'node:crypto';
import { readFileSync, writeFileSync, existsSync, mkdirSync, openSync, fsyncSync, closeSync,constants,fstatSync } from 'node:fs';
import { dirname, resolve,isAbsolute } from 'node:path';
import { pathToFileURL } from 'node:url';
import { ReleaseHarness, releaseScope } from './lib/release-harness.mjs';
import { restoredAuthProbeHeaders } from './m11-restored-credential-probes.mjs';
import { restoredOAuthRequiresTLS,restoredOAuthAuthorizationForm,restoredOAuthAuthorizationCode,restoredOAuthToken } from './m11-restored-oauth2-https-probes.mjs';
import { ordinaryV3HttpsOnce } from './lib/ordinary-v3-https-probe.mjs';

// Importing this module performs no ledger, file, SQL or network access.
export const ORDINARY_V3_FIELD = 'currentOrdinaryV3Acceptance20261018';
const CASE_FIELD_PREFIX = 'currentOrdinaryV3AcceptanceCase_';
export function ordinaryV3CaseSelection(env) {
  const caseId=env.RELEASE_LAB_M11_CURRENT_ORDINARY_V3_CASE,fixtureField=env.RELEASE_LAB_M11_CURRENT_ORDINARY_V3_FIXTURE;
  if(caseId===undefined&&fixtureField===undefined)return {caseId:'original',field:ORDINARY_V3_FIELD,fixtureField:'m9PcreNativeActual20261018'};
  requireThat(typeof caseId==='string'&&/^[a-z][a-z0-9-]{0,31}$/.test(caseId)&&caseId!=='original',
    'V3_EXPLICIT_NEW_CASE_REQUIRED');
  requireThat(typeof fixtureField==='string'&&/^[A-Za-z][A-Za-z0-9_]{0,63}$/.test(fixtureField)
    &&!Object.getOwnPropertyNames(Object.prototype).includes(fixtureField)&&fixtureField!=='prototype',
    'V3_EXPLICIT_FIXTURE_FIELD_REQUIRED');
  return {caseId,field:CASE_FIELD_PREFIX+caseId,fixtureField};
}
export const ORDINARY_V3_PRODUCT_PATCH = '4a3a0f510d8bb6541111ee0b93eb358777b929906da746aede8d8f06d4d61f7f';
export const CREDENTIAL_KINDS = Object.freeze(['key-auth','basic-auth','jwt','oauth2','hmac-auth','acls']);
export const ORDINARY_V3_STAGES = Object.freeze(['init-fixtures','delete-service','restore-service','delete-route','restore-route',
  'delete-upstream','restore-upstream','delete-consumer','restore-consumer','delete-certificate','restore-certificate',
  'create-probes','probe-restored','create-oauth-probes','probe-oauth-restored']);
const uuid = value => typeof value === 'string' && /^[a-f\d]{8}-[a-f\d]{4}-[1-8][a-f\d]{3}-[89ab][a-f\d]{3}-[a-f\d]{12}$/i.test(value);
const digest = value => typeof value === 'string' && /^[a-f\d]{64}$/.test(value);
const ref = value => typeof value === 'string' ? value : value?.id;
const deny = code => { throw Error(code); };
const requireThat = (value, code) => { if (!value) deny(code); };
// Diagnostic only: this value is persisted exclusively in Root's private
// ledger. Public reports must continue selecting their fixed allowlist.
function privateOriginalError(error) {
  const limits={name:256,message:4096,stack:16384},value={},truncated={};
  for(const [field,limit]of Object.entries(limits)){
    let text;try{const raw=error?.[field];text=raw===undefined?(field==='message'?String(error):''):String(raw);}catch{text='[unreadable original error field]';}
    value[field]=text.slice(0,limit);truncated[field]=text.length>limit;
  }
  return {...value,truncated};
}
function rootPemFile(file,privateKey=false) {
  requireThat(typeof file==='string'&&isAbsolute(file),'V3_ROOT_ABSOLUTE_PEM_FILE_REQUIRED');
  const fd=openSync(file,constants.O_RDONLY|constants.O_NOFOLLOW);try{const s=fstatSync(fd);
    requireThat(s.isFile()&&s.nlink===1&&s.size>0&&s.size<=65536&&(!privateKey||s.uid===process.getuid()&&(s.mode&0o077)===0),'V3_ROOT_PRIVATE_PEM_FILE_REQUIRED');
    return readFileSync(fd,'utf8');
  }finally{closeSync(fd);}
}

export function ordinaryV3Gate(env, attestation, stage, now = Date.now()) {
  ordinaryV3CaseSelection(env);
  requireThat(ORDINARY_V3_STAGES.includes(stage), 'V3_FIXED_STAGE_REQUIRED');
  requireThat(env.RELEASE_LAB_M11_CURRENT_ORDINARY_V3_READY === 'true', 'V3_ROOT_EXPLICIT_EXECUTION_GATE_REQUIRED');
  requireThat(attestation?.operatorConfirmed === true && attestation.noUnknownReplay === true
    && attestation.productPatchSha256 === ORDINARY_V3_PRODUCT_PATCH && digest(attestation.deployedSourceDigest)
    && Number.isFinite(Date.parse(attestation.deployedAt)) && Date.parse(attestation.deployedAt) <= now,
  'V3_EXACT_DEPLOYMENT_ATTESTATION_REQUIRED');
}
export function ordinaryV3Session(session, now = Date.now()) {
  requireThat(uuid(session?.user?.id) && uuid(session.sid) && typeof session.cookie === 'string', 'V3_ORIGINAL_SESSION_REQUIRED');
  const access = session.cookie.split('; ').find(pair => pair.startsWith('kongos_access='));
  let claims; try { claims = JSON.parse(Buffer.from(access?.slice('kongos_access='.length).split('.')[1] ?? '', 'base64url').toString()); } catch { deny('V3_ACCESS_COOKIE_INVALID'); }
  requireThat(claims.sub === session.user.id && claims.sid === session.sid && Number.isFinite(claims.exp)
    && claims.exp * 1000 > now + 120_000, 'V3_FRESH_SESSION_REQUIRED_NO_REFRESH');
  return session;
}
export function ordinaryV3Policy(definitions, adminId, reviewerId) {
  requireThat(uuid(adminId) && uuid(reviewerId) && adminId !== reviewerId, 'V3_DISTINCT_REVIEWER_REQUIRED');
  requireThat(Array.isArray(definitions?.items) && !definitions.nextCursor, 'V3_POLICY_COMPLETE_PAGE_REQUIRED');
  const native = definitions.items.filter(item => item.kind === 'native-change' && item.status === 'active');
  requireThat(native.length === 1, 'V3_SINGLE_NATIVE_POLICY_REQUIRED');
  const p = native[0].policy;
  requireThat(native[0].format === 2 && p?.version === 2 && p.kind === 'native-change' && p.allowSelfApproval === false
    && p.distinctAcrossStages === true && p.stages?.length === 1 && p.stages[0].mode === 'any' && p.stages[0].threshold === 1
    && JSON.stringify(p.stages[0].selector) === JSON.stringify({users:[reviewerId]}), 'V3_CURRENT_ONE_STAGE_INDEPENDENT_POLICY_REQUIRED');
  return native[0];
}
export function ordinaryV3Vote(detail) {
  requireThat(detail?.state === 'pending' && detail.approval?.format === 2 && Number.isSafeInteger(detail.revision)
    && digest(detail.planHash) && Number.isSafeInteger(detail.approval.candidateVersion) && detail.approval.candidateVersion > 0, 'V3_REAL_CURRENT_VOTE_TUPLE_REQUIRED');
  const active = detail.approval.stages.filter(item => item.state === 'active');
  requireThat(active.length === 1 && active[0].level === 1 && Number.isSafeInteger(active[0].revision), 'V3_REAL_CURRENT_STAGE_REQUIRED');
  return {revision:detail.revision,planHash:detail.planHash,confirmed:true,confirm_name:'native-change',execute:false,
    level:active[0].level,stageRevision:active[0].revision,candidateVersion:detail.approval.candidateVersion};
}
export function ordinaryV3GraphSpecs(g) {
  const m = g.m9;
  return {
    service:{type:'services',id:m.serviceId,members:[['services',m.serviceId],['routes',m.routeId],['plugins',m.pluginId]],references:[['upstreams',m.upstreamId]]},
    route:{type:'routes',id:m.routeId,members:[['routes',m.routeId],['plugins',m.pluginId]],references:[['services',m.serviceId],['upstreams',m.upstreamId]]},
    upstream:{type:'upstreams',id:m.upstreamId,members:[['upstreams',m.upstreamId],['targets',m.targetId]]},
    consumer:{type:'consumers',id:g.consumerId,members:[['consumers',g.consumerId],...CREDENTIAL_KINDS.map(k=>[k,g.credentialIds[k]])]},
    certificate:{type:'certificates',id:g.certificateId,members:[['certificates',g.certificateId],['snis',g.sniId]]},
  };
}
export function ordinaryV3Archive(preview, spec, expectedState) {
  requireThat(preview?.entry?.state === expectedState && preview.entry.mutation_id === null && preview.entry.original_id === spec.id
    && uuid(preview.entry.id) && preview.graph?.complete === true && Array.isArray(preview.graph.nodes) && Array.isArray(preview.nodes), 'V3_COMPLETE_ARCHIVE_REQUIRED');
  const nodes = preview.graph.nodes, affected = nodes.filter(n=>n.affected), key = n=>`${n.type}:${n.id}`;
  requireThat(preview.entry.node_count === nodes.length && preview.nodes.length === nodes.length
    && new Set(nodes.map(n=>n.key)).size === nodes.length, 'V3_EXACT_ARCHIVE_MANIFEST_REQUIRED');
  requireThat(JSON.stringify(affected.map(key).sort()) === JSON.stringify(spec.members.map(([t,id])=>`${t}:${id}`).sort()), 'V3_EXACT_AFFECTED_IDS_REQUIRED');
  const allowed = new Set([...(spec.references??[]),...spec.members].map(([t,id])=>`${t}:${id}`));
  requireThat(nodes.every(n=>allowed.has(key(n)) && Array.isArray(n.dependencies) && n.dependencies.every(d=>nodes.some(p=>p.key===d))), 'V3_UNSEALED_REFERENCE_OR_DEPENDENCY');
  for (const n of nodes) {
    const row = preview.nodes.find(r=>r.node_key===n.key);
    requireThat(row?.entity_type===n.type && row.original_id===n.id && row.affected===n.affected
      && JSON.stringify([...row.dependencies].sort())===JSON.stringify([...n.dependencies].sort()), 'V3_SQL23_LEGACY_MANIFEST_MISMATCH');
    if (n.affected) requireThat(row.delete_state==='deleted' && (expectedState==='deleted' ? row.restore_state!=='restored'
      : row.restore_state==='restored' && row.restored_id===n.id), 'V3_MEMBER_STATE_INCOMPLETE');
  }
  return {entryId:preview.entry.id,nodeCount:nodes.length,affectedCount:affected.length,referenceCount:nodes.length-affected.length};
}
export function ordinaryV3PublicSummary(g, stage, passed) {
  const record = g.stages[stage];
  return {milestone:'M11',stage,passed,sourceOnly:false,productionDeployment:false,overallM11Accepted:false,
    state:record?.state??'not-started',configurationVerification:record?.configurationVerification??'pending',
    sqlAeadVerification:'pending-root-readonly-worker',functionalVerification:Object.fromEntries(CREDENTIAL_KINDS.map(k=>[k,['pending-actual-proxy','actual-restored-positive-negative-proxy-verified','actual-restored-verified-HTTPS-code-token-positive-negative'].includes(g.functionalVerification?.[k])?g.functionalVerification[k]:'pending-actual-proxy'])),
    counts:{graphs:Object.keys(g.graphs??{}).length,credentials:Object.keys(g.credentialIds??{}).length},
    requests:Object.values(g.operations??{}).filter(o=>o.stage===stage).map(o=>({label:o.label,state:o.state,status:o.status??null,requestId:o.requestId??null})),
    credentialValuesRecorded:false,headersRecorded:false,sessionCookiesRecorded:false,privateProofPublished:false};
}
export function ordinaryV3InspectionInput(g,stage) {
  requireThat(/^(delete|restore)-(service|route|upstream|consumer|certificate)$/.test(stage)&&g.stages[stage]?.state==='succeeded','V3_COMPLETED_GRAPH_STAGE_REQUIRED');
  const r=g.intents[stage],kind=stage.slice(stage.startsWith('delete-')?7:8),spec=ordinaryV3GraphSpecs(g)[kind],graph=g.graphs[kind];
  requireThat(r&&uuid(r.workflowId)&&uuid(r.executionId)&&uuid(r.baselineId)&&uuid(graph?.entryId),'V3_ORIGINAL_INSPECTION_TUPLE_REQUIRED');
  return {version:1,clusterId:g.clusterId,workspaceId:g.workspaceId,workflowId:r.workflowId,executionId:r.executionId,
    baselineId:r.baselineId,entryId:graph.entryId,direction:stage.startsWith('delete-')?'delete':'restore',members:spec.members.map(([type,id])=>({type,id}))};
}
/** Operator evidence aggregation only, never a server permission or proof.
 * Root supplies the separately executed readonly worker's actual records. */
export function ordinaryV3CombinedResult(g,inspections) {
  requireThat(ORDINARY_V3_STAGES.every(s=>g.stages[s]?.state==='succeeded'),'V3_ALL_ORIGINAL_STAGES_REQUIRED');
  const graphStages=ORDINARY_V3_STAGES.filter(s=>/^(delete|restore)-/.test(s));
  for(const stage of graphStages){const expected=ordinaryV3InspectionInput(g,stage),p=inspections?.[stage];
    requireThat(p?.readOnly===true&&p.configurationVerified===true&&p.baselineAeadVerified===true&&p.intentAeadVerified===true
      &&p.archiveAeadVerified===true&&p.sql23ManifestVerified===true&&p.originalTransportAndReciprocalMutationVerified===true
      &&p.workflowId===expected.workflowId&&p.executionId===expected.executionId&&p.baselineId===expected.baselineId&&p.entryId===expected.entryId
      &&p.affectedCount===expected.members.length&&p.receipts===expected.members.length
      &&p.nativeStatus===(expected.direction==='delete'?204:201)&&p.nativeRequestsSent===0&&p.sqlWritesSent===0,'V3_MATCHED_ROOT_READONLY_EVIDENCE_REQUIRED');}
  requireThat(CREDENTIAL_KINDS.every(k=>g.functionalVerification?.[k]===(k==='oauth2'?'actual-restored-verified-HTTPS-code-token-positive-negative':'actual-restored-positive-negative-proxy-verified')),'V3_ALL_SIX_REAL_AUTH_RESULTS_REQUIRED');
  return {cohortAccepted:true,ordinaryEntityChangeOnly:true,graphs:5,deleteRestoreCycles:5,credentialKinds:6,
    configurationVerified:true,sqlAeadAndReciprocalReceiptsVerified:true,functionalVerification:'six-schemes-actual-controlled-proxy',
    configurationV2TargetAccepted:false,portalWholeAccepted:false,overallM11Accepted:false,commercialAccepted:false};
}
export function ordinaryV3Inputs(suffix, certificate) {
  requireThat(uuid(suffix) && typeof certificate?.cert==='string' && typeof certificate.key==='string', 'V3_ROOT_TLS_FIXTURE_REQUIRED');
  const x509 = new X509Certificate(certificate.cert);
  requireThat(x509.checkPrivateKey(createPrivateKey(certificate.key)) && x509.checkHost('kongpilot-v3-acceptance.invalid'), 'V3_CERTIFICATE_KEY_SAN_REQUIRED');
  const secret=()=>randomBytes(32).toString('hex');
  return {consumer:{username:`v3-${suffix}`,custom_id:`v3-${suffix}`},
    'key-auth':{key:secret()},'basic-auth':{username:`v3-${suffix}`,password:secret()},jwt:{key:secret(),secret:secret(),algorithm:'HS256'},
    oauth2:{name:`v3-${suffix}`,client_id:secret(),client_secret:secret(),redirect_uris:[`https://v3-${suffix}.invalid/callback`]},
    'hmac-auth':{username:`v3-${suffix}`,secret:secret()},acls:{group:`v3-${suffix}`},certificate:{...certificate},sni:{name:'kongpilot-v3-acceptance.invalid'}};
}

/** Only actual Root invocation constructs ReleaseHarness. No direct Admin API,
 * SQL process, login/refresh, retry, stage resume or unknown reconciliation. */
export async function runOrdinaryV3Stage(h, stage, {env=process.env,attestation,certificate,oauthTls}={}) {
  ordinaryV3Gate(env,attestation,stage);
  const selection=ordinaryV3CaseSelection(env);
  requireThat(uuid(h.state.cid)&&uuid(h.state.wid), 'V3_ORIGINAL_SCOPE_REQUIRED');
  const admin=()=>ordinaryV3Session(h.state.sessions?.admin), reviewer=()=>ordinaryV3Session(h.state.metadataAcceptance?.reviewerSession);
  requireThat(admin().user.id!==reviewer().user.id, 'V3_DISTINCT_REVIEWER_REQUIRED');h.assertWritable();
  const cid=h.state.cid,wid=h.state.wid,path=(s,q={})=>releaseScope(cid,wid,s,q);
  let g=Object.hasOwn(h.state,selection.field)?h.state[selection.field]:undefined;
  if(stage==='init-fixtures') {
    requireThat(!g, 'V3_ORIGINAL_FIELD_EXISTS_NO_REPLAY');
    requireThat(Object.hasOwn(h.state.metadataAcceptance??{},selection.fixtureField),'V3_EXPLICIT_FIXTURE_MISSING');
    const m=h.state.metadataAcceptance[selection.fixtureField];
    requireThat(m&&['upstreamId','targetId','serviceId','routeId','pluginId'].every(k=>uuid(m[k])), 'V3_ORIGINAL_COMPLETED_M9_FIXTURE_REQUIRED');
    // A new cohort never resumes a prior stage. Reusing the read-only M9
    // fixture is safe only while no prior cohort has started a graph change.
    for(const [field,prior]of Object.entries(h.state))if(field===ORDINARY_V3_FIELD||field.startsWith(CASE_FIELD_PREFIX)){
      requireThat(prior&&typeof prior==='object'&&prior.stages&&prior.m9,'V3_PRIOR_CASE_INVALID');
      const shared=['upstreamId','targetId','serviceId','routeId','pluginId'].some(k=>prior.m9[k]===m[k]);
      if(shared)requireThat(Object.keys(prior.stages).every(s=>s==='init-fixtures'),'V3_PRIOR_GRAPH_ALREADY_USED');
    }
    const suffix=randomUUID();g={version:1,clusterId:cid,workspaceId:wid,suffix,m9:structuredClone(m),subjects:{admin:admin().user.id,reviewer:reviewer().user.id},
      ...(selection.caseId==='original'?{}:{caseBinding:structuredClone(selection)}),
      deployment:structuredClone(attestation),inputs:ordinaryV3Inputs(suffix,certificate),credentialIds:{},stages:{},operations:{},intents:{},graphs:{},
      evidenceKey:randomBytes(32).toString('hex'),functionalVerification:Object.fromEntries(CREDENTIAL_KINDS.map(k=>[k,'pending-actual-proxy']))};
    h.state[selection.field]=g;
  }
  requireThat(selection.caseId==='original'?!g?.caseBinding:
    g?.caseBinding?.caseId===selection.caseId&&g.caseBinding.field===selection.field&&g.caseBinding.fixtureField===selection.fixtureField,
    'V3_ORIGINAL_CASE_BINDING_CHANGED');
  requireThat(g?.version===1&&g.clusterId===cid&&g.workspaceId===wid&&g.subjects.admin===admin().user.id&&g.subjects.reviewer===reviewer().user.id, 'V3_ORIGINAL_ACCEPTANCE_BINDING_REQUIRED');
  requireThat(g.deployment?.productPatchSha256===attestation.productPatchSha256&&g.deployment.deployedSourceDigest===attestation.deployedSourceDigest,'V3_ORIGINAL_DEPLOYED_SOURCE_CHANGED');
  requireThat(!g.stages[stage], 'V3_STAGE_ALREADY_STARTED_NO_REPLAY');
  for(const [key,s] of Object.entries(g.stages))requireThat(s.state==='succeeded', 'V3_PRIOR_STAGE_STOPPED_NO_REPLAY');
  const at=ORDINARY_V3_STAGES.indexOf(stage);if(at)requireThat(g.stages[ORDINARY_V3_STAGES[at-1]]?.state==='succeeded','V3_PREVIOUS_STAGE_REQUIRED');
  if(stage==='probe-restored')requireThat(Number.isFinite(g.probeNotBefore)&&Date.now()>=g.probeNotBefore,'V3_PROPAGATION_WAIT_REQUIRED_BEFORE_STAGE_ALLOCATION');
  if(stage==='probe-oauth-restored')requireThat(Number.isFinite(g.oauthNotBefore)&&Date.now()>=g.oauthNotBefore,'V3_PROPAGATION_WAIT_REQUIRED_BEFORE_STAGE_ALLOCATION');
  g.stages[stage]={state:'started',startedAt:new Date().toISOString()};h.save();
  const canonical=v=>Array.isArray(v)?v.map(canonical):v&&typeof v==='object'?Object.fromEntries(Object.keys(v).sort().map(k=>[k,canonical(v[k])])):v;
  const hmac=v=>createHmac('sha256',g.evidenceKey).update(JSON.stringify(canonical(v))).digest('hex');
  const read=async(p,expected=[200])=>(await h.request(admin(),p,'GET',undefined,{expected})).data;
  async function once(label,p,body,who='admin') {
    const full=`m11-v3-current-${g.suffix}-${stage}-${label}`;
    requireThat(!g.operations[full]&&!h.state.requests.some(r=>r.label===full), 'V3_ORIGINAL_REQUEST_ALREADY_ALLOCATED_NO_REPLAY');
    const key=randomUUID();g.operations[full]={label:full,stage,key,path:p,state:'allocated',body:structuredClone(body)};h.save();
    const r=await h.once(full,who==='reviewer'?reviewer():admin(),p,'POST',body,{key});
    Object.assign(g.operations[full],{state:'observed',status:r.status,requestId:r.requestId,responseHmac:hmac(r.data)});h.save();return r.data;
  }
  async function change(label,operation,count,nativeStatus=201,expectedMembers) {
    requireThat(!g.intents[label], 'V3_ORIGINAL_INTENT_EXISTS_NO_REPLAY');const r=g.intents[label]={stage,operation:structuredClone(operation)};h.save();
    const intent=await once(`${label}-prepare`,path('entity-changes/prepare'),{change:operation});
    requireThat(uuid(intent.id)&&intent.review?.impact?.nativePackets===count&&intent.review.changes.length===count, 'V3_EXACT_PREPARED_PACKET_COUNT_REQUIRED');
    if(expectedMembers)requireThat(hmac(intent.review.changes.map(c=>`${c.entityType}:${c.nativeId}`).sort())===hmac(expectedMembers.map(([t,id])=>`${t}:${id}`).sort())
      &&intent.review.changes.every(c=>c.action===operation.action),'V3_EXACT_PREPARED_GRAPH_IDS_REQUIRED');
    Object.assign(r,{intentId:intent.id,receipt:intent});h.save();
    const submitted=await once(`${label}-submit`,path(`entity-changes/${intent.id}/submit`),{revision:intent.revision,materialHmac:intent.materialHmac,confirmed:true,confirm_name:'native-change'});
    requireThat(uuid(submitted.workflowId), 'V3_REAL_WORKFLOW_REQUIRED');r.workflowId=submitted.workflowId;h.save();
    const before=(await read(path(`workflows/${r.workflowId}`))).entity;
    await once(`${label}-vote`,path(`workflows/${r.workflowId}/approve`),ordinaryV3Vote(before),'reviewer');
    const approved=(await read(path(`workflows/${r.workflowId}`))).entity;
    requireThat(approved.state==='approved'&&approved.capabilities?.execute===true&&uuid(approved.approval?.approvalSetId), 'V3_REAL_INDEPENDENT_APPROVAL_REQUIRED');
    const result=await once(`${label}-execute`,path(`workflows/${r.workflowId}/execute`),{revision:approved.revision,planHash:approved.planHash,confirmed:true,confirm_name:'native-change'});
    Object.assign(r,{executionId:result.executionId,baselineId:result.baselineId,executionReceipt:result});h.save();
    requireThat(result.state==='succeeded'&&uuid(result.executionId)&&uuid(result.baselineId), 'V3_REAL_COMPLETE_EXECUTION_REQUIRED');
    const detail=await read(path(`workflows/${r.workflowId}`));
    requireThat(detail.entity.state==='succeeded'&&detail.nativeChange?.packets?.length===count
      &&detail.nativeChange.packets.every(p=>p.state==='succeeded'&&p.nativeStatus===nativeStatus)
      &&detail.nativeChange.baseline?.nativeAuthority===false&&detail.nativeChange.baseline.baseline?.baselineId===result.baselineId, 'V3_EXACT_ORIGINAL_NATIVE_RECEIPTS_REQUIRED');
    r.detail=detail;r.receiptHmac=hmac(detail);h.save();return intent.review.changes;
  }
  const entity=async(t,id,reveal=false)=>(await read(path(`entities/${t}/${id}`,reveal?{reveal:'true'}:{}))).entity;
  async function authIsolation(oauth=false) {
    const workspaces=await read(`/clusters/${cid}/workspaces?size=100`);requireThat(Array.isArray(workspaces.items)&&!workspaces.nextCursor,'V3_WORKSPACE_INVENTORY_EOF_REQUIRED');
    for(const w of workspaces.items){const globals=await read(releaseScope(cid,w.id,'plugin-center/instances',{binding_scope:'global',size:'100'}));requireThat(Array.isArray(globals.items)&&!globals.nextCursor&&globals.items.every(p=>p.enabled===false||p.name==='prometheus'),'V3_GLOBAL_PLUGIN_INTERFERENCE');}
    const cp=await read(path(`entities/consumers/${g.consumerId}/relations/plugins`,{size:'100'}));requireThat(Array.isArray(cp.items)&&!cp.nextCursor&&cp.items.length===0,'V3_CONSUMER_PLUGIN_INTERFERENCE');
    const sp=await read(path(`entities/services/${g.probeServiceId}/relations/plugins`,{size:'100'}));requireThat(Array.isArray(sp.items)&&!sp.nextCursor&&sp.items.length===0,'V3_SERVICE_PLUGIN_INTERFERENCE');
    const routes=oauth?[g.oauthRoute]:Object.values(g.probeRoutes);
    for(const r of routes){const current=await entity('routes',r.id);for(const k of ['name','protocols','hosts','paths','strip_path'])requireThat(hmac(current[k])===hmac(r[k]),'V3_AUTH_ROUTE_CHANGED');requireThat(ref(current.service)===g.probeServiceId,'V3_AUTH_SERVICE_CHANGED');
      const bindings=await read(path(`entities/routes/${r.id}/relations/plugins`,{size:'100'})),expected=oauth?[{id:g.oauthPluginId,body:g.oauthPluginBody}]:g.probePlugins.filter(p=>p.body.route.id===r.id);
      requireThat(Array.isArray(bindings.items)&&!bindings.nextCursor&&hmac(bindings.items.map(p=>p.id).sort())===hmac(expected.map(p=>p.id).sort()),'V3_AUTH_PLUGIN_SET_CHANGED');
      for(const p of expected){const actual=await entity('plugins',p.id,true);requireThat(actual.enabled===true&&actual.name===p.body.name&&ref(actual.route)===r.id&&!ref(actual.service)&&!ref(actual.consumer),'V3_AUTH_PLUGIN_BINDING_CHANGED');for(const[k,v]of Object.entries(p.body.config))requireThat(hmac(actual.config[k])===hmac(v),'V3_AUTH_PLUGIN_CONFIG_CHANGED');}}
  }
  try {
    const cluster=await read(`/clusters/${cid}`);requireThat(/^1\.5\.\d+$/.test(cluster.version)&&cluster.execution_mode==='approval','V3_KONG15_APPROVAL_CLUSTER_REQUIRED');
    ordinaryV3Policy(await read(path('workflow-definitions',{size:'100'})),admin().user.id,reviewer().user.id);
    if(stage==='init-fixtures') {
      g.originals={};for(const [type,id]of [['services',g.m9.serviceId],['routes',g.m9.routeId],['plugins',g.m9.pluginId],['upstreams',g.m9.upstreamId]])g.originals[`${type}:${id}`]=await entity(type,id,true);
      const target=(await read(path(`upstreams/${g.m9.upstreamId}/targets`,{size:'100'})));
      requireThat(Array.isArray(target.items)&&!target.nextCursor&&target.items.some(t=>t.id===g.m9.targetId), 'V3_ORIGINAL_ACTIVE_TARGET_REQUIRED');
      g.originals[`targets:${g.m9.targetId}`]=target.items.find(t=>t.id===g.m9.targetId);
      const history=await read(path(`upstreams/${g.m9.upstreamId}/targets/history`,{size:'100'}));requireThat(Array.isArray(history.items)&&!history.nextCursor&&history.items.length===1&&history.items[0].id===g.m9.targetId,'V3_ORIGINAL_SINGLE_TARGET_HISTORY_REQUIRED');g.originalTargetHistory=history.items;h.save();
      const one=(await change('consumer',{kind:'entity',action:'create',entityType:'consumers',body:g.inputs.consumer},1))[0];g.consumerId=one.nativeId;h.save();
      const credentials=CREDENTIAL_KINDS.map(k=>({kind:'credential',action:'create',consumerId:g.consumerId,credentialKind:k,body:g.inputs[k]}));
      await change('credentials',{kind:'batch',confirmed:true,operations:credentials},6);
      for(const k of CREDENTIAL_KINDS){const found=await read(path(`consumers/${g.consumerId}/credentials/${k}`,{size:'100'}));requireThat(Array.isArray(found.items)&&!found.nextCursor&&found.items.length===1&&uuid(found.items[0].id),'V3_SIX_DISTINCT_CREDENTIAL_IDS_REQUIRED');g.credentialIds[k]=found.items[0].id;}h.save();
      g.certificateId=(await change('certificate',{kind:'entity',action:'create',entityType:'certificates',body:g.inputs.certificate},1))[0].nativeId;h.save();
      g.sniId=(await change('sni',{kind:'entity',action:'create',entityType:'snis',body:{...g.inputs.sni,certificate:{id:g.certificateId}}},1))[0].nativeId;h.save();
    } else if(stage.startsWith('delete-')||stage.startsWith('restore-')) {
      const restoring=stage.startsWith('restore-'),kind=stage.slice(restoring?8:7),spec=ordinaryV3GraphSpecs(g)[kind];requireThat(spec,'V3_FIXED_GRAPH_REQUIRED');
      const before=restoring?g.graphs[kind]:{spec,root:await entity(spec.type,spec.id,true)};
      requireThat(before&&(!restoring||uuid(before.entryId)), 'V3_ORIGINAL_ARCHIVE_REQUIRED');
      const name=String(before.root.name??before.root.username??spec.id);
      await change(stage,{kind:'recycle',action:restoring?'restore':'delete',...(restoring?{entryId:before.entryId}:{entityType:spec.type,entityId:spec.id}),confirmed:true,confirm_name:name},spec.members.length,restoring?201:204,spec.members);
      if(!restoring) {
        const entries=await read(path('recycle-bin',{type:spec.type,search:spec.id,size:'100'}));requireThat(Array.isArray(entries.items)&&!entries.nextCursor,'V3_EXACT_ARCHIVE_LIST_PAGE_REQUIRED');
        const matched=entries.items.filter(e=>e.original_id===spec.id&&e.state==='deleted'&&e.mutation_id===null);requireThat(matched.length===1,'V3_ONE_COMPLETE_NEW_ARCHIVE_REQUIRED');
        const preview=await read(path(`recycle-bin/${matched[0].id}`));g.graphs[kind]={...before,...ordinaryV3Archive(preview,spec,'deleted'),archiveHmac:hmac(preview)};h.save();
        for(const[t,id]of spec.members)if(t!=='targets')await read(CREDENTIAL_KINDS.includes(t)?path(`consumers/${g.consumerId}/credentials/${t}/${id}`):path(`entities/${t}/${id}`),[404]);
        if(kind==='upstream')await read(path(`upstreams/${g.m9.upstreamId}/targets/history`,{size:'100'}),[404]);
      } else {
        const preview=await read(path(`recycle-bin/${before.entryId}`));ordinaryV3Archive(preview,spec,'restored');
        for(const[t,id]of spec.members){const value=CREDENTIAL_KINDS.includes(t)?(await read(path(`consumers/${g.consumerId}/credentials/${t}/${id}`,{reveal:'true'}))).entity:t==='targets'?await (async()=>{const page=await read(path(`upstreams/${g.m9.upstreamId}/targets/history`,{size:'100'}));requireThat(Array.isArray(page.items)&&!page.nextCursor,'V3_TARGET_HISTORY_EOF_REQUIRED');return page.items.find(item=>item.id===id);})():await entity(t,id,true);requireThat(value?.id===id,'V3_RESTORE_EXACT_ORIGINAL_ID_REQUIRED');
          if(CREDENTIAL_KINDS.includes(t)){requireThat(ref(value.consumer)===g.consumerId,'V3_RESTORED_CREDENTIAL_PARENT_CHANGED');for(const[field,v]of Object.entries(g.inputs[t]))requireThat(hmac(value[field])===hmac(v),'V3_ORIGINAL_SECRET_OR_CONFIGURATION_CHANGED');if(t==='basic-auth')requireThat(value.recovery_capability==='complete','V3_ORIGINAL_BASIC_CUSTODY_REQUIRED');}
          else {const old=t==='consumers'?g.inputs.consumer:t==='certificates'?g.inputs.certificate:t==='snis'?{...g.inputs.sni,certificate:{id:g.certificateId}}:g.originals[`${t}:${id}`];requireThat(old,'V3_ORIGINAL_OBJECT_INPUT_REQUIRED');for(const[field,v]of Object.entries(old))if(!['created_at','updated_at','ttl'].includes(field))requireThat(hmac(value[field])===hmac(v),'V3_ORIGINAL_OBJECT_CONFIGURATION_CHANGED');}}
        before.restored=true;before.restoreReceiptHmac=g.intents[stage].receiptHmac;h.save();
      }
    } else if(stage==='create-probes') {
      const source=g.originals[`services:${g.m9.serviceId}`],tags=['owner:m11-v3-acceptance'];
      const service={name:`v3-probes-${g.suffix}`,tags};for(const k of ['protocol','host','port','path','retries','connect_timeout','write_timeout','read_timeout'])if(Object.hasOwn(source,k))service[k]=source[k];
      g.probeServiceId=(await change('probe-service',{kind:'entity',action:'create',entityType:'services',body:service},1))[0].nativeId;h.save();
      const kinds=['key-auth','basic-auth','jwt','hmac-auth','acls','acls-denied'];g.probeRoutes={};g.probePlugins=[];
      for(const k of kinds){const body={name:`v3-${k}-${g.suffix}`,service:{id:g.probeServiceId},protocols:['http'],hosts:[`v3-${k}-${g.suffix}.invalid`],paths:[`/v3-${k}-${g.suffix}`],strip_path:false,tags};
        g.probeRoutes[k]={...body,id:(await change(`probe-route-${k}`,{kind:'entity',action:'create',entityType:'routes',body},1))[0].nativeId};h.save();}
      for(const k of kinds)for(const name of k.startsWith('acls')?['key-auth','acl']:[k]){
        const config=name==='key-auth'?{key_names:['apikey'],hide_credentials:true}:name==='basic-auth'?{hide_credentials:true}:name==='jwt'?{key_claim_name:'iss',claims_to_verify:['exp'],secret_is_base64:false}
          :name==='hmac-auth'?{algorithms:['hmac-sha256'],enforce_headers:['date','digest','request-line'],validate_request_body:true,hide_credentials:true}:{whitelist:[k==='acls'?g.inputs.acls.group:`denied-${g.suffix}`]};
        const body={name,enabled:true,route:{id:g.probeRoutes[k].id},protocols:['http'],config,tags};const id=(await change(`probe-plugin-${k}-${name}`,{kind:'entity',action:'create',entityType:'plugins',body},1))[0].nativeId;g.probePlugins.push({id,body});h.save();}
      await authIsolation();g.probeNotBefore=Date.now()+5000;h.save();
    } else if(stage==='create-oauth-probes') {
      requireThat(oauthTls?.requiresTLS===true&&oauthTls.rejectUnauthorized===true&&oauthTls.servername===g.inputs.sni.name,'V3_ROOT_CONTROLLED_TLS_PROFILE_REQUIRED');
      const body={name:`v3-oauth2-${g.suffix}`,service:{id:g.probeServiceId},protocols:['https'],hosts:[oauthTls.servername],paths:[`/v3-oauth2-${g.suffix}`],strip_path:false,tags:['owner:m11-v3-acceptance']};
      g.oauthRoute={...body,id:(await change('oauth-route',{kind:'entity',action:'create',entityType:'routes',body},1))[0].nativeId};g.provisionKey=randomBytes(32).toString('hex');h.save();
      const config={scopes:['m11-read'],mandatory_scope:true,provision_key:g.provisionKey,token_expiration:3600,enable_authorization_code:true,enable_implicit_grant:false,enable_client_credentials:false,enable_password_grant:false,hide_credentials:true,accept_http_if_already_terminated:false,global_credentials:false,auth_header_name:'authorization',refresh_token_ttl:3600};
      g.oauthPluginBody={name:'oauth2',enabled:true,protocols:['https'],route:{id:g.oauthRoute.id},tags:['owner:m11-v3-acceptance'],config};g.oauthPluginId=(await change('oauth-plugin',{kind:'entity',action:'create',entityType:'plugins',body:g.oauthPluginBody},1))[0].nativeId;
      g.oauthTlsProfile={origin:oauthTls.origin,servername:oauthTls.servername,publicCaSha256:oauthTls.publicCaSha256};g.oauthNotBefore=Date.now()+5000;h.save();
    } else if(stage==='probe-oauth-restored') {
      requireThat(oauthTls?.requiresTLS===true&&oauthTls.rejectUnauthorized===true&&Date.now()>=g.oauthNotBefore
        &&hmac(g.oauthTlsProfile)===hmac({origin:oauthTls.origin,servername:oauthTls.servername,publicCaSha256:oauthTls.publicCaSha256}),'V3_ORIGINAL_TLS_PROFILE_AND_PROPAGATION_REQUIRED');
      await authIsolation(true);const send=(label,input)=>ordinaryV3HttpsOnce(h,g,label,oauthTls,input),root=g.oauthRoute.paths[0],state=randomBytes(32).toString('hex');
      const noToken=await send('missing-bearer',{method:'GET',path:root,expected:[401]});requireThat(noToken.body.error==='invalid_request','V3_REAL_MISSING_BEARER_DENIAL_REQUIRED');
      const bad=await send('wrong-bearer',{method:'GET',path:root,headers:{authorization:`Bearer ${randomBytes(32).toString('hex')}`},expected:[401]});requireThat(bad.body.error==='invalid_token','V3_REAL_INVALID_BEARER_DENIAL_REQUIRED');
      const authorization=await send('authorize-original-restored-client',{method:'POST',path:root+'/oauth2/authorize',form:restoredOAuthAuthorizationForm(g.inputs.oauth2,g.provisionKey,g.consumerId,state),expected:[200]});
      const code=restoredOAuthAuthorizationCode(authorization.body,g.inputs.oauth2,state);
      const tokenResponse=await send('issue-original-restored-client',{method:'POST',path:root+'/oauth2/token',form:{grant_type:'authorization_code',client_id:g.inputs.oauth2.client_id,client_secret:g.inputs.oauth2.client_secret,redirect_uri:g.inputs.oauth2.redirect_uris[0],code},expected:[200]});
      g.oauthToken=restoredOAuthToken(tokenResponse.body);h.save();
      await send('actual-restored-bearer-positive',{method:'GET',path:root,headers:{authorization:`Bearer ${g.oauthToken.access_token}`},expected:[200]});
      g.functionalVerification.oauth2='actual-restored-verified-HTTPS-code-token-positive-negative';h.save();
    } else {
      requireThat(Date.now()>=g.probeNotBefore,'V3_PROPAGATION_WAIT_REQUIRED');
      requireThat(stage==='probe-restored','V3_FIXED_RESTORED_AUTH_STAGE_REQUIRED');await authIsolation();
      for(const k of ['key-auth','basic-auth','jwt','hmac-auth','acls'])for(const positive of [true,false]){
        const route=g.probeRoutes[k==='acls'&&!positive?'acls-denied':k],requestPath=`${route.paths[0]}/credentials/live`,headers=restoredAuthProbeHeaders(k,g.inputs,requestPath,positive);
        const r=await once(`proxy-${k}-${positive?'positive':'negative'}`,path('toolbox/probes'),{routeId:route.id,input:{method:'GET',url:`http://${route.hosts[0]}${requestPath}`,headers},confirmed:true,confirm_name:route.name});
        const wanted=positive?200:k==='acls'?403:401;requireThat(r.status===wanted&&r.bodyReturned===false,'V3_EXACT_AUTH_PROXY_RESULT_REQUIRED_NO_RETRY');
        g.functionalVerification[k]='actual-restored-positive-negative-proxy-verified';h.save();
      }
    }
    g.stages[stage]={...g.stages[stage],state:'succeeded',finishedAt:new Date().toISOString(),configurationVerification:stage.startsWith('restore-')?'verified':'pending'};
    h.save();return ordinaryV3PublicSummary(g,stage,true);
  } catch(error) {
    const previous=g.stages[stage],finishedAt=new Date().toISOString();
    const failure=previous.failure??{observedAt:finishedAt,previousState:structuredClone(previous),error:privateOriginalError(error)};
    g.stages[stage]={...previous,state:'stopped-no-replay',finishedAt,failure};h.save();return ordinaryV3PublicSummary(g,stage,false);
  }
}

async function main() {
  const stage=process.argv[2];requireThat(ORDINARY_V3_STAGES.includes(stage)&&process.argv.length===3,'V3_EXACT_STAGE_ARGUMENT_REQUIRED');
  // Validate gates before any ReleaseHarness construction/private read.
  let attestation;try{attestation=JSON.parse(process.env.RELEASE_LAB_M11_CURRENT_ORDINARY_V3_DEPLOYMENT??'');}catch{deny('V3_DEPLOYMENT_JSON_REQUIRED');}
  ordinaryV3Gate(process.env,attestation,stage);
  const h=new ReleaseHarness('M11',{resume:true}),file=resolve(dirname(h.reportPath),`current-ordinary-v3-${stage}-original.json`);
  requireThat(!existsSync(file),'V3_ORIGINAL_PUBLIC_REPORT_EXISTS_NO_REPLAY');
  const certificate=stage==='init-fixtures'?{cert:rootPemFile(process.env.RELEASE_LAB_M11_V3_CERT_FILE),key:rootPemFile(process.env.RELEASE_LAB_M11_V3_KEY_FILE,true)}:undefined;
  const oauthTls=stage.includes('oauth')?restoredOAuthRequiresTLS(process.env,rootPemFile(process.env.RELEASE_LAB_M11_V3_CA_FILE??resolve(process.env.RELEASE_LAB_OAUTH2_TLS_BASE_DIRECTORY,'ca.pem'))):undefined;
  const result=await runOrdinaryV3Stage(h,stage,{attestation,certificate,oauthTls});mkdirSync(dirname(file),{recursive:true});
  const fd=openSync(file,'wx',0o600);try{writeFileSync(fd,JSON.stringify(result,null,2)+'\n');fsyncSync(fd);}finally{closeSync(fd);}
  console.log(JSON.stringify({passed:result.passed,stage,overallM11Accepted:false,sqlAeadVerification:'pending-root-readonly-worker',oauth2:result.functionalVerification.oauth2}));if(!result.passed)process.exitCode=1;
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href){try{await main();}catch{console.error(JSON.stringify({passed:false,errorCode:'V3_ACCEPTANCE_STOPPED_NO_REPLAY',privateDetailsRecorded:false}));process.exitCode=1;}}
