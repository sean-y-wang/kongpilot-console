import { createHash } from 'node:crypto';
import { PRODUCTION_UI_ACTIONS, PRODUCTION_ENTITY_TYPES } from './production-ui-fixtures.mjs';
export const productionUuid = value => typeof value === 'string' && /^[a-f\d]{8}-[a-f\d]{4}-[1-5][a-f\d]{3}-[89ab][a-f\d]{3}-[a-f\d]{12}$/.test(value);
export const productionSha = value => createHash('sha256').update(typeof value === 'string' || Buffer.isBuffer(value) ? value : JSON.stringify(value)).digest('hex');
export function canonicalUi(value) {
  const normalize = input => Array.isArray(input) ? input.map(normalize) : input && typeof input === 'object' ? Object.fromEntries(Object.keys(input).sort().filter(key => input[key] !== undefined).map(key => [key,normalize(input[key])])) : input;
  return JSON.stringify(normalize(value));
}
const requireUi = (condition, code) => { if (!condition) throw Error(code); };
export function validateProductionHandoff(reference, report, reportBytes, now = Date.now()) {
  const h = reference?.uiHandoff, session = reference?.session;
  requireUi(reference?.version === 1 && reference.milestone === 'M0-M8-production-ui' && reference.phase === 'ready' && !reference.uiJournal && !reference.uiHistory && reference.inFlight == null, 'PRODUCTION_FRESH_UI_HANDOFF_REQUIRED');
  requireUi(h?.version === 1 && h.phase === 'ready' && h.exclusiveRuntimeOwner === 'production-ui' && h.testTag === reference.testTag
    && /^prod-ui-[a-f\d]{8}$/.test(h.testTag ?? '') && canonicalUi(h.approvedActions) === canonicalUi(PRODUCTION_UI_ACTIONS), 'PRODUCTION_EXACT_INTENTS_REQUIRED');
  let origin;try{origin=new URL(h.origin);}catch{throw Error('PRODUCTION_CANONICAL_ORIGIN_REQUIRED');}
  requireUi(origin.protocol === 'https:' && origin.origin === h.origin && !origin.username && !origin.password && !origin.search && !origin.hash && origin.port !== '8001'
    && productionUuid(h.clusterId) && productionUuid(h.workspaceId) && h.executionMode === 'direct' && h.isolatedAcceptanceCluster === true, 'PRODUCTION_HTTPS_ISOLATED_SCOPE_REQUIRED');
  requireUi(['artifacts/production/production-ui-handoff.json','artifacts/production/production-ui-handoff-unused-session.json','artifacts/production/production-ui-handoff-unused-preflight.json','artifacts/production/production-ui-handoff-safe-destinations.json'].includes(h.securityReportPath) && /^[a-f\d]{64}$/.test(h.securityReportSha256 ?? '')
    && productionSha(reportBytes) === h.securityReportSha256 && report?.allPassed === true && report.failed === 0 && report.unknownWrites === 0
    && report.testTag === h.testTag && report.origin === h.origin && report.clusterId === h.clusterId && report.workspaceId === h.workspaceId
    && report.actorId === session?.user?.id && report.sessionId === session?.sid && report.sessionExpiresAt === session?.expiresAt
    && report.m8ClosureComplete === true && report.productionHttpsVerified === true && report.freshScopeVerified === true, 'PRODUCTION_ACTUAL_HANDOFF_PROOF_REQUIRED');
  requireUi(session && productionUuid(session.user?.id) && productionUuid(session.sid) && typeof session.cookie === 'string' && typeof session.csrf === 'string' && session.csrf.length >= 16
    && session.currentSessionVerified === true && session.signedAccessVerified === true && session.currentUserProven === true && session.user.capabilities?.platformAdmin === true
    && Date.parse(session.expiresAt) - now >= 840000 && Date.parse(session.expiresAt)-now<=900000
    && typeof h.clusterLabel==='string' && h.clusterLabel.length>0 && typeof h.workspaceName==='string' && h.workspaceName.length>0, 'PRODUCTION_CURRENT_SIGNED_ADMIN_SESSION_REQUIRED');
  requireUi(Array.isArray(reference.requests) && reference.requests.every(row => !['prepared','response_unknown'].includes(row.state)) && Array.isArray(reference.secrets), 'PRODUCTION_OLD_UNKNOWN_BLOCKS_UI');
  requireUi(reference.pem && ['certificate','privateKey','caCertificate'].every(name => typeof reference.pem[name] === 'string' && reference.pem[name].includes('-----BEGIN ')), 'PRODUCTION_RAM_PEM_FIXTURE_REQUIRED');
  return {origin:h.origin,cid:h.clusterId,wid:h.workspaceId,tag:h.testTag,session:structuredClone(session),priorKeys:reference.requests.map(row=>row.key)};
}
export function createProductionUiJournal(config, now = Date.now()) {
  return {version:1,purpose:'production-ui-8-entities-34-plugins',phase:'active',origin:config.origin,cid:config.cid,wid:config.wid,tag:config.tag,
    actorId:config.session.user.id,sessionId:config.session.sid,session:structuredClone(config.session),priorKeys:[...config.priorKeys],actorProven:false,
    nextIndex:0,inFlight:null,armed:null,attempts:[],reviews:[],bindings:{},startedAt:new Date(now).toISOString(),stopCode:null};
}
export function stopProductionUi(journal, code, persist) {
  journal.phase='stopped-without-replay';journal.stopCode=code;persist(journal);throw Error(code);
}
export function proveProductionActor(journal, data) {
  requireUi(data?.user?.id === journal.actorId && data.user.capabilities?.platformAdmin === true && data.csrfToken === journal.session.csrf,'PRODUCTION_CURRENT_ACTOR_CHANGED');journal.actorProven=true;
}
export function revalidateProductionAuthority(journal,data,requestId,expectedVersion){
  requireUi(productionUuid(requestId)&&data?.user?.id===journal.actorId&&data.csrfToken===journal.session.csrf
    &&data.user.capabilities?.platformAdmin===true&&data.user.permissionsVersion===expectedVersion
    &&canonicalUi(data.user.capabilities)===canonicalUi(journal.session.user.capabilities),'PRODUCTION_CURRENT_UNCHANGED_AUTHORITY_REQUIRED');
  journal.currentPermissionsVersion=expectedVersion;journal.authorityRevalidations??=[];
  journal.authorityRevalidations.push({requestId,permissionsVersion:expectedVersion,capabilitiesSha256:productionSha(canonicalUi(data.user.capabilities)),sameActor:true,currentSessionAccepted:true});
}
export function armProductionUi(journal, expected, persist) {
  requireUi(journal.phase==='active' && journal.inFlight==null && journal.armed==null && expected.action === PRODUCTION_UI_ACTIONS[journal.nextIndex], 'PRODUCTION_ONLY_NEXT_UNUSED_INTENT');
  requireUi(['POST','PATCH','DELETE'].includes(expected.method) && PRODUCTION_ENTITY_TYPES.includes(expected.entityType) && ['create','update','delete','restore'].includes(expected.mutationAction), 'PRODUCTION_CANONICAL_ENTITY_WRITE_REQUIRED');
  const prefix=`/api/v1/clusters/${journal.cid}/`, entityPrefix=`${prefix}entities/${expected.entityType}`;
  requireUi(expected.path === entityPrefix && expected.method==='POST' && expected.mutationAction==='create'
    || expected.path===`${entityPrefix}/${expected.entityId}` && productionUuid(expected.entityId) && (expected.method==='PATCH'&&expected.mutationAction==='update'||expected.method==='DELETE'&&expected.mutationAction==='delete')
    || expected.path===`${prefix}recycle-bin/${expected.entryId}/restore` && productionUuid(expected.entryId) && expected.method==='POST' && expected.mutationAction==='restore', 'PRODUCTION_UNEXPECTED_WRITE_ROUTE');
  requireUi(expected.body && typeof expected.body==='object' && !Array.isArray(expected.body), 'PRODUCTION_EXACT_EXPECTED_BODY_REQUIRED');
  if (expected.entityType==='plugins' && ['create','update'].includes(expected.mutationAction)) {
    requireUi(expected.body.enabled===false && expected.body.name && expected.body.name===expected.pluginName, 'PRODUCTION_PLUGIN_MUST_STAY_DISABLED');
    const isolated=journal.bindings.services?.id;
    if (expected.pluginSweep === true) requireUi(expected.pluginName==='kubernetes-sidecar-injector'
      ? !expected.body.service && !expected.body.route && !expected.body.consumer
      : productionUuid(isolated) && expected.body.service?.id===isolated && !expected.body.route && !expected.body.consumer, 'PRODUCTION_PLUGIN_UNROUTED_BINDING_REQUIRED');
  }
  journal.armed=structuredClone(expected); persist(journal);
}
export function proveProductionIsolation(journal,packet,data,requestId,persist,now=Date.now()){
  const url=new URL(packet.url),id=journal.bindings.services?.id;
  requireUi(productionUuid(id)&&packet.method==='GET'&&url.origin===journal.origin&&url.pathname===`/api/v1/clusters/${journal.cid}/entities/services/${id}`&&url.search===`?workspaceId=${journal.wid}`&&productionUuid(requestId)
    &&data?.entity?.id===id&&Array.isArray(data.relations?.routes?.items)&&data.relations.routes.items.length===0&&data.relations.routes.nextCursor==null&&!['forbidden','missing'].includes(data.relations.routes.availability),'PRODUCTION_UNROUTED_SERVICE_READBACK_REQUIRED');
  journal.isolation={serviceId:id,requestId,observedAt:new Date(now).toISOString()};persist(journal);
}
export function armProductionUiToggle(journal,enabled,persist,now=Date.now()){
  const action=enabled?'bindings.service.enable':'bindings.service.disable',id=journal.bindings['plugin:rate-limiting']?.id,entity=journal.bindings['plugin:rate-limiting']?.entity;
  requireUi(journal.phase==='active'&&journal.inFlight==null&&journal.armed==null&&PRODUCTION_UI_ACTIONS[journal.nextIndex]===action&&productionUuid(id)
    &&entity?.name==='rate-limiting'&&entity.service?.id===journal.bindings.services?.id&&!entity.route&&!entity.consumer
    &&journal.isolation?.serviceId===entity.service.id&&now-Date.parse(journal.isolation.observedAt)>=0&&now-Date.parse(journal.isolation.observedAt)<=30000,'PRODUCTION_ONLY_UNROUTED_LOCAL_TOGGLE_ALLOWED');
  journal.armed={action,method:'POST',path:`/api/v1/clusters/${journal.cid}/plugin-center/instances/${id}/toggle`,body:{enabled},entityType:'plugins',entityId:id,mutationAction:'update',pluginName:'rate-limiting',toggle:true,isolatedServiceId:entity.service.id};persist(journal);
}
export function packetForProductionUi(request, headers) { return {method:request.method(),url:request.url(),rawBody:request.postData(),headers}; }
function requestIdentity(journal, packet, cookies, now) {
  const url=new URL(packet.url), headers=Object.fromEntries(Object.entries(packet.headers??{}).map(([key,value])=>[key.toLowerCase(),value])), key=headers['x-idempotency-key'];
  requireUi(url.origin===journal.origin && url.pathname.startsWith('/api/v1/clusters/'+journal.cid+'/') && url.searchParams.getAll('workspaceId').length===1 && url.searchParams.get('workspaceId')===journal.wid && [...url.searchParams.keys()].every(name=>name==='workspaceId') && !url.hash, 'PRODUCTION_PACKET_FOREIGN_SCOPE');
  requireUi(journal.actorProven && Date.parse(journal.session.expiresAt)>now && productionUuid(key) && !journal.priorKeys.includes(key) && ![...journal.attempts,...journal.reviews].some(row=>row.key===key)
    && headers['x-csrf-token']===journal.session.csrf && typeof packet.rawBody==='string' && packet.rawBody.length<=1024*1024, 'PRODUCTION_ORIGINAL_KEY_SESSION_BODY_REQUIRED');
  const expectedCookies=new Map(journal.session.cookie.split('; ').map(pair=>{const at=pair.indexOf('=');return[pair.slice(0,at),pair.slice(at+1)];}));
  for (const name of ['kongos_access','kongos_refresh','kongos_csrf']) {
    const matching=cookies.filter(row=>row.name===name && new URL(journal.origin).hostname === row.domain.replace(/^\./,''));
    requireUi(matching.length===1 && matching[0].value===expectedCookies.get(name) && matching[0].secure===true && matching[0].path===(name==='kongos_refresh'?'/api/v1/auth':'/api'), 'PRODUCTION_ORIGINAL_COOKIE_JAR_REQUIRED');
    const actual=(headers.cookie??'').split('; ').filter(pair=>pair.startsWith(name+'='));
    // Refresh path restricts its transport to /api/v1/auth; it is present in the
    // context jar but must not be widened or artificially added to entity writes.
    if (name!=='kongos_refresh') requireUi(actual.length===1 && actual[0]===`${name}=${expectedCookies.get(name)}`, 'PRODUCTION_ORIGINAL_COOKIE_HEADER_REQUIRED');
    else requireUi(actual.length===0,'PRODUCTION_REFRESH_COOKIE_CANNOT_BE_WIDENED');
  }
  requireUi(!headers.authorization,'PRODUCTION_EXTRA_AUTHORIZATION_FORBIDDEN');
  return {url,headers,key,body:JSON.parse(packet.rawBody)};
}
export function beforeProductionUiPacket(journal, packet, cookies, persist, now=Date.now()) {
  if (journal.phase==='stopped-without-replay') throw Error('PRODUCTION_UNKNOWN_GLOBAL_STOP');
  try {
    const identity=requestIdentity(journal,packet,cookies,now), {url,key,body,headers}=identity;
    const review=packet.method==='POST' && url.pathname===`/api/v1/clusters/${journal.cid}/authorization/entity-capabilities`;
    if (review) {
      requireUi(journal.reviews.length<1024 && Object.keys(body).join()==='entities' && Array.isArray(body.entities) && body.entities.length>=1 && body.entities.length<=50
        && body.entities.every(row=>Object.keys(row).sort().join()==='id,type' && PRODUCTION_ENTITY_TYPES.includes(row.type) && productionUuid(row.id)), 'PRODUCTION_EXACT_READONLY_CAPABILITY_QUERY');
    } else requireUi(journal.phase==='active' && journal.armed && journal.inFlight==null && packet.method===journal.armed.method && url.pathname===journal.armed.path && canonicalUi(body)===canonicalUi(journal.armed.body), 'PRODUCTION_ONLY_ARMED_DOM_WRITE');
    const row={index:review?journal.reviews.length:journal.nextIndex,category:review?'readonly-authorization-review':'dom-business',action:review?'entity-capabilities':journal.armed.action,
      method:packet.method,path:url.pathname,query:url.search,key,rawBody:packet.rawBody,body,bodySha256:productionSha(packet.rawBody),headers,actorId:journal.actorId,sessionId:journal.sessionId,clusterId:journal.cid,workspaceId:journal.wid,state:'prepared',startedAt:new Date(now).toISOString(),...(review?{}:{expected:structuredClone(journal.armed)})};
    if(review)journal.reviews.push(row);else{journal.attempts.push(row);journal.inFlight=row.index;journal.armed=null;}
    // The caller must fsync a 0600 atomic private journal before route.continue.
    persist(journal);return row;
  } catch(error) { journal.phase='stopped-without-replay';journal.stopCode='before-packet-not-durable-or-contract';try{persist(journal);}catch{}throw error; }
}
export function productionAttemptFor(journal,packet) {const url=new URL(packet.url), key=Object.entries(packet.headers??{}).find(([name])=>name.toLowerCase()==='x-idempotency-key')?.[1];return [...journal.attempts,...journal.reviews].find(row=>row.key===key&&row.method===packet.method&&row.path===url.pathname&&row.query===url.search&&row.rawBody===packet.rawBody);}
export function observeProductionUiAck(journal, attempt, result, persist) {
  try {
    requireUi(attempt?.state==='prepared', 'PRODUCTION_RESPONSE_WITHOUT_ORIGINAL_ATTEMPT');
    attempt.status=result.status;attempt.requestId=result.requestId;attempt.responseData=structuredClone(result.data);
    requireUi(result.status>=200 && result.status<300 && productionUuid(result.requestId), 'PRODUCTION_RESPONSE_NOT_SAFE_SUCCESS');
    if(attempt.category==='readonly-authorization-review') {requireUi(Array.isArray(result.data?.items)&&result.data.permissionsVersion===(journal.currentPermissionsVersion??journal.session.user.permissionsVersion),'PRODUCTION_CAPABILITY_RESPONSE_CHANGED');attempt.state='succeeded';}
    else {const e=attempt.expected;if(e.mutationAction==='delete')requireUi(productionUuid(result.data?.entryId)&&result.data.state==='deleted','PRODUCTION_ARCHIVE_NOT_PROVEN');
      else if(e.mutationAction==='restore')requireUi(result.data?.entryId===e.entryId&&result.data.state==='restored'&&result.data.entity?.id===e.entityId,'PRODUCTION_RESTORE_NOT_PROVEN');
      else requireUi(productionUuid(result.data?.entity?.id)&&(!e.entityId||result.data.entity.id===e.entityId),'PRODUCTION_ENTITY_ACK_NOT_PROVEN');
      if(e.entityType==='plugins'&&['create','update'].includes(e.mutationAction))requireUi(result.data.entity.enabled===(e.toggle?e.body.enabled:false)&&result.data.entity.name===e.pluginName&&(!e.toggle||result.data.entity.service?.id===e.isolatedServiceId&&!result.data.entity.route&&!result.data.entity.consumer),'PRODUCTION_PLUGIN_ENABLED_OR_DIFFERENT');
      attempt.state='acknowledged';}
    persist(journal);
  } catch(error) {if(attempt)attempt.state='response_unknown';journal.phase='stopped-without-replay';journal.stopCode='response-not-proven';try{persist(journal);}catch{}throw error;}
}
export function productionReceiptPath(journal,attempt) {return `/api/v1/clusters/${journal.cid}/mutations/by-key/${attempt.key}?workspaceId=${journal.wid}`;}
export function confirmProductionUiReceipt(journal,attempt,packet,data,requestId,persist) {
  try {
    const url=new URL(packet.url),e=attempt?.expected,entityId=e?.entityId??attempt?.responseData?.entity?.id;
    requireUi(journal.phase==='active'&&attempt?.state==='acknowledged'&&packet.method==='GET'&&url.origin===journal.origin&&url.pathname+url.search===productionReceiptPath(journal,attempt)&&productionUuid(requestId), 'PRODUCTION_ORIGINAL_RECEIPT_GET_REQUIRED');
    requireUi(productionUuid(data?.id)&&data.actor_id===journal.actorId&&data.cluster_id===journal.cid&&data.workspace_id===journal.wid&&data.entity_type===e.entityType&&data.entity_id===entityId&&data.action===e.mutationAction
      &&data.state==='succeeded'&&data.remote_completed===true&&data.remote_started===true&&!data.error_code,'PRODUCTION_ORIGINAL_TERMINAL_RECEIPT_REQUIRED');
    if(e.mutationAction==='delete')requireUi(data.safe_result?.entryId===attempt.responseData.entryId&&data.safe_result.state==='deleted','PRODUCTION_ARCHIVE_RECEIPT_MISMATCH');
    else if(e.mutationAction==='restore')requireUi(data.safe_result?.entryId===e.entryId&&data.safe_result.state==='restored'&&data.safe_result.entity?.id===entityId,'PRODUCTION_RESTORE_RECEIPT_MISMATCH');
    else requireUi((data.safe_result?.entity??data.safe_result)?.id===entityId,'PRODUCTION_ENTITY_RECEIPT_MISMATCH');
    attempt.receiptId=data.id;attempt.receiptRequestId=requestId;attempt.receipt=structuredClone(data);attempt.state='succeeded';journal.nextIndex++;journal.inFlight=null;
    if(journal.nextIndex===PRODUCTION_UI_ACTIONS.length)journal.phase='complete';persist(journal);
  }catch(error){journal.phase='stopped-without-replay';journal.stopCode='original-receipt-not-proven';try{persist(journal);}catch{}throw error;}
}
export function productionUiSecrets(value, output=new Set(), path=[]) {
  if(!value||typeof value!=='object')return output;
  for(const[name,item]of Object.entries(value)) {
    if(typeof item==='string' && (/^(password|secret|token|csrf|csrfToken|accessToken|refreshToken|client_secret|provision_key|apikey|aws_key|aws_secret|privateKey)$/i.test(name)||name==='key'&&(item.includes('-----BEGIN ')||path.includes('config')))) {if(item.length&&!/^\[REDACTED/.test(item))output.add(item);}
    else if(item&&typeof item==='object')productionUiSecrets(item,output,[...path,name]);
  }return output;
}
