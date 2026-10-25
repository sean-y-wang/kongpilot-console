import { createHash } from 'node:crypto';
import { parse } from 'yaml';

const secretField={test(name){const compact=name.replace(/[^a-z\d]/gi,'').toLowerCase();if(['keyname','keynames','keyid','keyids','keyversion','credentialtype','credentialid','credentialids','secretid','secretids','tokenendpoint','tokenexpiration','tokentype','tokenexp','tokenexpirationtime','secretisbase64','enablepasswordgrant'].includes(compact))return false;return ['key','keys','token','tokensecret','authorization','csrf','csrftoken','accesstoken','refreshtoken','idtoken'].includes(compact)||/password|secret|privatekey|apikey|provisionkey/.test(compact);}};
const hash=value=>createHash('sha256').update(value).digest('hex');
const cookieValues=value=>value.split(';').flatMap(pair=>{const at=pair.indexOf('=');return at>0&&/^kongos_(?:portal_)?(?:access|refresh|csrf)$/.test(pair.slice(0,at).trim())?[pair.slice(at+1).trim()]:[];});
const packetMethods=['POST','PUT','PATCH','DELETE'];
const uuid=value=>typeof value==='string'&&/^[a-f\d]{8}-[a-f\d]{4}-[1-8][a-f\d]{3}-[89ab][a-f\d]{3}-[a-f\d]{12}$/i.test(value);
// A copied recovery receipt is transport metadata only when it can be bound
// to its original wire packet. Never classify UUIDs by their shape alone.
function transportPacket(reference,p){
 if(!p||reference.requests[p.index]!==p||!uuid(p.key)||!uuid(p.actorId)||!uuid(p.sessionId)||!uuid(p.clusterId)||!uuid(p.workspaceId)
  ||p.method!=='POST'||!p.path.startsWith(`/api/v1/clusters/${p.clusterId}/`)||p.bodySha256!==hash(JSON.stringify(p.body)))return false;
 const header=name=>Object.entries(p.headers??{}).filter(([k])=>k.toLowerCase()===name).map(([,v])=>v);
 const key=header('x-idempotency-key'),cookie=header('cookie'),csrf=header('x-csrf-token');
 try{if(new URLSearchParams(p.query).get('workspaceId')!==p.workspaceId)return false;}catch{return false;}
 return key.length===1&&key[0]===p.key&&cookie.length===1&&typeof cookie[0]==='string'&&cookie[0].length>0&&csrf.length===1&&typeof csrf[0]==='string'&&csrf[0].length>0;
}
function recoveryMetadataStructures(reference,histories){
 const result=new Map(),packets=reference.requests.filter(p=>transportPacket(reference,p));
 const bind=(node,p,kind)=>{if(node&&p)result.set(hash(JSON.stringify(node)),{key:p.key,kind});};
 const one=predicate=>{const matches=packets.filter(predicate);return matches.length===1?matches[0]:undefined;};
 for(const a of[reference,...histories]){
  const n=a.exportCommitContinuation?.newOperation;
  if(n?.purpose==='fresh-export-after-proven-original-expiry')bind(n,one(p=>p.key===n.key&&p.actorId===n.actorId&&p.sessionId===n.sessionId
   &&p.path===`/api/v1/clusters/${p.clusterId}/snapshots/${n.sourceSnapshotId}/export`
   &&packets.some(old=>old.key===n.originalExportKey&&old.path===p.path&&old.actorId===p.actorId&&old.sessionId===p.sessionId)),'original-export-transport-marker');
  for(const n of a.downloads??[])bind(n,one(p=>p.key===n.key&&p.state==='response_observed'&&p.status>=200&&p.status<300
   &&p.path===`/api/v1/clusters/${p.clusterId}/configuration/exports/${n.exportId}/download`&&uuid(n.jobId)&&n.mode==='deployment'
   &&typeof p.rawResponseText==='string'&&p.responseSha256===n.sha256&&hash(p.rawResponseText)===n.sha256
   &&p.responseByteCount===n.bytes&&Buffer.byteLength(p.rawResponseText)===n.bytes),'original-download-transport-marker');
  const d=a.downloadStatus201Continuation?.newDownload;
  if(d)bind(d,one(p=>p.key===d.key&&p.requestId===d.requestId&&p.responseByteCount===d.byteCount&&p.responseSha256===d.sha256
   &&(a.downloads??[]).some(n=>n.key===d.key&&n.jobId===d.jobId&&n.bytes===d.byteCount&&n.sha256===d.sha256)
   &&result.has(hash(JSON.stringify((a.downloads??[]).find(n=>n.key===d.key))))),'original-download-continuation-marker');
  const s=a.consumerRestoreReadonlyDiagnosis?.safe;
  if(s?.actual===true&&s.newBusinessWrites===0&&s.newAuthWrites===0&&s.newNativeWrites===0&&s.sql?.nonOwnerReadOnly===true)bind(s,one(p=>p.index===s.packetIndex&&p.key===s.key
   &&p.requestId===s.requestId&&p.status===s.status&&p.errorCode===s.errorCode&&p.clusterId===s.scope?.cid&&p.workspaceId===s.scope?.wid
   &&p.path===`/api/v1/clusters/${p.clusterId}/recycle-bin/${s.scope.entryId}/restore`),'original-restore-readonly-marker');
  for(const field of['deckSetContinuation','deckWireBodyContinuation']){
   const n=a[field]?.abandonAttempt;if(!n||!['prepared','completed'].includes(n.state))continue;
   bind(n,one(p=>p.key===n.key&&p.bodySha256===n.bodySha256&&JSON.stringify(p.body)===JSON.stringify(n.body)
    &&p.path===`/api/v1/clusters/${p.clusterId}/configuration/jobs/${n.originalJob?.id??n.originalJob?.jobId}/abandon`
    &&(n.actorId==null||n.actorId===p.actorId)&&(n.sessionId==null||n.sessionId===p.sessionId)
    &&(n.index==null||n.index===p.index)&&(n.requestId==null||n.requestId===p.requestId)
    &&(n.packetSha256==null||n.packetSha256===hash(JSON.stringify(p)))),'original-abandon-transport-marker');
  }
  const q=a.consumedReviewDownloadRecovery?.protectedReadProof,c=q?.currentReceipt;
  if(q?.readonlyOnly===true&&q.newWrites===0&&q.newNative===0&&q.status===200&&q.original181Unchanged===true
   &&c?.state==='succeeded'&&c.executionCompleted===true&&c.downloadPermitConsumed===true&&c.sessionMatches===true)
   bind(q,one(p=>p.key===q.key&&p.key===c.idempotencyKey&&p.state==='response_unknown'&&p.actorId===c.actorId&&p.clusterId===c.clusterId&&p.workspaceId===c.workspaceId
    &&p.path.endsWith('/download')&&a.consumedReviewDownloadRecovery.originalPacketSha256===hash(JSON.stringify(p))),'original-consumed-download-readonly-marker');
 }
 return result;
}
export const M8_LOG_SERVICES=Object.freeze(['kong','kong-secondary','kong-portal','console-api','console-web','portal-web','telemetry-collector','event-receiver','event-mail']);
export function m8SecretForms(values){return [...new Set(values.filter(v=>typeof v==='string'&&v.length>0).flatMap(v=>[v,JSON.stringify(v).slice(1,-1),encodeURIComponent(v),Buffer.from(v).toString('base64')]))];}

/** Public JWT issuers are excluded only through a complete, actual successful
 * Consumer/JWT create body and returned credential identity. Signing secrets
 * remain in every registry and every raw-state secret collection. */
export function m8PublicJwtIssuer(reference,value){
 const f=reference.nativeFixture,actor=reference.sessions?.admin;
 if(!f||value!==`${reference.testTag}-jwt`||value!==f.inputs?.jwt?.key)return false;
 const match=reference.requests.filter(p=>p.method==='POST'&&p.path===`/api/v1/clusters/${f.area.cid}/consumers/${f.consumer.id}/credentials/jwt`
  &&p.query===`?workspaceId=${f.area.wid}`&&p.clusterId===f.area.cid&&p.workspaceId===f.area.wid&&p.actorId===actor?.user?.id
  &&uuid(p.key)&&uuid(p.requestId)&&uuid(p.sessionId)&&p.sessionId===actor?.sid&&Number.isInteger(p.index)&&p.index>=0
  &&p.state==='response_observed'&&p.status===201&&p.body?.key===value&&p.body?.secret===f.inputs.jwt.secret
  &&p.bodySha256===hash(JSON.stringify(p.body))&&p.responseData?.entity?.id===f.credentials.jwt.id&&p.responseData.entity.consumer?.id===f.consumer.id
  &&(p.responseData.entity.key===value||/^\[REDACTED:[a-f\d]{16}\]$/.test(p.responseData.entity.key??''))
  &&p.responseData.entity.key===f.credentials.jwt.key&&typeof p.headers?.Cookie==='string'&&/(?:^|;\s*)kongos_access=[^;\s]+(?:;|$)/.test(p.headers.Cookie)&&typeof p.headers?.['X-CSRF-Token']==='string'
  &&p.headers['X-CSRF-Token'].length>0&&p.headers['X-Idempotency-Key']===p.key);
 return match.length===1;
}
export function m8PublicProxyMediaType(reference,value){
 if(value!=='application/json')return false;
 const f=reference.nativeFixture;
 return reference.proxyChecks?.some(p=>p.method==='POST'&&p.path===f?.routes?.oauth2?.proxyPath+'/oauth2/token'&&p.cid===f.area.cid&&p.wid===f.area.wid
  &&p.port===(p.tls?8443:8000)&&p.body?.grant_type==='client_credentials'&&p.body.client_id===f.inputs.oauth2.client_id
  &&p.body.client_secret===f.inputs.oauth2.client_secret&&p.bodySha256===hash(JSON.stringify(p.body))&&p.headers?.['Content-Type']===value
  &&['response_observed','response_unknown'].includes(p.state))===true;
}
/** Secret collection retains every original registry and every complete
 * history. Complete duplicate structures can share classification work only
 * in the same owner/body/response provenance. All raw files are still scanned. */
export function m8CapturedSecrets(reference,histories=[]){
 if(reference?.version!==1||reference.milestone!=='M8'||!Array.isArray(reference.secrets)||reference.secrets.some(v=>typeof v!=='string'||!v)
   ||!Array.isArray(histories)||histories.length>32||histories.some(v=>v?.version!==1||v.milestone!=='M8'||v.testTag!==reference.testTag))throw Error('M8_SCAN_REGISTRY_HISTORY_INVALID');
 const originalRegistry=new Set(reference.secrets),secrets=new Set(reference.secrets),digests=new WeakMap(),heights=new WeakMap(),active=new WeakSet(),unique=new Set();let bytes=0;
 function digest(value,depth=0){
  if(!value||typeof value!=='object'){const text=String(JSON.stringify(value));bytes+=Buffer.byteLength(text);if(bytes>160*1024*1024)throw Error('M8_SCAN_HISTORY_BYTE_BUDGET');return hash(typeof value+':'+text);}
  if(depth>64||active.has(value))throw Error('M8_SCAN_HISTORY_DEPTH_CYCLE');
  if(digests.has(value)){if(depth+heights.get(value)>64)throw Error('M8_SCAN_HISTORY_DEPTH_CYCLE');return digests.get(value);}
  active.add(value);const h=createHash('sha256').update(Array.isArray(value)?'array:':'object:');let height=0;
  for(const[name,child]of Object.entries(value)){const token=JSON.stringify(name);bytes+=Buffer.byteLength(token)+2;if(bytes>160*1024*1024)throw Error('M8_SCAN_HISTORY_BYTE_BUDGET');h.update(token).update(':').update(digest(child,depth+1)).update(';');if(child&&typeof child==='object')height=Math.max(height,1+heights.get(child));}
  const result=h.digest('hex');active.delete(value);digests.set(value,result);heights.set(value,height);unique.add(result);if(unique.size>200000)throw Error('M8_SCAN_HISTORY_UNIQUE_BUDGET');return result;
 }
 [reference,...histories].forEach(v=>digest(v));
 const originalPacket=new Map(reference.requests.map(p=>[hash(JSON.stringify(p)),p])),originalProxy=new Map((reference.proxyChecks??[]).map(p=>[hash(JSON.stringify(p)),p])),originalCli=new Map((reference.cliIntents??[]).map(p=>[hash(JSON.stringify(p)),p]));
 const actualResponseStructures=new Set(reference.requests.filter(p=>p.state==='response_observed'&&p.status>=200&&p.status<300)
  .flatMap(p=>[p.responseData,p.responseData?.entity]).filter(v=>v&&typeof v==='object').map(v=>hash(JSON.stringify(v))));
 const manualAttemptStructures=new Set(),recoveryMetadata=recoveryMetadataStructures(reference,histories),publicMetadata=new Map();
 for(const aggregate of [reference,...histories]){
  for(const journal of[aggregate.manualUiJournal,aggregate.independentManualPreparation?.originalManualJournal]){if(journal?.version!==1||journal.milestone!=='M8'||journal.source!=='manual-ui'
    ||journal.testTag!==reference.testTag||!Array.isArray(journal.attempts)||!journal.scope)continue;
  for(const attempt of journal.attempts){
   if(!attempt||attempt.role!=='admin'||!['prepared','acknowledged','succeeded','response_unknown'].includes(attempt.state)
    ||typeof attempt.rawBody!=='string'||attempt.bodySha256!==hash(attempt.rawBody))continue;
   let body,url;try{body=JSON.parse(attempt.rawBody);url=new URL(attempt.url);}catch{continue;}
   if(url.origin!=='http://127.0.0.1:8080'||url.hash||url.username||url.password||url.pathname!==attempt.path||url.search!==attempt.query
    ||attempt.clusterId!==journal.scope.cid||attempt.workspaceId!==journal.scope.wid
    ||attempt.actorId!==journal.sessions?.admin?.user?.id||attempt.sessionId!==journal.sessions.admin.sid
    ||JSON.stringify(body)!==JSON.stringify(attempt.body))continue;
   const matches=reference.requests.filter(p=>p.source==='manual-ui'&&p.manualIndex===attempt.index&&p.key===attempt.key&&p.method===attempt.method
    &&p.path===attempt.path&&p.query===attempt.query&&p.actorId===attempt.actorId&&p.sessionId===attempt.sessionId
    &&p.clusterId===attempt.clusterId&&p.workspaceId===attempt.workspaceId&&p.bodySha256===attempt.bodySha256
    &&JSON.stringify(p.body)===JSON.stringify(body)&&JSON.stringify(p.headers)===JSON.stringify(attempt.headers)
    &&p.headers?.['x-idempotency-key']===p.key&&typeof p.headers?.cookie==='string'&&p.headers.cookie.length>0
    &&typeof p.headers?.['x-csrf-token']==='string'&&p.headers['x-csrf-token'].length>0
    &&(attempt.state==='response_unknown'?p.state==='response_unknown'&&attempt.status==null&&attempt.requestId==null
      &&reference.consumedReviewDownloadRecovery?.originalPacketSha256===hash(JSON.stringify(p))
      &&recoveryMetadata.has(hash(JSON.stringify(reference.consumedReviewDownloadRecovery.protectedReadProof)))
      :attempt.state==='prepared'?attempt.status==null&&attempt.requestId==null:p.status===attempt.status&&p.requestId===attempt.requestId));
   if(matches.length===1)manualAttemptStructures.add(hash(JSON.stringify(attempt)));
  }
  }
 }
 const confidential=new Set(),f=reference.nativeFixture;
 const provenIssuer=m8PublicJwtIssuer(reference,f?.inputs?.jwt?.key);
 const issuerStructures=new Set(provenIssuer?[f.inputs.jwt,f.credentials.jwt,
  ...reference.requests.filter(p=>p.body?.key===f.inputs.jwt.key&&p.path.endsWith(`/consumers/${f.consumer.id}/credentials/jwt`)).flatMap(p=>[p.body,p.responseData?.entity])].filter(Boolean).map(v=>hash(JSON.stringify(v))):[]);
 const remember=(value,response=false,typedPublic=false)=>{if(typeof value==='string'&&value&&!(response&&/^\[REDACTED:[a-f\d]{16}\]$/.test(value))){secrets.add(value);if(!typedPublic)confidential.add(value);}};
 const aggregates=new WeakSet([reference,...histories]),seen=new Set(),pending=[reference,...histories].map(v=>[v,0,null,false,false]);let visits=0;
 while(pending.length){
  const[node,depth,owner,fromBody,fromResponse]=pending.pop();if(!node||typeof node!=='object')continue;
  if(depth>64)throw Error('M8_SCAN_HISTORY_DEPTH_CYCLE');const ctx=`${owner}:${fromBody}:${fromResponse}`,id=digests.get(node)+':'+ctx;if(seen.has(id))continue;
  if(++visits>200000)throw Error('M8_SCAN_HISTORY_UNIQUE_BUDGET');seen.add(id);
  if(Array.isArray(node)){for(const child of node)pending.push([child,depth+1,owner,fromBody,fromResponse]);continue;}
  const actualResponse=fromResponse||!fromBody&&actualResponseStructures.has(hash(JSON.stringify(node)));
  const packet=!fromBody&&!actualResponse&&originalPacket.get(hash(JSON.stringify(node))),proxy=!fromBody&&!actualResponse&&originalProxy.get(hash(JSON.stringify(node))),cli=!fromBody&&!actualResponse&&originalCli.get(hash(JSON.stringify(node)));
  const operation=!fromBody&&!fromResponse&&owner==='configurationOperations'&&reference.requests.find(p=>p.key===node.key&&p.actorId===node.actorId&&p.sessionId===node.sessionId
    &&p.clusterId===node.area?.cid&&p.workspaceId===node.area?.wid&&p.bodySha256===node.bodySha256&&p.method===node.method&&p.path.endsWith('/'+node.path));
  for(const[name,value]of Object.entries(node)){
   if(name==='secrets'&&Array.isArray(value)&&aggregates.has(node)){for(const v of value){if(typeof v!=='string'||!v||!originalRegistry.has(v))throw Error('M8_SCAN_HISTORY_SECRET_REGISTRY_INCOMPLETE');}}
   if(secretField.test(name)){
    const manualMetadata=owner==='attempts'&&!fromBody&&!fromResponse&&manualAttemptStructures.has(hash(JSON.stringify(node)));
    const recovery=!fromBody&&!actualResponse&&recoveryMetadata.get(hash(JSON.stringify(node)));
    const metadataKey=name==='key'&&!fromBody&&!fromResponse&&(packet||proxy||cli||operation||manualMetadata||recovery?.key===value);
    if(metadataKey&&recovery)publicMetadata.set(value,recovery.kind);
    const issuerKey=name==='key'&&provenIssuer&&value===f.inputs.jwt.key&&issuerStructures.has(hash(JSON.stringify(node)));
    if(!metadataKey)remember(value,actualResponse&&!fromBody,issuerKey);
    if(Array.isArray(value)&&!(name==='secrets'&&aggregates.has(node)))for(const entry of value)remember(entry,actualResponse&&!fromBody);
   }
   if(['cookie','Cookie'].includes(name)&&typeof value==='string')cookieValues(value).forEach(v=>remember(v));
   if(name==='responseCookies'&&Array.isArray(value)){
    for(const v of value){if(typeof v==='string')cookieValues(v.split(';')[0]).forEach(x=>remember(x));else if(v&&/^kongos_(?:portal_)?(?:access|refresh|csrf)$/.test(v.name))remember(v.value);else throw Error('M8_SCAN_COOKIE_HEADER_INVALID');}
   }
   if(name==='rawResponseText'&&packet&&packet.state==='response_observed'&&packet.status>=200&&packet.status<300&&packet.path.includes('/configuration/exports/')){
    if(typeof value!=='string'||!/^[a-f\d]{64}$/.test(packet.responseSha256??'')||packet.responseSha256!==hash(value)
      ||packet.responseByteCount!==Buffer.byteLength(value,'utf8'))throw Error('M8_SCAN_RAW_YAML_PROVENANCE_INVALID');
    const yaml=parse(value,{uniqueKeys:true,maxAliasCount:0});if(yaml?._format_version!=='1.1')throw Error('M8_SCAN_RAW_YAML_INVALID');
    // YAML belongs to a genuine one-time download response; secret fields stay
    // confidential even when passwords are native bcrypt hashes.
    const collect=[yaml];let n=0;while(collect.length){const item=collect.pop();if(++n>100000)throw Error('M8_SCAN_RAW_YAML_BUDGET');if(!item||typeof item!=='object')continue;for(const[k,v]of Object.entries(item)){if(secretField.test(k)){remember(v,false,k==='key'&&provenIssuer&&v===f.inputs.jwt.key&&item.id===f.credentials.jwt.id&&item.secret===f.inputs.jwt.secret);if(Array.isArray(v))for(const entry of v)remember(entry);}if(v&&typeof v==='object')collect.push(v);}}
   }
   if(value&&typeof value==='object'){
    const body=fromBody||name==='body'&&(!!packet||!!proxy||!!cli||['requests','attempts','originalHttpRequests'].includes(owner));
    const response=!body&&(actualResponse||(['responseData','receiptData','receipt'].includes(name)&&(['response_observed','succeeded','submitted'].includes(node.state)||owner==='configurationOperations')));
    pending.push([value,depth+1,name,body,response]);
   }
  }
 }
 const classifiedPublic=[];
 for(const[value,kind]of publicMetadata)if(!secrets.has(value))classifiedPublic.push({kind,sha256:hash(value)});
 for(const value of secrets){if(!confidential.has(value)&&(m8PublicJwtIssuer(reference,value)||m8PublicProxyMediaType(reference,value))){secrets.delete(value);classifiedPublic.push({kind:m8PublicJwtIssuer(reference,value)?'exact-created-jwt-issuer':'exact-OAuth-content-type',sha256:hash(value)});}}
 if(!secrets.size)throw Error('M8_SCAN_SECRET_REGISTRY_EMPTY');
 return {values:[...secrets],classifiedPublic,uniqueStructures:unique.size,semanticVisits:visits};
}
