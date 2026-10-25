import assert from 'node:assert/strict';
import {createHash,createHmac,randomBytes,randomUUID} from 'node:crypto';
import {existsSync,mkdirSync,readFileSync,writeFileSync} from 'node:fs';
import {dirname,resolve} from 'node:path';
import {ReleaseHarness,releaseScope} from './lib/release-harness.mjs';

// Source script only until Root explicitly runs one stage against the isolated
// actual BFF. Private credentials never leave the original M11 RAM ledger.
// A failed/unknown write is never relabelled, retried, or given a new key.
assert.equal(process.env.RELEASE_LAB_M11_ALL_CREDENTIALS_READY,'true');
const stage=process.argv[2];
assert(['prepare-five-credentials','prepare-five-credentials-after-schema-fix','delete-consumer','restore-consumer'].includes(stage));
if(stage==='prepare-five-credentials-after-schema-fix'){
  const proof=JSON.parse(readFileSync(resolve('artifacts/M11/gate3-five-credential-prepare-no-send-proof-attempt1.json'),'utf8'));
  assert.equal(proof.nativeRequestsSent,0);assert.deepEqual(proof.rows,[{intents:0,mutations:0,executions:0}]);
}
const attempt=Number(process.argv[3]??1);assert(Number.isSafeInteger(attempt)&&attempt>=1&&attempt<=2,'EXPLICIT_SUPPORTED_ATTEMPT_REQUIRED');
if(attempt===2){
  assert.equal(stage,'prepare-five-credentials');
  const original=JSON.parse(readFileSync(resolve(`artifacts/M11/gate3-all-credentials-${stage}-http-attempt1.json`),'utf8'));
  const recovery=JSON.parse(readFileSync(resolve('artifacts/M11/auth-runtime-exit-recovery-attempt1.json'),'utf8'));
  assert.equal(original.passed,false);assert.equal(original.requests.length,0,'ORIGINAL_BUSINESS_WRITES_MUST_BE_ABSENT');
  assert.equal(recovery.originalSessionRefreshUnchanged,true);assert.equal(recovery.rotationsSinceUnknown,0);assert.equal(recovery.freshActualLogin,true);
}
const reportPath=resolve(`artifacts/M11/gate3-all-credentials-${stage}-http-attempt${attempt}.json`);
assert(!existsSync(reportPath),'ORIGINAL_REPORT_EXISTS');
const h=new ReleaseHarness('M11',{resume:true}),cid=h.state.cid,wid=h.state.wid,admin=h.state.sessions.admin,fixtures=h.state.gate2?.fixtures;
assert(fixtures?.consumer?.id&&fixtures?.credential?.id&&fixtures?.key&&fixtures?.route?.id&&admin);
const g=h.state.gate3AllCredentials??={intents:{},writeKeys:{},checks:[],proxyBodies:{},proxyReceipts:{},authEndpointValidation:{
  'key-auth':'pending-actual-proxy','basic-auth':'pending-dedicated-approved-route-and-plugin',jwt:'pending-dedicated-approved-route-and-plugin',
  'hmac-auth':'pending-dedicated-approved-route-and-plugin',acls:'pending-dedicated-approved-route-and-plugin',oauth2:'pending-actual-TLS-token-chain'}};
const kinds=['key-auth','basic-auth','jwt','oauth2','hmac-auth','acls'];
const dao={'key-auth':'keyauth_credentials','basic-auth':'basicauth_credentials',jwt:'jwt_secrets',oauth2:'oauth2_credentials','hmac-auth':'hmacauth_credentials',acls:'acls'};
const plugin={'key-auth':'key-auth','basic-auth':'basic-auth',jwt:'jwt',oauth2:'oauth2','hmac-auth':'hmac-auth',acls:'acl'};
const expectedFields={'key-auth':['key'],'basic-auth':['username','password'],jwt:['key','secret','algorithm'],oauth2:['name','client_id','client_secret','redirect_uris'],'hmac-auth':['username','secret'],acls:['group']};
const scope=(suffix,extra={})=>releaseScope(cid,wid,suffix,extra);
const digest=value=>createHash('sha256').update(JSON.stringify(value)).digest('hex');
const code=value=>typeof value==='string'&&/^[A-Z][A-Z0-9_]{1,127}$/.test(value)?value:undefined;

function check(condition,name,facts={}){assert(condition,name);const item={stage,name,passed:true,...facts};g.checks.push(item);h.check(condition,name,{stage,...facts});}
function report(passed){
  const stageKeys=new Set(Object.entries(g.writeKeys).filter(([label])=>label.startsWith(`m11-all-creds-${stage}-`)).map(([,key])=>key));
  const requests=h.state.requests.filter(packet=>stageKeys.has(packet.key)).map(packet=>({
    method:packet.method,path:packet.path.split('?')[0],key:packet.key,state:packet.state,status:packet.status,requestId:packet.requestId,
    ...(code(packet.errorCode)?{errorCode:packet.errorCode}:{}),bodyHash:packet.bodyHash,responseHash:packet.responseHash}));
  const body={passed,stage,attempt,milestone:'M11',environment:'isolated actual Kong OSS 1.5.x via authenticated BFF',sourceOnly:false,productionDeployment:false,
    overallM11Accepted:false,credentialsRecorded:false,checks:g.checks.filter(item=>item.stage===stage),requests,
    originalCredentialIds:g.credentialIds??null,authEndpointValidation:{...g.authEndpointValidation},
    limitations:['OAuth2 credential storage and original-ID restoration do not prove HTTPS token issuance or OAuth login.',
      'Basic/JWT/HMAC/ACL proxy authentication remains pending until dedicated routes/plugins are created through new approved typed intents and actual positive/negative probes run.'],
    ...(!passed?{errorCode:'M11_ALL_CREDENTIALS_HTTP_STOPPED'}:{})};
  mkdirSync(dirname(reportPath),{recursive:true});writeFileSync(reportPath,JSON.stringify(body,null,2)+'\n',{flag:'wx'});
}
async function once(label,path,method,body){
  const key=g.writeKeys[label]??=randomUUID();h.save();
  // h.once labels only successful requests. Pin the original key ourselves so
  // a crash/error before label persistence cannot cause a second wire request.
  const original=h.state.requests.filter(packet=>packet.key===key);
  if(original.length){assert.equal(original.length,1,'ONE_ORIGINAL_REQUEST_REQUIRED');const packet=original[0];
    assert(packet.label===label&&packet.state==='response_observed'&&packet.status>=200&&packet.status<300,'ORIGINAL_WRITE_NOT_SUCCESSFUL_NO_REPLAY');}
  return h.once(label,admin,path,method,body,{key});
}
async function prerequisites(){
  const cluster=(await h.request(admin,`/clusters/${cid}`)).data;
  assert(/^1\.5\.\d+$/.test(cluster.version),'ACTUAL_KONG15_REQUIRED');assert.equal(cluster.execution_mode,'approval');
  assert(Array.isArray(cluster.enabled_plugins),'ACTUAL_ENABLED_PLUGIN_LIST_REQUIRED');
  for(const kind of kinds)assert(cluster.enabled_plugins.includes(plugin[kind]),'REQUIRED_REAL_PLUGIN_NOT_ENABLED');
  for(const kind of kinds){
    // BFF accepts its fixed credential kind and maps it to the Kong1.5 DAO;
    // neither the BFF nor this script invents a modern plugin-schema path.
    const schema=(await h.request(admin,scope(`schemas/${kind}`))).data;
    const fields=Array.isArray(schema.fields)?Object.assign({},...schema.fields):schema.fields;
    assert(fields&&typeof fields==='object','ACTUAL_DAO_SCHEMA_FIELDS_REQUIRED');
    for(const field of expectedFields[kind])assert(Object.hasOwn(fields,field),'ACTUAL_CREDENTIAL_FIELD_REQUIRED');
    if(kind==='jwt'&&fields.algorithm.one_of)assert(fields.algorithm.one_of.includes('HS256'),'ACTUAL_HS256_SCHEMA_REQUIRED');
    g.schemaEvidence??={};g.schemaEvidence[kind]={dao:dao[kind],schemaHash:digest(schema),fieldNames:Object.keys(fields)};h.save();
  }
}
async function ids(kind){
  // The isolated fixture has one entity per DAO. Inspect one real cursor page
  // and require EOF; unexpected extra records or cursors stop before mutation.
  const result=(await h.request(admin,scope(`consumers/${fixtures.consumer.id}/credentials/${kind}`,{size:'20'}))).data;
  assert(Array.isArray(result.items),'ACTUAL_CREDENTIAL_PAGE_REQUIRED');assert(!result.nextCursor,'ISOLATED_CREDENTIAL_PAGE_NOT_COMPLETE');
  return result.items.map(item=>item.id).sort();
}
async function wholeIds(){const result={};for(const kind of kinds)result[kind]=await ids(kind);return result;}
async function voteAndExecute(record,label,count,deleting=false){
  record.submitBody??={revision:record.receipt.revision,materialHmac:record.receipt.materialHmac,confirmed:true,confirm_name:'native-change'};h.save();
  record.workflowId=(await once(`m11-all-creds-${label}-submit`,scope(`entity-changes/${record.id}/submit`),'POST',record.submitBody)).data.workflowId;h.save();
  for(const [index,reviewer]of ['a','b','c'].entries()){
    const view=(await h.request(admin,scope(`workflows/${record.workflowId}`))).data.entity;assert.equal(view.state,'pending');
    const active=view.approval.stages.find(item=>item.state==='active');assert(active,'ACTUAL_ACTIVE_APPROVAL_STAGE_REQUIRED');
    record.votes??={};record.votes[reviewer]??={revision:view.revision,planHash:view.planHash,confirmed:true,confirm_name:'native-change',execute:false,
      level:active.level,stageRevision:active.revision,candidateVersion:view.approval.candidateVersion};h.save();
    // Each real reviewer uses its own actual session; no administrator vote,
    // fabricated decision, reused approval set or automatic execution occurs.
    const labelKey=`m11-all-creds-${label}-vote-${reviewer}`,key=g.writeKeys[labelKey]??=randomUUID();h.save();
    const prior=h.state.requests.filter(packet=>packet.key===key);if(prior.length)assert(prior.length===1&&prior[0].label===labelKey&&prior[0].state==='response_observed'&&prior[0].status>=200&&prior[0].status<300,'ORIGINAL_VOTE_NOT_SUCCESSFUL_NO_REPLAY');
    await h.once(labelKey,h.state.sessions[reviewer],scope(`workflows/${record.workflowId}/approve`),'POST',record.votes[reviewer],{key});
    assert.equal((await h.request(admin,scope(`workflows/${record.workflowId}`))).data.entity.state,index===2?'approved':'pending');
  }
  const approved=(await h.request(admin,scope(`workflows/${record.workflowId}`))).data.entity;assert.equal(approved.state,'approved');assert.equal(approved.capabilities.execute,true);
  record.executeBody??={revision:approved.revision,planHash:approved.planHash,confirmed:true,confirm_name:'native-change'};h.save();
  const receipt=(await once(`m11-all-creds-${label}-execute`,scope(`workflows/${record.workflowId}/execute`),'POST',record.executeBody)).data;
  record.executionId=receipt.executionId;record.executionReceipt=receipt;h.save();assert.equal(receipt.state,'succeeded');assert(receipt.baselineId);
  const detail=(await h.request(admin,scope(`workflows/${record.workflowId}`))).data;
  assert.equal(detail.entity.state,'succeeded');assert.equal(detail.nativeChange.packets.length,count);
  for(const packet of detail.nativeChange.packets){assert.equal(packet.state,'succeeded');assert(deleting?packet.nativeStatus===204:packet.nativeStatus>=200&&packet.nativeStatus<300);}
  assert.equal(detail.nativeChange.baseline.nativeAuthority,false);assert.equal(detail.nativeChange.baseline.baseline.baselineId,receipt.baselineId);
  assert.equal(detail.nativeChange.baseline.baseline.objectCount,count===5?6:7,'COMPLETE_ACTUAL_BASELINE_OBJECT_COUNT_REQUIRED');
  // This is the actual historical baseline DTO, not a reconstructed local
  // graph or native permit. Original private recovery contents remain server-side.
  record.baselineId=receipt.baselineId;record.nativePacketCount=count;record.historyHash=digest(detail.nativeChange.baseline);h.save();return detail;
}
async function prepare(record,label){record.receipt=(await once(`m11-all-creds-${label}-prepare`,scope('entity-changes/prepare'),'POST',record.body)).data;record.id=record.receipt.id;h.save();return record.receipt;}
async function probe(label,expected,route=fixtures.route,headers={apikey:fixtures.key}){
  for(let index=0;index<60;index++){
    const name=`m11-all-creds-${label}-proxy-${index}`;
    g.proxyBodies[name]??={routeId:route.id,input:{method:'GET',url:`http://${route.hosts[0]}${route.paths[0]}/credentials/live`,headers},confirmed:true,confirm_name:route.name};h.save();
    const result=(await once(name,scope('toolbox/probes'),'POST',g.proxyBodies[name])).data;
    g.proxyReceipts[name]={status:result.status,observedAt:result.observedAt,timingSource:result.timingSource};h.save();
    if(result.status===expected)return result;assert([200,401,403,404,502,503,504].includes(result.status),'UNEXPECTED_ACTUAL_PROXY_STATUS');
    await new Promise(resolve=>setTimeout(resolve,200));
  }throw Error('ACTUAL_PROXY_PROPAGATION_TIMEOUT');
}
function makeAuthProbePlans(){
  // These are unsubmitted typed plans. A new approved route must first yield
  // its actual ID; only then may a separate plugin typed intent bind that ID.
  // Creating credentials alone never enables an authentication plugin.
  return Object.fromEntries(['basic-auth','jwt','hmac-auth','acls'].map(kind=>[kind,{routeChange:{kind:'entity',action:'create',entityType:'routes',body:{
    name:`${h.state.tag}-allcreds-${kind}`,service:{id:fixtures.service.id},protocols:['http'],hosts:[`${h.state.tag}-${kind}.invalid`],paths:[`/${h.state.tag}-allcreds-${kind}`],tags:['team:m11-acceptance','owner:m11-acceptance']}},
    pluginTemplate:{name:plugin[kind],config:kind==='jwt'?{claims_to_verify:['exp'],key_claim_name:'iss'}:kind==='hmac-auth'?{algorithms:['hmac-sha256'],enforce_headers:['date','request-line']}:kind==='acls'?{whitelist:[g.privateInputs.acls.group]}:{hide_credentials:true}},
    state:'pending-new-typed-route-and-plugin-intents'}]));
}
async function verifyRegisteredAuthProbe(kind,route,label){
  // Optional function for Root's later explicit invocation after separate
  // actual typed route/plugin executions. It is not run in the three stages.
  assert(g.authProbeFixtures?.[kind]?.routeId===route.id&&g.authProbeFixtures[kind].routeWorkflowId&&g.authProbeFixtures[kind].pluginWorkflowId,'NEW_APPROVED_AUTH_FIXTURES_REQUIRED');
  const raw=g.privateInputs[kind],valid={apikey:fixtures.key},invalid={apikey:fixtures.key};
  if(kind==='basic-auth'){valid.authorization=`Basic ${Buffer.from(`${raw.username}:${raw.password}`).toString('base64')}`;invalid.authorization=`Basic ${Buffer.from(`${raw.username}:invalid-${randomBytes(12).toString('hex')}`).toString('base64')}`;}
  else if(kind==='jwt'){
    const unsigned=`${Buffer.from(JSON.stringify({alg:'HS256',typ:'JWT'})).toString('base64url')}.${Buffer.from(JSON.stringify({iss:raw.key,exp:Math.floor(Date.now()/1000)+120})).toString('base64url')}`;
    valid.authorization=`Bearer ${unsigned}.${createHmac('sha256',raw.secret).update(unsigned).digest('base64url')}`;
    invalid.authorization=`Bearer ${unsigned}.${createHmac('sha256',randomBytes(32)).update(unsigned).digest('base64url')}`;
  }else if(kind==='hmac-auth'){
    const date=new Date().toUTCString(),requestPath=`${route.paths[0]}/credentials/live`,signed=`date: ${date}\nGET ${requestPath} HTTP/1.1`;
    valid.date=date;invalid.date=date;valid.authorization=`hmac username="${raw.username}", algorithm="hmac-sha256", headers="date request-line", signature="${createHmac('sha256',raw.secret).update(signed).digest('base64')}"`;
    invalid.authorization=`hmac username="${raw.username}", algorithm="hmac-sha256", headers="date request-line", signature="${randomBytes(32).toString('base64')}"`;
  }else if(kind==='acls'){
    // ACL's negative must be a separately approved route/plugin with a real
    // nonmatching group, not a synthetic header or success-shaped response.
    assert(g.authProbeFixtures.acls.deniedRoute&&g.authProbeFixtures.acls.deniedPluginWorkflowId,'REAL_ACL_NEGATIVE_ROUTE_REQUIRED');
    await probe(`${label}-acl-allowed`,200,route,valid);await probe(`${label}-acl-denied`,403,g.authProbeFixtures.acls.deniedRoute,invalid);
    g.authEndpointValidation.acls='actual-positive-and-negative-proxy-verified';h.save();return;
  }else throw Error('UNSUPPORTED_AUTH_PROXY_FUNCTION');
  await probe(`${label}-${kind}-valid`,200,route,valid);await probe(`${label}-${kind}-invalid`,401,route,invalid);
  g.authEndpointValidation[kind]='actual-positive-and-negative-proxy-verified';h.save();
}

try{
  h.assertWritable();await prerequisites();
  if(stage.startsWith('prepare-five-credentials')){
    const before=await wholeIds();assert.deepEqual(before['key-auth'],[fixtures.credential.id]);for(const kind of kinds.slice(1))assert.equal(before[kind].length,0,'FIVE_NEW_DAOS_MUST_START_EMPTY');
    g.privateInputs??={
      'basic-auth':{username:`${h.state.tag}-basic`,password:`Kp!A7${randomBytes(24).toString('hex')}`},
      jwt:{key:randomUUID(),secret:randomBytes(32).toString('hex'),algorithm:'HS256'},
      oauth2:{name:`${h.state.tag}-oauth`,client_id:randomUUID(),client_secret:randomBytes(32).toString('hex'),redirect_uris:[`https://${h.state.tag}.invalid/oauth/callback`]},
      'hmac-auth':{username:`${h.state.tag}-hmac`,secret:randomBytes(32).toString('hex')},acls:{group:`${h.state.tag}-acl`}};h.save();
    const record=g.intents[stage]??={body:{change:{kind:'batch',confirmed:true,operations:kinds.slice(1).map(kind=>({kind:'credential',action:'create',consumerId:fixtures.consumer.id,credentialKind:kind,body:g.privateInputs[kind]}))}}};h.save();
    const receipt=await prepare(record,stage);assert.equal(receipt.review.impact.nativePackets,5);const detail=await voteAndExecute(record,stage,5);
    const after=await wholeIds();for(const kind of kinds)assert.equal(after[kind].length,1,'EXACTLY_ONE_CREDENTIAL_PER_DAO_REQUIRED');
    assert.deepEqual(after['key-auth'],before['key-auth']);g.credentialIds=Object.fromEntries(kinds.map(kind=>[kind,after[kind][0]]));g.pendingAuthProbePlans=makeAuthProbePlans();h.save();
    await probe(`${stage}-original-key`,200);check(true,'five real credential DAOs created by one typed batch and independent three-vote approval',{workflowId:record.workflowId,executionId:record.executionId,nativePackets:5,credentialKinds:5,historicalBaselineRead:true});
  }else if(stage==='delete-consumer'){
    assert(g.credentialIds,'ORIGINAL_SIX_CREDENTIAL_IDS_REQUIRED');const actual=await wholeIds();for(const kind of kinds)assert.deepEqual(actual[kind],[g.credentialIds[kind]]);
    await probe(`${stage}-before`,200);
    const record=g.intents[stage]??={body:{change:{kind:'recycle',action:'delete',entityType:'consumers',entityId:fixtures.consumer.id,confirmed:true,confirm_name:fixtures.consumer.username}}};h.save();
    const receipt=await prepare(record,stage);assert.equal(receipt.review.impact.nativePackets,7);await voteAndExecute(record,stage,7,true);
    await h.request(admin,scope(`entities/consumers/${fixtures.consumer.id}`),'GET',undefined,{expected:[404]});
    for(const kind of kinds)await h.request(admin,scope(`consumers/${fixtures.consumer.id}/credentials/${kind}/${g.credentialIds[kind]}`),'GET',undefined,{expected:[404]});
    const listing=(await h.request(admin,scope('recycle-bin',{type:'consumers',search:fixtures.consumer.id,size:'20'}))).data;
    assert(!listing.nextCursor,'RECYCLE_CANDIDATE_PAGE_NOT_COMPLETE');
    const candidates=listing.items.filter(entry=>entry.original_id===fixtures.consumer.id&&entry.state==='deleted'&&entry.mutation_id===null&&entry.node_count===7);
    assert.equal(candidates.length,1,'EXACT_NEW_SOURCE23_SEVEN_NODE_ARCHIVE_REQUIRED');record.entryId=candidates[0].id;record.nodeCount=7;h.save();
    await probe(`${stage}-original-key-rejected`,401);g.authEndpointValidation['key-auth']='actual-consumer-deletion-rejects-original-key';h.save();
    check(true,'the Consumer and all six credential IDs have actual204 native receipts, verified point404 and a complete seven-node source-bound archive',{workflowId:record.workflowId,executionId:record.executionId,entryId:record.entryId,nativePackets:7,nodeCount:7,historicalBaselineRead:true});
  }else{
    const deleted=g.intents['delete-consumer'];assert(deleted?.entryId&&g.credentialIds,'ORIGINAL_SEVEN_NODE_ARCHIVE_REQUIRED');
    const record=g.intents[stage]??={body:{change:{kind:'recycle',action:'restore',entryId:deleted.entryId,confirmed:true,confirm_name:fixtures.consumer.username}}};h.save();
    const receipt=await prepare(record,stage);assert.equal(receipt.review.impact.nativePackets,7);await voteAndExecute(record,stage,7);
    assert.equal((await h.request(admin,scope(`entities/consumers/${fixtures.consumer.id}`))).data.entity.id,fixtures.consumer.id);
    const after=await wholeIds();for(const kind of kinds)assert.deepEqual(after[kind],[g.credentialIds[kind]]);
    for(const kind of kinds){
      const current=(await h.request(admin,scope(`consumers/${fixtures.consumer.id}/credentials/${kind}/${g.credentialIds[kind]}`,{reveal:'true'}))).data.entity;
      for(const [field,original]of Object.entries(kind==='key-auth'?{key:fixtures.key}:g.privateInputs[kind]))assert(digest(current[field])===digest(original),'PRIVATE_RECOVERY_CONTENT_MISMATCH');
    }
    const listing=(await h.request(admin,scope('recycle-bin',{type:'consumers',search:fixtures.consumer.id,size:'20'}))).data;
    assert.equal(listing.items.find(entry=>entry.id===deleted.entryId)?.state,'restored');await probe(`${stage}-original-key-restored`,200);
    g.authEndpointValidation['key-auth']='actual-original-key-200-before-401-deleted-200-restored';h.save();
    check(true,'a new independently approved restore reuses all seven original native IDs and original private credential material; actual original API Key authenticates',{workflowId:record.workflowId,executionId:record.executionId,entryId:deleted.entryId,nativePackets:7,nodeCount:7,historicalBaselineRead:true,originalCredentialMaterialMatches:true});
  }
  g.stages??={};g.stages[stage]={state:'succeeded',finishedAt:new Date().toISOString()};h.state.phase=`m11-all-credentials-${stage}-complete`;h.save();report(true);
  console.log(JSON.stringify({passed:true,stage,expectedNativePackets:stage.startsWith('prepare-five-credentials')?5:7,overallM11Accepted:false,oauth2AuthEndToEnd:'pending-actual-TLS-token-chain'}));
}catch(error){
  g.stages??={};g.stages[stage]={state:'stopped',finishedAt:new Date().toISOString()};h.state.phase=`m11-all-credentials-${stage}-stopped`;h.save();report(false);
  // Assertion messages and upstream details can contain credential values.
  console.error(JSON.stringify({passed:false,stage,errorCode:'M11_ALL_CREDENTIALS_HTTP_STOPPED',kind:error?.name==='AssertionError'?'assertion':'runtime'}));process.exitCode=1;
}
