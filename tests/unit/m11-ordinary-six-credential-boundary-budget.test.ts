import 'reflect-metadata';
import {beforeEach,afterEach,describe,it,expect,vi} from 'vitest';
import {Logger} from '@nestjs/common';
import {randomUUID,createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {EntityChangeCompilerService} from '../../apps/console-api/src/modules/entities/entity-change-compiler.service';
import {EntityChangeBoundaryService} from '../../apps/console-api/src/modules/entities/entity-change-boundary.service';
import {EntityPreparedWriterService} from '../../apps/console-api/src/modules/entities/entity-prepared-writer.service';
import {EntityChangeBaselineCapturerService} from '../../apps/console-api/src/modules/workflows/entity-change-baseline-capturer.service';
import {EntityChangeExecutionService} from '../../apps/console-api/src/modules/workflows/entity-change-execution.service';
import {GraphCapturerService} from '../../apps/console-api/src/modules/recycle-bin/graph-capturer.service';
import {KongExecutionContextService} from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import {KongService} from '../../apps/console-api/src/infrastructure/kong/kong.service';
import {outboundJson} from '../../apps/console-api/src/infrastructure/kong/outbound';
import {SecretService} from '../../apps/console-api/src/infrastructure/secret.service';
import {NativeKongPolicyService} from '../../apps/console-api/src/modules/authorization/native-kong-policy.service';
import {PortalAuthBoundaryService} from '../../apps/console-api/src/modules/portal-boundary/portal-auth-boundary.service';
import {transportScopeFor} from '../../apps/console-api/src/infrastructure/kong/transport-scope';
import {DEFAULT_WORKSPACE_ID as wid,workspaceTestResolver} from './workspace-test-helper';

vi.mock('../../apps/console-api/src/infrastructure/kong/outbound',()=>({outboundJson:vi.fn(),outboundText:vi.fn()}));
const transport=vi.mocked(outboundJson),kinds=['key-auth','basic-auth','jwt','oauth2','hmac-auth','acls'];
/** Real Context/SDK/NativePolicy/PortalBoundary meters. Ownership SQL, native
 * responses, user grants and deployment rows are controlled Source adapters.
 * This is not an actual approval, database, HTTP or Native execution receipt. */
function fixture(){
 const context=new KongExecutionContextService(),secrets=new SecretService(),cid=randomUUID(),consumerId=randomUUID(),managedId=randomUUID(),uid=randomUUID(),sid=randomUUID(),publicationId=randomUUID(),serviceId=randomUUID();
 const actor:any={id:uid,username:'source-owner',superAdmin:true},consumer:any={id:consumerId,username:'ordinary-six-scheme',tags:[]},managedConsumer={id:managedId,username:'kos-portal-source-managed',tags:[]};
 const cluster:any={id:cid,admin_url:'http://kong:8001',transport_scope:null,connection_secret:null,version:'1.5.1',revision:1,status:'healthy',execution_mode:'approval'};
 const history:any={publications:[{id:publicationId,cluster_id:cid,workspace_id:wid,service_id:serviceId,acl_group:`kos-portal-api-${publicationId}`,published_revision:null,state:'pending'}],
  grants:[{id:randomUUID(),consumer_id:managedId,publication_id:publicationId,acl_group:`kos-portal-api-${publicationId}`,state:'active',reservation_released_at:null}],credentials:[]};
 const state:any={history,consumer,managedConsumer,onQuery:undefined,onPoint:undefined};
 const db:any={query:vi.fn(async(sql:string)=>{state.onQuery?.(sql);if(sql.includes('FROM portal_publications'))return structuredClone(history.publications);if(sql.includes('FROM portal_application_grants'))return structuredClone(history.grants);if(sql.includes('FROM portal_credentials'))return structuredClone(history.credentials);throw Error('UNEXPECTED_SOURCE_SQL_QUERY');}),
  one:vi.fn(async(sql:string)=>{if(sql.includes('FROM clusters'))return cluster;throw Error('UNEXPECTED_SOURCE_SQL_POINT');}),exec:vi.fn(async()=>1)};
 const authz:any={snapshot:vi.fn(async()=>({user:actor,grants:[],version:'source-current-1'})),permissionVersion:vi.fn(async()=> 'source-current-1'),assertCluster:vi.fn(),assertEntity:vi.fn()};
 const redis:any={rateLimit:vi.fn(async()=>({allowed:true,retryAfterMs:0})),assertLeaseOwnership:vi.fn(),assertLeaseActive:vi.fn()},audit:any={append:vi.fn()};
 const kong=new KongService(db,redis,secrets,audit,context),workspace=workspaceTestResolver(cid).resolver,boundary=new PortalAuthBoundaryService(db,secrets,kong,context,workspace),native=new NativeKongPolicyService(db,secrets,kong,context,authz,workspace,undefined,boundary);
 native.install();
 transport.mockImplementation(async(_base,path,method,_body,_query,_auth,_timeout,fence,prepare)=>{await prepare?.();fence?.();expect(method).toBe('GET');
  let body:any,status=200;
  if(path===`/consumers/${consumerId}`){state.onPoint?.();body=structuredClone(state.consumer);}
  else if(/^\/consumers\/[a-f\d-]{36}$/.test(path)&&history.grants.some((g:any)=>`/consumers/${g.consumer_id}`===path)&&(!state.presentManagedIds||state.presentManagedIds.has(path.split('/')[2])))body={...managedConsumer,id:path.split('/')[2]};
  else if(/^\/consumers\/[a-f\d-]{36}\/acls$/.test(path)&&history.grants.some((g:any)=>`/consumers/${g.consumer_id}/acls`===path)&&(!state.presentManagedIds||state.presentManagedIds.has(path.split('/')[2])))body={data:[{id:randomUUID(),consumer:{id:path.split('/')[2]},group:history.grants.find((g:any)=>g.consumer_id===path.split('/')[2]).acl_group}],next:null};
  else if(path==='/services')body={data:history.publications.map((p:any)=>({id:p.service_id,protocol:'http',tags:[]})),next:null};
  else if(/^\/services\/[a-f\d-]{36}$/.test(path)){state.onServicePoint?.();body=state.serviceRecord??{message:'Not found'};status=state.serviceRecord?200:404;}
  else if(path==='/schemas/services')body={fields:[{protocol:{type:'string',default:'http'}}]};
  else if(path==='/routes'||path==='/plugins')body={data:[],next:null};
  else{status=404;body={message:'Not found'};}
  return{status,body,bytes:Buffer.byteLength(JSON.stringify(body)),jsonParsed:true};
 });
 const packets=kinds.map(kind=>{const id=randomUUID();return{clusterId:cid,workspaceId:wid,transportScope:transportScopeFor(cluster.admin_url),nativeId:id,method:'POST',canonicalPath:`/consumers/${consumerId}/${kind}`,parentId:consumerId,credentialKind:kind,mutationAction:'create',before:null,body:{id,...(kind==='acls'?{group:'ordinary-business'}:{})}} as any;});
 const run=<T>(fn:()=>Promise<T>)=>context.runHttp({},async()=>{context.bindHttpActor(actor,sid);return context.runActor({actor,clusterId:cid,workspaceId:wid,module:'workflows',action:'write'},fn);});
 return{context,secrets,boundary,db,kong,packets,state,consumerId,managedId,history,run,actor,cid,sid,cluster,authz,redis,audit,workspace};
}
beforeEach(()=>{vi.stubEnv('CONSOLE_ENCRYPTION_KEY','ca'.repeat(32));vi.stubEnv('APP_SECRET','source-six-credential-boundary-key'.repeat(3));vi.stubEnv('KONG_RATE_WAIT_MS','0');transport.mockReset();vi.spyOn(Logger.prototype,'warn').mockImplementation(()=>undefined);});
afterEach(()=>{vi.restoreAllMocks();vi.unstubAllEnvs();});
describe('ordinary six-scheme preparation inside one unchanged shared actor meter',()=>{
 it('keeps five current preflight rounds for all six credential kinds below the original 100-page/500-call ceilings',async()=>{
  const f=fixture();let usage:any;
  await f.run(async()=>{for(let round=0;round<5;round++)for(const p of f.packets)await f.boundary.assertPreparedChange(p);usage=f.context.currentUsage();});
  expect(usage.pages).toBeLessThanOrEqual(100);expect(usage.calls).toBeLessThanOrEqual(500);expect(f.db.query).toHaveBeenCalled();expect(f.db.exec).not.toHaveBeenCalled();
  expect(transport.mock.calls.every(c=>c[2]==='GET')).toBe(true);console.info(JSON.stringify({sourceOnlySixCredentialPreflight:{schemes:kinds.length,rounds:5,usage,nativeRequests:0,sqlAdapter:true}}));
 });
});
describe('ordinary absent Service create compiler preflight',()=>{
 const packet=(f:ReturnType<typeof fixture>)=>{const nativeId=randomUUID();return{clusterId:f.cid,workspaceId:wid,
  transportScope:transportScopeFor(f.cluster.admin_url),nativeId,method:'POST',canonicalPath:'/services',mutationAction:'create',
  before:null,body:{id:nativeId,name:'new-source-service',host:'echo',protocol:'http',tags:[]}}as any;};
 it('uses fresh SDK absence on every preflight and preserves the original page ceiling',async()=>{
  const f=fixture(),p=packet(f);let usage:any;
  await f.run(async()=>{for(let n=0;n<30;n++)await f.boundary.assertPreparedChange(p);usage=f.context.currentUsage();});
  expect(usage.pages).toBe(0);expect(usage.calls).toBe(30);expect(transport.mock.calls.every(c=>c[1]===`/services/${p.nativeId}`&&c[2]==='GET')).toBe(true);
  expect(f.db.exec).not.toHaveBeenCalled();
 });
 it('rejects ownership change during the absent point response',async()=>{
  const f=fixture(),p=packet(f);f.state.onServicePoint=()=>{f.history.publications[0].service_id=p.nativeId;};
  await expect(f.run(()=>f.boundary.assertPreparedChange(p))).rejects.toMatchObject({response:{code:'PORTAL_AUTH_GRAPH_CHANGED'}});
 });
 it('rejects a packet changed during the absent point response',async()=>{
  const f=fixture(),p=packet(f);f.state.onServicePoint=()=>{p.body.host='changed';};
  await expect(f.run(()=>f.boundary.assertPreparedChange(p))).rejects.toMatchObject({response:{code:'PORTAL_AUTH_GRAPH_CHANGED'}});
 });
 it('does not accept a malformed established publication proof',async()=>{
  const f=fixture(),p=packet(f);f.history.publications[0].published_revision=1;
  await expect(f.run(()=>f.boundary.assertPreparedChange(p))).rejects.toMatchObject({response:{code:'PORTAL_PUBLICATION_PROOF_INVALID'}});
  expect(transport).not.toHaveBeenCalled();
 });
 it.each(['restore','nonnull-before','published-id','existing-id','foreign-parent'])('keeps complete preflight for %s',async kind=>{
  const f=fixture(),p=packet(f);
  if(kind==='restore')p.mutationAction='restore';
  if(kind==='nonnull-before')p.before={id:p.nativeId};
  if(kind==='published-id')p.body.id=p.nativeId=f.history.publications[0].service_id;
  if(kind==='existing-id')f.state.serviceRecord={id:p.nativeId,protocol:'http',tags:[]};
  if(kind==='foreign-parent')p.parentId=randomUUID();
  await f.run(async()=>{try{await f.boundary.assertPreparedChange(p);}catch(error){expect((error as any).getResponse?.()?.code).toBe('PORTAL_AUTH_GRAPH_CHANGED');}});
  expect(transport.mock.calls.some(c=>c[1]==='/services')).toBe(true);
 });
});

/** Genuine ordinary Kernel issues private Source/packet/binding; Compiler,
 * baseline capturer, Boundary, SDK, NativePolicy and fixed writer execute.
 * SQL/facts/approval/Mutation persistence are controlled adapters. */
async function kernelFixture(riskConsumers=1,presentConsumers=riskConsumers){
 const f=fixture();for(let i=1;i<riskConsumers;i++)f.history.grants.push({...f.history.grants[0],id:randomUUID(),consumer_id:randomUUID()});f.state.presentManagedIds=new Set(f.history.grants.slice(0,presentConsumers).map((g:any)=>g.consumer_id));for(const g of f.history.grants)if(riskConsumers===8||!f.state.presentManagedIds.has(g.consumer_id))g.state='pending';if(riskConsumers===8)for(let i=1;i<8;i++){const pub={...f.history.publications[0],id:randomUUID(),service_id:randomUUID()};pub.acl_group=`kos-portal-api-${pub.id}`;f.history.publications.push(pub);f.history.grants[i].publication_id=pub.id;f.history.grants[i].acl_group=pub.acl_group;}const {context,secrets,cid,consumerId,actor,db,kong,redis,audit,authz,workspace}=f,workflowId=randomUUID(),intentId=randomUUID();
 const initial=f.packets.map((p,i)=>({...p,key:`packet-${i+1}`,order:i+1,nativeType:p.credentialKind,dependencies:[],permissionAction:'write',body:{...p.body,...(i===0?{key:'source-original-key'}:i===1?{username:'source-basic',password:'source-original-password'}:i===2?{key:'source-jwt',secret:'source-jwt-secret',algorithm:'HS256'}:i===3?{name:'source-client',client_id:'source-client-id',client_secret:'source-client-secret',redirect_uris:['https://source.invalid/callback']}:i===4?{username:'source-hmac',secret:'source-hmac-secret'}:{})},bodyHmac:'',beforeHmac:secrets.fingerprint(null)}));
 for(const p of initial)p.bodyHmac=secrets.fingerprint(p.body);
 const current=new Map<string,any>(),sent:any[]=[],custody:any[]=[],mutations=new Map<string,any>(),events:any[]=[],attempts:any[]=[];let source:any,execution:any,baseline:any,capture:any,factsPolicy:any,usage:any;
 const nativeSchemas:any={};for(const [kind,name]of [['key-auth','keyauth_credentials'],['basic-auth','basicauth_credentials'],['jwt','jwt_secrets'],['oauth2','oauth2_credentials'],['hmac-auth','hmacauth_credentials'],['acls','acls']])nativeSchemas[name]=JSON.parse(readFileSync(new URL(`../fixtures/kong15-recorded-admin/schema-${name}.json`,import.meta.url),'utf8')).response;
 nativeSchemas.consumers=JSON.parse(readFileSync(new URL('../fixtures/kong-1.5.1/schema-consumers.json',import.meta.url),'utf8'));
 const priorTransport=transport.getMockImplementation()!;transport.mockImplementation(async(...args:any[])=>{
  const path=args[1],method=args[2];
  if(path.startsWith('/schemas/')){await args[8]?.();args[7]?.();const body=nativeSchemas[path.slice(9)];if(!body)throw Error('UNEXPECTED_SOURCE_SCHEMA');return{status:200,body,bytes:Buffer.byteLength(JSON.stringify(body)),jsonParsed:true};}
  if(method==='POST'){await args[8]?.();args[7]?.();const packet=initial.find(p=>p.canonicalPath===path)!;const body:any={...args[3],consumer:{id:consumerId}};if(packet.credentialKind==='basic-auth')body.password=createHash('sha1').update(body.password+consumerId).digest('hex');current.set(path+'/'+packet.nativeId,body);sent.push(packet);return{status:201,body,bytes:Buffer.byteLength(JSON.stringify(body)),jsonParsed:true};}
  if(current.has(path)){await args[8]?.();args[7]?.();const body=structuredClone(current.get(path));return{status:200,body,bytes:Buffer.byteLength(JSON.stringify(body)),jsonParsed:true};}
  return (priorTransport as any)(...args);
 });
 const schemas:any[]=await f.run(async()=>{const result=[];for(const p of initial)result.push(await kong.prepareSchema(cid,p.canonicalPath,p.body));return result;});
 const raw:any={version:1,clusterId:cid,workspaceId:wid,requesterId:actor.id,permissionVersion:'source-current-1',scope:{transportScope:transportScopeFor(f.cluster.admin_url),clusterRevision:1,workspaceRevision:1,kongVersion:'1.5.1',adapter:'kong-oss-1.5-v1'},
  request:{kind:'batch',confirmed:true,operations:initial.map(p=>({kind:'credential',action:'create',consumerId,credentialKind:p.credentialKind,body:Object.fromEntries(Object.entries(p.body).filter(([k])=>k!=='id'))}))},
  prerequisites:[{type:'consumers',path:`/consumers/${consumerId}`,nativeId:consumerId,before:f.state.consumer,absent:false,fingerprint:secrets.fingerprint(f.state.consumer),permissionAction:'write',purpose:'private-parent'},...initial.map(p=>({type:p.nativeType,path:p.canonicalPath+'/'+p.nativeId,nativeId:p.nativeId,parentId:consumerId,before:null,absent:true,fingerprint:secrets.fingerprint(null),permissionAction:'write'}))],schemas,packets:initial,
  metadataObligations:initial.map(p=>({kind:'credential-remember',packetKey:p.key,consumerId,credentialKind:p.credentialKind,rawInput:p.body})),recovery:{state:'baseline-required',blockerCodes:[],objects:[]}};
 const prepared:any={...raw,changeDigest:secrets.fingerprint(raw)},envelope:any={version:1,intentId,revision:1,credentialEpoch:'1',prepared,packetManifestHmac:secrets.fingerprint(initial),expiresAt:new Date(Date.now()+86400000).toISOString()};
 const metadata={intentId,intentRevision:1,materialHmac:secrets.fingerprint(envelope),changeDigest:prepared.changeDigest,packetManifestHmac:envelope.packetManifestHmac};
 const plan:any={version:1,kind:'native-change',workflowId,clusterId:cid,workspaceId:wid,planRevision:1,executionMode:'approval',approvalRequired:true,subject:{type:'entity_change_intents',id:intentId},requester:{type:'console',id:actor.id},definition:{id:randomUUID(),version:1,policyHash:secrets.fingerprint('source-policy')},expiresAt:envelope.expiresAt,scope:raw.scope,prerequisites:[],steps:[{id:randomUUID(),key:'entity',order:1,kind:'metadata',handler:'entity.change',entityType:'entity_change_intents',entityId:intentId,permissionAction:'write',dependencies:[],nativeRequests:[],metadata,metadataRevision:1,metadataPayloadHmac:secrets.fingerprint(metadata),metadataBeforeHmac:secrets.fingerprint(metadata)}]};
 const workflow:any={id:workflowId,state:'approved',revision:1,plan_hash:secrets.fingerprint(plan),approved_by:randomUUID()},entityActor:any={user:actor,workspaceId:wid,idempotencyKey:'source-six-original-execution'};
 const priorOne=db.one.getMockImplementation()!;db.one.mockImplementation(async(q:string,v:any[]=[])=>{
  if(q.includes('FROM mutation_operations'))return mutations.get(v[0])??null;
  if(q.includes('FROM entity_change_execution_sources'))return source??null;
  if(q.includes('FROM auth_sessions'))return{expires_at:new Date(Date.now()+86400000),credential_epoch:'1',user_epoch:'1'};
  if(q.includes('FROM workflow_executions')&&q.includes('JOIN workflows'))return{state:execution?.state,workflow_state:workflow.state};
  if(q.includes('FROM workflow_executions'))return execution??null;
  if(q.includes('FROM iam_epoch'))return{version:1};
  if(q.includes('FROM workspaces'))return{id:wid,cluster_id:cid,code:'default',is_default:true,deleted_at:null,revision:1,status:'active'};
  if(q.includes('FROM workflows'))return workflow;
  return priorOne(q,v);
 });
 const priorQuery=db.query.getMockImplementation()!;db.query.mockImplementation(async(q:string,v:any[]=[])=>q.includes('entity_change_packet_attempts')?events.map(e=>({packet_key:e.binding.packetKey,event_kind:e.kind,outcome:e.outcome,error_code:e.errorCode})):priorQuery(q,v));
 db.exec.mockImplementation(async(q:string,v:any[]=[])=>{
  if(q.startsWith('INSERT INTO entity_change_execution_sources'))source=Object.fromEntries(['id','cluster_id','workspace_id','intent_id','intent_revision','material_hmac','change_digest','packet_manifest_hmac','workflow_id','workflow_plan_revision','workflow_plan_hash','workflow_execution_id','execution_actor_id','credential_epoch','session_id','permission_version_hmac','issued_at','expires_at'].map((k,i)=>[k,v[i]]));
  else if(q.startsWith('INSERT INTO workflow_executions'))execution={id:v[0],state:'executing'};
  else if(q.startsWith("UPDATE workflows SET state='executing'")){workflow.state='executing';workflow.revision++;}
  else if(q.startsWith("UPDATE workflows SET state='succeeded'")){workflow.state='succeeded';workflow.revision++;}
  else if(q.startsWith('UPDATE workflows SET state=$2'))workflow.state=v[1];
  else if(q.startsWith("UPDATE workflow_executions SET state='succeeded'"))execution.state='succeeded';
  else if(q.startsWith('UPDATE workflow_executions SET state=$2'))execution.state=v[1];
  return 1;
 });db.transaction=async(fn:any)=>fn(db);Object.assign(redis,{withLock:async(_k:any,fn:any)=>fn()});
 const boundary=new EntityChangeBoundaryService(db,secrets,context,authz,workspace,kong,{} as any,f.boundary),compiler=new EntityChangeCompilerService({}as any,kong,authz,workspace,secrets,context);
 compiler.installPreparationBoundary(boundary);const credentials:any={save:async(...v:any[])=>custody.push(v),getRestorePayload:async()=>{throw Error('NO_OLD_CREDENTIAL_EXPECTED');}},graphs=new GraphCapturerService(kong,credentials,context),capturer=new EntityChangeBaselineCapturerService(kong,context,graphs,credentials,compiler,secrets);
 const facts:any={installFixedDelegate:(p:any)=>factsPolicy=p,persistReady:async(id:string,value:any,proof:object)=>{await factsPolicy.verifySource(id,'capture',db);await factsPolicy.verifyCapture(id,value,proof,db);capture=value;return baseline={sourceId:id,baselineId:randomUUID(),pinId:randomUUID(),baselineHmac:secrets.fingerprint(value),captureHmac:secrets.fingerprint(value),objectManifestHmac:secrets.fingerprint(value),objectCount:value.objects.length,graphCount:value.graphs.length,protectedUntil:'2099-01-01T00:00:00.000Z'};},assertReadyForPacket:async(_s:string,_b:string,key:string)=>({capture,baseline,packet:initial.find(p=>p.key===key)}),appendAttempt:async(b:any,p:any)=>{await factsPolicy.verifySource(b.sourceId,'packet',db);await factsPolicy.verifyPacketFact(b,null,p,db);attempts.push(b);},appendSendIntent:async(v:any,p:any)=>{await factsPolicy.verifySource(v.binding.sourceId,'before-send',db);await factsPolicy.verifyPacketFact(v.binding,v,p,db);events.push(v);},appendOutcome:async(v:any,p:any)=>{await factsPolicy.verifySource(v.binding.sourceId,'outcome',db);await factsPolicy.verifyPacketFact(v.binding,v,p,db);events.push(v);}};
 const mutationAdapter:any={execute:async(input:any,callback:any)=>{const binding:any=await context.approvedMutationBinding(input),id=randomUUID(),m:any={id,cluster_id:cid,workspace_id:wid,actor_id:actor.id,workflow_id:workflowId,entity_type:'credentials',entity_id:binding.nativeId,action:'create',parent_id:consumerId,credential_kind:input.credentialKind,idempotency_key:input.idempotencyKey,state:'running',remote_started:false,remote_completed:false,result_secret:null,workflow_step_id:null,configuration_step_id:null,entity_change_source_id:binding.sourceId,entity_change_baseline_id:binding.baselineId,entity_change_attempt_id:binding.attemptId,entity_change_packet_key:binding.packetKey,before_secret:secrets.encrypt(null,`mutation:${id}:before`),payload_secret:secrets.encrypt(input.payload,`mutation:${id}:payload`)};mutations.set(id,m);await context.bindApprovedOperation(input,binding,id,db);m.remote_started=true;const result=await context.runOperation({...input,operationId:id,entityId:binding.nativeId},callback);m.state='succeeded';m.remote_completed=true;m.result_secret=secrets.encrypt(result,`mutation:${id}:result`);return result;}};
 const writer=new EntityPreparedWriterService(mutationAdapter,kong,{upsert:async()=>undefined}as any,credentials,secrets),kernel=new EntityChangeExecutionService(db,redis,secrets,context,kong,authz,audit,{load:async()=>({plan,row:workflow}),revalidateEntityChange:async()=>compiler.revalidateStored(prepared,entityActor,'write','claim')}as any,{verifyApprovalSet:async()=>({format:2,setId:randomUUID(),setHmac:secrets.fingerprint('source-approved')})}as any,{executionMaterial:async()=>envelope}as any,facts,capturer,writer,boundary);
 kernel.onModuleInit();const run=()=>f.run(async()=>{try{return await kernel.execute(plan,{revision:1,planHash:workflow.plan_hash,confirmed:true,confirm_name:'native-change'},entityActor);}finally{usage=context.currentUsage();}});
 return{...f,run,usage:()=>usage,sent,custody,events,attempts,mutations,workflow};
}
describe('ordinary credential disjoint preflight keeps current ownership and old fallback boundaries',()=>{
 it('rechecks ownership after each real current Consumer point, without memo across rounds',async()=>{
  const f=fixture();await f.run(async()=>{await f.boundary.assertPreparedChange(f.packets[0]);f.history.grants.push({id:randomUUID(),consumer_id:f.consumerId,state:'revoked'});await expect(f.boundary.assertPreparedChange(f.packets[1])).rejects.toMatchObject({response:{code:'PORTAL_MANAGED_OBJECT'}});});
  expect(transport.mock.calls.filter(c=>c[1]===`/consumers/${f.consumerId}`)).toHaveLength(1);
 });
 it('rejects an ownership change while the actual Consumer read is awaited',async()=>{
  const f=fixture();f.state.onPoint=()=>{f.history.grants.push({id:randomUUID(),consumer_id:f.consumerId,state:'active'});};
  await expect(f.run(()=>f.boundary.assertPreparedChange(f.packets[0]))).rejects.toMatchObject({response:{code:'PORTAL_AUTH_GRAPH_CHANGED'}});expect(transport.mock.calls).toHaveLength(1);
 });
 it('rejects an input tuple changed while the actual point read is awaited',async()=>{
  const f=fixture();f.state.onPoint=()=>{f.packets[0].body.id=randomUUID();};
  await expect(f.run(()=>f.boundary.assertPreparedChange(f.packets[0]))).rejects.toMatchObject({response:{code:'PORTAL_AUTH_GRAPH_CHANGED'}});expect(transport.mock.calls).toHaveLength(1);
 });
 it('retains authenticated published ownership proof checks for a disjoint packet',async()=>{
  const f=fixture();f.history.publications[0].published_revision=1;
  await expect(f.run(()=>f.boundary.assertPreparedChange(f.packets[0]))).rejects.toMatchObject({response:{code:'PORTAL_PUBLICATION_PROOF_INVALID'}});expect(transport).not.toHaveBeenCalled();
 });
 it('keeps a missing active managed Consumer denied on the complete original path',async()=>{
  const f=fixture();f.state.presentManagedIds=new Set();const p={...f.packets[0],mutationAction:'update'};
  await expect(f.run(()=>f.boundary.assertPreparedChange(p))).rejects.toMatchObject({response:{code:'PORTAL_MANAGED_CONSUMER_MISSING'}});
 });
 it.each(['managed-parent','historical-credential','reserved-acl'] as const)('keeps %s denied before a disjoint read',async kind=>{
  const f=fixture(),p=structuredClone(f.packets[kind==='reserved-acl'?5:0]);
  if(kind==='managed-parent'){p.canonicalPath=`/consumers/${f.managedId}/key-auth`;p.parentId=f.managedId;}
  if(kind==='historical-credential')f.history.credentials.push({kong_id:p.nativeId});
  if(kind==='reserved-acl')p.body.group=f.history.publications[0].acl_group;
  await expect(f.run(()=>f.boundary.assertPreparedChange(p))).rejects.toMatchObject({response:{code:'PORTAL_MANAGED_OBJECT'}});expect(transport).not.toHaveBeenCalled();
 });
 it.each(['different-current-id','reserved-current-name','different-workspace','unknown-parent','unknown-action'] as const)('retains complete original graph reads for %s',async kind=>{
  const f=fixture(),p=structuredClone(f.packets[0]);if(kind==='different-current-id')f.state.consumer.id=randomUUID();
  if(kind==='reserved-current-name')f.state.consumer.username='kos-portal-not-in-owner-dto';
  if(kind==='different-workspace')f.state.consumer.tags=['kos-ws-pay'];
  if(kind==='unknown-parent')p.parentId=randomUUID();if(kind==='unknown-action')p.mutationAction='update';
  let usage:any;await f.run(async()=>{await f.boundary.assertPreparedChange(p);usage=f.context.currentUsage();});expect(usage.pages).toBe(4);expect(transport.mock.calls.some(c=>c[1]==='/services')).toBe(true);
 });
 it('does not erase or increase the aggregate hundred-page ceiling after the zero-page narrow checks',async()=>{
  const f=fixture();await expect(f.run(async()=>{for(const p of f.packets)await f.boundary.assertPreparedChange(p);for(let i=0;i<101;i++)await f.context.runInternalRead(f.cid,'entity-preflight',()=>f.kong.request(f.cid,'GET','/plugins'),{paths:['/plugins'],maxCalls:1,maxPages:1});})).rejects.toMatchObject({response:{code:'KONG_EXECUTION_RESPONSE_LIMIT'}});
  expect(Logger.prototype.warn).toHaveBeenCalledWith({event:'kong_execution_budget_exceeded',frame:{kind:'actor',purpose:null},budgetKind:'pages',limit:100,current:101});
 });
});
describe('ordinary actual six-packet Kernel execution with real current/read components',()=>{
 it.each([[1,1],[5,5],[8,1],[8,0]])('creates all six original schemes once with %s SQL risk Consumers and %s physically present in the one unchanged execution meter',async(riskConsumers,presentConsumers)=>{
  const f=await kernelFixture(riskConsumers,presentConsumers);transport.mockClear();let result:any;try{result=await f.run();}catch(error){console.info(JSON.stringify({sourceOnlySixCredentialKernelFailure:{usage:f.usage(),diagnostic:vi.mocked(Logger.prototype.warn).mock.calls.at(-1)?.[0],nativeWrites:f.sent.length,nativeRequestsKnownSent:f.events.filter(e=>e.kind==='send-intent').length}}));throw error;}
  expect(result.state).toBe('succeeded');expect(f.sent).toHaveLength(6);expect(f.custody).toHaveLength(6);expect(f.attempts).toHaveLength(6);expect(f.events.filter(e=>e.kind==='outcome'&&e.nativeStatus===201)).toHaveLength(6);
  expect([...f.mutations.values()].every(m=>m.state==='succeeded'&&m.remote_started&&m.remote_completed)).toBe(true);
  expect(f.usage().pages).toBeLessThanOrEqual(100);expect(f.usage().calls).toBeLessThanOrEqual(500);console.info(JSON.stringify({sourceOnlySixCredentialKernel:{riskConsumers,presentConsumers,nativeWrites:f.sent.length,usage:f.usage(),sqlAndApprovalAdapters:true,actualContextKernelSdkBoundary:true}}));
 });
});
