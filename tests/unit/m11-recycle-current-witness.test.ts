import 'reflect-metadata';
import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {randomUUID,createHash} from 'node:crypto';
import {ForbiddenException} from '@nestjs/common';
import {SecretService} from '../../apps/console-api/src/infrastructure/secret.service';
import {KongService} from '../../apps/console-api/src/infrastructure/kong/kong.service';
import {KongExecutionContextService} from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import {outboundJson} from '../../apps/console-api/src/infrastructure/kong/outbound';
import {immutableJson} from '../../apps/console-api/src/infrastructure/kong/immutable-json';
import {GraphCapturerService,type GraphNode,type RecycleGraph} from '../../apps/console-api/src/modules/recycle-bin/graph-capturer.service';
import {EntityRecycleCurrentWitnessService} from '../../apps/console-api/src/modules/recycle-bin/entity-recycle-current-witness.service';
import {EntityChangeBoundaryService} from '../../apps/console-api/src/modules/entities/entity-change-boundary.service';
import {derivePreparedRecyclePackets} from '../../apps/console-api/src/modules/recycle-bin/entity-prepared-recycle-writer.service';
import type {EntityRecycleCurrentDescriptor as Descriptor} from '../../apps/console-api/src/modules/recycle-bin/entity-recycle-current-witness.types';

vi.mock('../../apps/console-api/src/infrastructure/kong/outbound',()=>({outboundJson:vi.fn(),outboundText:vi.fn()}));
const transport=vi.mocked(outboundJson),kinds=['key-auth','basic-auth','jwt','oauth2','hmac-auth','acls'];
/** Real SDK tickets/status/parsed404, real Context, GraphCapturer and opaque
 * provider. The once-installed Coordinator/source delegate and DB are explicit
 * controlled adapters; this is not real SQL, IAM, approval or native evidence. */
function fixture(type:'consumer'|'certificate'|'service'|'ca'|'upstream'|'target'='consumer',restoring=true){
 const cid=randomUUID(),wid=randomUUID(),actor={id:randomUUID(),username:'current-reader',superAdmin:true},context=new KongExecutionContextService(),secrets=new SecretService();
 const id=randomUUID(),nodes:GraphNode[]=[],tags=['kos-ws-default'];
 const add=(type:string,data:any,dependencies:string[]=[],parent?:string)=>{const n:GraphNode={key:parent?`${type}:${parent}:${data.id}`:`${type}:${data.id}`,id:data.id,type,path:parent?`/${type==='targets'?'upstreams':'consumers'}/${parent}/${type}/${data.id}`:`/${type}/${data.id}`,data,restoreData:structuredClone(data),affected:true,dependencies,restorable:true};nodes.push(n);return n;};
 let root:GraphNode;
 if(type==='consumer'){
  root=add('consumers',{id,username:'archive-consumer',tags});
  for(const kind of kinds){const data:any={id:randomUUID(),consumer:{id},tags};
   if(kind==='key-auth')data.key='unit-opaque-original-key';
   if(kind==='basic-auth'){data.username='basic';data.password=createHash('sha1').update('unit-original-password'+id).digest('hex');}
   if(kind==='jwt'){data.key='jwt';data.secret='unit-jwt-secret';data.algorithm='HS256';}
   if(kind==='oauth2'){data.name='application';data.client_id='client';data.client_secret='unit-original-client-secret';}
   if(kind==='hmac-auth'){data.username='hmac';data.secret='unit-original-hmac-secret';}
   if(kind==='acls')data.group='application';
   const n=add(kind,data,[root.key],id);if(kind==='basic-auth')n.restoreData.password='unit-original-password';
  }
 }else if(type==='certificate'){
  root=add('certificates',{id,cert:'unit-cert',key:'unit-key',snis:['unit.example'],tags});add('snis',{id:randomUUID(),name:'unit.example',certificate:{id},tags},[root.key]);
 }else if(type==='service'){
  root=add('services',{id,name:'archive-service',host:'192.0.2.20',tags});const route=add('routes',{id:randomUUID(),name:'archive-route',paths:['/unit'],service:{id},tags},[root.key]);
  add('plugins',{id:randomUUID(),name:'key-auth',service:null,consumer:null,route:{id:route.id},config:{key_names:['apikey']},tags},[route.key]);
 }else if(type==='upstream'||type==='target'){
  root=add('upstreams',{id,name:'archive-upstream',tags});const target=add('targets',{id:randomUUID(),upstream:{id},target:'192.0.2.20:8080',weight:100,tags},[root.key],id);
  if(type==='target'){root.affected=false;root=target;}
 }else root=add('ca_certificates',{id,cert:'unit-ca',tags});
 const graph:RecycleGraph={purpose:'recycle',complete:true,capturedAt:new Date().toISOString(),rootKey:root.key,nodes,...(type==='upstream'?{targetHistory:[{upstreamId:id,items:[nodes[1].data]}]}:{})},ordered=restoring?nodes.filter(n=>n.affected):[...nodes].filter(n=>n.affected).reverse(),keys=new Map<string,string>();
 const packets:any[]=ordered.map((n,i)=>{const body=restoring?structuredClone(n.restoreData):undefined,before=restoring?null:structuredClone(n.data),parent=kinds.includes(n.type)||n.type==='targets'?id:undefined;
  if(body&&n.type==='certificates')delete body.snis;
  if(body&&n.type==='targets')delete body.upstream;
  if(!restoring&&n.type==='certificates')before.snis=[];
  const p:any={key:`packet-${i+1}`,order:i+1,nativeType:n.type,nativeId:n.id,method:restoring?'POST':'DELETE',canonicalPath:restoring?n.path.replace(/\/[^/]+$/,''):n.path,
   permissionAction:restoring?'write':'delete',mutationAction:restoring?'restore':'delete',before,...(body?{body}:{}),...(parent?{parentId:parent,...(n.type==='targets'?{}:{credentialKind:n.type})}:{}),
   dependencies:restoring?n.dependencies.flatMap(dep=>keys.get(dep)??[]):nodes.filter(child=>child.dependencies.includes(n.key)).flatMap(child=>keys.get(child.key)??[])};
  p.bodyHmac=secrets.fingerprint(body??null);p.beforeHmac=secrets.fingerprint(before);keys.set(n.key,p.key);return p;
 });
 const obligation:any={kind:restoring?'recycle-restore':'recycle-archive',graph,graphHmac:secrets.fingerprint(graph),packetKeys:packets.map(p=>p.key),...(restoring?{entryId:randomUUID(),sealedEntry:{}}:{})};
 if(restoring)obligation.sealedEntry={entryId:obligation.entryId,clusterId:cid,workspaceId:wid,payloadHmac:obligation.graphHmac};
 const prepared:any={version:1,clusterId:cid,workspaceId:wid,requesterId:actor.id,prerequisites:[],metadataObligations:[obligation],packets};
 const source:any={id:randomUUID(),clusterId:cid,workspaceId:wid,executionActorId:actor.id,expiresAt:new Date(Date.now()+200000).toISOString()};
 let descriptor:Descriptor=immutableJson({source,prepared,obligation,packets,packet:packets[0],nodeKey:ordered[0].key,completed:[]});
 const current=new Map<string,any>(restoring?nodes.filter(n=>!n.affected).map(n=>[n.path,structuredClone(n.data)]):nodes.map(n=>[n.path,structuredClone(n.data)])),extra:any[]=[];let active=true,frame:any,afterRead:undefined|(()=>void);
 const cluster={id:cid,admin_url:'http://kong:8001',connection_secret:null,version:'1.5.1',execution_mode:'approval',status:'healthy',revision:1,capabilities:{}};
 const db:any={one:vi.fn(async(sql:string)=>{if(sql.includes('FROM clusters'))return cluster;throw new Error('Unexpected SDK fixture SQL');})};
 const redis:any={rateLimit:vi.fn(async()=>({allowed:true,retryAfterMs:0})),withLock:vi.fn(async(_key:any,fn:any)=>fn()),assertLeaseActive:vi.fn()};
 const kong=new KongService(db,redis,secrets,{append:vi.fn()} as any,context),custody={getRestorePayload:vi.fn(async()=>{throw new Error('Current raw witness cannot require custody');})};
 const graphs=new GraphCapturerService(kong,custody as any,context),provider=new EntityRecycleCurrentWitnessService(kong,graphs,context,secrets),original=Object.freeze({});
 const delegate={describe:vi.fn(async(h:object)=>{if(h!==original||!active)throw new ForbiddenException({code:'TEST_ORIGINAL_REQUIRED'});return descriptor;}),assertLive:(h:object)=>{if(h!==original||!active||context.current()!==frame)throw new ForbiddenException({code:'TEST_ORIGINAL_REQUIRED'});}};
 provider.installFixedDelegate(delegate);
 context.installPolicy({authorizeRequest:async(_f:any,_c:any,method:any)=>{if(method!=='GET')throw new ForbiddenException();return{platformAdmin:true};},authorizeResponse:async(_d:any,response:any)=>response});
 transport.mockImplementation(async(_base,path,method,_body,query,_auth,_timeout,fence,prepare)=>{
  expect(method).toBe('GET');if(prepare)await prepare();fence?.();const value=current.get(path);afterRead?.();
  if(value!==undefined)return{status:200,body:structuredClone(value),bytes:100};
  if(path===`/services/${id}/routes`)return{status:200,body:{data:[...current.values()].filter(v=>v.service?.id===id&&v.paths).concat(extra),next:null},bytes:100};
  if(path===`/certificates/${id}/snis`)return{status:200,body:{data:[...current.values()].filter(v=>v.certificate?.id===id).concat(extra),next:null},bytes:100};
  if(path===`/upstreams/${id}/targets`||path===`/upstreams/${id}/targets/all`)return{status:200,body:{data:[...current.entries()].filter(([p])=>p.startsWith(`/upstreams/${id}/targets/`)).map(([,v])=>v).concat(extra),next:null},bytes:100};
  if(path==='/services')return{status:200,body:{data:[],next:null},bytes:20};
  if(path==='/plugins')return{status:200,body:{data:[...current.values()].filter(v=>v.config).concat(extra.filter(v=>v.config)),next:null},bytes:50};
  const kind=kinds.find(kind=>path===`/consumers/${id}/${kind}`);if(kind){
   expect(query).toMatchObject({size:100});const data=[...current.entries()].filter(([p])=>p.startsWith(path+'/')).map(([,v])=>v);
   if(kind==='key-auth'&&extra.length){return{status:200,body:{data:query?.offset?extra:data,next:query?.offset?null:`${path}?size=100&offset=opaque-two`},bytes:100};}
   return{status:200,body:{data,next:null},bytes:100};
  }
  return{status:404,body:{message:'Not found'},bytes:20};
 });
 const run=<T>(fn:()=>Promise<T>)=>context.runHttp({},async()=>{context.bindHttpActor(actor,randomUUID());return context.runActor({actor,clusterId:cid,workspaceId:wid,module:'workflows',action:'write'},async()=>{frame=context.current();return fn();});});
 const complete=(index:number)=>{const packet=packets[index],n=ordered[index],response=restoring?{...structuredClone(n.data),created_at:100+index}:null;
  if(restoring&&n.type==='certificates')response.snis=[];
  if(restoring){current.set(n.path,response);if(n.type==='snis'){const certificate=current.get(`/certificates/${id}`);if(certificate)certificate.snis.push(n.data.name);}}
  else{current.delete(n.path);if(n.type==='snis')current.get(`/certificates/${id}`).snis=[];}
  descriptor=immutableJson({...descriptor,packet,nodeKey:n.key,completed:[...descriptor.completed,{nodeKey:n.key,packet,operationId:randomUUID(),responseHmac:secrets.fingerprint(response),response,source:'current-original-response' as const}]});
  return descriptor;
 };
 return{provider,context,graphs,kong,custody,run,original,delegate,graph,packets,ordered,current,extra,complete,secrets,source,actor,cid,wid,
  select:(index:number)=>{descriptor=immutableJson({...descriptor,packet:packets[index],nodeKey:ordered[index].key});},descriptor:()=>descriptor,
  afterRead:(fn:()=>void)=>afterRead=fn,revoke:()=>active=false,changeDescriptor:()=>{descriptor=immutableJson({...descriptor,source:{...descriptor.source,id:randomUUID()}});},readCount:()=>transport.mock.calls.length};
}

beforeEach(()=>{vi.stubEnv('CONSOLE_ENCRYPTION_KEY','85'.repeat(32));vi.stubEnv('KONG_RATE_WAIT_MS','0');vi.stubEnv('APP_SECRET','unit-cursor-key-'.repeat(4));transport.mockReset();});
afterEach(()=>{vi.restoreAllMocks();vi.unstubAllEnvs();vi.useRealTimers();});
describe('V3 current whole-graph witness with actual SDK GET and transport404',()=>{
 it('rejects DTO/copied handles, replacement delegate and use after current frame closes',async()=>{const f=fixture();expect(()=>f.provider.installFixedDelegate(f.delegate)).toThrow();await f.run(()=>expect(f.provider.observe({},'before-native')).rejects.toMatchObject({response:{code:'TEST_ORIGINAL_REQUIRED'}}));let issued:any;
  await f.run(async()=>{issued=await f.provider.observe(f.original,'before-native');expect(()=>f.provider.resolve({} as any)).toThrow();expect(()=>f.provider.resolve({...issued})).toThrow();expect(f.provider.resolve(issued).absent).toHaveLength(7);});expect(()=>f.provider.resolve(issued)).toThrow();
 });
 it('verifies all seven Consumer/credential packets in one original shared-budget frame without claiming proxy authentication',async()=>{const f=fixture();await f.run(async()=>{
  for(let index=0;index<f.packets.length;index++){f.select(index);const before=await f.provider.observe(f.original,'before-native');expect(f.provider.resolve(before).nodes).toHaveLength(index);f.provider.close(before);f.complete(index);
   const witness=await f.provider.observe(f.original,'after-native'),value=f.provider.resolve(witness);expect(value.nodes).toHaveLength(index+1);expect(value.configurationVerification).toBe('verified');expect(value.functionalVerification).toBe('pending');f.provider.close(witness);
  }
 });expect(f.custody.getRestorePayload).not.toHaveBeenCalled();expect(transport.mock.calls.every(call=>call[2]==='GET')).toBe(true);expect(f.readCount()).toBeGreaterThan(100);});
 it('keeps explicit Certificate→SNI current names consistent without mutating archived bytes or POST receipts',async()=>{const f=fixture('certificate');await f.run(async()=>{f.complete(0);let h=await f.provider.observe(f.original,'after-native');expect(f.provider.resolve(h).nodes.find(n=>n.type==='certificates')!.data.snis).toEqual([]);f.provider.close(h);f.complete(1);h=await f.provider.observe(f.original,'after-native');expect(f.provider.resolve(h).nodes.find(n=>n.type==='certificates')!.data.snis).toEqual(['unit.example']);expect(f.descriptor().completed[0].response).toMatchObject({snis:[]});expect(f.graph.nodes[0].data.snis).toEqual(['unit.example']);f.provider.close(h);});});
 it('checks Service/Route/Plugin restore relation prefixes and CA current reflection',async()=>{for(const type of ['service','ca'] as const){const f=fixture(type);await f.run(async()=>{for(let i=0;i<f.packets.length;i++){f.select(i);f.complete(i);const h=await f.provider.observe(f.original,'after-native');expect(f.provider.resolve(h).nodes).toHaveLength(i+1);f.provider.close(h);}});}});
 it('verifies Upstream/Target restoration current effective UUID and complete original-response history, including a single Target with retained parent',async()=>{for(const type of ['upstream','target'] as const){const f=fixture(type);await f.run(async()=>{for(let index=0;index<f.packets.length;index++){f.select(index);const before=await f.provider.observe(f.original,'before-native');f.provider.close(before);f.complete(index);const after=await f.provider.observe(f.original,'after-native');expect(f.provider.resolve(after).nodes.some(n=>n.type==='targets')).toBe(index===f.packets.length-1);f.provider.close(after);}});}});
 it('refuses a newly effective foreign Target before the related restore POST and refuses unexplained zero-history at whole closure',async()=>{for(const weight of [100,0]){const f=fixture('upstream');f.complete(0);f.select(1);f.extra.push({...f.graph.nodes[1].data,id:randomUUID(),weight});await f.run(()=>expect(f.provider.observe(f.original,'before-native')).rejects.toThrow());}});
 it('rejects a hidden foreign-tag next-page child before the first Native even when original child points still match',async()=>{const f=fixture('consumer',false);f.extra.push({id:randomUUID(),consumer:{id:f.graph.nodes[0].id},key:'foreign',tags:['kos-ws-foreign']});await f.run(()=>expect(f.provider.observe(f.original,'before-native')).rejects.toMatchObject({response:{code:'ENTITY_RECYCLE_CURRENT_COLLECTION_DRIFT'}}));expect(transport.mock.calls.some(call=>(call[4] as any)?.offset==='opaque-two')).toBe(true);});
 it('does not accept a copied POST receipt as current after the current stored credential secret drifts',async()=>{const f=fixture();for(let i=0;i<2;i++)f.complete(i);const credential=f.graph.nodes[1];f.current.get(credential.path).key='changed-current-secret';await f.run(()=>expect(f.provider.observe(f.original,'after-native')).rejects.toMatchObject({response:{code:'ENTITY_RECYCLE_CURRENT_GRAPH_CHANGED'}}));});
 it('rejects actual GET200 in an expected absent slot and current parent or workspace drift',async()=>{for(const change of ['present','parent','workspace']){const f=fixture();f.complete(0);if(change==='present')f.current.set(f.graph.nodes[1].path,structuredClone(f.graph.nodes[1].data));else if(change==='workspace')f.current.get(f.graph.nodes[0].path).tags=['kos-ws-other'];else{f.complete(1);f.current.get(f.graph.nodes[1].path).consumer={id:randomUUID()};}await f.run(()=>expect(f.provider.observe(f.original,'after-native')).rejects.toThrow());}});
 it('rechecks private original source/descriptor after awaits and never issues a current witness after revocation',async()=>{for(const revoke of [true,false]){const f=fixture('ca');let count=0;f.afterRead(()=>{if(++count===2){if(revoke)f.revoke();else f.changeDescriptor();}});await f.run(()=>expect(f.provider.observe(f.original,'before-native')).rejects.toThrow());}});
 it('rejects wrong Basic secret reflection and never upgrades configuration proof to proxy authentication',async()=>{const f=fixture();f.complete(0);f.complete(1);f.complete(2);const d:any=f.descriptor();const altered=structuredClone(d);altered.completed[2].response.password='0'.repeat(40);altered.completed[2].responseHmac=f.secrets.fingerprint(altered.completed[2].response);
  const other=new EntityRecycleCurrentWitnessService(f.kong,f.graphs,f.context,f.secrets);other.installFixedDelegate({describe:async()=>altered,assertLive:()=>undefined});await f.run(()=>expect(other.observe(f.original,'after-native')).rejects.toMatchObject({response:{code:'ENTITY_RECYCLE_CREDENTIAL_CONFIG_UNVERIFIED'}}));
 });
 it('performs two fresh DNS guard observations per packet plus all seven restore readbacks in the original shared 100-page budget',async()=>{const f=fixture();await f.run(async()=>{for(let i=0;i<f.packets.length;i++){f.select(i);for(let dns=0;dns<2;dns++){const before=await f.provider.observe(f.original,'before-native');f.provider.close(before);}f.complete(i);const after=await f.provider.observe(f.original,'after-native');f.provider.close(after);}});const pages=transport.mock.calls.filter(call=>(call[4] as any)?.size!==undefined);expect(pages).toHaveLength(14);expect(f.readCount()).toBeLessThan(500);});
 it('validates requester and each reviewer current IAM independently against a genuine witness, preserving the executor ALS actor',async()=>{const f=fixture('service',false),reviewer=randomUUID(),otherReviewer=randomUUID(),users=new Map([f.actor.id,reviewer,otherReviewer].map(id=>[id,{id,super_admin:false,credential_epoch:'1'}]));
  const grant=(module:string,action:string)=>({module,action,cluster_id:f.cid,workspace_id:f.wid,scope_type:'workspace',scope_values:[f.wid]});
  const grants=new Map([[f.actor.id,[grant('workflows','write'),grant('services','delete'),grant('routes','delete')]],...[reviewer,otherReviewer].map(id=>[id,[grant('workflows','approve'),grant('services','read'),grant('routes','read')]] as [string,any[]])]);let epoch='1';
  const sql:any={one:vi.fn(async(q:string,values:any[])=>q.includes('iam_epoch')?{version:epoch}:users.get(values[0])??null),query:vi.fn(async(_q:string,values:any[])=>(grants.get(values[0])??[]).map(g=>({...g,binding_current:true,binding_remaining_ms:null})))};
  const boundary=new EntityChangeBoundaryService(sql,f.secrets,f.context,{} as any,{get:async()=>({id:f.wid,code:'default',is_default:true,status:'active'})} as any,f.kong,{} as any,{} as any);
  boundary.installCurrentRecycleWitnessReader({resolve:h=>f.provider.resolve(h)});expect(()=>boundary.installCurrentRecycleWitnessReader({resolve:h=>f.provider.resolve(h)})).toThrow();
  await f.run(async()=>{const h=await f.provider.observe(f.original,'before-native'),material=f.descriptor().prepared;
   await boundary.assertCurrentRecycleSubject(f.actor.id,material as any,'write',h);for(const id of [reviewer,otherReviewer])await boundary.assertCurrentRecycleSubject(id,material as any,'approve',h);
   expect(f.context.current().actor?.id).toBe(f.actor.id);
   grants.set(otherReviewer,[grant('workflows','approve')]);await expect(boundary.assertCurrentRecycleSubject(otherReviewer,material as any,'approve',h)).rejects.toMatchObject({response:{code:'ENTITY_CHANGE_SUBJECT_SCOPE_DENIED'}});
   users.delete(reviewer);await expect(boundary.assertCurrentRecycleSubject(reviewer,material as any,'approve',h)).rejects.toMatchObject({response:{code:'ENTITY_RECYCLE_CURRENT_PARTY_INACTIVE'}});
   await expect(boundary.assertCurrentRecycleSubject(f.actor.id,material as any,'approve',h)).rejects.toMatchObject({response:{code:'ENTITY_RECYCLE_CURRENT_SUBJECT_INVALID'}});
   await expect(boundary.assertCurrentRecycleSubject(f.actor.id,material as any,'write',{} as any)).rejects.toMatchObject({response:{code:'ENTITY_RECYCLE_CURRENT_WITNESS_REQUIRED'}});
   f.provider.close(h);
  });
 });
 it('rejects IAM epoch/user credential changes during fresh current authorization without caching an old witness permit',async()=>{for(const change of ['epoch','credential']){const f=fixture('ca',false);let epoch=1,user={id:f.actor.id,super_admin:true,credential_epoch:'1'};
  const sql:any={one:vi.fn(async(q:string)=>q.includes('iam_epoch')?{version:epoch}:structuredClone(user)),query:vi.fn(async()=>{if(change==='epoch')epoch++;else user.credential_epoch='2';return[];})};
  const b=new EntityChangeBoundaryService(sql,f.secrets,f.context,{} as any,{get:async()=>({code:'default',is_default:true,status:'active'})} as any,f.kong,{} as any,{} as any);b.installCurrentRecycleWitnessReader({resolve:h=>f.provider.resolve(h)});
  await f.run(async()=>{const h=await f.provider.observe(f.original,'before-native');await expect(b.assertCurrentRecycleSubject(f.actor.id,f.descriptor().prepared as any,'write',h)).rejects.toMatchObject({response:{code:'ENTITY_CHANGE_PERMISSIONS_CHANGED'}});f.provider.close(h);});
 }});
 it('rejects naturally expired user/team binding provenance and closes a binding that expires while current authorization awaits',async()=>{for(const mode of ['user-expired','team-expired','during-await']){const f=fixture('ca',false);const grant=(module:string,action:string)=>({module,action,cluster_id:f.cid,workspace_id:f.wid,scope_type:'workspace',scope_values:[f.wid],binding_source:mode==='team-expired'?'team':'user',binding_current:mode==='during-await',binding_remaining_ms:mode==='during-await'?2:-1});
  const db:any={one:async(q:string)=>q.includes('iam_epoch')?{version:1}:{id:f.actor.id,super_admin:false,credential_epoch:'1'},query:vi.fn(async(q:string)=>{expect(q).toContain('clock_timestamp()');expect(q).toContain('LEFT JOIN user_role_bindings');expect(q).toContain('LEFT JOIN team_role_bindings');return[grant('workflows','write'),grant('ca_certificates','delete')];})};
  const b=new EntityChangeBoundaryService(db,f.secrets,f.context,{} as any,{get:async()=>{if(mode==='during-await')await new Promise(resolve=>setTimeout(resolve,5));return{code:'default',is_default:true,status:'active'};}} as any,f.kong,{} as any,{} as any);b.installCurrentRecycleWitnessReader({resolve:h=>f.provider.resolve(h)});
  await f.run(async()=>{const h=await f.provider.observe(f.original,'before-native');await expect(b.assertCurrentRecycleSubject(f.actor.id,f.descriptor().prepared as any,'write',h)).rejects.toMatchObject({response:{code:mode==='during-await'?'ENTITY_RECYCLE_CURRENT_BINDING_EXPIRED':'ENTITY_CHANGE_SUBJECT_SCOPE_DENIED'}});f.provider.close(h);});
 }});
 it('requires each current party sensitive-field permission even when its Consumer write/approve grants remain valid',async()=>{const f=fixture();for(let i=0;i<f.packets.length;i++)f.complete(i);const reviewer=randomUUID();let secret=false;
  const grant=(module:string,action:string)=>({module,action,cluster_id:f.cid,workspace_id:f.wid,scope_type:'workspace',scope_values:[f.wid],binding_current:true,binding_remaining_ms:null});
  const db:any={one:async(q:string,v:any[])=>q.includes('iam_epoch')?{version:1}:{id:v[0],super_admin:false,credential_epoch:'1'},query:async()=>[grant('workflows','approve'),grant('consumers','read'),...(secret?[grant('secrets','read')]:[])]};
  const b=new EntityChangeBoundaryService(db,f.secrets,f.context,{} as any,{get:async()=>({code:'default',is_default:true,status:'active'})} as any,f.kong,{} as any,{} as any);b.installCurrentRecycleWitnessReader({resolve:h=>f.provider.resolve(h)});
  await f.run(async()=>{const h=await f.provider.observe(f.original,'after-native');await expect(b.assertCurrentRecycleSubject(reviewer,f.descriptor().prepared as any,'approve',h)).rejects.toMatchObject({response:{code:'ENTITY_RECYCLE_CURRENT_SECRET_SCOPE_DENIED'}});secret=true;await b.assertCurrentRecycleSubject(reviewer,f.descriptor().prepared as any,'approve',h);f.provider.close(h);});
 });
 it('closes the private witness and cannot turn a stale handle into a new observation',async()=>{const f=fixture('ca');await f.run(async()=>{const h=await f.provider.observe(f.original,'before-native');f.provider.close(h);expect(()=>f.provider.resolve(h)).toThrow();const next=await f.provider.observe(f.original,'before-native');expect(next).not.toBe(h);f.provider.close(next);});});
});
