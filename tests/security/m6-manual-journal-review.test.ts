import {describe,expect,it,vi} from 'vitest';
import {randomUUID} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {runInNewContext} from 'node:vm';
import ts from 'typescript';
import {authorizeFreshBootstrap,beforeManualMutation,completeManualMutation,createManualJournal,interruptManualMutation,MANUAL_ACTIONS,manualAttemptForPacket,manualJournalSummary,stopManualJournal,writeManualReferenceAtomic} from './lib/m6-manual-journal.mjs';
import {mergeManualWriteEvidence} from './lib/m6-manual-read-evidence.mjs';

const roles=['owner','administrator','approver'] as const;
function fixture(){
 const cid=randomUUID(),wid=randomUUID(),content={slug:'independent-manual-page',title:'Independent manual page',markdown:'# Public fixture'},actors=Object.fromEntries(roles.map(role=>[role,{id:randomUUID(),username:'offline-'+role,password:'Offline!'+role+'Password2026'}]));
 const journal=createManualJournal({clusterId:cid,workspaceId:wid,actors,content,priorKeys:[],forbiddenEntityIds:[]});
 const saves:any[]=[],persist=vi.fn(()=>{saves.push(structuredClone(journal));});
 return{cid,wid,content,actors,journal,saves,persist};
}
type Fixture=ReturnType<typeof fixture>;
function packet(f:Fixture,role:typeof roles[number],action='login',key=randomUUID()){
 const portal=role==='owner',origin=portal?'http://127.0.0.1:8082':'http://127.0.0.1:8080',scope=portal?`?clusterId=${f.cid}&workspaceId=${f.wid}`:'',body=action==='login'?{username:f.actors[role].username,password:f.actors[role].password,...(portal?{clusterId:f.cid,workspaceId:f.wid}:{})}:portal?{clusterId:f.cid,workspaceId:f.wid}:{};
 return{url:origin+(portal?'/api/v1/portal/auth/':'/api/v1/auth/')+action+scope,method:'POST',headers:{'X-Idempotency-Key':key},rawBody:JSON.stringify(body)};
}
function login(f:Fixture,role:typeof roles[number],bootstrap=false){
 authorizeFreshBootstrap(f.journal,role,[],f.persist);
 if(bootstrap){const a=beforeManualMutation(f.journal,role,packet(f,role,'refresh'),[],f.persist);completeManualMutation(f.journal,a,401,{error:{code:role==='owner'?'PORTAL_SESSION_EXPIRED':'SESSION_EXPIRED'},meta:{requestId:randomUUID()}},f.persist);}
 const a=beforeManualMutation(f.journal,role,packet(f,role),[],f.persist),actor=f.actors[role];
 completeManualMutation(f.journal,a,201,{data:role==='owner'?{developer:{...actor,clusterId:f.cid,workspaceId:f.wid,status:'active'}}:{user:{id:actor.id,username:actor.username}},meta:{requestId:randomUUID()}},f.persist);return a;
}
function metadataPacket(f:Fixture,action:string,key=randomUUID()){
 const suffix=action==='page-create'?'':`/${f.journal.pageId}`+(action==='page-publish'?'/publish':action==='page-restore-draft'?'/restore':'');
 return{url:`http://127.0.0.1:8080/api/v1/clusters/${f.cid}/portal/pages${suffix}?workspaceId=${f.wid}`,method:action==='page-archive'?'DELETE':'POST',headers:{'X-Idempotency-Key':key},rawBody:JSON.stringify(action==='page-create'?f.content:{revision:f.journal.pageRevision,confirmed:true,confirm_name:f.content.title})};
}
function completePage(f:Fixture,action:string){
 const a=beforeManualMutation(f.journal,'administrator',metadataPacket(f,action),[],f.persist),wf=randomUUID(),entity={id:f.journal.pageId??randomUUID(),slug:f.content.slug,title:f.content.title,state:({'page-create':'draft','page-publish':'published','page-archive':'deleted','page-restore-draft':'draft'} as any)[action],revision:(f.journal.pageRevision??0)+1};
 const payload={data:{entity,workflowId:wf,receipt:{state:'succeeded',workflowId:wf,clusterId:f.cid,workspaceId:f.wid,idempotencyKey:a.key}},meta:{requestId:randomUUID()}};completeManualMutation(f.journal,a,201,payload,f.persist);return{a,payload};
}
const runner=readFileSync('tests/security/manual-m6-ui.mjs','utf8'),tree=ts.createSourceFile('manual-m6-ui.mjs',runner,ts.ScriptTarget.ES2022,true,ts.ScriptKind.JS);
function actualFunction(name:string,sandbox:Record<string,unknown>){const statement=tree.statements.find(s=>ts.isFunctionDeclaration(s)&&s.name?.text===name);expect(statement).toBeTruthy();return runInNewContext(statement!.getText(tree)+`;${name};`,{URL,...sandbox});}
function actualClient(path:string,fetch:unknown){
 const exports:any={},code=ts.transpileModule(readFileSync(path,'utf8'),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.CommonJS}}).outputText;
 runInNewContext(code,{exports,require:(name:string)=>{if(name==='./idempotency')return{newIdempotencyKey:randomUUID};
  if(name==='./workspace-scope'){
   const dependency:any={},source=ts.transpileModule(readFileSync('apps/console-web/src/api/workspace-scope.ts','utf8'),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.CommonJS}}).outputText;
   runInNewContext(source,{exports:dependency,URL,URLSearchParams});return dependency;
  }
  throw Error('Unexpected offline dependency');},Headers,URL,Response,FormData,AbortController,DOMException,fetch,crypto:{randomUUID},window:{dispatchEvent:vi.fn()},CustomEvent:class{},Event:class{}});return exports;
}

describe('independent manual authority, bounded fresh bootstrap and durable no replay',()=>{
 it('owns exactly three trusted logins and four Markdown mutations in fixed order',()=>{expect(MANUAL_ACTIONS).toEqual(['portal-owner-login','console-administrator-login','page-create','page-publish','page-archive','page-restore-draft','console-approver-login']);});
 it.each(['owner','administrator','approver'])('fresh %s context authorization rejects even anonymous pre-existing cookies',role=>{
  const f=fixture();f.journal.nextIndex=role==='owner'?0:role==='administrator'?1:6;
  expect(()=>authorizeFreshBootstrap(f.journal,role,[{name:'kongos_csrf',value:'offline'}],f.persist)).toThrow();expect(f.journal.phase).toBe('stopped-without-replay');expect(f.journal.attempts).toHaveLength(0);
 });
 it.each(['owner','administrator','approver'])('fresh %s context cannot be authorized a second time',role=>{
  const f=fixture();f.journal.nextIndex=role==='owner'?0:role==='administrator'?1:6;authorizeFreshBootstrap(f.journal,role,[],f.persist);
  expect(()=>authorizeFreshBootstrap(f.journal,role,[],f.persist)).toThrow();expect(f.journal.phase).toBe('stopped-without-replay');
 });
 it.each(['owner','administrator','approver'])('pre-login %s actual old access/refresh cookie blocks before a packet',role=>{
  const f=fixture();f.journal.nextIndex=role==='owner'?0:role==='administrator'?1:6;authorizeFreshBootstrap(f.journal,role,[],f.persist);
  expect(()=>beforeManualMutation(f.journal,role,packet(f,role),[{name:role==='owner'?'kongos_portal_refresh':'kongos_access',value:'offline-old-session'}],f.persist)).toThrow();expect(f.journal.attempts).toHaveLength(0);expect(f.journal.phase).toBe('stopped-without-replay');
 });
 it.each(['owner','administrator','approver'])('pre-login %s actual Cookie header blocks old session before a packet',role=>{
  const f=fixture();f.journal.nextIndex=role==='owner'?0:role==='administrator'?1:6;authorizeFreshBootstrap(f.journal,role,[],f.persist);const p:any=packet(f,role);p.headers.Cookie=(role==='owner'?'kongos_portal_access':'kongos_refresh')+'=offline-old-session';
  expect(()=>beforeManualMutation(f.journal,role,p,[],f.persist)).toThrow();expect(f.journal.attempts).toHaveLength(0);expect(f.journal.phase).toBe('stopped-without-replay');
 });
 it('allows one genuine anonymous Portal refresh with actor null and exact original scope/body/key, then only known401 permits owner login',()=>{
  const f=fixture();authorizeFreshBootstrap(f.journal,'owner',[],f.persist);const p=packet(f,'owner','refresh'),a=beforeManualMutation(f.journal,'owner',p,[{name:'kongos_portal_csrf',value:'offline-anonymous-csrf'}],f.persist);
  expect(a).toMatchObject({category:'anonymous-bootstrap',actorId:null,expectedLoginActorId:f.actors.owner.id,rawBody:p.rawBody,body:{clusterId:f.cid,workspaceId:f.wid},key:p.headers['X-Idempotency-Key'],state:'before-single-send'});expect(f.saves.at(-1).inFlight).toBe(a.key);expect(f.journal.nextIndex).toBe(0);
  completeManualMutation(f.journal,a,401,{error:{code:'PORTAL_SESSION_EXPIRED'},meta:{requestId:randomUUID()}},f.persist);expect(f.journal.nextIndex).toBe(0);expect(f.journal.inFlight).toBeNull();expect(a.state).toBe('expected-auth-missing-rejection');
  const next=beforeManualMutation(f.journal,'owner',packet(f,'owner'),[{name:'kongos_portal_csrf',value:'offline-anonymous-csrf'}],f.persist);expect(next.actorId).toBe(f.actors.owner.id);expect(next.category).toBe('planned');
 });
 it.each([[200,'PORTAL_SESSION_EXPIRED',true],[401,'OTHER',true],[401,'PORTAL_SESSION_EXPIRED',false],[500,'PORTAL_SESSION_EXPIRED',true],[0,'PORTAL_SESSION_EXPIRED',true]])('bootstrap result %s/%s/reqID%s stops all later packets', (status,code,requestId)=>{
  const f=fixture();authorizeFreshBootstrap(f.journal,'owner',[],f.persist);const a=beforeManualMutation(f.journal,'owner',packet(f,'owner','refresh'),[],f.persist);
  expect(()=>completeManualMutation(f.journal,a,status,{error:{code},meta:requestId?{requestId:randomUUID()}:{}},f.persist)).toThrow();expect(f.journal.phase).toBe('stopped-without-replay');
  expect(()=>beforeManualMutation(f.journal,'owner',packet(f,'owner'),[],f.persist)).toThrow();expect(f.journal.attempts).toHaveLength(1);
 });
 it('a second anonymous bootstrap after known401 is blocked globally instead of replayed',()=>{const f=fixture();authorizeFreshBootstrap(f.journal,'owner',[],f.persist);const a=beforeManualMutation(f.journal,'owner',packet(f,'owner','refresh'),[],f.persist);completeManualMutation(f.journal,a,401,{error:{code:'PORTAL_SESSION_EXPIRED'},meta:{requestId:randomUUID()}},f.persist);expect(()=>beforeManualMutation(f.journal,'owner',packet(f,'owner','refresh'),[],f.persist)).toThrow();expect(f.journal.attempts).toHaveLength(1);});
 it.each(['wrong-password','wrong-username','extra-field','foreign-scope','duplicate-query','foreign-origin','prior-key'])('trusted login rejects %s before packet',kind=>{
  const f=fixture();authorizeFreshBootstrap(f.journal,'owner',[],f.persist);const p:any=packet(f,'owner'),body=JSON.parse(p.rawBody);
  if(kind==='wrong-password')body.password+='-wrong';if(kind==='wrong-username')body.username='other';if(kind==='extra-field')body.extra=true;if(kind==='foreign-scope')body.workspaceId=randomUUID();if(kind==='duplicate-query')p.url+='&workspaceId='+f.wid;if(kind==='foreign-origin')p.url=p.url.replace(':8082',':8080');if(kind==='prior-key')f.journal.priorKeys.push(p.headers['X-Idempotency-Key']);p.rawBody=JSON.stringify(body);
  expect(()=>beforeManualMutation(f.journal,'owner',p,[],f.persist)).toThrow();expect(f.journal.attempts).toHaveLength(0);expect(f.journal.phase).toBe('stopped-without-replay');
 });
 it.each(['null-payload','wrong-identity','wrong-scope','missing-requestid','non-2xx'])('planned login %s stops metadata and subsequent login packets',kind=>{
  const f=fixture();authorizeFreshBootstrap(f.journal,'owner',[],f.persist);const a=beforeManualMutation(f.journal,'owner',packet(f,'owner'),[],f.persist),payload:any={data:{developer:{id:f.actors.owner.id,username:f.actors.owner.username,clusterId:f.cid,workspaceId:f.wid,status:'active'}},meta:{requestId:randomUUID()}};
  if(kind==='wrong-identity')payload.data.developer.id=randomUUID();if(kind==='wrong-scope')payload.data.developer.workspaceId=randomUUID();if(kind==='missing-requestid')delete payload.meta.requestId;
  expect(()=>completeManualMutation(f.journal,a,kind==='non-2xx'?403:201,kind==='null-payload'?undefined:payload,f.persist)).toThrow();expect(()=>beforeManualMutation(f.journal,'administrator',packet(f,'administrator'),[],f.persist)).toThrow();expect(f.journal.attempts).toHaveLength(1);
 });
 it('transport unknown remains durably tied to original packet and blocks cross-context writes without retry',()=>{
  const f=fixture();authorizeFreshBootstrap(f.journal,'owner',[],f.persist);const p=packet(f,'owner'),a=beforeManualMutation(f.journal,'owner',p,[],f.persist);interruptManualMutation(f.journal,a,f.persist);
  expect(f.saves.at(-1).attempts[0]).toMatchObject({key:a.key,rawBody:p.rawBody,state:'transport-interrupted',actorId:f.actors.owner.id});expect(()=>beforeManualMutation(f.journal,'administrator',packet(f,'administrator'),[],f.persist)).toThrow();expect(f.journal.attempts).toHaveLength(1);
 });
 it('an in-flight packet blocks overlap even from another trusted role and does not append a second intent',()=>{const f=fixture();authorizeFreshBootstrap(f.journal,'owner',[],f.persist);beforeManualMutation(f.journal,'owner',packet(f,'owner'),[],f.persist);expect(()=>beforeManualMutation(f.journal,'approver',packet(f,'approver'),[],f.persist)).toThrow();expect(f.journal.attempts).toHaveLength(1);expect(f.journal.phase).toBe('stopped-without-replay');});
 it.each([false,true])('complete flow with owner bootstrap=%s has exactly7 planned packets and 4 metadata writes, no forced extra refresh',bootstrap=>{
  const f=fixture();login(f,'owner',bootstrap);login(f,'administrator');const ids=[];for(const action of ['page-create','page-publish','page-archive','page-restore-draft'])ids.push(completePage(f,action).payload.data.entity.id);login(f,'approver');
  expect(new Set(ids).size).toBe(1);expect(f.journal.pageRevision).toBe(4);expect(manualJournalSummary(f.journal)).toMatchObject({complete:true,plannedWrites:7,successfulPlannedWrites:7,expectedDeniedAnonymousBootstrapWrites:bootstrap?1:0});expect(f.journal.attempts.filter(a=>a.action.startsWith('page-'))).toHaveLength(4);
  expect(()=>beforeManualMutation(f.journal,'administrator',metadataPacket(f,'page-create'),[],f.persist)).toThrow();expect(f.journal.attempts.filter(a=>a.category==='planned')).toHaveLength(7);
 });
 it.each(['wrong-workspace','wrong-page','wrong-revision','extra-body','unconfirmed'])('metadata rejects %s before a packet and preserves original page identity',kind=>{
  const f=fixture();login(f,'owner');login(f,'administrator');completePage(f,'page-create');const p:any=metadataPacket(f,'page-publish'),body=JSON.parse(p.rawBody),id=f.journal.pageId;
  if(kind==='wrong-workspace')p.url=p.url.replace(f.wid,randomUUID());if(kind==='wrong-page')p.url=p.url.replace(id,randomUUID());if(kind==='wrong-revision')body.revision++;if(kind==='extra-body')body.extra=true;if(kind==='unconfirmed')body.confirmed=false;p.rawBody=JSON.stringify(body);
  expect(()=>beforeManualMutation(f.journal,'administrator',p,[],f.persist)).toThrow();expect(f.journal.attempts).toHaveLength(3);expect(f.journal.pageId).toBe(id);
 });
 it('metadata create cannot return an existing historical ID or a receipt with another original key',()=>{
  for(const mismatch of ['historic-id','receipt-key']){const f=fixture();login(f,'owner');login(f,'administrator');const p=metadataPacket(f,'page-create'),a=beforeManualMutation(f.journal,'administrator',p,[],f.persist),id=randomUUID(),wf=randomUUID();if(mismatch==='historic-id')f.journal.forbiddenEntityIds.push(id);
   expect(()=>completeManualMutation(f.journal,a,201,{data:{entity:{id,slug:f.content.slug,title:f.content.title,state:'draft',revision:1},workflowId:wf,receipt:{state:'succeeded',workflowId:wf,clusterId:f.cid,workspaceId:f.wid,idempotencyKey:mismatch==='receipt-key'?randomUUID():a.key}},meta:{requestId:randomUUID()}},f.persist)).toThrow();expect(f.journal.pageId).toBeNull();expect(f.journal.phase).toBe('stopped-without-replay');}
 });
 it('response lookup requires exact original role method origin path query and key',()=>{
  const f=fixture();authorizeFreshBootstrap(f.journal,'owner',[],f.persist);const p=packet(f,'owner'),a=beforeManualMutation(f.journal,'owner',p,[],f.persist);expect(manualAttemptForPacket(f.journal,'owner',p)).toBe(a);
  for(const patch of [{method:'DELETE'},{url:p.url+'&extra=1'},{headers:{'X-Idempotency-Key':randomUUID()}},{url:p.url.replace(':8082',':8080')},{rawBody:p.rawBody+' '}])expect(manualAttemptForPacket(f.journal,'owner',{...p,...patch})).toBeUndefined();expect(manualAttemptForPacket(f.journal,'administrator',p)).toBeUndefined();
 });
 it('a completed metadata original key cannot be reused for the next action, and a fresh retry key remains blocked',()=>{
  const f=fixture();login(f,'owner');login(f,'administrator');const original=completePage(f,'page-create').a,duplicated=metadataPacket(f,'page-publish',original.key);
  expect(()=>beforeManualMutation(f.journal,'administrator',duplicated,[],f.persist)).toThrow();expect(()=>beforeManualMutation(f.journal,'administrator',metadataPacket(f,'page-publish'),[],f.persist)).toThrow();expect(f.journal.attempts).toHaveLength(3);expect(f.journal.attempts[2].key).toBe(original.key);expect(f.journal.phase).toBe('stopped-without-replay');
 });
});

describe('actual frontend cold contexts, runner boundary and atomic private persistence without transport',()=>{
 it('actual Portal client produces one anonymous refresh POST only after missing auth/me and nonce; scoped body/key match journal',async()=>{
  const f=fixture(),packets:any[]=[],fetch=vi.fn(async(url:string,options:any)=>{packets.push({url,options});const csrf=url.includes('/auth/csrf');return new Response(JSON.stringify(csrf?{data:{csrfToken:'offline-anonymous-csrf'}}:{error:{code:'PORTAL_SESSION_EXPIRED'},meta:{requestId:randomUUID()}}),{status:csrf?200:401,headers:{'Content-Type':'application/json'}});});
  const c=actualClient('apps/portal-web/src/api/portal-client.ts',fetch),scope={clusterId:f.cid,workspaceId:f.wid};c.setPortalScope(scope);await expect(c.portalRequest('/auth/me',scope)).rejects.toMatchObject({status:401,code:'PORTAL_SESSION_EXPIRED'});
  expect(packets.map(p=>new URL(p.url,'http://fixture.invalid').pathname)).toEqual(['/api/v1/portal/auth/me','/api/v1/portal/auth/csrf','/api/v1/portal/auth/refresh']);const p=packets[2];expect(JSON.parse(p.options.body)).toEqual(scope);expect(p.options.headers.get('X-Portal-CSRF')).toBe('offline-anonymous-csrf');expect(p.options.credentials).toBe('same-origin');
  authorizeFreshBootstrap(f.journal,'owner',[],f.persist);expect(beforeManualMutation(f.journal,'owner',{url:'http://127.0.0.1:8082'+p.url,method:p.options.method,headers:Object.fromEntries(p.options.headers),rawBody:p.options.body},[],f.persist).category).toBe('anonymous-bootstrap');
 });
 it('actual Console client missing refresh receives GET csrf401 and never fabricates a POST refresh',async()=>{
  const packets:any[]=[],fetch=vi.fn(async(url:string,options:any)=>{packets.push({url,options});return new Response(JSON.stringify({error:{code:'SESSION_EXPIRED'},meta:{requestId:randomUUID()}}),{status:401,headers:{'Content-Type':'application/json'}});}),c=actualClient('apps/console-web/src/api/client.ts',fetch);
  await expect(c.api('/auth/me')).rejects.toMatchObject({status:401,code:'SESSION_EXPIRED'});expect(packets.map(p=>p.url)).toEqual(['/api/v1/auth/me','/api/v1/auth/csrf']);expect(packets.every(p=>p.options.method==='GET')).toBe(true);
 });
 it('actual retain merges latest original failures pending rows old jars lifecycle and secrets without replacing history',()=>{
  const latest:any={secrets:['offline-historic-key'],failedIssue:{state:'failed',nativePending:3,cipher:'offline-old-cipher'},browserRemaining:{latestNamedJars:[[{name:'offline',value:'offline-old-jar'}]]},priorFixtureRuns:[{old:true}],writeAttempts:[{state:'response-unknown',key:randomUUID()}]},history=structuredClone(latest),write=vi.fn();
  const f=fixture(),retain=actualFunction('retain',{privateReference:vi.fn(()=>latest),M6_REFERENCE:'offline-only',writeManualReferenceAtomic:write,mergeManualWriteEvidence,newSecrets:new Set(['offline-new-cookie','offline-historic-key']),journal:f.journal,manualMetadata:[],manualAttempts:f.journal.attempts,writes:[]});retain();const merged=write.mock.calls[0][1];
  expect(merged.failedIssue).toEqual(history.failedIssue);expect(merged.browserRemaining).toEqual(history.browserRemaining);expect(merged.priorFixtureRuns).toEqual(history.priorFixtureRuns);expect(merged.writeAttempts).toEqual(history.writeAttempts);expect(merged.secrets).toEqual(['offline-historic-key','offline-new-cookie']);expect(merged.manualJournal).toBe(f.journal);
 });
 it('actual boundary serializes exact intent and returns durable callback before route.continue',async()=>{
  const f=fixture(),events:string[]=[],persist=()=>{events.push('persist');f.persist();},boundary=actualFunction('boundary',{authorizeFreshBootstrap,beforeManualMutation,interruptManualMutation,stopManualJournal,journal:f.journal,retain:persist,newSecrets:new Set()}),context:any={cookies:vi.fn(async()=>[]),route:vi.fn(async(_pattern:string,callback:any)=>{context.callback=callback;})};
  await boundary(context,'owner');const p=packet(f,'owner'),request={url:()=>p.url,method:()=>p.method,allHeaders:async()=>p.headers,headers:()=>p.headers,postData:()=>p.rawBody},route={request:()=>request,continue:vi.fn(async()=>{events.push('continue');}),abort:vi.fn(async()=>{})};await context.callback(route);
  expect(events).toEqual(['persist','persist','continue']);expect(f.saves.at(-1).attempts[0]).toMatchObject({rawBody:p.rawBody,key:p.headers['X-Idempotency-Key'],actorId:f.actors.owner.id});expect(route.continue).toHaveBeenCalledOnce();expect(route.abort).not.toHaveBeenCalled();
 });
 it('actual boundary persistence failure aborts before first packet; every later write remains blocked',async()=>{
  const f=fixture();let saves=0;const persist=()=>{saves++;if(saves>1)throw Error('offline-disk-failure');},boundary=actualFunction('boundary',{authorizeFreshBootstrap,beforeManualMutation,interruptManualMutation,stopManualJournal,journal:f.journal,retain:persist,newSecrets:new Set()}),context:any={cookies:vi.fn(async()=>[]),route:vi.fn(async(_p:string,callback:any)=>{context.callback=callback;})};await boundary(context,'owner');
  const p=packet(f,'owner'),route={request:()=>({url:()=>p.url,method:()=>p.method,allHeaders:async()=>p.headers,headers:()=>p.headers,postData:()=>p.rawBody}),continue:vi.fn(async()=>{}),abort:vi.fn(async()=>{})};await context.callback(route);await context.callback(route);expect(route.continue).not.toHaveBeenCalled();expect(route.abort).toHaveBeenCalledTimes(2);expect(f.journal.attempts).toHaveLength(1);expect(f.journal.phase).toBe('stopped-without-replay');
 });
 it('actual boundary blocks Admin API writes and prevents all later mutations',async()=>{
  const f=fixture(),boundary=actualFunction('boundary',{authorizeFreshBootstrap,beforeManualMutation,interruptManualMutation,stopManualJournal,journal:f.journal,retain:f.persist,newSecrets:new Set()}),context:any={cookies:vi.fn(async()=>[]),route:vi.fn(async(_p:string,callback:any)=>{context.callback=callback;})};await boundary(context,'owner');const denied={request:()=>({url:()=> 'http://kong:8001/services',method:()=> 'POST'}),continue:vi.fn(async()=>{}),abort:vi.fn(async()=>{})};await context.callback(denied);expect(denied.continue).not.toHaveBeenCalled();expect(denied.abort).toHaveBeenCalledOnce();expect(f.journal.phase).toBe('stopped-without-replay');expect(f.journal.attempts).toHaveLength(0);
 });
 function ioFixture(failAt?:string){const events:string[]=[],io:any={},hit=(name:string)=>{events.push(name);if(name===failAt)throw Error('offline-failure');};io.openSync=vi.fn((path:string,flags:string,mode?:number)=>{hit(flags==='wx'?'open-file':'open-dir');if(flags==='wx'){expect(mode).toBe(0o600);expect(path).toBe('/offline/reference.test.manual.tmp');return 7;}return 8;});io.writeFileSync=vi.fn(()=>hit('write'));io.fsyncSync=vi.fn((fd:number)=>hit(fd===7?'sync-file':'sync-dir'));io.closeSync=vi.fn((fd:number)=>hit(fd===7?'close-file':'close-dir'));io.renameSync=vi.fn(()=>hit('rename'));io.unlinkSync=vi.fn(()=>hit('unlink-temp'));return{io,events};}
 it('atomic private writer uses exclusive0600 file fsync rename then directory fsync in order',()=>{const f=ioFixture();writeManualReferenceAtomic('/offline/reference',{offline:true},f.io,()=> 'test');expect(f.events).toEqual(['open-file','write','sync-file','close-file','rename','open-dir','sync-dir','close-dir']);expect(f.io.writeFileSync.mock.calls[0][1]).toBe(JSON.stringify({offline:true}));});
 it.each(['open-file','write','sync-file','rename','open-dir','sync-dir'])('atomic writer %s failure does not falsely return durable success',failure=>{const f=ioFixture(failure);expect(()=>writeManualReferenceAtomic('/offline/reference',{offline:true},f.io,()=> 'test')).toThrow();if(['write','sync-file','rename'].includes(failure))expect(f.io.unlinkSync).toHaveBeenCalledOnce();if(failure==='sync-file')expect(f.io.renameSync).not.toHaveBeenCalled();if(['open-dir','sync-dir'].includes(failure))expect(f.io.unlinkSync).not.toHaveBeenCalled();});
 it('scope and confirmation paths are actual current PortalAdminPage fields and Backend controller routes',()=>{
  const ui=readFileSync('apps/console-web/src/features/PortalAdminPage.tsx','utf8'),controller=readFileSync('apps/console-api/src/modules/portal/portal.controller.ts','utf8');expect(ui).toContain("post(scope.path('portal/pages'), value)");expect(ui).toContain('revision: row.revision, confirmed: true, confirm_name: row.title');for(const route of ["@Post('pages')","@Post('pages/:id/publish')","@Delete('pages/:id')","@Post('pages/:id/restore')"])expect(controller).toContain(route);
 });
});
