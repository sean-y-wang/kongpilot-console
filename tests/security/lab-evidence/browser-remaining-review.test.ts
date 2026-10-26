import {describe,expect,it,vi} from 'vitest';
import {readFileSync} from 'node:fs';
import {createHash,randomUUID} from 'node:crypto';
import {createRequire} from 'node:module';
import vm from 'node:vm';
import {BROWSER_COOKIE_READER_PROGRAM,BROWSER_COOKIE_SESSION_SQL,FIRST_BROWSER_FAILURE_SHA,FIRST_BROWSER_LOGIN_IAT,FIRST_BROWSER_LOGIN_REQUEST,browserRemainingCheckpoint,browserSha,journalBrowserMutation,originalCookieJar,proveRemainingApplicationReceipt,readOriginalBrowserCookies} from './lib/m6-browser-remaining.mjs';

const jwt=createRequire(new URL('../../../apps/console-api/package.json',import.meta.url))('jsonwebtoken');
const failure=readFileSync('artifacts/M6/browser-first-masked-credential-attempt.json');
const hash=(value:string)=>createHash('sha256').update(value).digest('hex');
function fixture(){
 const cid=randomUUID(),wid=randomUUID(),owner=randomUUID(),sid=randomUUID();
 const browser={clusterId:cid,workspaceId:wid,applicationId:randomUUID(),publicationId:randomUUID(),activeGrantId:randomUUID(),activeCredentialId:randomUUID()};
 const reference:any={testTag:'offline-independent-browser-resumption',phase:'HTTP-complete',portalUsers:[{id:owner,label:'developer-a',tenant:{clusterId:cid,workspaceId:wid}}],
  browserWriteEvidence:[{method:'POST',path:'/api/v1/portal/auth/login',requestId:FIRST_BROWSER_LOGIN_REQUEST}],browser,
  portalTestTargets:{primary:{id:cid,adminUrl:'http://kong-portal-admin-endpoint:8001',proxyOrigin:'http://127.0.0.1:10000'}},
  fixtures:[{workspace:{id:wid}}],grants:[{grant:{id:browser.activeGrantId},credential:{id:browser.activeCredentialId}}],
  abandonmentAcknowledgment:{totalFormalPosts:2,phase:'certificate-verified'},secrets:[],writeAttempts:[],writeEvidence:[],consoleAdministrator:{user:{id:randomUUID()}}};
 const live={testTag:reference.testTag,passed:1057,failed:0,fixturesForBrowser:browser,auditCoverage:{distinctRequestIds:145,auditedRequestIds:145}};
 const signingSecret='independent-offline-cookie-reader-signature-32bytes';
 const claims={kind:'portal_developer',sid,cid,wid,sub:owner,credential_epoch:1,iat:FIRST_BROWSER_LOGIN_IAT};
 const sign=(extra:any={},options:any={})=>jwt.sign({...claims,...extra},signingSecret,{algorithm:'HS256',issuer:'kongos-portal',audience:'kongos-portal',expiresIn:900,...options});
 const refresh='independent-refresh-'.padEnd(64,'r'),csrf='independent-csrf-'.padEnd(43,'c');
 reference.secrets=[sign(),sid+'.'+refresh,csrf];
 const context=browserRemainingCheckpoint(reference,live,failure);
 const row={id:sid,credential_epoch:1,expires_at:new Date(Date.now()+3_600_000).toISOString(),refresh_token_hash:hash(refresh),csrf_token_hash:hash(csrf),original_login_audited:true};
 return{reference,live,context,row,sign,claims,signingSecret,sid};
}

/** Execute the exported production-shaped reader program, with actual JWT and
 * crypto but an in-memory pg transport. No Docker, HTTP or database is used. */
async function reader(f:ReturnType<typeof fixture>,options:{row?:any;dbError?:any;clock?:number}={}){
 const handlers:Record<string,Function>={},queries:Array<{sql:string;args?:any}>=[],stdout:string[]=[];
 let released=0,ended=0;
 const processFake:any={env:{PORTAL_SECRET:f.signingSecret,DATABASE_URL:'offline-placeholder'},stdin:{on(event:string,handler:Function){handlers[event]=handler;}},stdout:{write(value:string){stdout.push(value);}}};
 class Pool{async connect(){return{async query(sql:string,args?:any){queries.push({sql,args});if(sql===BROWSER_COOKIE_SESSION_SQL&&options.dbError)throw options.dbError;return{rows:sql===BROWSER_COOKIE_SESSION_SQL?[options.row??f.row]:[]};},release(){released++;}};}async end(){ended++;}}
 vm.runInNewContext(BROWSER_COOKIE_READER_PROGRAM,{require(name:string){if(name==='pg')return{Pool};if(name==='jsonwebtoken')return jwt;if(name==='node:crypto')return{createHash};throw Error('Unexpected offline dependency');},
  process:processFake,Buffer,Date:class extends Date{static now(){return options.clock??Date.now();}},JSON,Number,Array,Set,Error});
 handlers.data(JSON.stringify({expected:f.context.expected,candidates:f.context.candidates}));await handlers.end();
 return{exitCode:processFake.exitCode,output:stdout.join(''),queries,released,ended};
}
function request(f:ReturnType<typeof fixture>,path:string,options:any={}){
 return{url:()=>`${options.origin??'http://127.0.0.1:8082'}${path}`,method:()=>options.method??'POST',headers:()=>({'x-idempotency-key':options.key??randomUUID()}),postDataJSON:()=>options.body??{clusterId:f.context.fixture.clusterId,workspaceId:f.context.fixture.workspaceId}};
}

describe('independent original Portal cookie recovery provenance',()=>{
 it('uses the actual immutable audit table timestamp and explicit UUID-to-text comparison',()=>{
  const migration=readFileSync('apps/console-api/src/infrastructure/migrations/000_m0.sql','utf8');
  const audit=migration.slice(migration.indexOf('CREATE TABLE audit_events ('),migration.indexOf('CREATE INDEX audit_events_cluster_time'));
  expect(audit).toMatch(/entity_id text/);expect(audit).toMatch(/occurred_at timestamptz/);expect(audit).not.toMatch(/created_at/);
  expect(BROWSER_COOKIE_SESSION_SQL).toMatch(/a\.entity_id\s*=\s*d\.id::text/);
  expect(BROWSER_COOKIE_SESSION_SQL).toMatch(/a\.occurred_at BETWEEN s\.created_at/);expect(BROWSER_COOKIE_SESSION_SQL).not.toMatch(/a\.created_at/);
 });
 it('keeps the preserved first failure and original login untouched when selecting cookie candidates',()=>{
  const f=fixture(),before=structuredClone(f.reference);f.reference.secrets.push(f.reference.secrets[0]);
  const preserved=browserSha(f.reference);const c=browserRemainingCheckpoint(f.reference,f.live,failure);
  expect(c.candidates).toHaveLength(3);expect(browserSha(f.reference)).toBe(preserved);expect(c.before.failureSha256).toBe(FIRST_BROWSER_FAILURE_SHA);
  expect(f.reference.browserWriteEvidence).toEqual(before.browserWriteEvidence);expect(f.reference.writeAttempts).toEqual([]);
 });
 it.each([
  ['other tenant CID',{cid:randomUUID()},{}],['other tenant WID',{wid:randomUUID()},{}],['other developer',{sub:randomUUID()},{}],
  ['different original login',{iat:FIRST_BROWSER_LOGIN_IAT+1},{}],['Console token kind',{kind:'console_user'},{}],
  ['anonymous CSRF kind',{kind:'portal_csrf'},{}],['wrong audience',{}, {audience:'kongos-console'}],['wrong issuer',{}, {issuer:'other-issuer'}],
  ['different access lifetime',{}, {expiresIn:901}],['future issued token',{iat:FIRST_BROWSER_LOGIN_IAT+86_400},{}],
 ])('rejects signed %s before opening a database connection',async(_label,claims,options)=>{
  const f=fixture();f.context.candidates[0]=f.sign(claims,options);const result=await reader(f);
  expect(result.exitCode).toBe(2);expect(result.output).toBe('');expect(result.queries).toEqual([]);
 });
 it('rejects two distinct signed access tokens for the same original identity instead of choosing either',async()=>{
  const f=fixture();f.context.candidates.push(f.sign({}, {header:{kid:'different-valid-header'}}));
  expect(f.context.candidates[0]).not.toBe(f.context.candidates[3]);const result=await reader(f);
  expect(result.exitCode).toBe(2);expect(result.output).toBe('');expect(result.queries).toEqual([]);
 });
 it('accepts original expired access only with the independently current session and hash-bound refresh/CSRF',async()=>{
  const f=fixture(),result=await reader(f,{clock:(FIRST_BROWSER_LOGIN_IAT+3_600)*1_000});
  expect(result.exitCode).toBeUndefined();const proof=JSON.parse(result.output);expect(proof.accessExpired).toBe(true);
  expect(result.queries[1].args).toEqual([f.sid,f.claims.sub,f.claims.cid,f.claims.wid,FIRST_BROWSER_LOGIN_REQUEST]);
  expect(result.queries.map(q=>q.sql)).toEqual(['BEGIN READ ONLY',BROWSER_COOKIE_SESSION_SQL,'ROLLBACK']);
  const jar=originalCookieJar(f.context,proof);expect(jar.every(c=>c.path==='/api/v1/portal'&&c.domain==='127.0.0.1'&&c.httpOnly&&c.sameSite==='Strict')).toBe(true);
  expect(result.output).not.toContain(f.row.refresh_token_hash);expect(result.output).not.toContain(f.context.candidates[0]);
  expect(result.released).toBe(1);expect(result.ended).toBe(1);
 });
 it('rolls back and emits no cookie/query/error data when the actual reader gets a database error',async()=>{
  const f=fixture(),marker='offline-driver-detail-secret-canary',result=await reader(f,{dbError:{code:'42883',message:marker,detail:f.context.candidates[0]}});
  expect(result.exitCode).toBe(2);expect(result.output).toBe('');expect(result.queries.at(-1)?.sql).toBe('ROLLBACK');expect(result.released).toBe(1);expect(result.ended).toBe(1);
 });
 it('passes even hostile token strings only as stdin and suppresses child stderr on failure',()=>{
  const f=fixture(),canary='$(never-execute);offline-secret';f.context.candidates.push(canary);
  const execute=vi.fn(()=>{throw Object.assign(Error(canary),{stdout:canary,stderr:canary});});
  expect(()=>readOriginalBrowserCookies(f.context,execute)).toThrow('private diagnostics withheld');
  const [bin,args,options]=execute.mock.calls[0] as any;expect(bin).toBe('docker');expect(args.slice(0,6)).toEqual(['compose','exec','-T','console-api','node','-e']);
  expect(args.join(' ')).not.toContain(canary);expect(JSON.parse(options.input).candidates).toContain(canary);expect(options.stdio).toEqual(['pipe','pipe','pipe']);
 });
});

describe('independent remaining-browser intent and receipt isolation',()=>{
 it.each([
  ['Portal relogin','/api/v1/portal/auth/login',{}],['registration','/api/v1/portal/auth/register',{}],
  ['old request execute','/api/v1/clusters/'+randomUUID()+'/workflows/'+randomUUID()+'/execute',{origin:'http://127.0.0.1:8080'}],
  ['credential rotation','/api/v1/portal/grants/'+randomUUID()+'/rotate',{}],['foreign origin','/api/v1/portal/applications',{origin:'https://foreign.example'}],
  ['native Admin','/consumers',{origin:'http://127.0.0.1:8001'}],['alternate method','/api/v1/portal/applications',{method:'PATCH'}],
 ])('blocks %s without a durable new intent',(_label,path,options)=>{
  const f=fixture();f.reference.browserRemaining={phase:'original-cookies-verified'};const save=vi.fn(),before=browserSha(f.reference);
  expect(()=>journalBrowserMutation(f.reference,request(f,path,options),f.context,new Map(),save)).toThrow();expect(save).not.toHaveBeenCalled();expect(browserSha(f.reference)).toBe(before);
 });
 it('persists the exact new actor/body/key once, then disallows every subsequent packet after unknown',()=>{
  const f=fixture();f.reference.browserRemaining={phase:'original-cookies-verified'};const sent=new Map(),key=randomUUID(),events:string[]=[];
  const req=request(f,'/api/v1/portal/applications',{key});const attempt=journalBrowserMutation(f.reference,req,f.context,sent,()=>{
   events.push('persist');expect(sent.size).toBe(0);expect(f.reference.writeAttempts[0].key).toBe(key);expect(f.reference.writeAttempts[0].actorId).toBe(f.claims.sub);
  });events.push('transport-permitted');expect(events).toEqual(['persist','transport-permitted']);
  attempt.state='response-uncertain';f.reference.browserRemaining.phase='stopped-without-replay';const save=vi.fn();
  expect(()=>journalBrowserMutation(f.reference,request(f,'/api/v1/portal/applications'),f.context,new Map(),save)).toThrow();
  expect(()=>journalBrowserMutation(f.reference,request(f,'/api/v1/portal/auth/refresh'),f.context,new Map(),save)).toThrow();expect(save).not.toHaveBeenCalled();
 });
 it.each([
  ['wrong actor',(f:any,r:any)=>f.reference.browserUnknown.actorId=randomUUID()],['wrong scope',(f:any,r:any)=>r.workspaceId=randomUUID()],
  ['wrong application',(f:any,r:any)=>r.safeResult.entity.id=randomUUID()],['unknown outcome',(f:any,r:any)=>r.state='uncertain'],
  ['partial outcome',(f:any,r:any)=>r.state='failed'],['missing terminal proof',(f:any,r:any)=>r.remoteCompleted=false],
  ['wrong operation module',(f:any,r:any)=>r.module='developers'],['wrong mutation action',(f:any,r:any)=>r.action='update'],
 ])('does not unlock a new request from %s application receipt',(_label,change)=>{
  const f=fixture();f.reference.browserApplication={id:randomUUID()};f.reference.browserUnknown={key:randomUUID(),actorId:f.claims.sub,clusterId:f.claims.cid,workspaceId:f.claims.wid,state:'uncertain'};
  const receipt:any={id:randomUUID(),clusterId:f.claims.cid,workspaceId:f.claims.wid,state:'succeeded',remoteCompleted:true,module:'applications',action:'create',safeResult:{entity:{id:f.reference.browserApplication.id}}};
  change(f,receipt);const before=browserSha(f.reference);expect(()=>proveRemainingApplicationReceipt(f.reference,receipt,f.context.fixture)).toThrow();expect(browserSha(f.reference)).toBe(before);
 });
 it('allows one new credential request only after the original application receipt proves completion',()=>{
  const f=fixture();f.reference.browserRemaining={phase:'remaining-actions-started'};f.reference.browserApplication={id:randomUUID()};
  f.reference.browserUnknown={key:randomUUID(),actorId:f.claims.sub,clusterId:f.claims.cid,workspaceId:f.claims.wid,state:'uncertain'};
  const body={clusterId:f.claims.cid,workspaceId:f.claims.wid,applicationId:f.reference.browserApplication.id,publicationId:f.context.fixture.publicationId},save=vi.fn(),sent=new Map();
  expect(()=>journalBrowserMutation(f.reference,request(f,'/api/v1/portal/requests',{body}),f.context,sent,save)).toThrow();expect(save).not.toHaveBeenCalled();
  proveRemainingApplicationReceipt(f.reference,{id:randomUUID(),clusterId:f.claims.cid,workspaceId:f.claims.wid,state:'succeeded',remoteCompleted:true,module:'applications',action:'create',safeResult:{entity:{id:body.applicationId}}},f.context.fixture);
  journalBrowserMutation(f.reference,request(f,'/api/v1/portal/requests',{body}),f.context,sent,save);expect(save).toHaveBeenCalledOnce();
  expect(()=>journalBrowserMutation(f.reference,request(f,'/api/v1/portal/requests',{body}),f.context,sent,save)).toThrow();expect(save).toHaveBeenCalledOnce();
 });
});
