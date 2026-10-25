import {describe,it,expect,vi} from 'vitest';
import {createRequire} from 'node:module';
import {createHash,randomUUID} from 'node:crypto';
import vm from 'node:vm';
import {manualSessionRecoveryContext,MANUAL_PAIR_SESSION_SQL,MANUAL_SESSION_READER_PROGRAM,originalManualCookieJar,readOriginalManualSessionCookies} from './lib/m6-manual-session-recovery.mjs';
const jwt=createRequire(new URL('../../apps/console-api/package.json',import.meta.url))('jsonwebtoken');
function fixture(){
 const now=Date.now(),iat=Math.floor(now/1000),portalKey='SyntheticUnitIndependentPortalManualKey2026',consoleKey='SyntheticUnitIndependentConsoleManualKey2026',hash=(v:string)=>createHash('sha256').update(v).digest('hex');
 const expected:any={owner:{actorId:randomUUID(),clusterId:randomUUID(),workspaceId:randomUUID(),loginRequestId:randomUUID(),startedAt:new Date(now-1000).toISOString(),responseObservedAt:new Date(now+1000).toISOString()},administrator:{actorId:randomUUID(),loginRequestId:randomUUID(),startedAt:new Date(now-1000).toISOString(),responseObservedAt:new Date(now+1000).toISOString()}};
 const candidates=['unrelated-synthetic-value'],rows:any[]=[];
 for(const role of ['owner','administrator']){const portal=role==='owner',x=expected[role],sid=randomUUID(),refresh=(portal?'R':'S').repeat(64),csrf=(portal?'C':'D').repeat(43);const token=jwt.sign({sid,iat,...(portal?{kind:'portal_developer',cid:x.clusterId,wid:x.workspaceId,credential_epoch:1}:{})},portal?portalKey:consoleKey,{algorithm:'HS256',issuer:portal?'kongos-portal':'kongos-console',audience:portal?'kongos-portal':'kongos-api',subject:x.actorId,expiresIn:900});candidates.push(token,`${sid}.${refresh}`,csrf);rows.push({role,session:{id:sid,refresh_token_hash:hash(refresh),csrf_token_hash:hash(csrf),credential_epoch:1,login_count:1}});}
 return {context:manualSessionRecoveryContext({candidates,expected}),rows,now,portalKey,consoleKey};
}
async function run(f:any,patch:any={}){
 const input={...f.context,...patch},callbacks:any={},output:string[]=[],queries:any[]=[];let ended=false;
 const processFake:any={env:{PORTAL_SECRET:f.portalKey,APP_SECRET:f.consoleKey,DATABASE_URL:'synthetic-runtime-only'},stdin:{on:(event:string,fn:any)=>callbacks[event]=fn},stdout:{write:(s:string)=>output.push(s)}};
 class Pool{async connect(){return {query:async(sql:string,args:any[])=>{queries.push([sql,args]);return {rows:sql===MANUAL_PAIR_SESSION_SQL?f.rows:[]};},release(){}};}async end(){ended=true;}}
 vm.runInNewContext(MANUAL_SESSION_READER_PROGRAM,{require:(name:string)=>name==='pg'?{Pool}:name==='jsonwebtoken'?jwt:name==='node:crypto'?{createHash,timingSafeEqual:createRequire(import.meta.url)('node:crypto').timingSafeEqual}:null,process:processFake,Buffer,Date:class extends Date{static now(){return f.clock??Date.now();}},JSON,Number,Array,Set,Error});
 callbacks.data(JSON.stringify(input));await callbacks.end();return {exit:processFake.exitCode,output:output.join(''),queries,ended};
}
describe('manual original pair session RAM reader',()=>{
 it('verifies both signed namespaces and unique current pairs in one readonly snapshot with safe output',async()=>{const f=fixture(),r=await run(f),proof=JSON.parse(r.output);expect(r.exit).toBeUndefined();expect(r.queries.map(v=>v[0])).toEqual(['BEGIN READ ONLY',MANUAL_PAIR_SESSION_SQL,'ROLLBACK']);expect(proof.owner.accessIndex).toBe(1);expect(proof.administrator.accessIndex).toBe(4);expect(proof.owner.accessExpired).toBe(false);expect(r.ended).toBe(true);for(const role of ['owner','administrator'])expect(Object.keys(proof[role]).sort()).toEqual(['accessIndex','refreshIndex','csrfIndex','sessionId','issuedAt','accessExpired','originalLoginAudited','currentSessionVerified','refreshVerified','csrfVerified'].sort());for(const value of f.context.candidates)expect(r.output).not.toContain(value);});
 it('classifies expired signed access honestly, without login/refresh or dropping its cookie',async()=>{const f:any=fixture();f.clock=f.now+901000;const proof=JSON.parse((await run(f)).output);expect(proof.owner.accessExpired).toBe(true);expect(proof.administrator.accessExpired).toBe(true);const portal=originalManualCookieJar(f.context,proof,'owner'),consoleJar=originalManualCookieJar(f.context,proof,'administrator');expect(portal.map(v=>[v.name,v.path])).toEqual([['kongos_portal_access','/api/v1/portal'],['kongos_portal_refresh','/api/v1/portal'],['kongos_portal_csrf','/api/v1/portal']]);expect(consoleJar.map(v=>[v.name,v.path])).toEqual([['kongos_access','/api'],['kongos_refresh','/api/v1/auth'],['kongos_csrf','/api']]);expect([...portal,...consoleJar].every(v=>v.httpOnly&&v.sameSite==='Strict'&&!('expires'in v))).toBe(true);});
 it.each([
  ['another current original-window SID',(f:any)=>f.rows.push({...f.rows[0],session:{...f.rows[0].session,id:randomUUID(),login_count:0}})],
  ['duplicate original login audit',(f:any)=>f.rows[1].session.login_count=2],
  ['missing audited portal session',(f:any)=>f.rows[0].session.login_count=0],
  ['console refresh rotated',(f:any)=>f.rows[1].session.refresh_token_hash='0'.repeat(64)],
  ['portal CSRF changed',(f:any)=>f.rows[0].session.csrf_token_hash='0'.repeat(64)],
  ['portal credential epoch changed',(f:any)=>f.rows[0].session.credential_epoch=2],
  ['wrong console signing key',(f:any)=>f.consoleKey+='different'],
  ['ambiguous signed access',(f:any)=>f.context.candidates.push(f.context.candidates[1])],
  ['original login iat outside journal window',(f:any)=>{const e=f.context.expected.owner;e.startedAt=new Date(f.now+5000).toISOString();e.responseObservedAt=new Date(f.now+6000).toISOString();}]
 ])('emits neither partial proof nor diagnostics for %s',async(_n,change)=>{const f:any=fixture();change(f);const r=await run(f);expect(r.exit).toBe(2);expect(r.output).toBe('');});
 it('requires exact identity/time/budget input and leaves source candidates unchanged',()=>{const f=fixture(),before=JSON.stringify(f.context);manualSessionRecoveryContext(f.context);expect(JSON.stringify(f.context)).toBe(before);expect(()=>manualSessionRecoveryContext({...f.context,candidates:Array(4097).fill('x')})).toThrow();expect(()=>manualSessionRecoveryContext({...f.context,expected:{...f.context.expected,administrator:{...f.context.expected.administrator,clusterId:f.context.expected.owner.clusterId}}})).toThrow();expect(()=>manualSessionRecoveryContext({...f.context,expected:{...f.context.expected,owner:{...f.context.expected.owner,responseObservedAt:new Date(f.now+61001).toISOString()}}})).toThrow();});
 it('keeps all candidate material in stdin and suppresses subprocess private diagnostics',()=>{const f=fixture(),execute=vi.fn((..._args:any[])=>{throw Error('private-source-driver-error');});expect(()=>readOriginalManualSessionCookies(f.context,execute)).toThrow('private diagnostics withheld');const args=execute.mock.calls[0];expect(args[1].join(' ')).not.toContain(f.context.candidates[1]);expect(args[2].input).toContain(f.context.candidates[1]);});
 it('refuses wrong role/session and invalid proof flags before constructing cookies',async()=>{const f=fixture(),p=JSON.parse((await run(f)).output);p.owner.sessionId=randomUUID();expect(()=>originalManualCookieJar(f.context,p,'owner')).toThrow();p.owner.sessionId=f.rows[0].session.id;p.owner.csrfVerified=false;expect(()=>originalManualCookieJar(f.context,p,'owner')).toThrow();expect(()=>originalManualCookieJar(f.context,p,'approver')).toThrow();});
});
