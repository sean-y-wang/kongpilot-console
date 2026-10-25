import {randomUUID} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {describe,it,expect,vi} from 'vitest';
import {authorityBodyHash,authorityLedger,authorityPermissions,assertAuthorityBinding,assertAuthorityBlockedTimer,authorityPhase,assertAuthorityInitialLogin} from './lib/m10-native-authority-helper.mjs';
import {authorityTimerObserverProgram} from './lib/m10-native-authority-observer.mjs';
import {normalizePermission,resolveAssignedGrants} from '../../apps/console-api/src/modules/iam/iam-policy';

// Tool/contract tests use synthetic receipts only. No HTTP, console SQL or
// deployed timer/native acceptance is performed by these fixtures.
function journal(){
 const h:any={state:{requests:[]},save:vi.fn(),assertWritable:vi.fn()};
 h.request=vi.fn(async(session:any,path:string,method:string,body:any,options:any)=>{
  h.state.requests.push({key:options.key,actorId:session?.user.id??null,path,method,bodyHash:authorityBodyHash(body),state:'response_observed',status:options.expected[0],responseData:{id:randomUUID()},requestId:randomUUID()});
 });return{h,ledger:authorityLedger(h),session:{user:{id:randomUUID()}}};
}
describe('M10 exact source-only IAM contracts',()=>{
 it.each([true,false])('observes the real initial password policy %s without requiring or rewriting a forced-change flag',forcePasswordChange=>{
  const ownerId=randomUUID(),user={id:ownerId,superAdmin:false,forcePasswordChange};expect(assertAuthorityInitialLogin(user,ownerId)).toBe(forcePasswordChange);expect(user.forcePasswordChange).toBe(forcePasswordChange);
 });
 it.each([undefined,null,'false',0])('rejects nonboolean password policy %s instead of coercing an observation',forcePasswordChange=>{
  const ownerId=randomUUID();expect(()=>assertAuthorityInitialLogin({id:ownerId,superAdmin:false,forcePasswordChange},ownerId)).toThrow();
 });
 it('normalizes every generated permission against the actual current workspace IAM implementation',()=>{
  const cid=randomUUID(),wid=randomUUID(),owner={cluster_id:cid,workspace_id:wid},permissions=authorityPermissions(cid,wid);
  expect(permissions.length).toBe(28);for(const p of permissions){expect(normalizePermission(p,owner)).toEqual(p);expect(p.scope_type).toBe('workspace');expect(p.scope_values).toEqual([wid]);}
  const target={cluster_id:randomUUID(),workspace_id:randomUUID()};expect(()=>resolveAssignedGrants(permissions as any,owner,target)).toThrow();
  expect(resolveAssignedGrants(permissions as any,owner,owner)).toEqual(permissions);
  expect(permissions.some(p=>['users','roles','permissions','teams'].includes(p.module))).toBe(false);
 });
 it.each(['cluster_id','workspace_id','scope_values'])('rejects forged independent %s dimensions using the actual normalizePermission validator',field=>{
  const cid=randomUUID(),wid=randomUUID(),owner={cluster_id:cid,workspace_id:wid},p=authorityPermissions(cid,wid)[0];
  expect(()=>normalizePermission({...p,[field]:field==='scope_values'?[randomUUID()]:randomUUID()},owner)).toThrow();
 });
 it('checks the exact binding owner, role, workspace and next CAS revision',()=>{
  const userId=randomUUID(),roleId=randomUUID(),clusterId=randomUUID(),workspaceId=randomUUID(),row={id:randomUUID(),user_id:userId,role_id:roleId,role_name:'scoped authority role',cluster_id:clusterId,workspace_id:workspaceId,status:'revoked',revision:3};
  const expected={userId,roleId,roleName:row.role_name,clusterId,workspaceId,status:'revoked',previousRevision:2};expect(assertAuthorityBinding(row,expected)).toBe(row);
  for(const field of ['user_id','role_id','cluster_id','workspace_id'])expect(()=>assertAuthorityBinding({...row,[field]:randomUUID()},expected)).toThrow();
  expect(()=>assertAuthorityBinding({...row,revision:2},expected)).toThrow();expect(()=>assertAuthorityBinding({...row,status:'active'},expected)).toThrow();
 });
});
describe('M10 original authority HTTP intent retention',()=>{
 it('records the intent before the initial request and consumes only the exact original response on resume',async()=>{
  const{h,ledger,session}=journal(),body={role_id:randomUUID()},path=`/iam/users/${session.user.id}/role-bindings`;
  h.request.mockImplementationOnce(async(s:any,p:string,m:string,b:any,o:any)=>{expect(ledger.state.intents.binding.key).toBe(o.key);h.state.requests.push({key:o.key,actorId:s.user.id,path:p,method:m,bodyHash:authorityBodyHash(b),state:'response_observed',status:201,responseData:{id:randomUUID()},requestId:randomUUID()});});
  const initial=await ledger.once('binding',session,path,'POST',body);expect(initial.packet.label).toBe('binding');
  expect((await ledger.once('binding',session,path,'POST',body)).requestId).toBe(initial.requestId);expect(h.request).toHaveBeenCalledTimes(1);
 });
 it.each(['prepared','response_unknown','response_observed'])('never retries an old %s failed/unknown write under a replacement key',async(state)=>{
  const{h,ledger,session}=journal();await ledger.once('binding',session,'/iam/binding','POST',{x:1});const key=ledger.state.intents.binding.key;
  h.state.requests[0].state=state;h.state.requests[0].status=500;
  await expect(ledger.once('binding',session,'/iam/binding','POST',{x:1})).rejects.toThrow();expect(h.request).toHaveBeenCalledTimes(1);expect(ledger.state.intents.binding.key).toBe(key);
 });
 it.each(['actor','path','body','label','duplicate'])('rejects a forged %s receipt rather than creating another request',async(kind)=>{
  const{h,ledger,session}=journal();await ledger.once('binding',session,'/iam/binding','POST',{x:1});
  if(kind==='actor')h.state.requests[0].actorId=randomUUID();if(kind==='path')h.state.requests[0].path='/iam/other';if(kind==='body')h.state.requests[0].bodyHash=authorityBodyHash({x:2});
  if(kind==='label')h.state.requests[0].label='other';if(kind==='duplicate')h.state.requests.push({...h.state.requests[0]});
  await expect(ledger.once('binding',session,'/iam/binding','POST',{x:1})).rejects.toThrow();expect(h.request).toHaveBeenCalledTimes(1);
 });
 it('retains an original explicit 403 negative result and preserves a null actor for the separate real login request',async()=>{
  const{h,ledger,session}=journal();const denied=await ledger.once('denied',session,'/plans/immutable/apply','POST',{confirmed:true},[403]);expect(denied.status).toBe(403);
  await ledger.once('denied',session,'/plans/immutable/apply','POST',{confirmed:true},[403]);expect(h.request).toHaveBeenCalledTimes(1);
  const login=await ledger.once('actual-login',null,'/auth/login','POST',{username:'fixture',password:'private synthetic test only'},[201]);expect(login.packet.actorId).toBeNull();expect(h.request).toHaveBeenCalledTimes(2);
 });
});
describe('M10 exact naturally blocked current-version timer observation',()=>{
 const fixture=()=>{const due=new Date(Date.now()-60000).toISOString(),f={id:randomUUID(),ownerUserId:randomUUID(),currentVersion:1,nextRunAt:due};return{f,e:{...f,state:'active',enabled:true,executionBlocked:true,blockingState:'paused_authority',blockingOccurrenceId:randomUUID(),blockingVersion:1,blockingReasonCode:'PERMISSION_DENIED',scheduledAt:due}};};
 it('accepts only the exact original due/owner/version and paused_authority blocking occurrence',()=>{const{e,f}=fixture();expect(assertAuthorityBlockedTimer(e,f)).toBe(e);});
 it.each(['ownerUserId','currentVersion','blockingVersion','blockingState','blockingReasonCode','scheduledAt','executionBlocked'])('rejects altered %s facts',field=>{
  const{e,f}=fixture();const values:any={ownerUserId:randomUUID(),currentVersion:2,blockingVersion:2,blockingState:'uncertain',blockingReasonCode:'OTHER',scheduledAt:new Date().toISOString(),executionBlocked:false};
  expect(()=>assertAuthorityBlockedTimer({...e,[field]:values[field]},f)).toThrow();
 });
 it('rejects a future due even if caller supplied a blocked status',()=>{const{e,f}=fixture(),due=new Date(Date.now()+60000).toISOString();expect(()=>assertAuthorityBlockedTimer({...e,scheduledAt:due},{...f,nextRunAt:due})).toThrow();});
 it('generates syntactically valid READ ONLY worker text with actual LF and no DML, clock changes or Kong DB address',()=>{
  const text=authorityTimerObserverProgram({mode:'revoked'}),checked=spawnSync(process.execPath,['--input-type=module','--check'],{input:text,encoding:'utf8'});expect(checked.status,checked.stderr).toBe(0);
  expect(text).toContain('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');expect(text).toContain("'console-db'");expect(text).toContain("'kongpilot_lab_app'");
  expect(text).not.toMatch(/\b(?:INSERT|UPDATE|DELETE|ALTER|DROP|TRUNCATE)\s+(?:INTO|FROM|TABLE|[a-z_]+\s+SET)\b/i);expect(text).not.toContain('kong-db');expect(text).not.toContain('setSystemTime');
  expect(text).toContain('String.fromCharCode(10)');
 });
 it('uses only fixed operator phases',()=>{expect(authorityPhase(['--phase','prepare'])).toBe('prepare');expect(()=>authorityPhase(['--phase','tick'])).toThrow();expect(()=>authorityPhase(['--phase','restore','--force'])).toThrow();});
});
