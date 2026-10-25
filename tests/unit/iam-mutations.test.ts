import 'reflect-metadata';
import { afterEach,beforeEach,describe,expect,it,vi } from 'vitest';
import { ConflictException,ForbiddenException } from '@nestjs/common';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { IamMutationsService } from '../../apps/console-api/src/modules/iam/iam-mutations.service';
const actor={user:{id:'30000000-0000-4000-8000-000000000021',username:'actor',superAdmin:false},idempotencyKey:'same-operation'};
const context={actor,module:'roles',action:'write',targetId:'30000000-0000-4000-8000-000000000031',cluster_id:null,workspace_id:null,payload:{name:'changed',password:'Synthetic-password-to-mask'}};
function harness(){
 const records=new Map<string,any>();const audit={append:vi.fn().mockResolvedValue(undefined)},redis={withLock:vi.fn(async(_k:string,fn:any)=>fn()),assertLeaseOwnership:vi.fn().mockResolvedValue(undefined)};
 const authz={assertConsole:vi.fn().mockResolvedValue(undefined),assertCluster:vi.fn().mockResolvedValue(undefined)};
 const db:any={transaction:vi.fn(),one:vi.fn(async(sql:string,p:any[]=[])=>{
  if(sql.includes('iam_epoch'))return {version:1};if(sql.includes('FROM clusters'))return {execution_mode:'direct'};
  if(sql.includes('iam_operations'))return [...records.values()].find(r=>r.actor_id===p[0]&&(sql.includes('idempotency_key')?r.idempotency_key===p[1]:r.id===p[1]))??null;return null;
 }),exec:vi.fn(async(sql:string,p:any[]=[])=>{
  if(sql.startsWith('INSERT INTO iam_operations'))records.set(p[0],{id:p[0],actor_id:p[1],idempotency_key:p[2],request_hash:p[3],module:p[4],action:p[5],target_id:p[6],cluster_id:p[7],workspace_id:p[8],payload_secret:p[9],state:'running',remote_completed:false});
  if(sql.includes("state='succeeded'"))Object.assign(records.get(p[0]),{state:'succeeded',remote_completed:true,result_secret:p[1],safe_result:JSON.parse(p[2])});
  if(sql.includes('state=$2')){const row=records.get(p[0]);if(row.state==='running')Object.assign(row,{state:p[1],remote_completed:p[2],error_code:p[3],safe_result:JSON.parse(p[4])});}return 1;
 })};
 db.transaction.mockImplementation(async(fn:any)=>{const copy=structuredClone([...records]);try{return await fn(db);}catch(e){records.clear();for(const [k,v]of copy)records.set(k,v);throw e;}});
 const secrets=new SecretService(),service=new IamMutationsService(db,redis as any,secrets,audit as any,authz as any);return {db,redis,authz,secrets,audit,records,service};
}
describe('IAM durable SQL mutations and actor-private receipts',()=>{
 beforeEach(()=>vi.stubEnv('CONSOLE_ENCRYPTION_KEY','ab'.repeat(32)));afterEach(()=>vi.unstubAllEnvs());
 it('persists encrypted request and requested audit before entering SQL callback, then caches exactly once',async()=>{
  const f=harness(),fn=vi.fn(async()=>{expect([...f.records.values()]).toHaveLength(1);expect(f.audit.append).toHaveBeenCalledWith(expect.objectContaining({result:'pending'}),f.db);return {id:context.targetId,password:'Synthetic-result-secret'};});
  expect(await f.service.execute(context,fn)).toHaveProperty('password','Synthetic-result-secret');expect(await f.service.execute(context,fn)).toHaveProperty('password','Synthetic-result-secret');expect(fn).toHaveBeenCalledTimes(1);
  const stored=[...f.records.values()][0];expect(stored).toMatchObject({state:'succeeded',remote_completed:true});expect(JSON.stringify(stored)).not.toContain('Synthetic-result-secret');expect(JSON.stringify(stored)).not.toContain(context.payload.password);expect(stored.safe_result.password).toMatch(/^\[REDACTED/);
 });
 it('never executes a differently hashed request under an old key',async()=>{
  const f=harness(),fn=vi.fn().mockResolvedValue({ok:true});await f.service.execute(context,fn);
  await expect(f.service.execute({...context,payload:{name:'other'}},fn)).rejects.toMatchObject({response:{code:'IDEMPOTENCY_CONFLICT'}});expect(fn).toHaveBeenCalledTimes(1);
 });
 it('never treats a success-looking receipt without completed proof as safe replay',async()=>{
  const f=harness(),fn=vi.fn().mockResolvedValue({ok:true});await f.service.execute(context,fn);
  [...f.records.values()][0].remote_completed=false;
  await expect(f.service.completed(context)).resolves.toBeNull();
  await expect(f.service.execute(context,fn)).rejects.toMatchObject({response:{code:'IAM_RESULT_UNCERTAIN'}});
  expect(fn).toHaveBeenCalledTimes(1);
 });
 it('reattests authorization inside the SQL transaction and rolls back on immediate revocation',async()=>{
  const f=harness();f.authz.assertConsole.mockResolvedValueOnce(undefined).mockResolvedValueOnce(undefined).mockRejectedValueOnce(new ForbiddenException());const fn=vi.fn();
  await expect(f.service.execute(context,fn)).rejects.toMatchObject({status:403});expect(fn).not.toHaveBeenCalled();expect([...f.records.values()][0]).toMatchObject({state:'failed',remote_completed:true});
 });
 it('marks an indeterminate commit uncertain and forbids blind repeat callback',async()=>{
  const f=harness(),fn=vi.fn().mockRejectedValue(new Error('connection was lost'));
  await expect(f.service.execute(context,fn)).rejects.toMatchObject({status:503,response:{code:'IAM_RESULT_UNCERTAIN'}});await expect(f.service.execute(context,fn)).rejects.toMatchObject({status:409});expect(fn).toHaveBeenCalledTimes(1);expect([...f.records.values()][0]).toMatchObject({state:'uncertain',remote_completed:false});
 });
 it('persists a known CAS conflict as failed and does not execute it twice',async()=>{
  const f=harness(),fn=vi.fn().mockRejectedValue(new ConflictException({code:'IAM_CHANGED'}));await expect(f.service.execute(context,fn)).rejects.toMatchObject({status:409});expect([...f.records.values()][0]).toMatchObject({state:'failed',remote_completed:true});await expect(f.service.execute(context,fn)).rejects.toMatchObject({status:409});expect(fn).toHaveBeenCalledTimes(1);
 });
 it('a persistence failure prevents all business writes',async()=>{
  const f=harness(),fn=vi.fn();f.db.exec.mockRejectedValueOnce(new Error('storage unavailable'));await expect(f.service.execute(context,fn)).rejects.toThrow();expect(fn).not.toHaveBeenCalled();expect(f.records.size).toBe(0);
 });
 it('approval cluster metadata fails closed before ledger or callback',async()=>{
  const f=harness(),fn=vi.fn();f.db.one.mockImplementation(async(sql:string)=>sql.includes('FROM clusters')?{execution_mode:'approval'}:null);await expect(f.service.execute({...context,cluster_id:'30000000-0000-4000-8000-000000000001'},fn)).rejects.toMatchObject({response:{code:'APPROVAL_REQUIRED'}});expect(fn).not.toHaveBeenCalled();expect(f.records.size).toBe(0);
 });
 it('allows write-only principals to verify their own safe receipts while refusing another actor',async()=>{
  const f=harness();await f.service.execute(context,async()=>({password:'Synthetic-result-secret',ok:true}));f.authz.assertConsole.mockImplementation(async(_u:any,_m:any,action:any)=>{if(action==='read')throw new ForbiddenException();});
  const receipt=await f.service.receipt(actor,actor.idempotencyKey,true);expect(receipt).toMatchObject({state:'succeeded',remote_completed:true,safe_result:{ok:true}});expect(receipt.safe_result.password).toMatch(/^\[REDACTED/);expect(receipt).not.toHaveProperty('result_secret');
  await expect(f.service.receipt({...actor,user:{...actor.user,id:'30000000-0000-4000-8000-000000000022'}},actor.idempotencyKey,true)).rejects.toMatchObject({status:404});
 });
 it('lease loss after callback rolls back SQL result and persists unresolved proof',async()=>{
  const f=harness();f.redis.assertLeaseOwnership.mockResolvedValueOnce(undefined).mockRejectedValueOnce(new Error('lease lost'));
  await expect(f.service.execute(context,async()=>({ok:true}))).rejects.toMatchObject({status:503});expect([...f.records.values()][0]).toMatchObject({state:'uncertain',remote_completed:false});expect([...f.records.values()][0].result_secret).toBeUndefined();
 });
 it('binds actual callback subject and server operation ID to a terminal audit in the success transaction',async()=>{
  const f=harness(),before={id:context.targetId,name:'before'},after={id:context.targetId,name:'after',password:'Synthetic-private-after'};
  const result=await f.service.execute({...context,actor:{...actor,requestId:'actual-request',ip:'192.0.2.22'}},async(tx,id,setBusinessAudit)=>{
   expect(tx).toBe(f.db);expect([...f.records.values()][0].id).toBe(id);
   setBusinessAudit({entityType:'roles',entityId:context.targetId,before,after});after.name='changed-after-capture';return{entity:{id:context.targetId}};
  });
  expect(result).toEqual({entity:{id:context.targetId}});
  expect(f.audit.append).toHaveBeenCalledWith(expect.objectContaining({entityType:'roles',entityId:context.targetId,action:'iam.write',result:'success',requestId:'actual-request',ip:'192.0.2.22',before,after:{...after,name:'after'}}),f.db);
  expect(result).not.toHaveProperty('auditReceipt');
 });
 it('rolls back succeeded ledger and callback effects if terminal audit persistence fails',async()=>{
  const f=harness();f.audit.append.mockResolvedValueOnce(undefined).mockRejectedValueOnce(new Error('audit unavailable')).mockResolvedValueOnce(undefined);
  await expect(f.service.execute(context,async()=>({ok:true}))).rejects.toMatchObject({response:{code:'IAM_RESULT_UNCERTAIN'}});
  expect([...f.records.values()][0]).toMatchObject({state:'uncertain',remote_completed:false});expect([...f.records.values()][0].result_secret).toBeUndefined();
 });
 it.each(['actorId','clusterId','result','action'])('rejects %s injection into server business context',async(field)=>{
  const f=harness();await expect(f.service.execute(context,async(_tx,_id,set)=>{set({entityType:'roles',before:null,after:{ok:true},[field]:'injected'} as any);return{};})).rejects.toMatchObject({response:{code:'INVALID_IAM_BUSINESS_AUDIT'}});
  expect(f.audit.append.mock.calls.some(call=>call[0].result==='success')).toBe(false);
 });
 it('current revoke after actual SQL callback prevents terminal success and commits no result',async()=>{
  const f=harness();let revoked=false;f.authz.assertConsole.mockImplementation(async()=>{if(revoked)throw new ForbiddenException();});
  await expect(f.service.execute(context,async()=>{revoked=true;return{ok:true};})).rejects.toMatchObject({status:403});
  expect([...f.records.values()][0]).toMatchObject({state:'failed',remote_completed:true});expect(f.audit.append.mock.calls.some(call=>call[0].result==='success')).toBe(false);
 });
 it('expires server audit setter as soon as its callback exits',async()=>{
  const f=harness();let late:any;await f.service.execute(context,async(_tx,_id,set)=>{late=set;return{ok:true};});
  expect(()=>late({entityType:'roles',before:null,after:{forged:true}})).toThrow();
  expect(f.audit.append.mock.calls.find(call=>call[0].result==='success')?.[0].after).toEqual({ok:true});
 });
 it('rejects a direct-to-approval race inside the business transaction before its callback',async()=>{
  const f=harness(),fn=vi.fn();const original=f.db.one.getMockImplementation()!;let n=0;
  f.db.one.mockImplementation(async(sql:string,p:any[])=>sql.includes('FROM clusters')?{execution_mode:++n===1?'direct':'approval',status:'healthy'}:original(sql,p));
  await expect(f.service.execute({...context,cluster_id:'30000000-0000-4000-8000-000000000001'},fn)).rejects.toMatchObject({response:{code:'APPROVAL_REQUIRED'}});
  expect(fn).not.toHaveBeenCalled();expect([...f.records.values()][0]).toMatchObject({state:'failed',remote_completed:true});
 });
 it('lost COMMIT acknowledgement returns only the exact durable succeeded ledger without another callback or false failure audit',async()=>{
  const f=harness(),fn=vi.fn(async()=>({ok:true})),original=f.db.transaction.getMockImplementation()!;let n=0;
  f.db.transaction.mockImplementation(async(callback:any)=>{const result=await original(callback);if(++n===2)throw new Error('Synthetic-commit-ack-lost');return result;});
  await expect(f.service.execute(context,fn)).resolves.toEqual({ok:true});expect(fn).toHaveBeenCalledOnce();expect([...f.records.values()][0]).toMatchObject({state:'succeeded',remote_completed:true});
  expect(f.audit.append.mock.calls.some(call=>['failed','uncertain'].includes(call[0].result))).toBe(false);
 });
});
