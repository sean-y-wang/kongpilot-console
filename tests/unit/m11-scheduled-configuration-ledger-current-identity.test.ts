import 'reflect-metadata';
import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {m11LedgerIdentityFixture} from './helpers/m11-ledger-identity-fixture';

beforeEach(()=>{vi.stubEnv('CONSOLE_ENCRYPTION_KEY','ab'.repeat(32));vi.useFakeTimers();vi.setSystemTime(new Date('2026-10-14T08:00:00.000Z'));});
afterEach(()=>{vi.useRealTimers();vi.unstubAllEnvs();});

function noNative(f:ReturnType<typeof m11LedgerIdentityFixture>){
 expect(f.native).not.toHaveBeenCalled();expect(f.db.exec).not.toHaveBeenCalled();
 expect(f.fullVerify).toHaveBeenCalledTimes(1);
 expect(f.db.one.mock.calls.some(([sql]:any[])=>sql.includes('auth_sessions'))).toBe(false);
}

describe('Root scheduled configuration ledger uses the original executor and actual current SQL identity',()=>{
 it.each(['single','multi','all','quorum'] as const)('verifies a real %s approval policy and returns no capability',async layout=>{
  const f=m11LedgerIdentityFixture({layout});
  await f.namespace(async()=>{
   const originalFrame=f.context.current(),before=f.fullVerify.mock.calls.length;
   await expect(f.guard()).resolves.toBeUndefined();
   expect(f.identitySpy).toHaveBeenCalledWith(f.nsHandle,f.ns,f.owner,f.db);
   expect(f.context.current()).toBe(originalFrame);expect(originalFrame.sessionId).toBeUndefined();
   expect(f.fullVerify).toHaveBeenCalledTimes(before);
   expect(f.db.query.mock.calls.some(([sql]:any[])=>sql.includes('FROM workflow_candidates'))).toBe(true);
   const voters=f.db.one.mock.calls.filter(([sql]:any[])=>sql.includes('SELECT status,deleted_at')).map(([,args]:any[])=>args[0]);
   expect(voters).toEqual(expect.arrayContaining(f.approvalSet.reviewers.map((r:any)=>r.userId)));
  });noNative(f);
 });

 it.each(['all','quorum'] as const)('rejects a coherently sealed undersized %s set instead of counting local approval rows',async layout=>{
  const f=m11LedgerIdentityFixture({layout,frozenThreshold:1});
  // Vote count, set HMAC, candidate HMAC and stored stage headcount agree.
  // Only the actual policy-derived threshold makes this set insufficient.
  expect(f.values.votes).toHaveLength(1);expect(f.values.stages[0].required_approvals).toBe(1);
  await f.namespace(()=>expect(f.guard()).rejects.toMatchObject({response:{code:'WORKFLOW_BUSINESS_IDENTITY_APPROVAL_CHANGED'}}));
  expect(f.identitySpy).toHaveBeenCalledOnce();noNative(f);
 });

 it('enforces distinctAcrossStages even when every stage has its required count and authenticated rows',async()=>{
  const f=m11LedgerIdentityFixture({layout:'multi',duplicateReviewer:true});
  expect(f.values.votes).toHaveLength(3);
  await f.namespace(()=>expect(f.guard()).rejects.toMatchObject({response:{code:'WORKFLOW_BUSINESS_IDENTITY_APPROVAL_CHANGED'}}));
  noNative(f);
 });

 it.each(['team','role'] as const)('rechecks actual frozen %s selector provenance after Namespace issuance',async selection=>{
  const f=m11LedgerIdentityFixture({selection});
  await f.namespace(async()=>{
   await f.guard();f.values.membership=false;
   await expect(f.guard()).rejects.toMatchObject({response:{code:'WORKFLOW_APPROVER_SELECTOR_REVOKED'}});
  });expect(f.identitySpy).toHaveBeenCalledTimes(2);noNative(f);
 });

 it.each(['actorId','credentialEpoch','permissionVersion','role','readOnly'] as const)('checks returned identity %s after the complete real SQL verifier succeeds',async field=>{
  const f=m11LedgerIdentityFixture();let verified=false;
  f.identitySpy.mockImplementation(async(...args)=>{
   const actual=await Object.getPrototypeOf(f.identity).currentPrincipal.call(f.identity,...args);
   expect(actual).toEqual({actorId:f.owner,credentialEpoch:'1',permissionVersion:f.ns.permissionVersion,role:'executor',readOnly:false});
   verified=true;
   const invalid:any={actorId:f.approvalSet.reviewers[0].userId,credentialEpoch:'2',permissionVersion:`${f.owner}:2:1`,role:'reviewer',readOnly:true};
   return Object.freeze({...actual,[field]:invalid[field]});
  });
  await f.namespace(()=>expect(f.guard()).rejects.toMatchObject({response:{code:'WORKFLOW_SCHEDULE_CONFIGURATION_LEDGER_PERMISSIONS_CHANGED'}}));
  expect(verified).toBe(true);expect(f.identitySpy).toHaveBeenCalledOnce();
  expect(f.repository.inspectStored).toHaveBeenCalledTimes(2);
  expect(f.db.query.mock.calls.filter(([sql]:any[])=>sql.includes('FROM workflow_approval_set_members'))).toHaveLength(2);
  noNative(f);
 });

 it('rechecks approval invalidation at the SQL tail after the first complete approval pass',async()=>{
  const f=m11LedgerIdentityFixture();let invalidationReads=0;
  f.values.onSql=async(sql:string)=>{
   if(sql.includes('FROM workflow_approval_invalidations')&&++invalidationReads===2)f.values.invalidated=true;
  };
  await f.namespace(()=>expect(f.guard()).rejects.toMatchObject({response:{code:'WORKFLOW_BUSINESS_IDENTITY_APPROVAL_CHANGED'}}));
  expect(invalidationReads).toBe(2);expect(f.repository.inspectStored).toHaveBeenCalledTimes(2);
  expect(f.identitySpy).toHaveBeenCalledOnce();noNative(f);
 });

 it.each([
  ['storage contract',(f:any)=>{f.state.migration=false;}],
  ['executor removal',(f:any)=>{f.state.ownerActive=false;}],
  ['executor credential epoch',(f:any)=>{f.state.epoch='2';}],
  ['IAM permission epoch',(f:any)=>{f.state.principalVersion='2';}],
  ['forced password change',(f:any)=>{f.state.forceChange=true;}],
  ['reviewer removal',(f:any)=>{f.state.reviewerActive=false;}],
  ['reviewer frozen epoch',(f:any)=>{f.values.reviewerEpoch='2';}],
  ['approval invalidation',(f:any)=>{f.values.invalidated=true;}],
  ['missing approval vote',(f:any)=>{f.values.votes.pop();}],
  ['current policy',(f:any)=>{f.state.policyChanged=true;}],
  ['registry revision',(f:any)=>{f.values.registryRevision=2;}],
  ['claim progress',(f:any)=>{f.stored.progress.state='cancelled';}],
  ['SQL lease version',(f:any)=>{f.stored.latestLease.version=2;}],
  ['authority deadline',(f:any)=>{f.stored.claim.authorityExpiresAt=new Date(Date.now()-1).toISOString();}],
  ['SQL availability',(f:any)=>{f.values.sqlFailure=true;}],
 ] as const)('does fresh SQL work and rejects changed %s on the next ledger call',async(_name,mutate)=>{
  const f=m11LedgerIdentityFixture();
  await f.namespace(async()=>{
   await f.guard();const calls=f.db.one.mock.calls.length;mutate(f);
   await expect(f.guard()).rejects.toThrow();expect(f.db.one.mock.calls.length).toBeGreaterThan(calls);
  });expect(f.identitySpy).toHaveBeenCalledTimes(2);noNative(f);
 });

 it('uses the supplied transaction for the complete real identity read',async()=>{
  const f=m11LedgerIdentityFixture(),tx:any={one:vi.fn((...args:any[])=>f.db.one(...args)),query:vi.fn((...args:any[])=>f.db.query(...args)),
   exec:vi.fn(()=>{throw Error('LEDGER_SQL_WRITE_FORBIDDEN');}),transaction:vi.fn(()=>{throw Error('LEDGER_NESTED_TX_FORBIDDEN');})};
  await f.namespace(()=>f.guard(f.nsHandle,f.ns,tx));
  expect(f.identitySpy).toHaveBeenCalledWith(f.nsHandle,f.ns,f.owner,tx);expect(tx.one).toHaveBeenCalled();expect(tx.query).toHaveBeenCalled();
  expect(tx.exec).not.toHaveBeenCalled();expect(tx.transaction).not.toHaveBeenCalled();noNative(f);
 });

 it.each(['proof','handle'] as const)('rejects a copied original %s before observing SQL',async copied=>{
  const f=m11LedgerIdentityFixture();
  await f.namespace(()=>expect(f.guard(copied==='handle'?{...f.nsHandle}:f.nsHandle,copied==='proof'?{...f.ns}:f.ns)).rejects.toThrow());
  expect(f.identitySpy).not.toHaveBeenCalled();expect(f.db.one).not.toHaveBeenCalled();noNative(f);
 });

 it('cannot use an original handle outside its actual Context callback',async()=>{
  const f=m11LedgerIdentityFixture();await f.namespace(async()=>undefined);
  await expect(f.guard()).rejects.toThrow();expect(f.identitySpy).not.toHaveBeenCalled();expect(f.db.one).not.toHaveBeenCalled();noNative(f);
 });

 it.each(['executor','reviewer'] as const)('rejects a genuine readonly %s capsule before identity SQL',async role=>{
  const f=m11LedgerIdentityFixture();
  await f.namespace(()=>f.readonly(role,async()=>{
   const principal=f.context.requireWorkflowScheduledCurrentPrincipal(f.nsHandle);
   expect(principal).toMatchObject({role,readOnly:true});expect(principal.validationReadHandle).toBeDefined();
   await expect(f.guard()).rejects.toMatchObject({response:{code:'WORKFLOW_SCHEDULE_CONFIGURATION_LEDGER_PRINCIPAL_REQUIRED'}});
  }));expect(f.identitySpy).not.toHaveBeenCalled();expect(f.db.one).not.toHaveBeenCalled();noNative(f);
 });

 it('rejects current Namespace expiry instead of returning a ledger result',async()=>{
  const f=m11LedgerIdentityFixture();
  await expect(f.namespace(async()=>{vi.setSystemTime(new Date(Date.parse(f.ns.expiresAt)+1));await expect(f.guard()).rejects.toThrow();})).rejects.toMatchObject({response:{code:'KONG_EXECUTION_CONTEXT_EXPIRED'}});
  expect(f.identitySpy).not.toHaveBeenCalled();noNative(f);
 });

 it.each(['Namespace','Redis lease'] as const)('fences an actual SQL await after %s loss',async lost=>{
  const f=m11LedgerIdentityFixture();
  let release!:()=>void,started!:()=>void;const entered=new Promise<void>(resolve=>{started=resolve;});
  f.values.onSql=async()=>{f.values.onSql=null;started();await new Promise<void>(resolve=>{release=resolve;});};
  await f.namespace(async()=>{
   const pending=f.guard();await entered;
   if(lost==='Namespace')f.values.live=false;else f.state.lease=false;
   const rejected=expect(pending).rejects.toThrow();release();await rejected;
  });expect(f.identitySpy).toHaveBeenCalledOnce();noNative(f);
 });

 it('does not return a late result after the original Context frame closes during SQL',async()=>{
  const f=m11LedgerIdentityFixture();
  let release!:()=>void,started!:()=>void,outcome!:Promise<unknown>;const entered=new Promise<void>(resolve=>{started=resolve;});
  f.values.onSql=async()=>{f.values.onSql=null;started();await new Promise<void>(resolve=>{release=resolve;});};
  await f.namespace(async()=>{outcome=f.guard().then(()=>undefined,error=>error);await entered;});
  release();expect(await outcome).toBeInstanceOf(Error);expect(f.identitySpy).toHaveBeenCalledOnce();noNative(f);
 });

 it('fences lease loss during the final Root ownership await after a real successful identity result',async()=>{
  const f=m11LedgerIdentityFixture();let observed=false;
  f.identitySpy.mockImplementation(async(...args)=>{
   const value=await Object.getPrototypeOf(f.identity).currentPrincipal.call(f.identity,...args);observed=true;return value;
  });
  f.redis.assertLeaseOwnership.mockImplementation(async()=>{if(observed){f.state.lease=false;throw Error('FINAL_LEDGER_LEASE_LOST');}});
  await f.namespace(()=>expect(f.guard()).rejects.toThrow('FINAL_LEDGER_LEASE_LOST'));
  expect(observed).toBe(true);noNative(f);
 });
});
