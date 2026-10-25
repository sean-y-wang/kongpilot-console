import 'reflect-metadata';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { validateRejectedIssuePlan } from '../../apps/console-api/src/modules/portal/portal-rejected-issue-plan';
import { activationRecoveryFixture } from './m6-activation-recovery-fixture';
import { eid, wf } from './m6-approved-fixture';
import { actor, cid, id, physical, serviceId, wid } from './m6-approved-fixture';
import { ConflictException, ForbiddenException, HttpException } from '@nestjs/common';
import { abandonmentEndpointFixture, expectNeverNativeWrites } from './m6-abandonment-endpoint-fixture';

beforeEach(() => { vi.stubEnv('APP_SECRET', 'offline-abandonment-signing-secret-at-least32'); vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'de'.repeat(32)); });
afterEach(() => vi.unstubAllEnvs());

function rejectedFixture() {
  const f = activationRecoveryFixture();
  Object.assign(f.workflow, { state: 'failed' }); Object.assign(f.execution, { state: 'failed' });
  const operation = f.operations.get(f.rows[0].operation_id);
  Object.assign(operation, { state: 'failed', entity_id: null, remote_started: true, remote_completed: false, result_secret: null, error_code: 'KONG_VALIDATION_ERROR' });
  const originalOperationId = operation.id;
  f.operations.clear(); f.operations.set(operation.id, operation); f.refs.splice(0);
  f.nativeObjects.clear(); f.nativeObjects.set(f.plan.prerequisites[0].path, f.serviceObject);
  Object.assign(f.rows[0], { state: 'failed', receipt_secret: null, after_fingerprint: null, recycle_entry_id: null, safe_result: { remoteStarted: true, remoteCompleted: false }, error_code: 'KONG_VALIDATION_ERROR' });
  for (const row of f.rows.slice(1)) Object.assign(row, { state: 'pending', operation_id: null, safe_result: {}, receipt_secret: null, after_fingerprint: null,
    recycle_entry_id: null, started_at: null, completed_at: null, error_code: null });
  const facts = () => ({ grant: f.grant, workflow: f.workflow, execution: f.execution, version: f.version, steps: f.rows, operation, credential: f.credential });
  return { ...f, operation, facts, originalOperationId };
}

describe('M6 independent rejected issue immutable plan proof', () => {
  it('validates the unchanged failed CREATE-null original tuple without minting a capability or modifying any history', () => {
    const f = rejectedFixture(), operations = structuredClone([...f.operations.values()]), rows = structuredClone(f.rows), cipher = f.credential.key_secret;
    expect(validateRejectedIssuePlan(f.facts(), f.secrets)).toEqual(f.plan);
    expect(f.operation.entity_id).toBeNull(); expect(f.operation.workflow_execution_id).toBe(eid); expect(f.operation.workflow_id).toBe(wf);
    expect([...f.operations.values()]).toEqual(operations); expect(f.rows).toEqual(rows); expect(f.credential.key_secret).toBe(cipher);
    expect(f.db.exec).not.toHaveBeenCalled(); expect(f.kong.request).not.toHaveBeenCalled();
  });

  it.each([
    ['tampered encrypted plan', (f: ReturnType<typeof rejectedFixture>) => { f.version.payload_secret = f.credential.key_secret; }],
    ['changed plan hash', (f: ReturnType<typeof rejectedFixture>) => { f.workflow.plan_hash = '0'.repeat(64); }],
    ['wrong normalized native parent', (f: ReturnType<typeof rejectedFixture>) => { f.rows[1].parent_id = f.credential.kong_id; }],
    ['wrong normalized credential kind', (f: ReturnType<typeof rejectedFixture>) => { f.rows[1].credential_kind = 'key-auth'; }],
    ['wrong normalized final handler', (f: ReturnType<typeof rejectedFixture>) => { f.rows[3].handler = 'portal.credential.rotate'; }],
    ['normalized native body HMAC substituted', (f: ReturnType<typeof rejectedFixture>) => { f.rows[0].mutation_payload_hmac = '0'.repeat(64); }],
    ['original CREATE receipt hashed as known ID', (f: ReturnType<typeof rejectedFixture>) => { f.operation.request_hash = f.secrets.fingerprint({ entityId: f.grant.consumer_id }); }],
    ['wrong original sealed step key', (f: ReturnType<typeof rejectedFixture>) => { f.operation.idempotency_key = 'another-native-step-key'; }],
    ['different physical transport', (f: ReturnType<typeof rejectedFixture>) => { f.operation.transport_scope = '0'.repeat(64); }],
    ['successful native result even without ACK', (f: ReturnType<typeof rejectedFixture>) => { f.operation.result_secret = f.secrets.encrypt({ entity: { id: f.grant.consumer_id } }, `mutation:${f.operation.id}:result`); }],
    ['snapshot not durably ready', (f: ReturnType<typeof rejectedFixture>) => { f.execution.snapshot_state = 'capturing'; }],
    ['missing preallocated Key absence', (f: ReturnType<typeof rejectedFixture>) => { f.snapshot().objects.pop(); f.sealSnapshot(); }],
    ['duplicated absence instead of all three IDs', (f: ReturnType<typeof rejectedFixture>) => { f.snapshot().objects[3] = structuredClone(f.snapshot().objects[1]); f.sealSnapshot(); }],
    ['snapshot claimed allocated Consumer existed', (f: ReturnType<typeof rejectedFixture>) => { f.snapshot().objects[1].absent = false; f.sealSnapshot(); }],
    ['native manifest changed while original ledger unchanged', (f: ReturnType<typeof rejectedFixture>) => { f.rows[0].native_requests[0].body_hmac = '0'.repeat(64); }],
  ])('refuses %s without emitting writes or a replacement receipt', (_label, change) => {
    const f = rejectedFixture(); change(f);
    expect(() => validateRejectedIssuePlan(f.facts(), f.secrets)).toThrow();
    expect(f.db.exec).not.toHaveBeenCalled(); expect(f.kong.request).not.toHaveBeenCalled();
  });
});

describe('M6 independent actual rejected issue abandonment endpoint',()=>{
  it('releases only the pending reservation with an encrypted certificate, actual audit, unchanged failed history and three exact absence reads',async()=>{
    const f=abandonmentEndpointFixture(),history=structuredClone({workflow:f.workflow,execution:f.execution,rows:f.rows,operations:[...f.operations.values()],credential:f.credential});
    const result=await f.invoke();
    expect(result).toMatchObject({workflowId:wf,executionId:eid,state:'failed',action:'execute',idempotencyKey:f.originalKey,issueAbandonment:{completed:true,eligible:false,reservationReleased:true}});
    expect(result.issueAbandonment?.certificateId).toBe(f.certificateRows[0].id);
    expect(f.grant).toMatchObject({state:'disabled',revision:2,current_generation:0,current_credential_id:null});
    expect(f.events).toEqual(['grant-cas','audit','certificate','commit']);expect(f.audit.append).toHaveBeenCalledOnce();
    expect({workflow:f.workflow,execution:f.execution,rows:f.rows,operations:[...f.operations.values()],credential:f.credential}).toEqual(history);
    expect(f.kong.request.mock.calls.filter(c=>f.absencePaths.includes(c[2])).map(c=>c[2])).toEqual(f.absencePaths);
    expectNeverNativeWrites(f.kong.request.mock.calls);expect(JSON.stringify(result)).not.toContain(f.key);
    expect(f.authz.assertScopedResource).toHaveBeenCalledWith(actor,cid,'portal','write','services',f.serviceObject,wid);
    expect(f.authz.assertWholeWorkspace).not.toHaveBeenCalled();
    expect(f.authz.assertEntity).toHaveBeenCalledWith(actor,cid,'consumers','read',f.plan.steps[0].mutationPayload,wid);
  });
  it('replays the same original-key body from the sealed certificate without new audit, certificate, native absence scan or dispatch',async()=>{
    const f=abandonmentEndpointFixture(),original=await f.invoke();f.kong.request.mockClear();f.db.exec.mockClear();
    expect(await f.invoke()).toEqual(original);expect(f.db.exec).not.toHaveBeenCalled();expect(f.audit.append).toHaveBeenCalledOnce();expect(f.certificateRows).toHaveLength(1);
    expect(f.kong.request.mock.calls.every(c=>c[1]==='GET'&&c[2]===`/services/${serviceId}`)).toBe(true);
    await expect(f.invoke({revision:5})).rejects.toMatchObject({response:{code:'IDEMPOTENCY_CONFLICT'}});
  });
  it.each([
    ['unconfirmed', {confirmed:false}],['wrong confirmation', {confirm_name:'another-issue'}],['client handler injection', {handler:'portal.credential.activate'}],
    ['client native path injection',{nativePath:'/consumers'}],['wrong immutable hash',{planHash:'0'.repeat(64)}],['stale revision',{revision:3}],['different execution',{executionId:id(880)}],
  ])('refuses %s without changing the failed plan or issuing a native packet',async(_name,changes)=>{const f=abandonmentEndpointFixture();await expect(f.invoke(changes)).rejects.toBeInstanceOf(HttpException);f.unchanged();});
  it.each([
    ['different actor', (f:any)=>({actor:{...f.entityActor,user:{...actor,id:id(881)}}})],
    ['new header key',(f:any)=>({actor:{...f.entityActor,idempotencyKey:'new-abandonment-request-key'}})],
    ['no verified SID',()=>({noSID:true})],['different verified SID',()=>({sid:id(882)})],['frame/header key mismatch',()=>({frameKey:'different-trusted-http-key'})],
    ['different workspace',(f:any)=>({actor:{...f.entityActor,workspaceId:id(883)}})],
  ])('refuses %s before releasing any reservation',async(_name,options)=>{const f=abandonmentEndpointFixture();await expect(f.invoke({},options(f))).rejects.toBeInstanceOf(HttpException);f.unchanged();});
  it.each([
    ['revoked session',(f:any)=>{f.session.revoked_at=new Date();}],['credential epoch changed',(f:any)=>{f.session.credential_epoch++;}],
    ['expired session',(f:any)=>{f.session.expires_at=new Date(0);}],['inactive approver',(f:any)=>{f.approvedBy.status='disabled';}],
    ['revoked approver grant',(f:any)=>{f.grants.splice(0);}],['disabled workspace',(f:any)=>{f.workspace.status='disabled';}],
    ['remapped physical endpoint',(f:any)=>{f.cluster.transport_scope='d'.repeat(64);}],['cluster revision changed',(f:any)=>{f.cluster.revision++;}],
    ['execution mode changed',(f:any)=>{f.cluster.execution_mode='direct';}],['wrong gateway version',(f:any)=>{f.cluster.version='2.0.0';}],
    ['changed Service',(f:any)=>{f.serviceObject.host='changed.example';}],['unpublished publication',(f:any)=>{f.publication.state='draft';}],
    ['disabled developer',(f:any)=>{f.developer.status='disabled';}],['changed workflow definition',(f:any)=>{f.plans.definition.mockResolvedValue({...f.plan.definition,version:2});}],
  ])('checks current %s instead of trusting the failed historical authority',async(_name,change)=>{const f=abandonmentEndpointFixture();change(f);await expect(f.invoke()).rejects.toBeInstanceOf(HttpException);f.unchanged();});
  it.each([0,1,2])('refuses allocated object %s that actually exists, without projecting it to HTTP',async(index)=>{const f=abandonmentEndpointFixture();f.nativeObjects.set(f.absencePaths[index],{id:id(890),key:'OFFLINE_SECRET_OBJECT'});await expect(f.invoke()).rejects.toMatchObject({response:{code:'PORTAL_ABANDONMENT_NATIVE_OBJECT_EXISTS'}});f.unchanged();});
  it.each([403,503])('does not interpret native GET %s as an absence proof',async(status)=>{const f=abandonmentEndpointFixture(),original=f.kong.request.getMockImplementation()!;f.kong.request.mockImplementation(async(c,m,p)=>{if(p===f.absencePaths[1])throw new HttpException({code:'OFFLINE_READ_FAILED'},status);return original(c,m,p);});await expect(f.invoke()).rejects.toMatchObject({status});f.unchanged();});
  it('does not interpret a transport failure as absence or emit a second request',async()=>{const f=abandonmentEndpointFixture(),original=f.kong.request.getMockImplementation()!;f.kong.request.mockImplementation(async(c,m,p)=>{if(p===f.absencePaths[0])throw new Error('OFFLINE_RESPONSE_LOST');return original(c,m,p);});await expect(f.invoke()).rejects.toThrow('OFFLINE_RESPONSE_LOST');expect(f.kong.request.mock.calls.filter(c=>f.absencePaths.includes(c[2]))).toHaveLength(1);f.unchanged();});
  it('rechecks current permissions and SQL session after native absence awaits',async()=>{const f=abandonmentEndpointFixture(),original=f.kong.request.getMockImplementation()!;f.kong.request.mockImplementation(async(c,m,p)=>{if(p===f.absencePaths[2])f.session.revoked_at=new Date();return original(c,m,p);});await expect(f.invoke()).rejects.toMatchObject({response:{code:'PORTAL_ABANDONMENT_SESSION_INVALID'}});f.unchanged();});
  it('refuses an actor whose portal grant has been revoked while preserving Service-scoped portal write',async()=>{const f=abandonmentEndpointFixture();f.authz.assertScopedResource.mockImplementation(async(_u,_c,module)=>{if(module==='portal')throw new ForbiddenException({code:'PORTAL_SCOPE_DENIED'});});await expect(f.invoke()).rejects.toMatchObject({response:{code:'PORTAL_SCOPE_DENIED'}});f.unchanged();});
  it('rejects changed permission epoch after absence before committing the certificate',async()=>{const f=abandonmentEndpointFixture(),original=f.kong.request.getMockImplementation()!;f.kong.request.mockImplementation(async(c,m,p)=>{if(p===f.absencePaths[2])f.setVersion('epoch-2');return original(c,m,p);});await expect(f.invoke()).rejects.toMatchObject({response:{code:'PERMISSIONS_CHANGED'}});f.unchanged();});
  it.each(['cas','audit','insert'])('rolls back grant release when %s persistence fails',async(fault)=>{const f=abandonmentEndpointFixture();f.faults[fault]=true;await expect(f.invoke()).rejects.toBeInstanceOf(HttpException);f.unchanged();expect(f.workflow.state).toBe('failed');});
  it('rolls back the certificate and grant when the lease is lost at the final fence',async()=>{const f=abandonmentEndpointFixture();f.redis.assertLeaseOwnership.mockRejectedValue(new HttpException({code:'LOCK_LOST'},503));await expect(f.invoke()).rejects.toMatchObject({response:{code:'LOCK_LOST'}});f.unchanged();});
  it.each(['session','permission-epoch','physical-endpoint'])('rolls back after audit await when final %s authority changed',async(reason)=>{const f=abandonmentEndpointFixture(),original=f.audit.append.getMockImplementation()!;f.audit.append.mockImplementation(async(...args:any[])=>{const receipt=await original(...args);if(reason==='session')f.session.revoked_at=new Date();else if(reason==='permission-epoch')f.setVersion('revoked-after-audit');else f.cluster.transport_scope='e'.repeat(64);return receipt;});await expect(f.invoke()).rejects.toBeInstanceOf(HttpException);f.unchanged();expect(f.workflow.state).toBe('failed');});
  it('keeps a committed certificate on COMMIT acknowledgment loss and resolves by the original key without native replay or overwriting failed history',async()=>{const f=abandonmentEndpointFixture();f.faults.commitAck=true;await expect(f.invoke()).rejects.toMatchObject({response:{code:'PORTAL_ISSUE_ABANDONMENT_UNKNOWN',state:'uncertain'}});expect(f.certificateRows).toHaveLength(1);expect(f.grant.state).toBe('disabled');expect(f.workflow.state).toBe('failed');expect(f.execution.state).toBe('failed');f.kong.request.mockClear();const receipt=await f.receipt();expect(receipt).toMatchObject({state:'failed',issueAbandonment:{completed:true,eligible:false,reservationReleased:true}});expect(f.kong.request).not.toHaveBeenCalled();expect(f.audit.append).toHaveBeenCalledOnce();});
  it.each([
    ['known unrelated failure',(f:any)=>{f.operation.error_code='KONG_RESPONSE_TOO_LARGE';}],['unknown packet',(f:any)=>{f.operation.state='uncertain';}],
    ['later native ACK',(f:any)=>{f.rows[1].state='succeeded';}],['issued fact',(f:any)=>{f.refs.push({id:id(899)});}],
  ])('reports eligibility false for %s without concealing database outages',async(_name,change)=>{const f=abandonmentEndpointFixture();change(f);expect((await f.get()).entity.capabilities.abandonRejectedIssue).toBe(false);f.unchanged();});
  it('propagates unexpected SQL availability failures rather than returning false eligibility',async()=>{const f=abandonmentEndpointFixture();f.faults.candidate=new Error('OFFLINE_DB_UNAVAILABLE');await expect(f.get()).rejects.toThrow('OFFLINE_DB_UNAVAILABLE');f.unchanged();});
  it.each([
    ['tampered proof ciphertext',(f:any)=>{f.certificateRows[0].proof_secret=f.credential.key_secret;}],
    ['tampered proof HMAC',(f:any)=>{f.certificateRows[0].proof_hmac='0'.repeat(64);}],
    ['changed immutable key ciphertext',(f:any)=>{f.credential.key_secret=f.secrets.encrypt({key:f.key},'different-key-context');}],
    ['changed actual audit',(f:any)=>{f.auditRows[0].after.revision++;}],
    ['late SQL fact',(f:any)=>{f.faults.certificateProof=Object.assign(new Error('LATE_FACT'),{code:'23514'});}]
  ])('never calls a %s certificate completed',async(_name,change)=>{const f=abandonmentEndpointFixture();await f.invoke();change(f);await expect(f.receipt()).rejects.toMatchObject({response:{code:'PORTAL_FAILED_ISSUE_PROOF_INVALID'}});expect(f.audit.append).toHaveBeenCalledOnce();expectNeverNativeWrites(f.kong.request.mock.calls);});
});
