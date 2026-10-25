import 'reflect-metadata';
import { randomUUID } from 'node:crypto';
import { AsyncLocalStorage } from 'node:async_hooks';
import { KongService } from '../../apps/console-api/src/infrastructure/kong/kong.service';
import { outboundJson } from '../../apps/console-api/src/infrastructure/kong/outbound';
import { entityForPath } from '../../apps/console-api/src/infrastructure/kong/policy';
import { businessAbsenceFixture } from './helpers/workflow-business-absence-fixture';
import { SnapshotCryptoService } from '../../apps/console-api/src/modules/config-storage/snapshot-crypto.service';
import { WorkflowBusinessScopedReadService } from '../../apps/console-api/src/modules/workflows/workflow-business-scoped-read.service';
import { workflowSchedulePlanSeal } from '../../apps/console-api/src/modules/workflows/workflow-schedule.repository';
import { HttpException } from '@nestjs/common';
import { WorkflowBusinessMaterialService } from '../../apps/console-api/src/modules/workflows/workflow-business-material.service';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { KongExecutionContextService } from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import { WorkflowScheduleCandidateReadService } from '../../apps/console-api/src/modules/workflows/workflow-schedule-candidate-read.service';
import { WorkflowBusinessRuntimeService } from '../../apps/console-api/src/modules/workflows/workflow-business-runtime.service';
import { WorkflowCandidatesService } from '../../apps/console-api/src/modules/workflows/workflow-candidates.service';
import { candidateAbsenceFixture } from './helpers/workflow-scheduled-read-absence-fixture';

vi.mock('../../apps/console-api/src/infrastructure/kong/outbound',()=>({outboundJson:vi.fn()}));
const outbound=vi.mocked(outboundJson);

/** SOURCE ONLY: real Context/private Candidate state and real HMACs, with
 * controlled SQL result adapters. No network, PostgreSQL, Docker, ledger,
 * approval, mutation, permit or production acceptance is asserted here. */
function fixture(options: { admission?: boolean; maxCalls?: number; kind?: 'configuration_v2'|'portal-credential-issue'; team?:boolean } = {}) {
  const f = candidateAbsenceFixture(false,options.kind), context = new KongExecutionContextService();
  const sessions = new Map<string, any>(), users = new Map<string, any>();
  const h = (value: unknown) => f.secrets.fingerprint(value), ownerSid = randomUUID(), reviewerSid = randomUUID();
  const reviewers = f.approvalSet.reviewers.map(member => member.userId),teamId=randomUUID();
  const grant = (id: string, module: string, action: string) => ({ user_id: id, cluster_id: f.cid, workspace_id: f.wid,
    module, action, scope_type: 'global', scope_values: [] });
  const state: any = { iamEpoch: '1', originalParent: null, lastHandle: null, candidateValid: true, voteValid: true,
    row: null, manifest: null, parentReads: 0, teamMember:true, endpoint: 'http://kong:8001', secret: null, iamGrants: new Map<string, any[]>() };
  for (const id of [f.owner, ...reviewers]) {
    users.set(id, { id, username: id === f.owner ? 'current-owner' : 'actual-reviewer', super_admin: false,
      status: 'active', deleted_at: null, force_password_change: false, credential_epoch: '1', permissions_epoch: '1' });
    state.iamGrants.set(id, [grant(id, 'services', 'read'), grant(id, 'secrets', 'read'), grant(id, 'workflows', id === f.owner ? 'write' : 'approve')]);
  }
  sessions.set(ownerSid, { id: ownerSid, user_id: f.owner, credential_epoch: '1', revoked_at: null,
    expires_at: new Date(Date.now() + 600000).toISOString(), refresh_expires_at: new Date(Date.now() + 600000).toISOString() });
  sessions.set(reviewerSid, { ...sessions.get(ownerSid), id: reviewerSid, user_id: reviewers[0] });
  const policy: any = { version: 2, kind: f.plan.kind, allowSelfApproval: false, distinctAcrossStages: true, intentTtlHours: 1,
    stages: reviewers.map((id, index) => ({ level: index + 1, name: `stage-${index + 1}`, mode: 'any', threshold: 1, selector: options.team&&index===1?{teams:[teamId]}:{users:[id]} })) };
  f.values.definition = policy; f.values.selectorVersion = 2;
  f.plan.definition.policyHash = h(policy); f.draft.binding.policyHash = h(policy); f.draft.delegation.policyHash = h(policy); f.reseal();
  const stages = reviewers.map((id, index) => ({ level: index + 1, mode: 'any', threshold: 1,
    candidates: [{ userId: id, credentialEpoch: '1', provenance: [options.team&&index===1?{kind:'team',selectorId:teamId}:{kind:'user',selectorId:id}] }] }));
  const manifest: any = { version: 1, clusterId: f.cid, workspaceId: f.wid, workflowId: f.plan.workflowId, planRevision: f.plan.planRevision,
    planHash: h(f.plan), definitionId: f.plan.definition.id, definitionVersion: f.plan.definition.version,
    policyHash: f.plan.definition.policyHash, candidateVersion: 1, stages };
  const manifestHmac = h(manifest);
  state.manifest = manifest; f.values.frozen = { manifest, manifest_hmac: manifestHmac };
  state.row = { id: f.plan.workflowId, cluster_id: f.cid, workspace_id: f.wid, requester_id: f.owner,
    kind: f.plan.kind, subject_type: f.plan.subject.type, subject_id: f.plan.subject.id, requester_type: f.plan.requester.type,
    requester_user_id: f.plan.requester.type==='console'?f.owner:null, requester_developer_id: f.plan.requester.type==='developer'?f.plan.requester.id:null, definition_id: f.plan.definition.id, definition_version: f.plan.definition.version,
    execution_mode: f.plan.executionMode, approval_required: true, expires_at: f.plan.expiresAt,
    state: 'pending', plan_revision: f.plan.planRevision, plan_hash: h(f.plan), approval_format: 2,
    candidate_version: 1, candidate_manifest_hmac: manifestHmac };
  state.votes = reviewers.map((id, index) => ({ id: f.approvalSet.reviewers[index].approvalId, cluster_id: f.cid, workspace_id: f.wid,
    workflow_id: f.plan.workflowId, plan_revision: f.plan.planRevision, plan_hash: h(f.plan), level: index + 1,
    approver_id: id, decision: 'approve', candidate_version: 1, candidate_manifest_hmac: manifestHmac }));
  const baseOne = f.db.one.getMockImplementation()!, baseQuery = f.db.query.getMockImplementation()!;
  f.db.one.mockImplementation(async (sql: string, args: any[] = []) => {
    if(sql.includes('FROM team_members'))return state.teamMember?{current:true}:null;
    if (sql.includes('FROM iam_epoch')) return { version: state.iamEpoch };
    if (sql.includes('FROM users')) {
      const value = users.get(args[0]);
      if (!value || value.status !== 'active' || value.deleted_at !== null || value.force_password_change) return null;
      return { ...value };
    }
    if (sql.includes('FROM auth_sessions')) {
      const value = sessions.get(args[0]);
      if (!value || value.revoked_at !== null || Date.parse(value.expires_at) <= Date.now()) return null;
      if (args.length > 1 && typeof args[1] === 'string' && users.has(args[1]) && value.user_id !== args[1]) return null;
      const user = users.get(value.user_id);
      if (!user || user.status !== 'active' || user.deleted_at !== null || user.force_password_change) return null;
      return { session_id: value.id, user_id: value.user_id, session_credential_epoch: value.credential_epoch,
        user_credential_epoch: user.credential_epoch, permissions_epoch: user.permissions_epoch, iam_version: state.iamEpoch };
    }
    if (sql.includes('FROM workflow_candidate_versions')) return state.candidateValid ? f.values.frozen : null;
    if (sql.includes('FROM workflows')) return { ...state.row };
    if (sql.includes('FROM workflow_approvals')) return state.voteValid ? state.votes.find((vote: any) => args.includes(vote.approver_id)) ?? state.votes[0] : null;
    const value=await baseOne(sql,args);
    if(sql.includes('FROM clusters')&&value)return {...value,admin_url:state.endpoint,connection_secret:state.secret};
    return value;
  });
  f.db.query.mockImplementation(async (sql: string, args: any[] = []) => {
    if (sql.includes('iam_effective_grants')) return (state.iamGrants.get(args[0]) ?? []).filter((row:any)=>!row.valid_until||Date.parse(row.valid_until)>Date.now()).map((row: any) => ({ ...row, scope_values: [...row.scope_values] }));
    if (sql.includes('FROM workflow_approvals')) return state.voteValid ? state.votes.filter((vote: any) => args.length < 5 || args[4] === vote.approver_id).map((vote: any) => ({ ...vote })) : [];
    return baseQuery(sql, args);
  });
  f.plans.load.mockImplementation(async () => ({ plan: f.plan, row: { ...state.row } }));
  f.policies.resolveReadScope.mockImplementation(async () => ({ version: 1, resources: f.values.resources,
    limits: { maxCalls: options.maxCalls ?? 10, maxPages: 5, maxRecords: 10, maxBytes: 8192 } }));
  const service = new WorkflowScheduleCandidateReadService(f.db, f.secrets, context, f.plans, f.repository, new WorkflowCandidatesService(f.db));
  const provider = { verifyHandle: service.verifyHandle.bind(service), assertLive: service.assertLive.bind(service),
    authorizeRequest: service.authorizeRequest.bind(service), verifyRequest: service.verifyRequest.bind(service), authorizeResponse: service.authorizeResponse.bind(service) };
  const generic = vi.fn(async () => { throw new Error('ORDINARY_HTTP_POLICY_MUST_NOT_RUN'); });
  context.installPolicy({ authorizeRequest: generic, authorizeResponse: generic }); context.installWorkflowScheduleCandidateReadPolicy(provider);
  const verifyParent = vi.fn(async (handle: object, frame: any) => {
    state.parentReads++; return (service as any).assertOriginalHttpAcceptance(handle, frame);
  });
  if (options.admission !== false) (context as any).installWorkflowCandidateHttpAdmissionPolicy({ verifyParent });
  service.installStorageContract('a'.repeat(64)); service.installBusinessPolicy(f.plan.kind, f.policies);
  service.installContextRunner({ assertNoFrame() { (context as any).assertWorkflowScheduleCandidateReadAdmission(); },
    run(handle, fn) { state.lastHandle = handle; return context.runWorkflowScheduleCandidateRead(handle, fn); } });
  const actor = (id: string) => ({ id, username: users.get(id)?.username ?? 'unknown', superAdmin: false, forcePasswordChange: false,
    permissionsVersion: `${id}:1:1` });
  const http = <T>(fn: () => Promise<T>, config: any = {}) => context.runHttp({ requestId: 'source-admission' }, async () => {
    const actual = config.actor ?? actor(config.userId ?? f.owner);
    if (config.bind !== false) context.bindHttpActor(actual, config.noSid ? undefined : config.sid ?? (actual.id === f.owner ? ownerSid : reviewerSid));
    if (config.actorFrame === false) return fn();
    return context.runActor({ actor: actual, clusterId: config.clusterId ?? f.cid, workspaceId: config.workspaceId ?? f.wid,
      module: config.module ?? 'workflows', action: config.action ?? (actual.id === f.owner ? 'write' : 'approve') }, async () => {
      state.originalParent = context.current(); return fn();
    });
  });
  const run = <T>(fn: (handle: object) => Promise<T>, readActor = reviewers[1], role: 'executor' | 'reviewer' = 'reviewer') =>
    service.runOriginalPlan(f.plan, readActor, role, fn);
  const cluster: any = { id: f.cid, admin_url: 'http://kong:8001', version: '1.5.1', revision: 1, execution_mode: 'approval' };
  const packet = () => context.authorizeRequest(cluster, 'GET', f.values.resources[0].path, undefined, {});
  const response = () => ({ id: f.nativeId, host: 'controlled-source-response' });
  const read = async () => {
    const ticket = await packet(); await context.refreshAuthorization(ticket); await context.beforeNativeSend(ticket);
    return context.authorizeResponse(ticket, response());
  };
  const material:any={assertReadComplete:vi.fn(async()=>{if(!f.values.read)throw new Error('CURRENT_MATERIAL_REVOKED');})};
  const runtime:any=new WorkflowBusinessRuntimeService(...Array(22).fill(undefined) as ConstructorParameters<typeof WorkflowBusinessRuntimeService>);
  Object.assign(runtime,{candidates:service,context,secrets:f.secrets,material,kong:{request:vi.fn(async()=>read())}});
  runtime.installFixedCandidateReader();
  const fixed=(id=reviewers[1],role:'executor'|'reviewer'='reviewer')=>runtime.fixedCandidateGroup(f.plan,id,role,f.db);
  return { ...f, context, service, state, sessions, users, ownerSid, reviewerSid, reviewers, actor, http, run, packet, response, read,material,runtime,fixed,
    cluster, provider, generic, verifyParent, grant };
}

beforeEach(() => { vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'ab'.repeat(32)); vi.useFakeTimers(); vi.setSystemTime(new Date('2026-10-14T12:00:00Z')); outbound.mockReset(); });
afterEach(() => { vi.restoreAllMocks(); vi.useRealTimers(); vi.unstubAllEnvs(); });

describe('private fixed Candidate GET groups (draft; not executed during Source freeze)', () => {
  it('returns void only after full closing and the real Context HTTP tail, with the actual independent reviewer actor', async () => {
    const f=fixture(),current=vi.spyOn(f.service as any,'current');
    const original=f.runtime.readResources.bind(f.runtime);let readFrame:any,proof:any;
    vi.spyOn(f.runtime,'readResources').mockImplementation(async(...args:any[])=>{
      readFrame=f.context.current();proof=await f.service.verifyHandle(args[2].handle);
      expect(readFrame.actor).toBe(proof.actor);expect(proof.actor.id).toBe(f.reviewers[1]);
      expect(proof.sessionId).toBeNull();expect(readFrame.sessionId).toBeUndefined();
      expect(f.state.originalParent.actor.id).toBe(f.owner);return original(...args);
    });
    let restored=false;
    await f.http(async()=>{await expect(f.fixed()).resolves.toBeUndefined();restored=f.context.current()===f.state.originalParent;});
    expect(restored).toBe(true);expect(current).toHaveBeenCalledTimes(2);
    expect(f.policies.authorizeResponse).toHaveBeenCalledTimes(1);expect(f.material.assertReadComplete).toHaveBeenCalledTimes(1);
    expect(f.runtime.candidateObservations.get(f.state.lastHandle)).toBeUndefined();expect(f.generic).not.toHaveBeenCalled();expect(f.db.exec).not.toHaveBeenCalled();
    await expect(f.service.verifyHandle(f.state.lastHandle)).rejects.toBeDefined();
  });
  it('keeps voted HTTP reviewer SID separate from the executor read principal', async()=>{
    const f=fixture();await f.http(()=>f.fixed(f.owner,'executor'),{userId:f.reviewers[0],action:'approve'});
    expect(f.policies.authorizeResponse.mock.calls[0][0].principal.user.id).toBe(f.owner);
    expect(f.state.originalParent.actor.id).toBe(f.reviewers[0]);
  });
  it.each(['empty-parent','V1','Portal'] as const)('retains the complete original protocol for %s using the installed callback',async kind=>{
    const f=fixture(kind==='Portal'?{kind:'portal-credential-issue'}:{}),current=vi.spyOn(f.service as any,'current');
    if(kind==='V1')f.state.row.approval_format=1;
    if(kind==='empty-parent')await f.fixed(f.owner,'executor');else await f.http(()=>f.fixed(f.owner,'executor'));
    expect(current.mock.calls.length).toBeGreaterThan(2);expect(f.policies.authorizeResponse).toHaveBeenCalledTimes(1);
  });
  it('retains the complete public generic runOriginalPlan even after installation',async()=>{
    const f=fixture(),current=vi.spyOn(f.service as any,'current');
    await f.http(()=>f.run(async()=>{await f.read();return 'original-generic-result';}));
    expect(current.mock.calls.length).toBeGreaterThan(2);expect(f.policies.authorizeResponse).toHaveBeenCalledTimes(1);
  });
  it.each(['reader-grant','owner-grant','caller-grant','credential','iam','session','endpoint','connection-secret','row'] as const)
  ('rejects fresh %s changes at an existing send checkpoint',async reason=>{
    const f=fixture();const original=f.context.beforeNativeSend.bind(f.context);let changed=false;
    vi.spyOn(f.context,'beforeNativeSend').mockImplementation(async(...args:any[])=>{
      if(!changed){changed=true;
        if(reason==='reader-grant')f.state.iamGrants.set(f.reviewers[1],[]);
        if(reason==='owner-grant')f.state.iamGrants.set(f.owner,[]);
        if(reason==='caller-grant')f.state.iamGrants.set(f.owner,f.state.iamGrants.get(f.owner).filter((g:any)=>g.module!=='workflows'));
        if(reason==='credential')f.users.get(f.reviewers[1]).credential_epoch='2';
        if(reason==='iam')f.state.iamEpoch='2';
        if(reason==='session')f.sessions.get(f.ownerSid).revoked_at=new Date().toISOString();
        if(reason==='endpoint')f.state.endpoint='http://rotated-kong:8001';
        if(reason==='connection-secret')f.state.secret='synthetic-rotated-connection-secret';
        if(reason==='row')f.state.row.plan_hash='b'.repeat(64);
      }return original(...args as [any]);
    });
    await expect(f.http(()=>f.fixed())).rejects.toBeDefined();expect(f.policies.authorizeResponse).not.toHaveBeenCalled();
    expect(f.state.iamEpoch).toBe(reason==='iam'?'2':'1');expect(f.db.exec).not.toHaveBeenCalled();
  });
  it('rereads frozen reviewer selector membership without an epoch bump',async()=>{
    const f=fixture({team:true}),original=f.context.beforeNativeSend.bind(f.context);
    vi.spyOn(f.context,'beforeNativeSend').mockImplementation(async(...args:any[])=>{f.state.teamMember=false;return original(...args as [any]);});
    await expect(f.http(()=>f.fixed())).rejects.toBeDefined();expect(f.state.iamEpoch).toBe('1');expect(f.policies.authorizeResponse).not.toHaveBeenCalled();
  });
  it('rereads the authentic HTTP reviewer votes on each fixed acceptance',async()=>{
    const f=fixture(),original=f.context.beforeNativeSend.bind(f.context);
    vi.spyOn(f.context,'beforeNativeSend').mockImplementation(async(...args:any[])=>{f.state.voteValid=false;return original(...args as [any]);});
    await expect(f.http(()=>f.fixed(f.owner,'executor'),{userId:f.reviewers[0],action:'approve'})).rejects.toBeDefined();
    expect(f.policies.authorizeResponse).not.toHaveBeenCalled();
  });
  it('withholds completion when material changes after assertReadComplete, at explicit full closing',async()=>{
    const f=fixture();f.material.assertReadComplete.mockImplementation(async()=>{f.values.read=false;});
    await expect(f.http(()=>f.fixed())).rejects.toBeDefined();expect(f.policies.authorizeResponse).toHaveBeenCalledTimes(1);
    expect(f.runtime.candidateObservations.get(f.state.lastHandle)).toBeUndefined();
  });
  it('rejects copied handles and original handles after their closed group',async()=>{
    const f=fixture(),original=f.runtime.readResources.bind(f.runtime);
    vi.spyOn(f.runtime,'readResources').mockImplementation(async(...args:any[])=>{
      await expect(f.service.verifyHandle({...args[2].handle})).rejects.toBeDefined();return original(...args);
    });
    await f.http(()=>f.fixed());await expect(f.service.verifyHandle(f.state.lastHandle)).rejects.toBeDefined();
  });
  it('rejects a nested replacement actor frame even when it copies the proof actor',async()=>{
    const f=fixture();vi.spyOn(f.runtime,'readResources').mockImplementation(async(_resources:any,_observations:any,capsule:any)=>{
      const proof=await f.service.verifyHandle(capsule.handle);
      await f.context.runActor({actor:proof.actor,clusterId:f.cid,workspaceId:f.wid,module:'workflows',action:'read'},()=>f.service.verifyHandle(capsule.handle));
      return 0;
    });await expect(f.http(()=>f.fixed())).rejects.toBeDefined();
  });
  it('rejects detached provider verification and waits for its denied work in the test',async()=>{
    const f=fixture();let detached:Promise<unknown>|undefined;
    vi.spyOn(f.runtime,'readResources').mockImplementation(async(_r:any,_o:any,c:any)=>{
      detached=f.service.authorizeRequest(c.handle,{clusterId:f.cid,workspaceId:f.wid,method:'GET',path:f.values.resources[0].path,query:{}}).catch(error=>error);
      return 0;
    });await expect(f.http(()=>f.fixed())).rejects.toBeDefined();expect(detached).toBeDefined();await detached;
  });
  it('keeps an unawaited response pending through its full material callback',async()=>{
    const f=fixture();let detached:Promise<unknown>|undefined;
    vi.spyOn(f.runtime,'readResources').mockImplementation(async()=>{
      await f.read();const ticket=await f.packet();await f.context.refreshAuthorization(ticket);await f.context.beforeNativeSend(ticket);
      detached=f.context.authorizeResponse(ticket,f.response()).catch(error=>error);return 0;
    });await expect(f.http(()=>f.fixed())).rejects.toBeDefined();await detached;
  });
  it('still rejects 31 seconds with the original independent Candidate/Context deadlines',async()=>{
    const f=fixture(),original=f.runtime.readResources.bind(f.runtime);
    vi.spyOn(f.runtime,'readResources').mockImplementation(async(...args:any[])=>{const result=await original(...args);vi.advanceTimersByTime(31000);return result;});
    await expect(f.http(()=>f.fixed())).rejects.toBeDefined();
  });
  it('preserves the earlier Material response scope deadline independently of the Candidate deadline',async()=>{
    const f=fixture(),scope:any=Object.create(WorkflowBusinessMaterialService.prototype);scope.responses=new AsyncLocalStorage();
    const original=f.runtime.readResources.bind(f.runtime);
    vi.spyOn(f.runtime,'readResources').mockImplementation(async(...args:any[])=>{const result=await original(...args);vi.advanceTimersByTime(25001);return result;});
    await expect(f.http(()=>scope.runResponseScope(async()=>{vi.advanceTimersByTime(5000);await f.fixed();}))).rejects.toBeDefined();
  });
  it('rejects more actual calls than the original sealed scope allows',async()=>{
    const f=fixture({maxCalls:1});vi.spyOn(f.runtime,'readResources').mockImplementation(async()=>{await f.read();await f.read();return 0;});
    await expect(f.http(()=>f.fixed())).rejects.toBeDefined();
  });
});

describe('fresh clock predicates without epoch changes',()=>{
  it.each(['reader','executor','caller'] as const)('rejects natural %s grant expiry from the complete effective view',async who=>{
    const f=fixture(),id=who==='reader'?f.reviewers[1]:f.owner,original=f.context.beforeNativeSend.bind(f.context);
    const grants=f.state.iamGrants.get(id);for(const grant of grants)grant.valid_until=new Date(Date.now()+1000).toISOString();
    vi.spyOn(f.context,'beforeNativeSend').mockImplementation(async(...args:any[])=>{vi.advanceTimersByTime(1001);return original(...args as [any]);});
    await expect(f.http(()=>f.fixed())).rejects.toBeDefined();expect(f.state.iamEpoch).toBe('1');expect(f.policies.authorizeResponse).not.toHaveBeenCalled();
  });
  it('retains the authentic session clock predicate while Candidate time is still live',async()=>{
    const f=fixture(),original=f.context.beforeNativeSend.bind(f.context);f.sessions.get(f.ownerSid).expires_at=new Date(Date.now()+1000).toISOString();
    vi.spyOn(f.context,'beforeNativeSend').mockImplementation(async(...args:any[])=>{vi.advanceTimersByTime(1001);return original(...args as [any]);});
    await expect(f.http(()=>f.fixed())).rejects.toBeDefined();expect(f.state.iamEpoch).toBe('1');expect(f.policies.authorizeResponse).not.toHaveBeenCalled();
    expect(f.db.one.mock.calls.some((call:any[])=>String(call[0]).includes('s.expires_at>clock_timestamp()'))).toBe(true);
  });
});

function sdkParentChild(childKind='key-auth'){
  const f=fixture(),parentType=childKind==='targets'?'upstreams':'consumers',parentId=randomUUID(),childId=randomUUID();
  const parent:any={clusterId:f.cid,workspaceId:f.wid,path:`/${parentType}/${parentId}`,kind:'point',entityType:parentType,entityId:parentId,secrets:false,required:true,allowAbsent:true};
  const path=`/${parentType}/${parentId}/${childKind}/${childId}`,child:any={clusterId:f.cid,workspaceId:f.wid,path,kind:'point',entityType:entityForPath(path),
    entityId:childId,parentId,secrets:childKind!=='targets'&&childKind!=='acls',required:true,allowAbsent:true};
  f.values.resources=[parent,child];f.values.childGrant=true;f.values.parentCreate=true;
  const limits={maxCalls:1,maxPages:5,maxRecords:10,maxBytes:8192};
  f.policies.resolveReadScope.mockImplementation(async()=>({version:1,domain:'scoped-points-v1',resources:f.values.resources,limits}));
  f.policies.authorizeResponse.mockImplementation(async(input:any)=>{if(!f.values.read||input.status!==404)throw new Error('CURRENT_ORIGINAL_ABSENCE_POLICY_DENIED');});
  f.redis.rateLimit=vi.fn(async()=>({allowed:true}));const kong=new KongService(f.db,f.redis,f.secrets,{} as any,f.context);f.runtime.kong=kong;
  f.context.installScheduledReadAbsentTransportObserver({verifyTransport:(ticket,proof)=>kong.verifyScheduledReadAbsentTransport(ticket,proof)});
  f.service.installAbsentResponseVerifier({verifyOriginalResponse:(token,observation)=>f.context.verifyScheduledReadAbsentObservation(token,observation)});
  const parentPolicy={assertChild:vi.fn(async(input:any,actualChild:any,actualParent:any)=>{
    expect(input.transaction).toBe(f.db);expect(actualChild).toEqual(child);expect(actualParent).toEqual(parent);
    if(!f.values.childGrant||!f.values.parentCreate)throw new Error('CURRENT_FULL_PARENT_POLICY_DENIED');await f.values.beforeChildFinish?.();
  })};f.service.installParentAbsencePolicy(parentPolicy);
  outbound.mockImplementation(async(_base,_path,method,_body,_query,_auth,_timeout,beforeSend,prepareSend)=>{
    if(method!=='GET')throw new Error('NATIVE_WRITE_FORBIDDEN');await prepareSend?.();beforeSend?.();
    return{status:404,body:{message:'Not found'},bytes:20,jsonParsed:true};
  });
  return{...f,kong,parent,child,parentPolicy,limits};
}

describe('fixed Candidate reader with real SDK JSON404 and original private FK witness (Source only)',()=>{
  it.each(['key-auth','basic-auth','jwt','oauth2','hmac-auth','acls','targets'])('derives %s only after authentic parent SDK404 and complete helpers',async kind=>{
    const f=sdkParentChild(kind),current=vi.spyOn(f.service as any,'current'),witness=vi.spyOn(f.service,'requireObservedAbsentPoint');
    await expect(f.http(()=>f.fixed(f.owner,'executor'))).resolves.toBeUndefined();
    expect(outbound).toHaveBeenCalledTimes(1);expect(outbound.mock.calls[0][1]).toBe(f.parent.path);expect(outbound.mock.calls[0][2]).toBe('GET');
    expect(f.policies.authorizeResponse.mock.calls.map((call:any[])=>call[0].status)).toEqual([404]);
    expect(witness).toHaveBeenCalledTimes(1);expect(f.parentPolicy.assertChild).toHaveBeenCalledTimes(1);expect(current.mock.calls.length).toBeGreaterThan(2);
    expect(f.db.exec).not.toHaveBeenCalled();expect(f.runtime.candidateObservations.get(f.state.lastHandle)).toBeUndefined();
  });
  it('rejects a copied parent witness before the original full parent policy',async()=>{
    const f=sdkParentChild(),original=f.service.requireObservedAbsentPoint.bind(f.service);
    vi.spyOn(f.service,'requireObservedAbsentPoint').mockImplementation(async(handle,r)=>({...await original(handle,r)}));
    await expect(f.http(()=>f.fixed(f.owner,'executor'))).rejects.toBeDefined();expect(f.parentPolicy.assertChild).not.toHaveBeenCalled();
  });
  it('rejects a caught caller-shaped HTTP404 without an original transport observation',async()=>{
    const f=sdkParentChild();vi.spyOn(f.kong,'request').mockRejectedValue(new HttpException({upstreamStatus:404,message:'Not found'},404));
    await expect(f.http(()=>f.fixed(f.owner,'executor'))).rejects.toBeDefined();expect(f.parentPolicy.assertChild).not.toHaveBeenCalled();expect(outbound).not.toHaveBeenCalled();
  });
  it.each(['compiled-parent','child-grant','material-after-parent'] as const)('retains full %s checks around the FK helper',async reason=>{
    const f=sdkParentChild();
    if(reason==='compiled-parent')f.values.parentCreate=false;
    if(reason==='child-grant')f.values.childGrant=false;
    if(reason==='material-after-parent')f.values.beforeChildFinish=async()=>{f.values.read=false;};
    await expect(f.http(()=>f.fixed(f.owner,'executor'))).rejects.toBeDefined();expect(f.parentPolicy.assertChild).toHaveBeenCalledTimes(1);expect(outbound).toHaveBeenCalledTimes(1);
  });
  it('charges derived FK facts to the original record ceiling',async()=>{
    const f=sdkParentChild();f.limits.maxRecords=1;
    const id=randomUUID();f.values.resources.push({...f.child,entityId:id,path:`/consumers/${f.parent.entityId}/key-auth/${id}`});
    // The same fixed full parent policy must accept either compiled child.
    f.parentPolicy.assertChild.mockImplementation(async()=>{});
    await expect(f.http(()=>f.fixed(f.owner,'executor'))).rejects.toBeDefined();expect(outbound).toHaveBeenCalledTimes(1);
  });
});

/** Real Material SQL/AES rows, scoped grant compiler, SDK transport and Context
 * are combined here. Only SQL result storage and outbound bytes are controlled;
 * there are no Source policy stubs for material/current/response/FK decisions. */
async function realMaterialFixture(childKind?:'key-auth'|'targets'){
  const m=await businessAbsenceFixture(),{plan,db,tables,compiler,secrets}=m,h=(value:unknown)=>secrets.fingerprint(value),reviewers=[randomUUID(),randomUUID(),randomUUID()];
  delete plan.scheduling;
  if(childKind){
    const original=m.nested.steps[0],parentId=randomUUID(),childId=randomUUID(),parentType=childKind==='targets'?'upstreams':'consumers';
    const parentBody=childKind==='targets'?{id:parentId,name:'source-upstream',tags:['kos-ws-default']}:{id:parentId,username:'source-consumer',tags:['kos-ws-default']};
    const childBody=childKind==='targets'?{id:childId,target:'echo:80',weight:100,upstream:{id:parentId},tags:['kos-ws-default']}
      :{id:childId,key:'synthetic-source-credential',consumer:{id:parentId},tags:['kos-ws-default']};
    const parent={...original,stepId:randomUUID(),stepOrder:1,entityType:parentType,objectKey:`${parentType}:${parentId}`,allocatedNativeId:parentId,body:parentBody,
      nativeRequests:[{method:'POST',canonicalPath:`/${parentType}`,body:parentBody}],dependencies:[]};
    const child={...original,stepId:randomUUID(),stepOrder:2,entityType:childKind==='targets'?'targets':'credentials',credentialKind:childKind==='targets'?null:childKind,
      objectKey:`${childKind}:${childId}`,allocatedNativeId:childId,parentId,body:childBody,
      nativeRequests:[{method:'POST',canonicalPath:`/${parentType}/${parentId}/${childKind}`,body:childBody}],dependencies:[parent.stepId]};
    m.nested.steps=[parent,child];
    const version=tables.configuration_plan_versions[0],material=tables.configuration_materials[0],crypto=new SnapshotCryptoService(secrets);
    const identity={clusterId:m.cid,workspaceId:m.wid,jobId:version.source_job_id,materialId:material.id,artifactId:version.artifact_id,artifactKind:'plan' as const};
    await crypto.withKey(identity,material.wrapped_key_secret,async key=>{
      for(const step of m.nested.steps){step.bodyHmac=h(step.body);step.beforeHmac=h(step.before??null);
        for(const request of step.nativeRequests){request.bodyHmac=h(request.body);request.beforeHmac=step.beforeHmac;}}
      const hash=h(m.nested);m.job.plan_hash=hash;version.plan_hash=hash;version.input_hmac=hash;version.steps_hmac=h(m.nested.steps);
      version.step_count=m.nested.steps.length;version.native_packet_count=m.nested.steps.length;version.manifest_ciphertext=crypto.encrypt(key,identity,{section:'manifest',key:'plan'},m.nested);
      tables.configuration_plan_objects=m.nested.steps.map((step:any)=>({cluster_id:m.cid,workspace_id:m.wid,plan_id:m.job.plan_id,plan_revision:1,
        step_id:step.stepId,step_order:step.stepOrder,object_workspace_id:step.objectWorkspaceId,entity_type:step.entityType,mutation_action:step.mutationAction,
        body_hmac:step.bodyHmac,before_hmac:step.beforeHmac,reference_only:false,blocker_codes:[],dependencies:step.dependencies,native_id:null,
        allocated_native_id:step.allocatedNativeId,parent_id:step.parentId??null,credential_kind:step.credentialKind??null,
        payload_ciphertext:crypto.encrypt(key,identity,{section:'plan-step',key:step.stepId,entityType:step.entityType,nativeId:step.allocatedNativeId,parentId:step.parentId??null,credentialKind:step.credentialKind??null},step),
        native_requests:step.nativeRequests.map((request:any)=>({method:request.method,path_hmac:h(request.canonicalPath),body_hmac:request.bodyHmac,before_hmac:request.beforeHmac}))}));
      plan.steps[0].metadata.planHash=hash;plan.steps[0].metadataPayloadHmac=h(plan.steps[0].metadata);
    });
    if(childKind==='targets')tables.iam_effective_grants.push(...['read','write','approve'].map(action=>({user_id:m.actor,module:'upstreams',action,cluster_id:null,workspace_id:null,scope_type:'global',scope_values:[]})));
  }
  const policy:any={version:2,kind:'configuration_v2',allowSelfApproval:false,distinctAcrossStages:true,intentTtlHours:1,
    stages:reviewers.map((userId,index)=>({level:index+1,name:`stage-${index+1}`,mode:'any',threshold:1,selector:{users:[userId]}}))};
  plan.definition.policyHash=h(policy);m.persist();const seal=await compiler.subjectSealForPlan(plan,db),now=Date.now();
  const spec={version:1,notBefore:new Date(now-1000).toISOString(),windowStart:new Date(now-10000).toISOString(),windowEnd:new Date(now+60000).toISOString(),executorId:m.actor};
  const baseHash=h(plan),requester={...plan.requester,credentialEpoch:'1'},delegation:any={version:1,id:randomUUID(),revision:1,clusterId:m.cid,workspaceId:m.wid,
    workflowId:plan.workflowId,workflowPlanRevision:1,basePlanHash:baseHash,kind:'configuration_v2',subjectType:'configuration_jobs',subjectId:plan.subject.id,
    subjectSealHmac:h(seal),requester,ownerId:m.actor,executorId:m.actor,ownerCredentialEpoch:'1',executorCredentialEpoch:'1',policyHash:plan.definition.policyHash,
    specHmac:h(spec),issuedAt:plan.issuedAt,expiresAt:plan.expiresAt,statement:'execute-this-exact-approved-business-workflow-with-my-current-authority'};
  const impact={version:1,keyId:h('source-impact-key'),keys:[h('source-object-key')],domains:[],wildcards:[]},draft:any={binding:{clusterId:m.cid,workspaceId:m.wid,
    workflowId:plan.workflowId,workflowPlanRevision:1,workflowPlanHash:'',basePlanHash:baseHash,kind:'configuration_v2',subjectType:'configuration_jobs',subjectId:plan.subject.id,
    requester,definitionId:plan.definition.id,definitionVersion:1,policyHash:plan.definition.policyHash,subjectSeal:seal},scheduleId:randomUUID(),scheduleVersion:1,occurrenceId:randomUUID(),
    spec,specHmac:h(spec),delegation,delegationHmac:h(delegation),transportScope:plan.scope.transportScope,impact,impactHmac:h(impact)};
  plan.scheduling=workflowSchedulePlanSeal(draft);draft.binding.workflowPlanHash=h(plan);m.persist();
  const manifest:any={version:1,clusterId:m.cid,workspaceId:m.wid,workflowId:plan.workflowId,planRevision:1,planHash:h(plan),definitionId:plan.definition.id,definitionVersion:1,
    policyHash:plan.definition.policyHash,candidateVersion:1,stages:reviewers.map((userId,index)=>({level:index+1,mode:'any',threshold:1,candidates:[{userId,credentialEpoch:'1',provenance:[{kind:'user',selectorId:userId}]}]}))};
  const row=tables.workflows[0];Object.assign(row,{expires_at:plan.expiresAt,approval_format:2,candidate_version:1,candidate_manifest_hmac:h(manifest)});
  const ownerGrants=[...tables.iam_effective_grants];for(const userId of reviewers){tables.users.push({...m.user,id:userId,username:'source-reviewer'});
    tables.iam_effective_grants.push(...ownerGrants.map(grant=>({...grant,user_id:userId})));}
  const session:any={id:randomUUID(),user_id:m.actor,credential_epoch:'1',expires_at:new Date(now+600000).toISOString(),revoked_at:null};
  const beforeOne=db.one.getMockImplementation()!;
  db.one.mockImplementation(async(sql:string,args:any[]=[])=>{
    if(sql.includes('FROM schema_migrations'))return{checksum:'a'.repeat(64)};
    if(sql.includes('FROM workflow_definition_versions'))return{approval_format:2,policy,policy_hash:h(policy)};
    if(sql.includes('FROM workflow_candidate_versions'))return{manifest,manifest_hmac:h(manifest)};
    if(sql.includes('FROM users')){const user=tables.users.find(user=>user.id===args[0]);return user&&user.status==='active'&&user.deleted_at===null&&!user.force_password_change?{...user}:null;}
    if(sql.includes('FROM auth_sessions'))return session.revoked_at||Date.parse(session.expires_at)<=Date.now()?null:
      {session_id:session.id,user_id:m.actor,session_credential_epoch:'1',user_credential_epoch:'1',permissions_epoch:'1',iam_version:'1'};
    if(sql.includes('FROM workspaces')&&sql.includes('id=$1 AND cluster_id=$2'))return tables.workspaces.find(workspace=>workspace.id===args[0]&&workspace.cluster_id===args[1])??null;
    return beforeOne(sql,args);
  });
  db.transaction=vi.fn(async(fn:any)=>fn(db));const context=new KongExecutionContextService(),repository:any={inspectStored:vi.fn(async()=>({plan,draft}))};
  const plans:any={load:vi.fn(async()=>({plan,row})),definition:vi.fn(async()=>plan.definition)};
  const service=new WorkflowScheduleCandidateReadService(db,secrets,context,plans,repository,new WorkflowCandidatesService(db));
  const generic=vi.fn(async()=>{throw new Error('GENERIC_HTTP_POLICY_FORBIDDEN');});context.installPolicy({authorizeRequest:generic,authorizeResponse:generic});
  context.installWorkflowScheduleCandidateReadPolicy(service);context.installWorkflowCandidateHttpAdmissionPolicy({verifyParent:(handle,frame)=>service.assertOriginalHttpAcceptance(handle,frame)});
  service.installStorageContract('a'.repeat(64));service.installContextRunner({assertNoFrame:()=>context.assertWorkflowScheduleCandidateReadAdmission(),run:(handle,fn)=>context.runWorkflowScheduleCandidateRead(handle,fn)});
  compiler.installScopedReadBridge(new WorkflowBusinessScopedReadService());service.installBusinessPolicy('configuration_v2',compiler.businessReadPolicy('configuration_v2',true));
  service.installParentAbsencePolicy({assertChild:(input,child,parent)=>compiler.authorizeScopedParentAbsence(input,child,parent)});
  const redis:any={rateLimit:vi.fn(async()=>({allowed:true}))},kong=new KongService(db,redis,secrets,{} as any,context);
  context.installScheduledReadAbsentTransportObserver({verifyTransport:(ticket,proof)=>kong.verifyScheduledReadAbsentTransport(ticket,proof)});
  service.installAbsentResponseVerifier({verifyOriginalResponse:(token,observation)=>context.verifyScheduledReadAbsentObservation(token,observation)});
  const runtime:any=new WorkflowBusinessRuntimeService(...Array(22).fill(undefined) as ConstructorParameters<typeof WorkflowBusinessRuntimeService>);Object.assign(runtime,{candidates:service,context,secrets,material:compiler,kong});runtime.installFixedCandidateReader();
  const owner:any={id:m.actor,username:m.user.username,superAdmin:false,forcePasswordChange:false,permissionsVersion:`${m.actor}:1:1`};
  const run=(actorId=m.actor,role:'executor'|'reviewer'='executor')=>context.runHttp({requestId:'source-real-material'},async()=>{
    context.bindHttpActor(owner,session.id);return context.runActor({actor:owner,clusterId:m.cid,workspaceId:m.wid,module:'workflows',action:'write'},
      ()=>compiler.runResponseScope(()=>runtime.fixedCandidateGroup(plan,actorId,role,db)));
  });
  const controls:any={beforeResponse:undefined,present:false};
  outbound.mockImplementation(async(_base,path,_method,_body,_query,_auth,_timeout,beforeSend,prepareSend)=>{
    await prepareSend?.();beforeSend?.();await controls.beforeResponse?.(path);
    const schema=path.startsWith('/schemas/')||path.startsWith('/plugins/schema/'),step=m.nested.steps.find((step:any)=>path.endsWith(`/${step.allocatedNativeId}`));
    return{status:schema||controls.present?200:404,body:schema?{fields:[]}:controls.present?step?.body:{message:'Not found'},bytes:20,jsonParsed:true};
  });
  return{...m,service,context,runtime,run,controls,draft,manifest,reviewers,session};
}

describe('fixed Candidate integrated with unchanged full Material policy and genuine encrypted configuration',()=>{
  it.each(['executor','reviewer'] as const)('runs the complete %s material policy for authentic SDK404 and closes void',async role=>{
    const f=await realMaterialFixture(),authorizer=vi.spyOn(f.compiler,'authorizeResponse'),current=vi.spyOn(f.service as any,'current');
    await expect(f.run(role==='executor'?f.actor:f.reviewers[0],role)).resolves.toBeUndefined();
    expect(authorizer).toHaveBeenCalled();expect(authorizer.mock.calls.some(([input])=>input.status===404)).toBe(true);
    expect(current.mock.calls.length).toBeGreaterThanOrEqual(2);expect(f.db.exec).not.toHaveBeenCalled();
  });
  it.each(['key-auth','targets'] as const)('uses the real full Material parent policy for a future %s child with no child SDK request',async kind=>{
    const f=await realMaterialFixture(kind),parentPolicy=vi.spyOn(f.compiler,'authorizeScopedParentAbsence');await expect(f.run()).resolves.toBeUndefined();
    expect(parentPolicy).toHaveBeenCalledTimes(1);const requests=outbound.mock.calls.filter(call=>!call[1].startsWith('/schemas/')&&!call[1].startsWith('/plugins/schema/'));
    expect(requests).toHaveLength(1);expect(requests[0][2]).toBe('GET');expect(f.db.exec).not.toHaveBeenCalled();
  });
  it.each(['material','deadline','secret-grant'] as const)('rejects actual %s mutation at a full response fence',async reason=>{
    const f=await realMaterialFixture(reason==='secret-grant'?'key-auth':undefined);let changed=false;
    f.controls.beforeResponse=async(path:string)=>{if(changed||path.startsWith('/schemas/'))return;changed=true;
      if(reason==='material')f.tables.configuration_materials[0].state='deleted';
      if(reason==='deadline')f.job.expires_at=new Date(Date.now()+1000).toISOString();
      if(reason==='secret-grant')f.tables.iam_effective_grants=f.tables.iam_effective_grants.filter(grant=>grant.module!=='secrets');
    };await expect(f.run()).rejects.toBeDefined();expect(f.db.exec).not.toHaveBeenCalled();
  });
  it('detects a material mutation after actual assertReadComplete in the explicit complete closing',async()=>{
    const f=await realMaterialFixture(),original=f.compiler.assertReadComplete.bind(f.compiler);
    vi.spyOn(f.compiler,'assertReadComplete').mockImplementation(async input=>{await original(input);f.tables.configuration_materials[0].state='deleted';});
    await expect(f.run()).rejects.toBeDefined();expect(f.db.exec).not.toHaveBeenCalled();
  });
});

describe('original fixed Candidate aggregate limits and true completion',()=>{
  it.each(['bytes','records','pages','missing-required'] as const)('retains the original %s ceiling/fence',async reason=>{
    const f=fixture(),id=randomUUID();
    f.values.resources=reason==='missing-required'?[...f.values.resources,{...f.values.resources[0],entityId:id,path:`/services/${id}`}]
      :[{clusterId:f.cid,workspaceId:f.wid,path:'/services',kind:'collection',entityType:'services',secrets:false,required:true,query:{size:2}}];
    const limits={maxCalls:10,maxPages:reason==='pages'?1:5,maxRecords:reason==='records'?1:10,maxBytes:reason==='bytes'?1:8192};
    f.policies.resolveReadScope.mockImplementation(async()=>({version:1,resources:f.values.resources,limits}));
    let page=0;f.runtime.kong.request=vi.fn(async(_cid:string,_method:string,path:string,_body:unknown,query:any)=>{
      const ticket=await f.context.authorizeRequest(f.cluster,'GET',path,undefined,query??{});await f.context.refreshAuthorization(ticket);await f.context.beforeNativeSend(ticket);
      const result=reason==='missing-required'?f.response():{data:reason==='records'?[{id:randomUUID()},{id:randomUUID()}]:[],next:reason==='pages'&&page++===0?'/services?size=2&offset=authentic-next':null};
      return f.context.authorizeResponse(ticket,result);
    });
    if(reason==='missing-required')vi.spyOn(f.runtime,'readResources').mockImplementation(async()=>{await f.read();return 0;});
    await expect(f.http(()=>f.fixed())).rejects.toBeDefined();expect(f.db.exec).not.toHaveBeenCalled();
  });
});
