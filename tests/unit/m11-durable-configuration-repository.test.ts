import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { randomUUID } from 'node:crypto';
import type { DbService } from '../../apps/console-api/src/infrastructure/db.service';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { normalizeWorkflowApprovalPolicy } from '../../apps/console-api/src/modules/workflows/workflow-approval-policy';
import { planAad, type WorkflowPlanV1 } from '../../apps/console-api/src/modules/workflows/workflow.types';
import type { ConfigPlan, ConfigurationPlanStep } from '../../apps/console-api/src/modules/configuration/configuration.types';
import { ConfigurationDurableCodec, durableConfigurationLocator } from '../../apps/console-api/src/modules/configuration/configuration-durable.codec';
import { ConfigurationDurableRepository, configurationDurableMarker, DURABLE_BINDING_QUERY, DURABLE_ISSUE_QUERY } from '../../apps/console-api/src/modules/configuration/configuration-durable.repository';
import type { DurableConfigurationEnvelope } from '../../apps/console-api/src/modules/configuration/configuration-durable.types';

const NOW=Date.parse('2026-10-15T20:00:00.000Z');
const POLICY_QUERY='SELECT * FROM workflow_definition_versions WHERE cluster_id=$1 AND workspace_id=$2 AND definition_id=$3 AND version=$4';
const PLAN_QUERY='SELECT * FROM configuration_plan_versions WHERE cluster_id=$1 AND workspace_id=$2 AND plan_id=$3 AND plan_revision=$4';
const SNAPSHOT_QUERY='SELECT v.manifest_hmac,v.consistency,v.completeness,s.state AS snapshot_state,m.state AS material_state FROM config_snapshot_versions v JOIN config_snapshots s ON s.id=v.snapshot_id AND s.cluster_id=v.cluster_id AND s.workspace_id=v.workspace_id JOIN configuration_materials m ON m.id=v.material_id AND m.cluster_id=v.cluster_id AND m.workspace_id=v.workspace_id WHERE v.cluster_id=$1 AND v.workspace_id=$2 AND v.snapshot_id=$3 AND v.version=$4';
const JOB_QUERY='SELECT * FROM configuration_jobs WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3';
const WORKFLOW_QUERY='SELECT * FROM workflows WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3';
const WORKFLOW_VERSION_QUERY='SELECT * FROM workflow_versions WHERE workflow_id=$1 AND cluster_id=$2 AND workspace_id=$3 AND plan_revision=$4';
const INSERT_BINDING=`INSERT INTO configuration_durable_bindings(issue_id,cluster_id,workspace_id,job_id,plan_id,plan_revision,plan_hash,
      workflow_id,workflow_plan_revision,workflow_plan_hash,baseline_snapshot_id,baseline_version,baseline_manifest_hmac,material_hmac,envelope_ciphertext)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`;

function setup(){
  const secrets=new SecretService(),repository=new ConfigurationDurableRepository(secrets),codec=new ConfigurationDurableCodec(secrets);
  const ids={issue:randomUUID(),cluster:randomUUID(),workspace:randomUUID(),job:randomUUID(),owner:randomUUID(),sid:randomUUID(),
    definition:randomUUID(),sourceJob:randomUUID(),sourcePlan:randomUUID(),snapshot:randomUUID(),plan:randomUUID(),workflow:randomUUID(),service:randomUUID(),reviewer:randomUUID()};
  const issuedAt=new Date(NOW).toISOString(),expiresAt=new Date(NOW+24*3_600_000).toISOString();
  const policy=normalizeWorkflowApprovalPolicy({version:2,kind:'configuration_v2',allowSelfApproval:false,distinctAcrossStages:true,intentTtlHours:24,
    stages:[{level:1,name:'Configuration approval',mode:'any',threshold:1,selector:{users:[ids.reviewer]}}]},'configuration_v2');
  const before={id:ids.service,name:'before',host:'upstream.internal',tags:['workspace:test']};
  const body={name:'after'},scope={clusterId:ids.cluster,workspaceId:ids.workspace,transportScope:secrets.fingerprint('fixture-transport'),kind:'services' as const,rootIds:[ids.service]};
  const packet={method:'PATCH' as const,canonicalPath:`/services/${ids.service}`,body,bodyHmac:secrets.fingerprint(body),beforeHmac:secrets.fingerprint(before)};
  const step:ConfigurationPlanStep={stepId:randomUUID(),stepOrder:1,objectKey:`services:${ids.service}`,entityType:'services',objectWorkspaceId:ids.workspace,
    clearMap:[],nativeId:ids.service,permissionAction:'write',mutationAction:'update',dependencies:[],body,before,
    bodyHmac:packet.bodyHmac,beforeHmac:packet.beforeHmac,nativeRequests:[packet],referenceOnly:false,blockerCodes:[],maskedDiff:[]};
  const baselineHmac=secrets.fingerprint({fixture:'complete-fresh-baseline'});
  const plan:ConfigPlan={durableRef:{version:1,domain:'durable-configuration-v1',issueId:ids.issue},scope,mode:'merge',steps:[step],
    sourceManifestHmac:secrets.fingerprint({fixture:'new-source-manifest'}),baselineManifestHmac:baselineHmac,schemaHmac:secrets.fingerprint({fixture:'schemas'}),
    permissionVersion:`${ids.owner}:1:1`,clusterRevision:1,workspaceRevision:1,kongVersion:'1.5.1',recoveryComplete:true,expiresAt};
  const e:DurableConfigurationEnvelope={domain:'durable-configuration-v1',envelopeVersion:1,issueId:ids.issue,clusterId:ids.cluster,workspaceId:ids.workspace,
    jobId:ids.job,ownerId:ids.owner,authoringSessionId:ids.sid,credentialEpoch:1,permissionVersion:plan.permissionVersion,issuedAt,admissionExpiresAt:new Date(NOW+90_000).toISOString(),expiresAt,
    policy:{definitionId:ids.definition,version:1,hash:secrets.fingerprint(policy),intentTtlHours:24},
    provenance:{jobId:ids.sourceJob,planId:ids.sourcePlan,planRevision:1,planHash:secrets.fingerprint({fixture:'historical-provenance-plan'}),kind:'import'},
    baseline:{snapshotId:ids.snapshot,version:1,manifestHmac:baselineHmac},recipeHmac:secrets.fingerprint({fixture:'recipe'}),schemaHmac:plan.schemaHmac,
    scopeHmac:secrets.fingerprint(plan.scope),plan:{planId:ids.plan,planRevision:1,planHash:secrets.fingerprint(plan),stepsHmac:secrets.fingerprint(plan.steps),
      sourceManifestHmac:plan.sourceManifestHmac,baselineManifestHmac:baselineHmac}};
  const workflow:WorkflowPlanV1={version:1,clusterId:ids.cluster,workspaceId:ids.workspace,workflowId:ids.workflow,planRevision:1,kind:'configuration_v2',
    executionMode:'approval',approvalRequired:true,subject:{type:'configuration_jobs',id:ids.job},requester:{type:'console',id:ids.owner},
    definition:{id:ids.definition,version:1,policyHash:e.policy.hash},issuedAt,expiresAt,scope:{transportScope:scope.transportScope,clusterRevision:1,workspaceRevision:1},
    prerequisites:[],steps:[{id:randomUUID(),key:'configuration',order:1,kind:'metadata',handler:'configuration_v2',entityType:'configuration_jobs',entityId:ids.job,
      permissionAction:'write',dependencies:[],nativeRequests:[],metadata:{jobId:ids.job,planId:ids.plan,planRevision:1,planHash:e.plan.planHash}}]};
  const seal=codec.seal(e,durableConfigurationLocator(e),NOW);
  const job:any={id:ids.job,cluster_id:ids.cluster,workspace_id:ids.workspace,actor_id:ids.owner,origin_session_id:ids.sid,credential_epoch:1,
    permission_version:e.permissionVersion,authority_expires_at:expiresAt,expires_at:expiresAt,authority_domain:e.domain,durable_issue_id:ids.issue,
    kind:'apply',origin_type:'http',execution_mode:'approval',approval_required:true,required_origin_kind:null,required_origin_id:null,required_origin_hmac:null,
    plan_id:ids.plan,plan_revision:1,plan_hash:e.plan.planHash,workflow_id:ids.workflow};
  const rows:any={job,
    issue:{id:ids.issue,cluster_id:ids.cluster,workspace_id:ids.workspace,job_id:ids.job,owner_id:ids.owner,authoring_session_id:ids.sid,credential_epoch:1,
      permission_version:e.permissionVersion,issued_at:issuedAt,admission_expires_at:e.admissionExpiresAt,expires_at:expiresAt,definition_id:ids.definition,definition_version:1,policy_hash:e.policy.hash,intent_ttl_hours:24,
      source_job_id:ids.sourceJob,source_plan_id:ids.sourcePlan,source_plan_revision:1,source_plan_hash:e.provenance.planHash,source_kind:'import'},
    binding:{issue_id:ids.issue,cluster_id:ids.cluster,workspace_id:ids.workspace,job_id:ids.job,plan_id:ids.plan,plan_revision:1,plan_hash:e.plan.planHash,
      workflow_id:ids.workflow,workflow_plan_revision:1,workflow_plan_hash:secrets.fingerprint(workflow),baseline_snapshot_id:ids.snapshot,baseline_version:1,
      baseline_manifest_hmac:baselineHmac,envelope_ciphertext:seal.ciphertext,material_hmac:seal.materialHmac},
    policy:{cluster_id:ids.cluster,workspace_id:ids.workspace,definition_id:ids.definition,version:1,approval_format:2,policy_hash:e.policy.hash,policy:structuredClone(policy)},
    plan:{cluster_id:ids.cluster,workspace_id:ids.workspace,plan_id:ids.plan,plan_revision:1,source_job_id:ids.job,plan_hash:e.plan.planHash,
      steps_hmac:e.plan.stepsHmac,schema_hmac:e.schemaHmac,source_manifest_hmac:e.plan.sourceManifestHmac,baseline_manifest_hmac:baselineHmac,expires_at:expiresAt},
    snapshot:{manifest_hmac:baselineHmac,consistency:'console_fenced_best_effort',completeness:'complete',snapshot_state:'ready',material_state:'available'},
    workflow:{id:ids.workflow,cluster_id:ids.cluster,workspace_id:ids.workspace,plan_revision:workflow.planRevision,plan_hash:secrets.fingerprint(workflow)},
    workflowVersions:{'1':{workflow_id:ids.workflow,cluster_id:ids.cluster,workspace_id:ids.workspace,plan_revision:1,plan_hash:secrets.fingerprint(workflow),
      payload_secret:secrets.encrypt(workflow,planAad(ids.cluster,ids.workspace,ids.workflow,1))}}};
  const queries=new Map<string,{args:unknown[];key:string}>([
    [DURABLE_ISSUE_QUERY,{args:[ids.issue,ids.cluster,ids.workspace,ids.job],key:'issue'}],
    [DURABLE_BINDING_QUERY,{args:[ids.issue,ids.cluster,ids.workspace,ids.job],key:'binding'}],
    [POLICY_QUERY,{args:[ids.cluster,ids.workspace,ids.definition,1],key:'policy'}],
    [PLAN_QUERY,{args:[ids.cluster,ids.workspace,ids.plan,1],key:'plan'}],
    [SNAPSHOT_QUERY,{args:[ids.cluster,ids.workspace,ids.snapshot,1],key:'snapshot'}],
    [JOB_QUERY,{args:[ids.job,ids.cluster,ids.workspace],key:'job'}],
    [WORKFLOW_QUERY,{args:[ids.workflow,ids.cluster,ids.workspace],key:'workflow'}],
  ]);
  const one=vi.fn(async(sql:string,args:unknown[])=>{
    if(sql===WORKFLOW_VERSION_QUERY){
      expect(args.slice(0,3)).toEqual([ids.workflow,ids.cluster,ids.workspace]);expect(args).toHaveLength(4);
      if(args[3]!==1&&args[3]!==2)throw new Error('UNEXPECTED_EXACT_SQL_ARGUMENTS');
      return structuredClone(rows.workflowVersions[String(args[3])]??null);
    }
    const q=queries.get(sql);if(!q)throw new Error('UNEXPECTED_EXACT_SQL_QUERY');
    expect(args).toEqual(q.args);return structuredClone(rows[q.key]);
  });
  const exec=vi.fn(async()=>{throw new Error('UNEXPECTED_EXACT_SQL_EXEC');});
  const query=vi.fn(async()=>{throw new Error('UNEXPECTED_EXACT_SQL_QUERY');});
  const tx={one,exec,query} as unknown as DbService;
  return {secrets,repository,codec,e,plan,workflow,job,rows,ids,tx,one,exec,query,queries};
}
let originalKey:string|undefined;
beforeEach(()=>{originalKey=process.env.CONSOLE_ENCRYPTION_KEY;process.env.CONSOLE_ENCRYPTION_KEY='71'.repeat(32);vi.useFakeTimers();vi.setSystemTime(NOW);});
afterEach(()=>{vi.useRealTimers();if(originalKey===undefined)delete process.env.CONSOLE_ENCRYPTION_KEY;else process.env.CONSOLE_ENCRYPTION_KEY=originalKey;});

describe('M11 durable Configuration V2 repository exact SQL with real SecretService and codec',()=>{
  it('verifies a complete new ordinary J/P, full policy, complete baseline and sealed packet plan',async()=>{
    const f=setup();expect(await f.repository.verify(f.job,f.tx,true,f.plan)).toEqual(f.e);
    expect(f.one.mock.calls.map(call=>call[0])).toEqual([DURABLE_ISSUE_QUERY,DURABLE_BINDING_QUERY,POLICY_QUERY,PLAN_QUERY,SNAPSHOT_QUERY]);
    expect(f.query).not.toHaveBeenCalled();expect(f.exec).not.toHaveBeenCalled();
    expect(f.e.provenance.jobId).not.toBe(f.e.jobId);expect(f.e.provenance.planId).not.toBe(f.e.plan.planId);
  });
  it('verifies the complete ordinary configuration_v2 approval wrapper and its bound current plan',async()=>{
    const f=setup();await expect(f.repository.verifyWorkflow(f.workflow,f.tx)).resolves.toBeUndefined();
    expect(f.one.mock.calls[0]).toEqual([JOB_QUERY,[f.ids.job,f.ids.cluster,f.ids.workspace]]);
  });
  it.each([
    {authority_domain:'unknown'}, {authority_domain:null}, {durable_issue_id:null}, {durable_issue_id:'invalid'},
    {kind:'import'}, {origin_type:'scheduled-entity'}, {execution_mode:'direct'}, {approval_required:false},
    {required_origin_kind:'governance-promote'}, {required_origin_id:randomUUID()}, {required_origin_hmac:'1'.repeat(64)},
  ])('rejects unknown, partial or incompatible domain markers before any SQL: %j',async patch=>{
    const f=setup();await expect(f.repository.verify({...f.job,...patch},f.tx,true,f.plan)).rejects.toThrow();expect(f.one).not.toHaveBeenCalled();
  });
  it.each([{snapshot_state:'deleted'},{material_state:'destroyed'}])('rejects a purged or archived execution baseline: %j',async patch=>{const f=setup();Object.assign(f.rows.snapshot,patch);await expect(f.repository.verify(f.job,f.tx,true,f.plan)).rejects.toThrow();});
  it('returns legacy null only without a durable marker and refuses a fake long-lived durableRef',async()=>{
    const f=setup(),legacy={...f.job,authority_domain:null,durable_issue_id:null,expires_at:new Date(NOW+168*3_600_000).toISOString()};
    expect(configurationDurableMarker(legacy)).toBeNull();expect(await f.repository.verify(legacy,f.tx,true)).toBeNull();
    await expect(f.repository.verify(legacy,f.tx,true,f.plan)).rejects.toThrow();
    await expect(f.repository.verify(legacy,f.tx,false,{...f.plan,durableRef:{version:1,domain:'durable-configuration-v1',issueId:randomUUID()}})).rejects.toThrow();
    expect(f.one).not.toHaveBeenCalled();
  });
  it('rejects cross-tenant AEAD material even with that other material’s valid HMAC',async()=>{
    const f=setup(),foreign={...f.e,clusterId:randomUUID(),workspaceId:randomUUID()},seal=f.codec.seal(foreign,durableConfigurationLocator(foreign),NOW);
    f.rows.binding.envelope_ciphertext=seal.ciphertext;f.rows.binding.material_hmac=seal.materialHmac;
    await expect(f.repository.verify(f.job,f.tx,true,f.plan)).rejects.toMatchObject({response:{code:'CONFIGURATION_DURABLE_BINDING_INVALID'}});
  });
  it('rejects material HMAC substitution and ciphertext corruption before trusting policy or baseline SQL',async()=>{
    for(const field of ['material_hmac','envelope_ciphertext']){
      const f=setup();f.rows.binding[field]=field==='material_hmac'?'0'.repeat(64):'v1.invalid.invalid.invalid';
      await expect(f.repository.verify(f.job,f.tx,true,f.plan)).rejects.toMatchObject({response:{code:'CONFIGURATION_DURABLE_BINDING_INVALID'}});
      expect(f.one.mock.calls.map(call=>call[0])).toEqual([DURABLE_ISSUE_QUERY,DURABLE_BINDING_QUERY]);
    }
  });
  it('rejects plan packet path/body-row substitution when supplied plan hash and AEAD binding remain original',async()=>{
    for(const change of ['path','body','before']){
      const f=setup(),plan=structuredClone(f.plan),s=plan.steps[0] as any;
      if(change==='path')s.nativeRequests[0].canonicalPath=`/services/${randomUUID()}`;
      if(change==='body')s.nativeRequests[0].body={name:'unapproved'};
      if(change==='before')s.before={...s.before,name:'substituted-before'};
      await expect(f.repository.verify(f.job,f.tx,true,plan)).rejects.toThrow();
    }
  });
  it.each([
    ['issue','owner_id'],['issue','authoring_session_id'],['issue','permission_version'],['issue','policy_hash'],['issue','source_plan_hash'],
    ['binding','plan_hash'],['binding','baseline_manifest_hmac'],['plan','plan_hash'],['plan','steps_hmac'],['plan','schema_hmac'],
    ['plan','source_manifest_hmac'],['plan','baseline_manifest_hmac'],['snapshot','manifest_hmac'],
  ])('rejects persistent %s.%s tampering against the authentic envelope',async(table,key)=>{
    const f=setup();f.rows[table][key]='0'.repeat(64);await expect(f.repository.verify(f.job,f.tx,true,f.plan)).rejects.toThrow();
  });
  it.each(['consistency','completeness'])('rejects a baseline without original complete-fenced %s',async key=>{
    const f=setup();f.rows.snapshot[key]=key==='consistency'?'unverified':'incomplete';await expect(f.repository.verify(f.job,f.tx,true,f.plan)).rejects.toThrow();
  });
  it('authenticates all complete policy bytes rather than accepting unchanged kind and TTL alone',async()=>{
    const f=setup();f.rows.policy.policy.stages[0].selector.users=[randomUUID()];await expect(f.repository.verify(f.job,f.tx,true,f.plan)).rejects.toThrow();
  });
  it.each(['issue','binding','policy','plan','snapshot'])('rejects a missing mandatory %s row with no fallback',async table=>{
    const f=setup();f.rows[table]=null;await expect(f.repository.verify(f.job,f.tx,true,f.plan)).rejects.toThrow();
  });
  it('rejects original deadline expiry for current execution while preserving historical receipt integrity without a Native capability',async()=>{
    const f=setup();vi.setSystemTime(Date.parse(f.e.expiresAt));
    await expect(f.repository.verify(f.job,f.tx,true,f.plan)).rejects.toMatchObject({response:{code:'CONFIGURATION_DURABLE_BINDING_INVALID'}});
    const receipt=await f.repository.verify(f.job,f.tx,false,f.plan);expect(receipt).toEqual(f.e);
    expect(receipt).not.toHaveProperty('nativePermit');expect(receipt).not.toHaveProperty('claim');
    expect(f.exec).not.toHaveBeenCalled();
    f.rows.binding.material_hmac='0'.repeat(64);await expect(f.repository.verify(f.job,f.tx,false,f.plan)).rejects.toThrow();
  });
  it.each(['planRevision','issuedAt','scope'])('rejects a wrapper %s mutation against the immutable workflow binding',async key=>{
    const f=setup(),workflow=structuredClone(f.workflow);
    if(key==='planRevision')workflow.planRevision++;
    if(key==='issuedAt')workflow.issuedAt=new Date(NOW-1).toISOString();
    if(key==='scope')workflow.scope.transportScope=f.secrets.fingerprint('unapproved-transport');
    await expect(f.repository.verifyWorkflow(workflow,f.tx)).rejects.toThrow();
  });
  it.each(['workflow_plan_revision','workflow_plan_hash'])('rejects a stored workflow binding %s mutation',async key=>{
    const f=setup();f.rows.binding[key]=key==='workflow_plan_revision'?2:'0'.repeat(64);
    await expect(f.repository.verifyWorkflow(f.workflow,f.tx)).rejects.toThrow();
  });
  it('rejects stored wrapper ciphertext substitution even when the immutable binding and current hashes stay original',async()=>{
    const f=setup(),substituted={...f.workflow,scope:{...f.workflow.scope,transportScope:f.secrets.fingerprint('changed-current-transport')}};
    f.rows.workflowVersions['1'].payload_secret=f.secrets.encrypt(substituted,planAad(f.ids.cluster,f.ids.workspace,f.ids.workflow,1));
    await expect(f.repository.verifyWorkflow(f.workflow,f.tx)).rejects.toThrow();
  });
  it('rejects an initial wrapper ciphertext with another tenant’s AAD',async()=>{
    const f=setup();f.rows.workflowVersions['1'].payload_secret=f.secrets.encrypt(f.workflow,planAad(randomUUID(),f.ids.workspace,f.ids.workflow,1));
    await expect(f.repository.verifyWorkflow(f.workflow,f.tx)).rejects.toThrow();
  });
  it('checks the bound initial wrapper even when a later stored scheduled wrapper is the current revision',async()=>{
    const f=setup(),current={...f.workflow,planRevision:2,issuedAt:new Date(NOW+1_000).toISOString(),steps:[{...f.workflow.steps[0],id:randomUUID()}],
      scheduling:{scheduleId:randomUUID(),version:1}} as WorkflowPlanV1;
    f.rows.workflow.plan_revision=2;f.rows.workflow.plan_hash=f.secrets.fingerprint(current);
    f.rows.workflowVersions['2']={workflow_id:f.ids.workflow,cluster_id:f.ids.cluster,workspace_id:f.ids.workspace,plan_revision:2,
      plan_hash:f.secrets.fingerprint(current),payload_secret:f.secrets.encrypt(current,planAad(f.ids.cluster,f.ids.workspace,f.ids.workflow,2))};
    await expect(f.repository.verifyWorkflow(current,f.tx)).resolves.toBeUndefined();
    f.rows.workflowVersions['1'].payload_secret=f.secrets.encrypt({...f.workflow,issuedAt:new Date(NOW-1).toISOString()},planAad(f.ids.cluster,f.ids.workspace,f.ids.workflow,1));
    await expect(f.repository.verifyWorkflow(current,f.tx)).rejects.toThrow();
  });
  it('binds only the exact fifteen-value SQL tuple and real cryptographic envelope',async()=>{
    const f=setup();const exec=vi.fn(async(sql:string,args:unknown[])=>{
      if(sql!==INSERT_BINDING)throw new Error('UNEXPECTED_EXACT_SQL_EXEC');
      expect(args.slice(0,13)).toEqual([f.e.issueId,f.e.clusterId,f.e.workspaceId,f.e.jobId,f.e.plan.planId,f.e.plan.planRevision,f.e.plan.planHash,
        f.workflow.workflowId,f.workflow.planRevision,f.secrets.fingerprint(f.workflow),f.e.baseline.snapshotId,f.e.baseline.version,f.e.baseline.manifestHmac]);
      expect(args).toHaveLength(15);
      expect(f.codec.open({materialHmac:args[13],ciphertext:args[14]},durableConfigurationLocator(f.e),NOW)).toEqual(f.e);return 1;
    });
    await f.repository.bind({...f.tx,exec} as unknown as DbService,f.e,f.workflow);expect(exec).toHaveBeenCalledTimes(1);expect(f.one).not.toHaveBeenCalled();
  });
  it('makes every SQL adapter reject unknown statements, aliases and wrong argument order',async()=>{
    const f=setup();await expect(f.tx.one(`${DURABLE_ISSUE_QUERY} `,[f.ids.issue,f.ids.cluster,f.ids.workspace,f.ids.job])).rejects.toThrow('UNEXPECTED_EXACT_SQL_QUERY');
    await expect(f.tx.one(DURABLE_ISSUE_QUERY,[f.ids.issue,f.ids.workspace,f.ids.cluster,f.ids.job])).rejects.toThrow();
    await expect(f.tx.query('SELECT * FROM configuration_durable_issues',[])).rejects.toThrow('UNEXPECTED_EXACT_SQL_QUERY');
    await expect(f.tx.exec('DELETE FROM configuration_durable_bindings',[])).rejects.toThrow('UNEXPECTED_EXACT_SQL_EXEC');
  });
});
