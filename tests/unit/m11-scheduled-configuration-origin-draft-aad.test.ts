import 'reflect-metadata';
import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {randomUUID} from 'node:crypto';
import {SecretService} from '../../apps/console-api/src/infrastructure/secret.service';
import {KongExecutionContextService} from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import {WorkflowScheduledConfigurationOriginService} from '../../apps/console-api/src/modules/workflows/workflow-scheduled-configuration-origin.service';
import {workflowScheduleDraftAad} from '../../apps/console-api/src/modules/workflows/workflow-schedule.repository';

beforeEach(()=>vi.stubEnv('CONSOLE_ENCRYPTION_KEY','be'.repeat(32)));afterEach(()=>vi.unstubAllEnvs());
/** Actual private job handle minting, Context ancestry and SecretService AEAD.
 * SQL and configuration material are explicit dependency fixtures. The test
 * stops at current-principal verification after authenticated draft reading;
 * it does not mint or claim a complete job proof, runtime authority or send. */
function fixture(){
 const secrets=new SecretService(),context=new KongExecutionContextService(),originalNamespace=Object.freeze({});
 const cid=randomUUID(),wid=randomUUID(),scheduleId=randomUUID(),workflowId=randomUUID(),jobId=randomUUID(),wrapperE=randomUUID(),claimId=randomUUID(),occurrenceId=randomUUID();
 const actor={id:randomUUID(),username:'synthetic-source-principal',superAdmin:false},now=Date.now();
 const future=new Date(now+90000).toISOString(),past=new Date(now-5000).toISOString(),older=new Date(now-60000).toISOString();
 const subjectSeal={version:1,driver:'configuration-apply',subjectId:jobId,materialHmac:secrets.fingerprint('fixture-material'),nativeManifestHmac:secrets.fingerprint('fixture-native-manifest'),sourceScopes:[]};
 const c={id:claimId,scheduleId,occurrenceId,generation:1,workerOwnerHmac:secrets.fingerprint('fixture-worker'),issuedAt:past,authorityExpiresAt:future};
 const ns:any=Object.freeze({version:1,origin:'scheduled-workflow',sessionId:null,actor,clusterId:cid,workspaceId:wid,kind:'configuration_v2',expiresAt:future,
  claim:c,workflow:{id:workflowId,planRevision:2,planHash:secrets.fingerprint('fixture-wrapper')},credentialEpoch:'1',permissionVersion:`${actor.id}:1:1`,
  transportScope:secrets.fingerprint('fixture-scope'),subjectSealHmac:secrets.fingerprint(subjectSeal)});
 context.installWorkflowScheduledNamespacePolicy({assertLive(h){if(h!==originalNamespace)throw Error('ORIGINAL_NAMESPACE_REQUIRED');},async verifyHandle(h){if(h!==originalNamespace)throw Error('ORIGINAL_NAMESPACE_REQUIRED');return ns;}});
 const job:any={id:jobId,actor_id:actor.id,workflow_id:workflowId,permission_version:ns.permissionVersion,credential_epoch:1,authority_expires_at:future,expires_at:future,created_at:older};
 const material:any={job,plan:{expiresAt:future},version:{expires_at:future,created_at:older},subjectSeal};
 const draft={binding:{subjectSeal},sourceOnly:true};
 const schedule:any={id:scheduleId,kind:'configuration_v2',executor_id:actor.id,owner_id:actor.id,workflow_id:workflowId,workflow_plan_revision:2,workflow_plan_hash:ns.workflow.planHash,
  executor_credential_epoch:'1',owner_credential_epoch:'1',subject_seal_hmac:ns.subjectSealHmac,transport_scope:ns.transportScope,occurrence_id:occurrenceId,
  window_start:past,not_before:past,window_end:future,expires_at:future,created_at:past,
  draft_ciphertext:secrets.encrypt(draft,workflowScheduleDraftAad(cid,wid,scheduleId)),draft_hmac:secrets.fingerprint(draft)};
 const claim:any={id:claimId,schedule_id:scheduleId,occurrence_id:occurrenceId,generation:1,worker_owner_hmac:c.workerOwnerHmac,workflow_id:workflowId,
  workflow_plan_revision:2,workflow_plan_hash:ns.workflow.planHash,issued_at:past,authority_expires_at:future};
 const db:any={one:vi.fn(async(sql:string)=>{if(sql.includes('FROM workflow_schedules'))return schedule;if(sql.includes('FROM workflow_schedule_claims'))return claim;
  if(sql.includes('FROM workflow_schedule_progress'))return{claim_id:claimId,state:'running'};
  if(sql.includes('FROM workflow_schedule_leases'))return{claim_id:claimId,worker_owner_hmac:c.workerOwnerHmac,lease_until:future};throw Error('UNEXPECTED_SOURCE_SQL');}),query:vi.fn(),exec:vi.fn()};
 const redis:any={assertLeaseOwnership:vi.fn(async()=>undefined)},namespaces:any={assertLive:vi.fn((h:object)=>{if(h!==originalNamespace)throw Error('ORIGINAL_NAMESPACE_REQUIRED');})};
 const service=new WorkflowScheduledConfigurationOriginService(db,secrets,redis,context,namespaces);
 const noCombined=()=>{throw Error('DRAFT_AAD_FIXTURE_HAS_NO_COMBINED_AUTHORITY');};
 service.installRootVerifier({assertCandidateRead:vi.fn(),assertCandidateMaterial:vi.fn(),assertLedgerCurrent:vi.fn(),assertLiveMaterial:vi.fn(),
  openClosedCheckpoint:async()=>noCombined(),assertClosedCheckpoint:async()=>noCombined(),assertClosedCheckpointLive:noCombined,releaseClosedCheckpoint:vi.fn()});
 vi.spyOn(service as any,'material').mockResolvedValue(material);
 const reachedPrincipal=Error('SOURCE_AUTHENTICATED_DRAFT_STAGE_REACHED'),principal=vi.spyOn(service as any,'principal').mockRejectedValue(reachedPrincipal);
 const decrypt=vi.spyOn(secrets,'decrypt'),callback=vi.fn();
 const run=()=>context.runWorkflowScheduledNamespace(originalNamespace,()=>service.runOriginalJob(originalNamespace,wrapperE,jobId,callback));
 return{service,secrets,context,db,material,draft,schedule,claim,ns,cid,wid,scheduleId,originalNamespace,reachedPrincipal,principal,decrypt,callback,run};
}
describe('scheduled configuration uses the actual Repository draft AEAD AAD',()=>{
 it('authenticates genuine Repository-produced ciphertext through the actual private inspection path',async()=>{
  const f=fixture();await expect(f.run()).rejects.toBe(f.reachedPrincipal);
  expect(f.decrypt).toHaveBeenCalledOnce();expect(f.decrypt).toHaveBeenCalledWith(f.schedule.draft_ciphertext,workflowScheduleDraftAad(f.cid,f.wid,f.scheduleId));
  expect(f.principal).toHaveBeenCalledOnce();expect(f.callback).not.toHaveBeenCalled();expect(f.db.exec).not.toHaveBeenCalled();expect(f.context.peek()).toBeNull();
 });
 it('rejects the old mismatched prefix with real AEAD rather than a mocked decrypt result',async()=>{
  const f=fixture();f.schedule.draft_ciphertext=f.secrets.encrypt(f.draft,`workflow-schedule:${f.cid}:${f.wid}:${f.scheduleId}:draft`);
  await expect(f.run()).rejects.not.toBe(f.reachedPrincipal);expect(f.principal).not.toHaveBeenCalled();expect(f.callback).not.toHaveBeenCalled();expect(f.db.exec).not.toHaveBeenCalled();
 });
 it.each(['cluster','workspace','schedule'])('rejects ciphertext bound to another %s identity',async field=>{
  const f=fixture();f.schedule.draft_ciphertext=f.secrets.encrypt(f.draft,workflowScheduleDraftAad(field==='cluster'?randomUUID():f.cid,field==='workspace'?randomUUID():f.wid,field==='schedule'?randomUUID():f.scheduleId));
  await expect(f.run()).rejects.not.toBe(f.reachedPrincipal);expect(f.principal).not.toHaveBeenCalled();expect(f.db.exec).not.toHaveBeenCalled();
 });
 it('does not accept a successful decrypt if the persisted draft HMAC differs',async()=>{
  const f=fixture();f.schedule.draft_hmac='9'.repeat(64);
  await expect(f.run()).rejects.toMatchObject({response:{code:'WORKFLOW_SCHEDULE_CONFIGURATION_DRAFT_HMAC_INVALID'}});expect(f.principal).not.toHaveBeenCalled();expect(f.db.exec).not.toHaveBeenCalled();
 });
 it('does not infer current authority from an authenticated foreign subject seal',async()=>{
  const f=fixture(),foreign={...f.draft,binding:{subjectSeal:{...f.material.subjectSeal,subjectId:randomUUID()}}};
  f.schedule.draft_ciphertext=f.secrets.encrypt(foreign,workflowScheduleDraftAad(f.cid,f.wid,f.scheduleId));f.schedule.draft_hmac=f.secrets.fingerprint(foreign);
  await expect(f.run()).rejects.toMatchObject({response:{code:'WORKFLOW_SCHEDULE_CONFIGURATION_SEAL_CHANGED'}});expect(f.principal).not.toHaveBeenCalled();expect(f.callback).not.toHaveBeenCalled();expect(f.db.exec).not.toHaveBeenCalled();
 });
});
