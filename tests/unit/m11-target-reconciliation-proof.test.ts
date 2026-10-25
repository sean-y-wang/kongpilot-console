import 'reflect-metadata';
import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {randomUUID} from 'node:crypto';
import {SecretService} from '../../apps/console-api/src/infrastructure/secret.service';
import {certifyTargetReconciliationHistory} from '../../apps/console-api/src/modules/workflows/entity-change-target-reconciliation-proof';
import {entityBaselineAad,entityPacketFactAad} from '../../apps/console-api/src/modules/workflows/entity-change-execution-facts.service';
import {entityChangeIntentAad,normalizedEntityChangePackets} from '../../apps/console-api/src/modules/workflows/entity-change-workflow';
import {planAad} from '../../apps/console-api/src/modules/workflows/workflow.types';

import {targetReconciliationFixture as fixture} from './helpers/target-reconciliation-fixture';
const invalid={response:{code:'ENTITY_CHANGE_TARGET_RECONCILIATION_PROOF_INVALID'}};
describe('M11 original Target zero-weight response history (synthetic SELECT-only, no native201/provenance witness)',()=>{
 beforeEach(()=>vi.stubEnv('CONSOLE_ENCRYPTION_KEY','c3'.repeat(32)));afterEach(()=>vi.unstubAllEnvs());
 it('authenticates the complete old chain but explicitly requires frozen producer + fresh current observation before metadata closure',async()=>{
  const f=fixture(),old=structuredClone(f.rows),result=await certifyTargetReconciliationHistory(f.input);expect(result).toMatchObject({nativeAuthority:false,nativeWrites:0,operationId:f.op,nativeId:f.newId,originalNativeId:f.oldId,originalOutcome:'sent-unknown',nativeStatusRecorded:null,originalResponseAuthenticated:true,requiresFrozenOriginalProducerAttestation:true,requiresFreshCurrentStateObservation:true,metadataEligibility:'requires-frozen-producer-and-current-observation'});
  expect(result.resultHmac).toBe(f.secrets.fingerprint(f.raw));expect(result.proofHmac).toMatch(/^[a-f\d]{64}$/);expect(Object.isFrozen(result)).toBe(true);expect(f.rows).toEqual(old);expect(f.tx.exec).not.toHaveBeenCalled();expect(f.tx.transaction).not.toHaveBeenCalled();expect(f.rows.entity_change_packet_events[1].native_status).toBeNull();
  expect([...f.tx.one.mock.calls,...f.tx.query.mock.calls].every(([sql]:any)=>/^SELECT\s/.test(sql)&&!sql.includes('auth_sessions')&&!sql.includes('FROM users'))).toBe(true);
 });
 it('does not demand historical SID/role/lease remain current or reinterpret old unknown as a new succeeded receipt',async()=>{
  const f=fixture();expect(Date.parse(f.source.expiresAt)).toBeLessThan(Date.now());expect((await certifyTargetReconciliationHistory(f.input)).originalOutcome).toBe('sent-unknown');expect((await certifyTargetReconciliationHistory(f.input)).nativeStatusRecorded).toBeNull();
 });
 it.each([
  ['source CID',f=>{f.rows.entity_change_execution_sources[0].cluster_id=randomUUID();}],['old SID',f=>{f.rows.entity_change_execution_sources[0].session_id=randomUUID();}],['scheduled origin',f=>{f.rows.entity_change_execution_sources[0].origin_type='scheduled-entity';}],
  ['packet original ID',f=>{f.rows.entity_change_intent_packets[0].original_native_id=randomUUID();}],['packet DAG',f=>{f.rows.entity_change_intent_packets[0].dependencies=['foreign'];}],['submission actor',f=>{f.rows.entity_change_submissions[0].actor_id=randomUUID();}],['wrapper actor',f=>{f.rows.workflow_executions[0].execution_actor_id=randomUUID();}],
  ['snapshot hash',f=>{f.rows.workflow_executions[0].snapshot_hash='0'.repeat(64);}],['baseline object',f=>{f.rows.entity_change_baseline_objects[1].before_hmac='0'.repeat(64);}],['pin',f=>{f.rows.entity_change_baseline_pins[0].object_manifest_hmac='0'.repeat(64);}],['attempt parent',f=>{f.rows.entity_change_packet_attempts[0].parent_id=randomUUID();}],
  ['mutation still incomplete',f=>{f.mutation.remote_completed=false;}],['mutation response ID',f=>{f.mutation.entity_id=f.oldId;}],['mutation request hash',f=>{f.mutation.request_hash='0'.repeat(64);}],['borrowed V1 binding',f=>{f.mutation.workflow_execution_id=f.source.workflowExecutionId;}],
  ['missing original vote',f=>{f.rows.workflow_approvals.pop();}],['rejected vote',f=>{f.rows.workflow_approvals[1].decision='reject';}],['approval member',f=>{f.rows.workflow_approval_set_members[1].user_id=randomUUID();}],['frozen candidate epoch',f=>{f.rows.workflow_candidates[1].credential_epoch='2';}],
  ['missing send-intent',f=>{f.rows.entity_change_packet_events.shift();}],['extra attempted packet',f=>{f.rows.entity_change_packet_attempts.push({...f.attempt,id:randomUUID()});}],['extra mutation',f=>{f.rows.mutation_operations.push({...f.mutation,id:randomUUID()});}],['missing baseline',f=>{f.rows.entity_change_baselines=[];}],
 ] as Array<[string,(f:ReturnType<typeof fixture>)=>void]>)('rejects %s',async(_label,mutate)=>{const f=fixture();mutate(f);await expect(certifyTargetReconciliationHistory(f.input)).rejects.toMatchObject(invalid);expect(f.tx.exec).not.toHaveBeenCalled();});
 it.each([
  ['invented status201',(fact:any)=>{fact.nativeStatus=201;}],['different original error',(fact:any)=>{fact.errorCode='OTHER_RESULT_UNKNOWN';}],['changed old succeeded',(fact:any)=>{fact.outcome='succeeded';fact.nativeStatus=201;delete fact.errorCode;}],['metadataComplete true',(fact:any)=>{fact.evidence.metadataComplete=true;}],['fake response HMA',(fact:any)=>{fact.evidence.responseHmac='0'.repeat(64);}],['null private response',(fact:any)=>{fact.evidence.responseHmac=null;}],['extra invented wireSpent',(fact:any)=>{fact.evidence.wireSpent=true;}],
 ])('rejects coherently re-encrypted %s',async(_label,mutate)=>{const f=fixture();f.rewriteOutcome(mutate);await expect(certifyTargetReconciliationHistory(f.input)).rejects.toMatchObject(invalid);});
 it.each(['weight','tags','target','upstream','id'] as const)('rejects corrupted raw %s despite coherent AEAD/outcome responseHMA',async field=>{
  const f=fixture(),raw={...f.raw,[field]:field==='weight'?80:field==='tags'?['foreign']:field==='upstream'?{id:randomUUID()}:field==='id'?randomUUID():'other:8080'};f.mutation.result_secret=f.secrets.encrypt(raw,`mutation:${f.op}:result`);f.rewriteOutcome(fact=>{fact.evidence.responseHmac=f.secrets.fingerprint(raw);});await expect(certifyTargetReconciliationHistory(f.input)).rejects.toMatchObject(invalid);
 });
 it('rejects ciphertext substituted from another operation even when plaintext has the approved target shape',async()=>{const f=fixture();f.mutation.result_secret=f.secrets.encrypt(f.raw,`mutation:${randomUUID()}:result`);await expect(certifyTargetReconciliationHistory(f.input)).rejects.toMatchObject(invalid);});
});
