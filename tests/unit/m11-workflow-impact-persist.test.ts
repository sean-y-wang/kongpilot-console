import 'reflect-metadata';
import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest';
import { randomUUID } from 'node:crypto';
import { WorkflowPlansService } from '../../apps/console-api/src/modules/workflows/workflow-plans.service';
import { entityChangeIntentAad } from '../../apps/console-api/src/modules/workflows/entity-change-workflow';
import { terminalMetadataFixture } from './helpers/terminal-metadata-fixture';

/** Real repository projection/AEAD/HMA, synthetic transaction/verified-delegate
 * adapters only. This is not runtime SQL or native execution authorization. */
function fixture(){
  const f=terminalMetadataFixture(),request={revision:1,confirmed:true,confirm_name:'native-change'},key='synthetic-impact-submit';
  f.envelope.review={version:1,clusterId:f.source.clusterId,workspaceId:f.source.workspaceId,changeDigest:f.envelope.prepared.changeDigest,
    changes:f.packets.map((p:any)=>({entityType:p.nativeType,nativeId:p.nativeId,action:p.mutationAction,before:p.before,after:f.secrets.redact(p.body)})),
    impact:{changedObjects:7,nativePackets:7,traffic:null,trafficAvailability:'unavailable'},recovery:{state:'baseline-required',blockerCodes:[]}};
  f.resignEnvelope();
  const source:any={safe_review:structuredClone(f.envelope.review),envelope_ciphertext:f.secrets.encrypt(f.envelope,entityChangeIntentAad(f.source.clusterId,f.source.workspaceId,f.source.intentId,1)),
    material_hmac:f.source.materialHmac,change_digest:f.source.changeDigest,packet_manifest_hmac:f.source.packetManifestHmac};
  let impact:any;
  const tx:any={one:vi.fn(async(sql:string)=>{
    if(sql.includes('FROM entity_change_submissions'))return{actor_id:f.source.executionActorId,workflow_id:f.plan.workflowId,submit_key:key,request_hmac:f.secrets.fingerprint(request)};
    if(sql.includes('FROM entity_change_intent_versions'))return source;
    if(sql.startsWith('SELECT * FROM workflows WHERE id=$1'))return{id:f.plan.workflowId};
    if(sql.includes('FROM workflows'))return null;
    throw new Error('Unexpected isolated impact SELECT');
  }),exec:vi.fn(async(sql:string,params:any[]=[])=>{if(sql.startsWith('INSERT INTO workflow_versions('))impact=JSON.parse(params[13]);return 1;})};
  const delegate={verifyIntent:vi.fn(async()=>undefined),assertSubject:vi.fn(async()=>undefined),verifyReviewer:vi.fn(async()=>undefined),revalidate:vi.fn(async()=>undefined)},audit:any={append:vi.fn(async()=>undefined)};
  const plans=new WorkflowPlansService(tx,f.secrets,audit);plans.installEntityChangeIntentDelegate(delegate);
  const persist=()=>plans.persist(f.plan,key,request,tx,{requestId:randomUUID(),ip:'192.0.2.51'});
  return{...f,source,tx,delegate,plans,persist,impact:()=>impact};
}
beforeEach(()=>{vi.stubEnv('CONSOLE_ENCRYPTION_KEY','ad'.repeat(32));vi.stubEnv('APP_SECRET','m11-workflow-impact-unit-secret-'.repeat(2));});
afterEach(()=>vi.unstubAllEnvs());
describe('M11 newly persisted workflow impact authenticates its real source',()=>{
  it('removes stale runtime capability assertions without rewriting the original review or wrapper count',async()=>{
    const f=fixture(),original=structuredClone(f.source);await f.persist();
    expect(f.impact()).toMatchObject({nativeRequests:0,nativeRequestsScope:'metadata_wrapper',plannedNativePackets:7,objectCount:7,traffic:null,trafficReasonCode:'WORKFLOW_TRAFFIC_NOT_QUERIED',relatedRoutes:{coverage:'not_captured'}});
    expect(f.impact()).not.toHaveProperty('executionAvailable');expect(f.impact().rollback).not.toContain('尚未启用');expect(f.source).toEqual(original);
    expect(f.delegate.verifyIntent).toHaveBeenCalledWith(f.plan,f.tx);
    const version=f.tx.exec.mock.calls.find(([sql]:any[])=>sql.startsWith('INSERT INTO workflow_versions('));expect(version[1][10]).toBe(0);
    expect(JSON.stringify(f.impact())).not.toMatch(/synthetic-api-key|synthetic-basic-plaintext|synthetic-jwt-secret|synthetic-client-secret|canonicalPath|transportScope|password|rawInput/);
  });
  it.each([
    ['plain review substitution',(f:any)=>{f.source.safe_review.changes[0].nativeId=randomUUID();}],
    ['wrong row material seal',(f:any)=>{f.source.material_hmac='0'.repeat(64);}],
    ['wrong row packet manifest',(f:any)=>{f.source.packet_manifest_hmac='0'.repeat(64);}],
    ['wrong row change digest',(f:any)=>{f.source.change_digest='0'.repeat(64);}],
    ['wrong ciphertext context',(f:any)=>{f.source.envelope_ciphertext=f.secrets.encrypt(f.envelope,entityChangeIntentAad(randomUUID(),f.source.workspaceId,f.source.intentId,1));}],
  ])('rejects %s before persisting a fabricated safe impact',async(_name,modify)=>{
    const f=fixture();modify(f);await expect(f.persist()).rejects.toBeDefined();expect(f.impact()).toBeUndefined();
    expect(f.tx.exec.mock.calls.some(([sql]:any[])=>sql.startsWith('INSERT INTO workflow_versions('))).toBe(false);
  });
});
