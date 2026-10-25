import { describe, expect, it } from 'vitest';
import { randomUUID } from 'node:crypto';
import { canonicalJson } from '../../apps/console-api/src/infrastructure/secret.service';
import { decodeEntityExecutionSource } from '../../apps/console-api/src/modules/workflows/entity-change-source-codec';

const row=()=>({id:randomUUID(),cluster_id:randomUUID(),workspace_id:randomUUID(),intent_id:randomUUID(),intent_revision:1,
  material_hmac:'11'.repeat(32),change_digest:'22'.repeat(32),packet_manifest_hmac:'33'.repeat(32),workflow_id:randomUUID(),workflow_plan_revision:1,
  workflow_plan_hash:'44'.repeat(32),workflow_execution_id:randomUUID(),execution_actor_id:randomUUID(),credential_epoch:'1',session_id:randomUUID(),
  permission_version_hmac:'55'.repeat(32),issued_at:new Date('2026-10-13T13:00:00.000Z'),expires_at:new Date('2026-10-13T13:05:00.000Z')});
describe('M11 entity source origin codec (pure evidence, no runtime scheduled authority)',()=>{
  it('keeps old HTTP source shape and canonical bytes exactly before and after the schema discriminator',()=>{
    const r=row(),original={id:r.id,clusterId:r.cluster_id,workspaceId:r.workspace_id,intentId:r.intent_id,intentRevision:r.intent_revision,
      materialHmac:r.material_hmac,changeDigest:r.change_digest,packetManifestHmac:r.packet_manifest_hmac,workflowId:r.workflow_id,
      workflowPlanRevision:r.workflow_plan_revision,workflowPlanHash:r.workflow_plan_hash,workflowExecutionId:r.workflow_execution_id,
      executionActorId:r.execution_actor_id,credentialEpoch:r.credential_epoch,sessionId:r.session_id,permissionVersionHmac:r.permission_version_hmac,
      issuedAt:r.issued_at.toISOString(),expiresAt:r.expires_at.toISOString()};
    expect(canonicalJson(decodeEntityExecutionSource(r))).toBe(canonicalJson(original));
    expect(canonicalJson(decodeEntityExecutionSource({...r,origin_type:'http',claim_id:null}))).toBe(canonicalJson(original));
    expect(decodeEntityExecutionSource(r)).not.toHaveProperty('origin');expect(decodeEntityExecutionSource(r)).not.toHaveProperty('format');
  });
  it('rejects SID substitution, mixed or unknown origins and incomplete scheduled FK identity',()=>{
    const r=row();for(const extra of [{session_id:null},{origin_type:null},{origin_type:'worker'},{origin_type:'http',claim_id:randomUUID()},
      {origin_type:'scheduled-entity'},{origin_type:'scheduled-entity',session_id:null}])expect(()=>decodeEntityExecutionSource({...r,...extra})).toThrow();
  });
  it('decodes a complete distinct scheduled shape without an HTTP SID and fences its window and generation',()=>{
    const r={...row(),origin_type:'scheduled-entity',session_id:null,schedule_id:randomUUID(),schedule_version:1,spec_hmac:'66'.repeat(32),
      delegation_id:randomUUID(),delegation_version:1,delegation_hmac:'77'.repeat(32),occurrence_id:randomUUID(),claim_id:randomUUID(),
      claim_generation:1,worker_owner_hmac:'88'.repeat(32),window_start:new Date('2026-10-13T12:59:00.000Z'),window_end:new Date('2026-10-13T13:05:00.000Z')};
    const decoded=decodeEntityExecutionSource(r);expect(decoded).toMatchObject({format:2,origin:'scheduled-entity',sessionId:null,claimId:r.claim_id});
    for(const extra of [{session_id:randomUUID()},{claim_generation:2},{worker_owner_hmac:null},{window_end:new Date('2026-10-13T13:04:59.000Z')}])expect(()=>decodeEntityExecutionSource({...r,...extra})).toThrow();
  });
});
