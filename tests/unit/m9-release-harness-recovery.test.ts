import { describe, expect, it } from 'vitest';
import { randomUUID } from 'node:crypto';
import { ReleaseHarness, releaseScope } from '../security/lib/release-harness.mjs';

function fixture() {
  const actorId=randomUUID(),clusterId=randomUUID(),workspaceId=randomUUID(),workflowId=randomUUID(),executionId=randomUUID(),key=randomUUID(),requestId=randomUUID(),planHash='c'.repeat(64);
  const original:any={method:'POST',path:releaseScope(clusterId,workspaceId,`workflows/${workflowId}/execute`),key,actorId,requestId,state:'response_observed',status:503,
    resolution:{knownNativeComplete:true,factProofSha256:'a'.repeat(64),metadataRecovery:{kind:'workspace-migration',clusterId,workspaceId,workflowId,executionId,revision:4,planHash}}};
  const h:any=Object.create(ReleaseHarness.prototype);h.state={requests:[original]};
  const operation:any={session:{user:{id:actorId}},path:releaseScope(clusterId,workspaceId,`workflows/${workflowId}/reconcile-metadata`),method:'POST',key,metadataOnlyFor:requestId,
    body:{revision:4,planHash,executionId,confirmed:true,confirm_name:'workspace-migration'}};
  return{h,original,operation};
}
describe('actual release recovery never replaces an original native execution',()=>{
  it('permits only the exact original known-success migration ledger closure',()=>{
    const {h,original,operation}=fixture(),before=JSON.stringify(original);
    expect(()=>h.assertWritable(operation)).not.toThrow();expect(JSON.stringify(original)).toBe(before);
    expect(()=>h.assertWritable()).toThrow('NO_REPLAY');
  });
  it.each(['key','actor','cluster','workspace','workflow','execution','hash','revision','confirmation','extra body','method','native path','original request'])(
    'blocks altered %s without discarding the original failure',variant=>{
      const {h,operation,original}=fixture();
      if(variant==='key')operation.key=randomUUID();
      if(variant==='actor')operation.session.user.id=randomUUID();
      if(variant==='cluster')operation.path=operation.path.replace(original.resolution.metadataRecovery.clusterId,randomUUID());
      if(variant==='workspace')operation.path=operation.path.replace(original.resolution.metadataRecovery.workspaceId,randomUUID());
      if(variant==='workflow')operation.path=operation.path.replace(original.resolution.metadataRecovery.workflowId,randomUUID());
      if(variant==='execution')operation.body.executionId=randomUUID();
      if(variant==='hash')operation.body.planHash='d'.repeat(64);
      if(variant==='revision')operation.body.revision++;
      if(variant==='confirmation')operation.body.confirmed=false;
      if(variant==='extra body')operation.body.approved=true;
      if(variant==='method')operation.method='PATCH';
      if(variant==='native path')operation.path=original.path;
      if(variant==='original request')operation.metadataOnlyFor=randomUUID();
      expect(()=>h.assertWritable(operation)).toThrow('NO_REPLAY');expect(original.status).toBe(503);
    });
  it.each(['no native proof','bad proof digest','unknown response','second unresolved write'])('blocks %s',variant=>{
    const {h,original,operation}=fixture();
    if(variant==='no native proof')original.resolution.knownNativeComplete=false;
    if(variant==='bad proof digest')original.resolution.factProofSha256='';
    if(variant==='unknown response')original.state='response_unknown';
    if(variant==='second unresolved write')h.state.requests.push({state:'prepared'});
    expect(()=>h.assertWritable(operation)).toThrow('NO_REPLAY');
  });
  it('keeps normal writes blocked until original terminal receipt verification completes',()=>{
    const {h,original}=fixture();original.resolution.metadataRecovered=true;
    expect(()=>h.assertWritable()).toThrow('NO_REPLAY');
    original.resolution.receiptVerified=true;original.resolution.finalState='succeeded';
    expect(()=>h.assertWritable()).not.toThrow();expect(original.status).toBe(503);expect(original.state).toBe('response_observed');
    original.resolution.responseResolved=false;expect(original.resolution.responseResolved).toBe(false);
  });
});
