import {randomUUID} from 'node:crypto';
import {describe,it,expect} from 'vitest';
// This tests the acceptance tool boundary; no native or database evidence.
// @ts-expect-error The runner is a deliberately standalone JavaScript tool.
import {assertM10MetadataApprovalScope} from '../security/lib/m10-metadata-approval-runner.mjs';

describe('M10 metadata approval bound release scope',()=>{
 const state={cid:randomUUID(),wid:randomUUID(),targetCid:randomUUID(),targetWid:randomUUID()};
 it('can exercise the exact registered target while retaining the source timer scope',()=>{
  expect(()=>assertM10MetadataApprovalScope(state,state.targetCid,state.targetWid)).not.toThrow();
  expect(()=>assertM10MetadataApprovalScope(state,state.cid,state.wid)).not.toThrow();
 });
 it.each([[state.cid,state.targetWid],[state.targetCid,state.wid],[randomUUID(),state.targetWid],[state.targetCid,randomUUID()]])('rejects a mixed or unregistered cluster/workspace tuple', (cid,wid)=>{
  expect(()=>assertM10MetadataApprovalScope(state,cid,wid)).toThrow('EXACT_BOUND_METADATA_SCOPE_REQUIRED');
 });
 it('cannot substitute a single cluster alias or malformed handoff',()=>{
  expect(()=>assertM10MetadataApprovalScope({...state,targetCid:state.cid},state.cid,state.wid)).toThrow('REAL_INDEPENDENT_CLUSTER_HANDOFF_REQUIRED');
  expect(()=>assertM10MetadataApprovalScope({...state,targetWid:undefined},state.cid,state.wid)).toThrow('REAL_TWO_SCOPE_METADATA_HANDOFF_REQUIRED');
 });
});
