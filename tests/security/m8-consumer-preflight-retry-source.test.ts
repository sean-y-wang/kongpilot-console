// @ts-nocheck -- actual diagnostic predicate with synthetic safe metadata only.
import { describe,it,expect } from 'vitest';
import { M8_CONSUMER_RETRY as c,assertM8ConsumerZeroLedger,assertM8ConsumerProtectedPreview } from './lib/m8-consumer-preflight-retry.mjs';
import { randomUUID } from 'node:crypto';
function fixture(){
  const credentials=Object.fromEntries(['key-auth','basic-auth','jwt','oauth2','hmac-auth','acls'].map(kind=>[kind,{id:randomUUID()}]));
  const proof={ok:true,nonOwnerReadOnly:true,entry:{id:c.entryId,cluster_id:c.cid,workspace_id:c.wid,root_type:'consumers',original_id:c.consumerId,state:'deleted',node_count:7,owner_matches:true},
    nodes:[{entity_type:'consumers',original_id:c.consumerId},...Object.entries(credentials).map(([kind,row])=>({entity_type:kind,original_id:row.id}))].map(n=>({...n,affected:true,delete_state:'deleted',restore_state:'pending',restored_id:null})),operations:[],audits:[]};
  return {proof,native:{credentials}};
}
describe('exact original preflight-only Consumer retry evidence',()=>{
 it('uses public typed identities in protected previews whose internal node key is intentionally redacted',()=>{
  const{proof}=fixture(),preview={entry:proof.entry,graph:{rootKey:`consumers:${c.consumerId}`,nodes:proof.nodes.map(n=>({type:n.entity_type,id:n.original_id,affected:true,key:'[REDACTED:0000000000000000]'}))},nodes:proof.nodes};
  expect(()=>assertM8ConsumerProtectedPreview(preview)).not.toThrow();
  preview.graph.nodes[0].id=randomUUID();expect(()=>assertM8ConsumerProtectedPreview(preview)).toThrow();
 });
 it('accepts only zero original ledger/audit with all seven original nodes still untouched',()=>{const{proof,native}=fixture();expect(()=>assertM8ConsumerZeroLedger(proof,native)).not.toThrow();});
 for(const [name,mutate]of [
  ['existing original operation',p=>p.operations.push({state:'failed',remote_started:false})],
  ['existing original request audit',p=>p.audits.push({result:'failed'})],
  ['uncertain node',p=>p.nodes[0].restore_state='uncertain'],
  ['partial restored node',p=>p.nodes[1].restore_state='restored'],
  ['restored physical identity',p=>p.nodes[1].restored_id=p.nodes[1].original_id],
  ['foreign scope',p=>p.entry.workspace_id=randomUUID()],
  ['foreign principal',p=>p.entry.owner_matches=false],
  ['wrong typed root',p=>p.entry.root_type='services'],
  ['missing typed credential',p=>p.nodes.pop()],
  ['duplicate typed credential',p=>p.nodes[1]={...p.nodes[2]}],
  ['same credential UUID wrong kind',p=>p.nodes[1].entity_type='plugins'],
  ['shared credential node',p=>p.nodes[1].affected=false],
  ['owner or writable DB proof',p=>p.nonOwnerReadOnly=false],
  ['archive state advanced',p=>p.entry.state='restoring'],
 ] as const)it(`rejects ${name} before any retry`,()=>{const{proof,native}=fixture();mutate(proof);expect(()=>assertM8ConsumerZeroLedger(proof,native)).toThrow();});
});
