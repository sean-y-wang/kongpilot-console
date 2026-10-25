import{describe,it,expect}from'vitest';import{createHash}from'node:crypto';
import{productionAuthNoCommitResolved}from'./lib/production-auth-transport-proof.mjs';
const hash=(v:unknown)=>createHash('sha256').update(JSON.stringify(v)).digest('hex');
function fixture(){
 const p={state:'response_unknown',method:'POST',path:'/api/v1/auth/refresh',observedStatus:null,observedRequestId:null,body:{},key:'00000000-0000-4000-8000-000000000010',actorId:'00000000-0000-4000-8000-000000000011',sessionId:'00000000-0000-4000-8000-000000000012',bodySha256:'synthetic-body-digest'};
 const proof={originalKey:p.key,originalPacketSha256:hash(p),originalPath:p.path,originalBodySha256:p.bodySha256,actorId:p.actorId,sessionId:p.sessionId,originalHeadersObserved:false,noCommitProven:true,originalRequestReplayed:false,originalRawUnknownPreserved:true,facts:{id:p.sessionId,user_id:p.actorId,active:true,refresh_hash_matches:true,csrf_hash_matches:true,refresh_unused:true,no_rotation_after_original:true,signed_original_access_verified:true,read_only_transaction:true}};
 return{p,proof};
}
describe('exact original production auth no-commit resolution',()=>{
 it('accepts only the complete signed identity and current unchanged database proof, preserving the raw unknown',()=>{const{p,proof}=fixture(),old=structuredClone(p);expect(productionAuthNoCommitResolved(p,[proof])).toBe(true);expect(p).toEqual(old);expect(p.state).toBe('response_unknown');});
 it.each(['active','refresh_hash_matches','csrf_hash_matches','refresh_unused','no_rotation_after_original','signed_original_access_verified','read_only_transaction'])('rejects missing current %s proof',(name)=>{const{p,proof}=fixture();(proof.facts as any)[name]=false;expect(productionAuthNoCommitResolved(p,[proof])).toBe(false);});
 it('never resolves Native, prepared, observed HTTP, changed packet, actor, SID or body with a stale proof',()=>{
  const{p,proof}=fixture();
  for(const change of[(v:any)=>v.path='/api/v1/clusters/x/entities/services',(v:any)=>v.state='prepared',(v:any)=>v.observedStatus=201,(v:any)=>v.observedRequestId='actual-request',(v:any)=>v.key='different-key',(v:any)=>v.actorId='different-actor',(v:any)=>v.sessionId='different-session',(v:any)=>v.body={confirmed:true}]){const v=structuredClone(p);change(v);expect(productionAuthNoCommitResolved(v,[proof])).toBe(false);}
  expect(productionAuthNoCommitResolved(p,[])).toBe(false);expect(productionAuthNoCommitResolved(p,[{...proof,originalRequestReplayed:true}])).toBe(false);
 });
});
