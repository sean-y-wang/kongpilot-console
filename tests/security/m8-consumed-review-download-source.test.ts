// @ts-nocheck -- exact synthetic bytes stand in for pinned historical hashes.
import{beforeEach,describe,it,expect,vi}from'vitest';
const seals=vi.hoisted(()=>new Map());
vi.mock('./lib/m8-harness.mjs',async actual=>{const m=await actual();return{...m,sha256:b=>seals.get(typeof b==='string'?b:b.toString())??m.sha256(b)};});
import{M8_CONSUMED_REVIEW_DOWNLOAD as c,isM8ProvenConsumedUnknownDownload}from'./lib/m8-consumed-review-download.mjs';
beforeEach(()=>seals.clear());
function fixture(){
 const p={state:'response_unknown',key:c.key,actorId:c.actorId,sessionId:c.sid,clusterId:c.cid,workspaceId:c.wid,path:`/api/v1/clusters/${c.cid}/configuration/exports/${c.exportId}/download`,method:'POST',query:`?workspaceId=${c.wid}`};
 const requests=Array.from({length:181},(_,index)=>index===180?p:{index,state:'response_observed',status:201});
 seals.set(JSON.stringify(p),c.packetSha256);seals.set(JSON.stringify(requests),c.prefixSha256);
 const q={id:c.jobId,kind:'export',state:'succeeded',actor_matches:true,sid_matches:true,scope_matches:true,original_request_matches:true,export_matches:true,consumed:true,delivery_unconfirmed:true,grant_owner_matches:true,byte_count:c.bytes,grant_id:c.grantId,grant_state:'consumed'};
 const r={requests,consumedReviewDownloadRecovery:{state:'server-consumed-client-unconfirmed',originalPacketSha256:c.packetSha256,clientDeliveryProven:false,originalRequestReplayed:false,serverOriginalRequestId:c.serverRequestId,serverProof:{role:{name:'kongos_app',rolsuper:false,rolbypassrls:false},rows:[q]}}};return{r,p,q,m:r.consumedReviewDownloadRecovery};
}
describe('M8 one fixed consumed download retains client uncertainty',()=>{
 it('proves only server commit and never replaces the original unknown HTTP packet',()=>{const f=fixture(),old=JSON.stringify(f.p);expect(isM8ProvenConsumedUnknownDownload(f.r,f.p,180)).toBe(true);expect(JSON.stringify(f.p)).toBe(old);expect(f.p.state).toBe('response_unknown');expect(f.p.status).toBeUndefined();});
 it.each(['actor_matches','sid_matches','scope_matches','original_request_matches','export_matches','consumed','delivery_unconfirmed','grant_owner_matches'])('requires actual server %s',field=>{const f=fixture();f.q[field]=false;expect(isM8ProvenConsumedUnknownDownload(f.r,f.p,180)).toBe(false);});
 it.each(['job','bytes','grant','superuser','delivery-claim','replay','second-row','changed-original','packet-copy'])('refuses broadened recovery %s',kind=>{const f=fixture();if(kind==='job')f.q.id='foreign';if(kind==='bytes')f.q.byte_count++;if(kind==='grant')f.q.grant_state='ready';if(kind==='superuser')f.m.serverProof.role.rolsuper=true;if(kind==='delivery-claim')f.m.clientDeliveryProven=true;if(kind==='replay')f.m.originalRequestReplayed=true;if(kind==='second-row')f.m.serverProof.rows.push({...f.q});if(kind==='changed-original')f.r.requests[0].status=400;expect(isM8ProvenConsumedUnknownDownload(f.r,kind==='packet-copy'?{...f.p}:f.p,180)).toBe(false);});
});
