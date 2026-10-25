// @ts-nocheck: real ESM helper, synthetic RAM replies only.
import { describe,expect,it,vi } from 'vitest';
import { randomUUID } from 'node:crypto';
import {m8AllWritesAuditAcceptance,m8AuditPatchMatches} from './lib/m8-audit-acceptance.mjs';
const check=(v,n)=>{if(!v)throw Error(n);};
function fixture(){
 const cid=randomUUID(),wid=randomUUID(),actor=randomUUID(),requestId=randomUUID();
 const packet={index:0,method:'PATCH',path:`/api/v1/clusters/${cid}/entities/services/${randomUUID()}`,clusterId:cid,workspaceId:wid,actorId:actor,requestId,state:'response_observed',status:200};
 const view={id:randomUUID(),requestId,actorId:actor,clusterId:cid,workspaceId:wid,result:'success',scopeQuality:'verified',before:{retries:0},after:{retries:1},jsonPatch:[{op:'replace',path:'/retries',value:1}]};
 const h={check,state:{requests:[packet],scopes:{direct:{cid,wid}},fixtures:[],inFlight:null},save:vi.fn(),data:r=>r.payload.data,request:vi.fn(async(_a,path)=>({payload:{data:{items:path.includes(`/clusters/${cid}/audit`)?[view]:[],total:null,nextCursor:null}}}))};
 return{h,packet,view,actors:{admin:{user:{id:actor}}}};
}
describe('M8 passive actual audit closure contract',()=>{
 it('requires independent complete before/after patch rather than matching counts',()=>{
  const{view}=fixture();expect(m8AuditPatchMatches(view)).toBe(true);
  for(const changed of [{after:{retries:2}},{jsonPatch:[]},{jsonPatch:[{op:'replace',path:'/missing',value:1}]}])expect(m8AuditPatchMatches({...view,...changed})).toBe(false);
 });
 it('unknown, prepared and unconfirmed UI records cause zero reads',async()=>{
  for(const changed of [{state:'prepared'},{state:'response_unknown'},{state:'succeeded',status:200},{state:'response_observed',status:null}]){
   const{h,packet,actors}=fixture();Object.assign(packet,changed);await expect(m8AllWritesAuditAcceptance(h,actors)).rejects.toThrow('refuses');expect(h.request).not.toHaveBeenCalled();
  }
 });
 it('matches actual exact request actor CID WID with complete RFC6902',async()=>{
  const{h,actors}=fixture();expect(await m8AllWritesAuditAcceptance(h,actors)).toMatchObject({successfulWrites:1,requestMatchedWrites:1,coveredWrites:1,allCovered:true,legacyMissingRequestMetadata:0});expect(h.request.mock.calls.every(c=>c[2]===undefined||c[2]==='GET')).toBe(true);
 });
 it('foreign actor, WID, CID or request cannot close the original write',async()=>{
  for(const changed of [{actorId:randomUUID()},{workspaceId:randomUUID()},{clusterId:randomUUID()},{requestId:randomUUID()}]){
   const{h,view,actors}=fixture();Object.assign(view,changed);await expect(m8AllWritesAuditAcceptance(h,actors)).rejects.toThrow();
  }
 });
 it('matching request but false transition and private chain exposure cannot pass',async()=>{
  for(const changed of [{after:{retries:2}},{eventHash:'private-proof'},{scopeQuality:'legacy_unknown'}]){
   const{h,view,actors}=fixture();Object.assign(view,changed);await expect(m8AllWritesAuditAcceptance(h,actors)).rejects.toThrow();
  }
 });
 it('new normal same-SID auth refresh during reads is included in denominator',async()=>{
  const{h,packet,view,actors}=fixture(),refresh={...packet,index:1,path:'/api/v1/auth/refresh',clusterId:null,workspaceId:null,requestId:randomUUID()};let added=false;
  h.request=vi.fn(async(_a,path)=>{
   if(!added){h.state.requests.push(refresh);added=true;}
   const actual=new URL(path,'http://synthetic').searchParams.get('requestId'),items=actual===refresh.requestId&&path.startsWith('/audit/global')?[{...view,id:randomUUID(),clusterId:null,workspaceId:null,scopeQuality:'legacy_unknown',requestId:actual,action:'refresh'}]:actual===packet.requestId&&path.includes('/clusters/')?[view]:[];
   return{payload:{data:{items,total:null,nextCursor:null}}};
  });expect(await m8AllWritesAuditAcceptance(h,actors)).toMatchObject({successfulWrites:2,coveredWrites:2});
 });
 it('submission only requires original workflow.submit terminal without claiming execution',async()=>{
  const{h,packet,view,actors}=fixture(),workflowId=randomUUID();packet.responseData={workflowId,executionCompleted:false};view.action='workflow.submit';view.workflowId=workflowId;
  expect(await m8AllWritesAuditAcceptance(h,actors)).toMatchObject({submissionOnlyWrites:1});
  const bad=fixture();bad.packet.responseData={workflowId,executionCompleted:false};await expect(m8AllWritesAuditAcceptance(bad.h,bad.actors)).rejects.toThrow('submission');
 });
 it('repeated cursor never silently fabricates terminal EOF',async()=>{
  const{h,actors,view}=fixture();h.request=vi.fn(async()=>({payload:{data:{items:[view],total:null,nextCursor:'same'}}}));await expect(m8AllWritesAuditAcceptance(h,actors)).rejects.toThrow('cursor');expect(h.request).toHaveBeenCalledTimes(2);
 });
});
