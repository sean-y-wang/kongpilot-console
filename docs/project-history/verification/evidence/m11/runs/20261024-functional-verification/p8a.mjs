import {login,op,save,api} from './h.mjs'; import fs from 'node:fs';
const {A,wid}=JSON.parse(fs.readFileSync('ctx.json'));const c2=JSON.parse(fs.readFileSync('ctx2.json'));
const s=await login(),ap=await login(c2.apprUser,c2.pass);const ent=d=>d?.entity??d;const sleep=t=>new Promise(r=>setTimeout(r,t));
const cl=ent((await api(s,`/api/v1/clusters/${A}`)).data);
async function approveWf(wfId,label){
  let W=ent((await api(s,`/api/v1/clusters/${A}/workflows/${wfId}?workspaceId=${wid}`)).data);
  if(!process.env.SKIPAPPROVE)await op('vitals',label+': approver approves',()=>api(ap,`/api/v1/clusters/${A}/workflows/${wfId}/approve?workspaceId=${wid}`,'POST',{revision:W.revision,planHash:W.planHash,confirmed:true,confirm_name:W.kind,reason:'fv',...(W.approval?.format===2?(()=>{const st=W.approval.stages.find(x=>x.state==='active');return{level:st.level,stageRevision:st.revision,candidateVersion:W.approval.candidateVersion};})():{})}));
  W=ent((await api(s,`/api/v1/clusters/${A}/workflows/${wfId}?workspaceId=${wid}`)).data);
  if(W?.state==='approved')await op('vitals',label+': requester executes',()=>api(s,`/api/v1/clusters/${A}/workflows/${wfId}/execute?workspaceId=${wid}`,'POST',{revision:W.revision,planHash:W.planHash,confirmed:true,confirm_name:W.kind}));
  for(let i=0;i<60;i++){W=ent((await api(s,`/api/v1/clusters/${A}/workflows/${wfId}?workspaceId=${wid}`)).data);if(['succeeded','failed','cancelled','rejected','completed','partially_failed'].includes(W?.state))break;await sleep(1000);}
  await op('vitals',label+': workflow terminal state',async()=>({ok:['succeeded','completed'].includes(W?.state),status:200,code:W?.state,msg:JSON.stringify(W?.lastError||W?.error||'').slice(0,200)}));return W;}
let sid=process.env.SID;
if(process.env.WF){await approveWf(process.env.WF,'data source create');const list=ent((await api(s,`/api/v1/clusters/${A}/data-sources`)).data);sid=(list?.items||list||[]).find?.(x=>x.base_url==='http://127.0.0.1:39090')?.id;}
if(!sid){
 const p=await op('vitals','data source create: control-change prepare',()=>api(s,`/api/v1/clusters/${A}/control-changes/prepare`,'POST',{resource:'data-sources',operation:'create',input:{name:'fv-prom-a',type:'prometheus',base_url:'http://127.0.0.1:39090',enabled:true}}));
 const P=ent(p.data);console.log(JSON.stringify(P).slice(0,400));
 const sb=await op('vitals','data source create: submit',()=>api(s,`/api/v1/clusters/${A}/control-changes/${P.intentId||P.id}/submit`,'POST',{confirmed:true,materialHmac:P.materialHmac}));
 const S=ent(sb.data);console.log(JSON.stringify(S).slice(0,400));
 await approveWf(S.workflowId,'data source create');
 const list=ent((await api(s,`/api/v1/clusters/${A}/data-sources`)).data);sid=(list?.items||list||[]).find?.(x=>x.base_url==='http://127.0.0.1:39090')?.id;
}
console.log('sid',sid);if(!sid){save('p8a.json');process.exit(1);}
await op('vitals','probe data source',()=>api(s,`/api/v1/clusters/${A}/data-sources/${sid}/probe`,'POST',{}));
const pr=await op('vitals','setup prepare (native_prometheus)',()=>api(s,`/api/v1/clusters/${A}/vitals/setup/prepare?workspaceId=${wid}`,'POST',{sourceId:sid,mode:'native_prometheus',confirmed:true,confirm_name:cl?.name}));
const I=ent(pr.data);console.log(JSON.stringify(I).slice(0,500));
const sb=await op('vitals','setup submit',()=>api(s,`/api/v1/clusters/${A}/vitals/setup/intents/${I?.id||I?.intentId}/submit?workspaceId=${wid}`,'POST',{revision:I?.revision,materialHmac:I?.materialHmac,confirmed:true,confirm_name:cl?.name}));
const S2=ent(sb.data);console.log(JSON.stringify(S2).slice(0,500));
if(S2?.workflowId)await approveWf(S2.workflowId,'vitals setup');
fs.writeFileSync('p8a-state.json',JSON.stringify({sid,intent:I?.id||I?.intentId},null,1));
save('p8a.json');
