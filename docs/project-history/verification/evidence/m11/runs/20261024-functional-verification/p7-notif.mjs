import {login,op,save,api} from './h.mjs'; import fs from 'node:fs';
const ctx=JSON.parse(fs.readFileSync('ctx.json'));const {A,wid}=ctx;const c2=JSON.parse(fs.readFileSync('ctx2.json'));
const s=await login(),ap=await login(c2.apprUser,c2.pass);const ent=d=>d?.entity??d;
const qa=(p)=>`/api/v1/clusters/${A}/${p}${p.includes('?')?'&':'?'}workspaceId=${wid}`;
await op('notifications','approver subscribes to workflow.submitted (in-app)',()=>api(ap,'/api/v1/notifications/preferences','POST',{clusterId:A,workspaceId:wid,name:'fv-approvals',eventTypes:['workflow.submitted','workflow.approved','workflow.rejected'],inAppEnabled:true}),{expect:r=>r.status===201||(r.status===409&&r.code==='NOTIFICATION_PREFERENCE_NAME_EXISTS')});
const before=(await api(ap,'/api/v1/notifications/unread-count')).data;
const p=ent((await op('notifications','admin prepares change',()=>api(s,qa('entity-changes/prepare'),'POST',{change:{kind:'target',action:'weight',upstreamId:ctx.U,targetId:ctx.tg[3],body:{weight:43}}}))).data);
const tSubmit=Date.now()-2000;const sub=await op('notifications','admin submits -> pending workflow',()=>api(s,qa(`entity-changes/${p?.id}/submit`),'POST',{revision:p?.revision,materialHmac:p?.materialHmac,confirmed:true,confirm_name:'native-change'}));
let got=null,t0=Date.now();for(let i=0;i<60;i++){const l=(await api(ap,'/api/v1/notifications?size=20')).data;got=(l?.items||[]).find(n=>n.link?.kind==='event'&&Date.parse(n.createdAt||n.created_at||0)>=tSubmit);if(got)break;await new Promise(r=>setTimeout(r,1000));}
await op('notifications','approver receives workflow.submitted notification',async()=>({ok:!!got,status:200,code:got?`type=${got.eventType||got.type} after ${Date.now()-t0}ms`:'none in 60s'}));
const after=(await api(ap,'/api/v1/notifications/unread-count')).data;
await op('notifications','unread-count increased',async()=>({ok:JSON.stringify(after)!==JSON.stringify(before),status:200,code:JSON.stringify(before)+'->'+JSON.stringify(after)}));
if(got){await op('notifications','mark read',()=>api(ap,`/api/v1/notifications/${got.id}/read`,'POST',{revision:got.revision}));}
const wf=ent((await api(s,qa(`workflows/${sub.data?.workflowId}`))).data);
const wfa=ent((await api(ap,qa(`workflows/${sub.data?.workflowId}`))).data);const stg=wfa?.approval?.stages?.find(x=>x.state==='active');
await op('notifications','cleanup: approver rejects workflow',()=>api(ap,qa(`workflows/${wfa?.id}/reject`),'POST',{revision:wfa?.revision,planHash:wfa?.planHash,confirmed:true,confirm_name:wfa?.kind,reason:'fv cleanup',...(stg?{level:stg.level,stageRevision:stg.revision,candidateVersion:wfa.approval.candidateVersion}:{})}));
save('p7-notif.json');
