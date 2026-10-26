import {login,op,save,api} from './h.mjs'; import fs from 'node:fs';
const ctx=JSON.parse(fs.readFileSync('ctx.json'));const {A,wid}=ctx;const c2=JSON.parse(fs.readFileSync('ctx2.json'));
const s=await login(),ap=await login(c2.apprUser,c2.pass);const ent=d=>d?.entity??d;
const qa=(p)=>`/api/v1/clusters/${A}/${p}${p.includes('?')?'&':'?'}workspaceId=${wid}`;const N='/api/v1/notifications';
const sq=`clusterId=${A}&workspaceId=${wid}`;
const reset=await api(ap,`${N}/approval-settings?${sq}`);let rev=ent(reset.data)?.revision??0;
if(ent(reset.data)?.approvalRequestsEnabled===false){const r=await api(ap,`${N}/approval-settings`,'PUT',{clusterId:A,workspaceId:wid,approvalRequestsEnabled:true,revision:rev});rev=ent(r.data).revision;}
await op('approver-notif','approver setting default/explicit on',()=>api(ap,`${N}/approval-settings?${sq}`),{expect:r=>r.status===200&&ent(r.data).approvalRequestsEnabled===true});
await op('approver-notif','setting read rejects bad scope',()=>api(ap,`${N}/approval-settings?clusterId=x`),{expect:r=>r.status===400});
async function submit(w){const p=ent((await op('approver-notif',`admin prepares weight=${w}`,()=>api(s,qa('entity-changes/prepare'),'POST',{change:{kind:'target',action:'weight',upstreamId:ctx.U,targetId:ctx.tg[3],body:{weight:w}}}))).data);
 const sub=await op('approver-notif',`admin submits weight=${w}`,()=>api(s,qa(`entity-changes/${p?.id}/submit`),'POST',{revision:p?.revision,materialHmac:p?.materialHmac,confirmed:true,confirm_name:'native-change'}));return sub.data?.workflowId;}
async function find(u,wf,secs){for(let i=0;i<secs;i++){const l=(await api(u,`${N}?size=50`)).data;const g=(l?.items||[]).find(n=>n.link?.kind==='workflow'&&n.link?.id===wf);if(g)return g;await new Promise(r=>setTimeout(r,1000));}return null;}
const me=(await api(s,'/api/v1/auth/me')).data;const uname=(me?.user??me)?.username;
const wf1=await submit(47);let n1=null;
await op('approver-notif','approver auto-notified (no subscription needed), workflow link',async()=>{const t0=Date.now();n1=await find(ap,wf1,60);return {ok:!!n1&&n1.title.startsWith('待审批：')&&n1.title.includes('网关实体变更')&&n1.title.includes('集群 ')&&n1.title.includes(`发起人 ${uname}`),status:n1?200:404,msg:n1?`${n1.title} | ${n1.summary} | ${Date.now()-t0}ms`:'none'};});
await op('approver-notif','notification detail + link navigable (workflow readable by approver)',async()=>{const d=await api(ap,`${N}/${n1?.id}`);const w=await api(ap,qa(`workflows/${wf1}`));return {ok:d.status===200&&ent(d.data).link?.id===wf1&&w.status===200,status:d.status};});
await op('approver-notif','requester gets no approval-request notification',async()=>{const g=await find(s,wf1,3);return {ok:!g,status:g?409:200};});
await op('approver-notif','opt-out with stale revision -> 409',()=>api(ap,`${N}/approval-settings`,'PUT',{clusterId:A,workspaceId:wid,approvalRequestsEnabled:false,revision:rev+5}),{expect:r=>r.status===409});
const off=await op('approver-notif','approver opts out',()=>api(ap,`${N}/approval-settings`,'PUT',{clusterId:A,workspaceId:wid,approvalRequestsEnabled:false,revision:rev}),{expect:r=>r.status<300&&ent(r.data).approvalRequestsEnabled===false&&ent(r.data).explicit===true});
const wf2=await submit(48);
await op('approver-notif','opted-out approver gets no workflow notification',async()=>{const g=await find(ap,wf2,25);return {ok:!g,status:g?409:200};});
await op('approver-notif','opt back in',()=>api(ap,`${N}/approval-settings`,'PUT',{clusterId:A,workspaceId:wid,approvalRequestsEnabled:true,revision:ent(off.data).revision}),{expect:r=>r.status<300&&ent(r.data).approvalRequestsEnabled===true});
await op('approver-notif','audit has the setting change',async()=>{const r=await api(s,`/api/v1/clusters/${A}/audit?workspaceId=${wid}&action=notifications.personal.approval-settings.save&size=5`);return {ok:r.status===200&&JSON.stringify(r.data).includes('approval-settings.save'),status:r.status};});
for(const wf of [wf1,wf2]){const w=ent((await api(s,qa(`workflows/${wf}`))).data);if(!w)continue;const st=(w.approval?.stages||[]).find(x=>x.state==='active');
 await op('approver-notif',`cleanup: reject ${wf.slice(0,8)}`,()=>api(ap,qa(`workflows/${wf}/reject`),'POST',{revision:w.revision,planHash:w.planHash,confirmed:true,confirm_name:w.kind,reason:'fv p11 cleanup',level:st?.level,stageRevision:st?.revision,candidateVersion:w.approval?.candidateVersion}));}
save('p11-approver-notif.json');
