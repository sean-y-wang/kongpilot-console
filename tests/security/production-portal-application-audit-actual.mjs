import { randomUUID } from 'node:crypto';
import { existsSync } from 'node:fs';
import { ProductionHarness, productionDigest } from './lib/production-http-harness.mjs';
import { cookieMerge } from './lib/m8-harness.mjs';
import { durableProductionJson } from './lib/production-ui-storage.mjs';

const out='artifacts/Production/root-production-portal-application-four-terminal-audits-actual.json';
if(existsSync(out)||process.env.PRODUCTION_PORTAL_AUDIT_EXCLUSIVE_READY!=='true')throw Error('PRODUCTION_PORTAL_AUDIT_HANDOFF_REQUIRED');
const h=new ProductionHarness({resume:true}),area=h.state.scope,actor=h.state.sessions.bootstrap;await h.refresh(actor);
const old=h.state.portalChecks.at(-1),session={cookie:old.headers.Cookie,csrf:old.headers['X-Portal-CSRF']};
const tenant={clusterId:area.cid,workspaceId:area.wid},developerId=h.state.productionPortalFixture.developerId;
h.state.portalAuditChecks??=[];
const send=async(path,method,body)=>{
 if(h.state.portalAuditChecks.some(p=>p.state!=='response_observed'))throw Error('PORTAL_AUDIT_UNKNOWN_NO_REPLAY');
 const p={key:randomUUID(),path,method,body,bodySha256:productionDigest(body),state:'prepared',actorId:developerId};
 h.state.portalAuditChecks.push(p);h.save();let r,payload;
 try{r=await fetch('https://127.0.0.1:19443/api/v1/portal'+path,{method,headers:{Cookie:session.cookie,Origin:'https://127.0.0.1:19443','Content-Type':'application/json','X-Portal-CSRF':session.csrf,'X-Idempotency-Key':p.key},body:JSON.stringify(body),redirect:'manual',signal:AbortSignal.timeout(45000)});payload=await r.json();}
 catch{p.state='response_unknown';h.save();throw Error('PORTAL_AUDIT_UNKNOWN_NO_REPLAY');}
 Object.assign(p,{state:'response_observed',status:r.status,requestId:payload.meta?.requestId,responseData:payload.data??null});
 session.cookie=cookieMerge(session.cookie,r.headers.getSetCookie());session.csrf=payload.data?.csrfToken??session.csrf;
 for(const x of session.cookie.split('; '))h.state.secrets.push(x.slice(x.indexOf('=')+1));h.remember(payload.data,true);h.save();
 if(![200,201].includes(r.status))throw Error('PORTAL_AUDIT_ACTUAL_RESPONSE_NOT_SUCCESS');return payload.data;
};
await send('/auth/refresh','POST',tenant);
let entity=(await send('/applications','POST',{...tenant,name:h.state.testTag+' audited application'})).entity;
entity=(await send('/applications/'+entity.id,'PATCH',{...tenant,name:entity.name,description:'实际事务内审计验证',revision:entity.revision})).entity;
entity=(await send('/applications/'+entity.id,'DELETE',{...tenant,revision:entity.revision,confirmed:true,confirm_name:entity.name})).entity;
entity=(await send('/applications/'+entity.id+'/restore','POST',{...tenant,revision:entity.revision,confirmed:true,confirm_name:entity.name})).entity;
const rows=[];
for(const p of h.state.portalAuditChecks.filter(p=>!p.path.startsWith('/auth/'))){
 const view=(await h.request(actor,`/api/v1/clusters/${area.cid}/audit?${new URLSearchParams({scope:'cluster',requestId:p.requestId,result:'success',size:'100'})}`)).data;
 const matched=view.items.filter(r=>r.actorType==='developer'&&r.actorId===null&&r.entityType==='portal_applications'&&r.entityId===entity.id&&r.after?.developerId===developerId&&r.scopeQuality==='verified'&&r.sourceIp&&Array.isArray(r.jsonPatch));
 if(matched.length!==1||view.nextCursor!==null)throw Error('PORTAL_ACTUAL_TRANSACTION_TERMINAL_AUDIT_REQUIRED');
 rows.push({method:p.method,path:p.path,requestId:p.requestId,auditId:matched[0].id,action:matched[0].action,developerIdentityInImmutableBody:true,actualBeforeAfterDiff:true});
}
if(rows.length!==4)throw Error('PORTAL_ALL_FOUR_LIFECYCLE_AUDITS_REQUIRED');
h.state.productionPortalApplicationAuditComplete=true;h.save();durableProductionJson(out,{performedAt:new Date().toISOString(),allPassed:true,rows,actualTerminalAudits:4,historicalOldGapPreserved:true,originalBusinessRequestsReplayed:false},true,0o644);
console.log(JSON.stringify({allPassed:true,actualTerminalAudits:4,historicalAuditRewritten:false}));
