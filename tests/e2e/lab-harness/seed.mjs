import { readFileSync, writeFileSync } from 'node:fs'; import { randomBytes } from 'node:crypto';
import { login } from './c.mjs';
const env=Object.fromEntries(readFileSync('${PRIVATE}/rc1-e2e.env','utf8').split('\n').filter(l=>l.includes('=')).map(l=>[l.slice(0,l.indexOf('=')),l.slice(l.indexOf('=')+1)]));
const O='https://127.0.0.1:48443';globalThis.__S={consoleOrigin:O};
const S={consoleOrigin:O,portalOrigin:'https://127.0.0.1:49443',kongAdmin:'http://127.0.0.1:38101',adminUser:env.BOOTSTRAP_ADMIN_USERNAME,adminPass:env.BOOTSTRAP_ADMIN_PASSWORD};
writeFileSync((process.env.KP_LAB_SECRETS||'./secrets.json'),JSON.stringify(S),{mode:0o600});
const a=await login(S.adminUser,S.adminPass);const log=(k,r)=>{console.log(k,r.status,r.code??'',r.msg??'');if(r.status>=300)throw Error(k)};
const items=r=>r.data?.items??r.data;const sfx=randomBytes(3).toString('hex');
const roles=items(await a('GET','/api/v1/iam/roles?size=50'));const role=c=>roles.find(r=>r.code===c).id;
const cA=items(await a('GET','/api/v1/clusters'))[0];S.clusterId=cA.id;S.workspaceId=items(await a('GET',`/api/v1/clusters/${cA.id}/workspaces`))[0].id;
let r=await a('POST',`/api/v1/clusters/${cA.id}/workspaces`,{name:`rc1-other-${sfx}`,code:`rc1o${sfx}`});log('wsOther',r);S.otherWorkspaceId=r.data.id??r.data.workspace?.id;
// cluster B
r=await a('POST','/api/v1/clusters',{name:`rc1-kong-b`,environment:'staging',admin_url:"http://kong-b:8001",proxy_origin:`http://127.0.0.1:${env.KONG_B_PROXY_PORT}`,labels:['e2e'],execution_mode:'direct'});log('clusterB',r);
const cB=r.data.entity??r.data;S.clusterB=cB.id;S.clusterBLabel=`${cB.name} · ${cB.environment}`;S.kongProxyB=`http://127.0.0.1:${env.KONG_B_PROXY_PORT}`;
log('probeB',await a('POST',`/api/v1/clusters/${cB.id}/probe`,{}));
S.workspaceB=items(await a('GET',`/api/v1/clusters/${cB.id}/workspaces`))[0].id;
// users (global approver + global read-only auditor), seeded while every cluster is direct
for(const [who,code] of [['appr','approver'],['ro','read-only']]){const pw='Rc1!'+randomBytes(12).toString('base64url');const u=await a('POST','/api/v1/iam/users',{username:`rc1-${sfx}-${who}`,display_name:`rc1 ${who}`,password:pw});log('user-'+who,u);
 log('bind-'+who,await a('POST',`/api/v1/iam/users/${u.data.id}/role-bindings`,(who==='ro'?{role_id:role(code),cluster_id:cA.id,workspace_id:S.workspaceId}:{role_id:role(code)})));S[who+'User']=`rc1-${sfx}-${who}`;S[who+'Pass']=pw;S[who+'UserId']=u.data.id;}
// global user-directory auditor role (users:read global only) for the workspace-scoped ro user
{const cr=await a('POST','/api/v1/iam/roles',{code:`rc1-${sfx}-dir-auditor`,name:`rc1 directory auditor ${sfx}`,description:'E2E: global users:read only'});log('dirRole',cr);
 const pr=await a('PUT',`/api/v1/iam/roles/${cr.data.id}/permissions`,{revision:cr.data.revision,permissions:[{module:'users',action:'read',scope_type:'global',scope_values:[]}]});log('dirPerms',pr);
 log('bind-ro-dir',await a('POST',`/api/v1/iam/users/${S.roUserId}/role-bindings`,{role_id:cr.data.id}));}
// KP-004 fixture
const qa=`/api/v1/clusters/${cA.id}/entities`,wq=`workspaceId=${S.workspaceId}`;const n='rc1e2e-'+sfx;
r=await a('POST',`${qa}/services?${wq}`,{name:n,host:'203.0.113.10',port:80});log('kp004svc',r);
log('kp004rt',await a('POST',`${qa}/routes?${wq}`,{name:n+'-rt',paths:['/'+n],service:{id:(r.data.entity??r.data).id}}));S.kp004Service=n;
// legacy-origin recycle entry: a direct-mode delete (mutation writer) archives with mutation_id set
const ln='rc1legacy-'+sfx;r=await a('POST',`${qa}/services?${wq}`,{name:ln,host:'203.0.113.11',port:80});log('legacySvc',r);
log('legacyDelete',await a('DELETE',`${qa}/services/${(r.data.entity??r.data).id}?${wq}`,{confirmed:true,confirm_name:ln}));
const rb=items(await a('GET',`/api/v1/clusters/${cA.id}/recycle-bin?size=50&${wq}`));const le=rb.find(e=>(e.root_name??e.rootName??e.name)===ln);console.log('legacyEntry',!!le,Object.keys(le||{}).join(','));S.legacyEntryId=le?.id;S.legacyEntryName=ln;
// portal on cluster B
const qb=`/api/v1/clusters/${cB.id}`,wb=`workspaceId=${S.workspaceB}`;const path=`/m11/rc1${sfx}/portal`;
r=await a('POST',`${qb}/entities/services?${wb}`,{name:`rc1p-${sfx}-svc`,host:'e2e-echo',port:5678,protocol:'http'});log('pSvc',r);const ps=r.data.entity??r.data;
log('pRt',await a('POST',`${qb}/entities/routes?${wb}`,{name:`rc1p-${sfx}-rt`,paths:[path],protocols:['http'],service:{id:ps.id}}));
log('pSettings',await a('POST',`${qb}/portal/settings?${wb}`,{slug:`rc1p-${sfx}`,name:`rc1 Portal`,published:true,registrationEnabled:true,publicProxyOrigin:S.kongProxyB}));
r=await a('POST',`${qb}/portal/publications?${wb}`,{slug:`rc1p-${sfx}-api`,name:`rc1p${sfx} Evidence API`,category:'证据',serviceId:ps.id,document:{openapi:'3.0.3',info:{title:'Evidence API',version:'1.0.0'},paths:{[path]:{get:{responses:{200:{description:'Success'}}}}}}});log('pPub',r);
const pub=r.data.entity??r.data;const got=(await a('GET',`${qb}/portal/publications/${pub.id}?${wb}`)).data;const g=got.entity??got;
/* publish deferred to publish-approval.mjs (after approval-mode switch) so the proof binds the final cluster revision */
S.portalPublicationName=g.name;S.portalProxyPath=path;
writeFileSync((process.env.KP_LAB_SECRETS||'./secrets.json'),JSON.stringify(S,null,1),{mode:0o600});console.log('seeded');
