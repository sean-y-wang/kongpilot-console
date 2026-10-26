import { readFileSync, writeFileSync } from 'node:fs'; import { randomBytes } from 'node:crypto';
const env = Object.fromEntries(readFileSync('${PRIVATE}/rc1.env','utf8').split('\n').filter(l=>l.includes('=')).map(l=>[l.slice(0,l.indexOf('=')),l.slice(l.indexOf('=')+1)]));
const base='https://127.0.0.1:48443'; const s={};
async function req(m,p,b,k){const r=await fetch(base+p,{method:m,headers:{Accept:'application/json',Origin:base,'Content-Type':'application/json',...(s.cookie?{Cookie:s.cookie}:{}),...(s.csrf?{'X-CSRF-Token':s.csrf}:{}),...(k?{'X-Idempotency-Key':k}:{})},body:b?JSON.stringify(b):undefined});const set=r.headers.getSetCookie();if(set.length)s.cookie=[...(s.cookie?s.cookie.split('; '):[]).filter(c=>!set.some(x=>x.split('=')[0]===c.split('=')[0])),...set.map(x=>x.split(';')[0])].join('; ');let j=null;try{j=await r.json()}catch{} if(j?.data?.csrfToken)s.csrf=j.data.csrfToken;return {status:r.status,j};}
await req('POST','/api/v1/auth/login',{username:env.BOOTSTRAP_ADMIN_USERNAME,password:env.BOOTSTRAP_ADMIN_PASSWORD});
const roles=(await req('GET','/api/v1/iam/roles?size=50')).j.data; const items=roles.items||roles; console.log('roles',items.map(r=>r.code).join(','));
const cid=((await req('GET','/api/v1/clusters')).j.data.items||[])[0]?.id ?? (await req('GET','/api/v1/clusters')).j.data[0].id;
let ws=(await req('GET',`/api/v1/clusters/${cid}/workspaces`)).j.data; ws=ws.items||ws; console.log('ws',ws.map(w=>w.name).join(','));
const sfx=randomBytes(3).toString('hex'); const out={clusterId:cid,workspaceId:ws[0].id};
const o=await req('POST',`/api/v1/clusters/${cid}/workspaces`,{name:`rc1-other-${sfx}`,code:`rc1o${sfx}`},`ws-${sfx}`); console.log('ws create',o.status,o.j?.error?.code); out.otherWorkspaceId=o.j?.data?.id??o.j?.data?.workspace?.id;
for (const [who,code] of [['appr',process.argv[2]],['ro',process.argv[3]]]){const pw='Rc1!'+randomBytes(12).toString('base64url');const u=await req('POST','/api/v1/iam/users',{username:`rc1-${sfx}-${who}`,display_name:`rc1 ${who}`,password:pw},`u-${sfx}-${who}`);const uid=u.j?.data?.id;const role=items.find(r=>r.code===code);const b=await req('POST',`/api/v1/iam/users/${uid}/role-bindings`,{role_id:role?.id,cluster_id:cid,workspace_id:out.workspaceId},`b-${sfx}-${who}`);console.log(who,u.status,b.status,b.j?.error?.code);out[who+'User']=`rc1-${sfx}-${who}`;out[who+'Pass']=pw;}
out.adminUser=env.BOOTSTRAP_ADMIN_USERNAME;out.adminPass=env.BOOTSTRAP_ADMIN_PASSWORD;
writeFileSync((process.env.KP_LAB_SECRETS||'./secrets.json'),JSON.stringify(out,null,1),{mode:0o600});
