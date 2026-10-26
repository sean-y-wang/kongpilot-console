import { readFileSync, writeFileSync } from 'node:fs';
const S=JSON.parse(readFileSync((process.env.KP_LAB_SECRETS||'./secrets.json'),'utf8'));const base=S.consoleOrigin;const s={};
async function req(m,p,b,k){const r=await fetch(base+p,{method:m,headers:{Accept:'application/json',Origin:base,'Content-Type':'application/json',...(s.cookie?{Cookie:s.cookie}:{}),...(s.csrf?{'X-CSRF-Token':s.csrf}:{}),...(k?{'X-Idempotency-Key':k}:{})},body:b?JSON.stringify(b):undefined});const set=r.headers.getSetCookie();if(set.length)s.cookie=set.map(x=>x.split(';')[0]).join('; ');let j=null;try{j=await r.json()}catch{}if(j?.data?.csrfToken)s.csrf=j.data.csrfToken;return{status:r.status,j};}
await req('POST','/api/v1/auth/login',{username:S.adminUser,password:S.adminPass});
const n='rc1e2e-'+Date.now().toString(36);const q=`/api/v1/clusters/${S.clusterId}/entities`;
const sv=await req('POST',`${q}/services?workspaceId=${S.workspaceId}`,{name:n,host:'203.0.113.10',port:80},'fx-s-'+n);console.log('svc',sv.status,sv.j?.error?.code,JSON.stringify(sv.j?.data)?.slice(0,200));
const rt=await req('POST',`${q}/routes?workspaceId=${S.workspaceId}`,{name:n+'-rt',paths:['/'+n],service:{id:sv.j?.data?.id??sv.j?.data?.entity?.id}},'fx-r-'+n);console.log('rt',rt.status,rt.j?.error?.code);
S.kp004Service=n;writeFileSync((process.env.KP_LAB_SECRETS||'./secrets.json'),JSON.stringify(S,null,1),{mode:0o600});
