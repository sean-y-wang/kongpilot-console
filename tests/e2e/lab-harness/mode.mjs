import { readFileSync } from 'node:fs';
const S=JSON.parse(readFileSync((process.env.KP_LAB_SECRETS||'./secrets.json'),'utf8'));const base=S.consoleOrigin;const s={};
async function req(m,p,b,k){const r=await fetch(base+p,{method:m,headers:{Accept:'application/json',Origin:base,'Content-Type':'application/json',...(s.cookie?{Cookie:s.cookie}:{}),...(s.csrf?{'X-CSRF-Token':s.csrf}:{}),...(k?{'X-Idempotency-Key':k}:{})},body:b?JSON.stringify(b):undefined});const set=r.headers.getSetCookie();if(set.length)s.cookie=set.map(x=>x.split(';')[0]).join('; ');let j=null;try{j=await r.json()}catch{}if(j?.data?.csrfToken)s.csrf=j.data.csrfToken;return{status:r.status,j};}
await req('POST','/api/v1/auth/login',{username:S.adminUser,password:S.adminPass});
const c=(await req('GET',`/api/v1/clusters/${(process.argv[3]||S.clusterId)}`)).j.data;console.log('before',c.execution_mode,c.revision??c.version);
const u=await req('PATCH',`/api/v1/clusters/${(process.argv[3]||S.clusterId)}`,{execution_mode:process.argv[2],revision:c.revision},'mode-'+Date.now());console.log(u.status,u.j?.error?.code,u.j?.error?.message,u.j?.data?.execution_mode);
