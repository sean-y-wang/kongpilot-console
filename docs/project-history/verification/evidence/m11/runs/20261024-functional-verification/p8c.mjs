import {login,op,save,api} from './h.mjs'; import fs from 'node:fs';
const {A,wid}=JSON.parse(fs.readFileSync('ctx.json'));const s=await login();const q=o=>new URLSearchParams({workspaceId:wid,...o}).toString();
const end=new Date(Math.floor(Date.now()/1000)*1000),start=new Date(end-5*60000);const iso=d=>d.toISOString().replace(/\.\d{3}Z$/,'Z');
const r=await op('vitals','overview serviceId=svc-1 (with traffic)',()=>api(s,`/api/v1/clusters/${A}/vitals/overview?`+q({scope:'workspace',serviceId:'30114158-'+'',start:iso(start),end:iso(end)})),{expect:x=>x.status===400});
const ent=(await api(s,`/api/v1/clusters/${A}/vitals/entities?`+q({scope:'workspace',type:'services',search:'fvmvml15a1-svc-1',size:'5'}))).data;
console.log('search',JSON.stringify(ent).slice(0,300));const id=process.env.SID1;
const o=await op('vitals','overview serviceId=svc-1 (search via entities)',()=>api(s,`/api/v1/clusters/${A}/vitals/overview?`+q({scope:'workspace',serviceId:id,start:iso(start),end:iso(end)})));
console.log(JSON.stringify(o.data?.cards));console.log('topN',JSON.stringify(o.data?.topN).slice(0,400));console.log('units',JSON.stringify(o.data?.units));
save('p8c.json');
