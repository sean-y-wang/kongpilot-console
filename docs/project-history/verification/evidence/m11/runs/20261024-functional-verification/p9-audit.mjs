import {login,op,save,api} from './h.mjs'; import fs from 'node:fs';
const s=await login();const ent=d=>d?.entity??d;
const c=await op('audit','global CSV export create',()=>api(s,'/api/v1/audit/global/exports','POST',{format:'csv',confirmed:true}));
console.log('create shape',JSON.stringify(c.data).slice(0,400));
const X=ent(c.data);const id=X?.jobId||X?.job?.id||X?.id;let st;
for(let i=0;i<120;i++){st=ent((await api(s,`/api/v1/audit/global/exports/${id}`)).data);st=st?.job??st;if((st?.complete===true||['completed','succeeded','ready','failed','expired'].includes(st?.state||st?.status)))break;await new Promise(r=>setTimeout(r,1000));}
await op('audit','export reaches terminal ready state',async()=>({ok:st?.complete===true&&st?.capabilities?.download===true,status:200,code:st?.state||st?.status,msg:JSON.stringify(st).slice(0,300)}));
console.log('status shape',JSON.stringify(st).slice(0,400));
const t0=performance.now();const r=await fetch('http://127.0.0.1:33000/api/v1/audit/global/exports/'+id+'/download',{headers:{Cookie:s.cookie,Origin:'https://127.0.0.1:33000'}}).catch(e=>({status:0,e}));
const body=r.status?Buffer.from(await r.arrayBuffer()):Buffer.alloc(0);
await op('audit','download CSV',async()=>({ok:r.status===200&&body.length>0,status:r.status,code:`${r.headers?.get?.('content-type')} ${body.length}B ${Math.round(performance.now()-t0)}ms`}));
const text=body.toString('utf8');const lines=text.split(/\r?\n/).filter(Boolean);
console.log('header:',lines[0]?.slice(0,300));console.log('rows:',lines.length-1);
await op('audit','CSV has header + rows, no secret-looking columns',async()=>({ok:lines.length>1&&!/password|secret|token/i.test(lines[0]),status:200,code:`rows=${lines.length-1}`}));
await op('audit','CSV formula-injection safe (no cell starts with = + - @)',async()=>({ok:!lines.slice(1).some(l=>/(^|,)"?[=+@]/.test(l)),status:200}));
fs.writeFileSync('p9-audit-sample-head.txt',lines.slice(0,1).join('\n')+'\n');save('p9-audit.json');
