import {S,login,approve,execute,wfGet} from './c.mjs';
const a=await login(S.adminUser,S.adminPass),p=await login(S.apprUser,S.apprPass);const cid=S.clusterB,ws=S.workspaceB,qb=`/api/v1/clusters/${cid}`,wb=`workspaceId=${ws}`;
const items=r=>r.data?.items??r.data??[];
const run=async(label,r)=>{const wf=r.data?.workflowId??r.data?.workflow?.id;console.log(label,r.status,r.code??'',!!wf);if(!wf)throw Error(label);
 console.log(' approve',(await approve(p,cid,ws,wf,'rc1 fixture revalidation after approval-mode switch')).status);const ex=await execute(a,cid,ws,wf);console.log(' execute',ex.status,ex.code??'');
 let s;for(let i=0;i<30;i++){await new Promise(z=>setTimeout(z,1000));s=(await wfGet(a,cid,ws,wf))?.state;if(!['approved','running','queued','executing'].includes(s))break;}console.log(' state',s);if(s!=='succeeded')throw Error(label+s);};
const get=async()=>{const x=items(await a('GET',`${qb}/portal/publications?size=50&${wb}`)).find(x=>(x.entity??x).name===S.portalPublicationName);const g=(await a('GET',`${qb}/portal/publications/${(x.entity??x).id}?${wb}`)).data;return g.entity??g;};
const G=await get();
await run('publish',await a('POST',`${qb}/portal/publications/${G.id}/publish?${wb}`,{revision:G.revision,confirmed:true,confirm_name:G.name}));
