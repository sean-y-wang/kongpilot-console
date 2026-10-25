import{readFileSync,lstatSync}from'node:fs';
import{parseEnv}from'node:util';
import{ProductionHarness}from'./lib/production-http-harness.mjs';

const proof=JSON.parse(readFileSync('artifacts/Production/root-production-browser-node-tls-text-checked.json'));
if(proof.allPassed!==true||proof.authenticationWrites!==0||proof.businessWrites!==0)throw Error('PRODUCTION_REAL_STRICT_TLS_REQUIRED');
const envPath='/dev/shm/kongos-production-ram-m08-20261012-a3/private/production/.env',s=lstatSync(envPath);
if(!s.isFile()||s.isSymbolicLink()||s.uid!==process.getuid()||(s.mode&511)!==384)throw Error('PRODUCTION_ENV_BOUNDARY');
const env=parseEnv(readFileSync(envPath,'utf8'));if(env.KONGOS_API_IMAGE!=='kongos/console-api:prod-m08-20261012-a3-sec4')throw Error('PRODUCTION_FINAL_RUNTIME_IMAGE_REQUIRED');
const h=new ProductionHarness();let error;
try{
 for(const[k,v]of Object.entries(env))if(/PASSWORD|SECRET|ENCRYPTION_KEY/.test(k))h.state.secrets.push(v);h.save();
 const actor=await h.login('bootstrap',env.BOOTSTRAP_ADMIN_USERNAME,env.BOOTSTRAP_ADMIN_PASSWORD);
 h.check(actor.user.capabilities?.platformAdmin===true,'real bootstrap current platform admin');
 const list=(await h.request(actor,'/api/v1/clusters')).data,clusters=Array.isArray(list)?list:list.items;
 h.check(clusters.length===1,'fresh isolated production metadata has one Kong cluster');h.state.clusterId=clusters[0].id;h.save();
 const cid=h.state.clusterId;
 await h.request(actor,`/api/v1/clusters/${cid}/probe`,'POST',{});
 const cluster=(await h.request(actor,`/api/v1/clusters/${cid}`)).data;
 h.check(cluster.version==='1.5.1'&&cluster.execution_mode==='direct'&&cluster.enabled_plugins?.length===34,'actual Kong1.5.1 direct mode and 34 installed plugins');h.state.cluster=cluster;h.save();
 const areas=(await h.request(actor,`/api/v1/clusters/${cid}/workspaces?size=20`)).data;
 h.check(areas.items.length===1&&areas.items[0].code==='default','fresh default workspace available');h.state.defaultWorkspaceId=areas.items[0].id;h.save();
 const workspace=(await h.request(actor,`/api/v1/clusters/${cid}/workspaces`,'POST',{code:h.state.testTag,name:h.state.testTag,owner_user_id:actor.user.id,description:'独立生产验收的隔离工作区'})).data;
 h.state.scope={cid,wid:workspace.id};h.state.workspace=workspace;h.save();
 for(const type of['services','routes','consumers','plugins','upstreams','certificates','ca_certificates','snis']){
  const page=(await h.request(actor,`/api/v1/clusters/${cid}/entities/${type}?workspaceId=${workspace.id}&size=10`)).data;
  h.check(Array.isArray(page.items)&&page.items.length===0&&page.nextCursor==null,'fresh workspace server cursor page is empty',{type});
 }
}catch(e){error=true;}
process.exitCode=h.finish('artifacts/Production/root-production-http-initial-actual.json',error,{scope:h.state.scope??null,actualProductionHttpsVerified:true,m8ClosureComplete:true});
