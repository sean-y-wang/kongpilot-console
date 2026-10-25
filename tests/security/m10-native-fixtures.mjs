import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {randomBytes} from 'node:crypto';
import {ReleaseHarness,releaseScope} from './lib/release-harness.mjs';

// Root is the only runner of real gateway writes. Each fixture is registered in
// an owner-only WAL before the request and retains its original request key.
const h=new ReleaseHarness('M10',{resume:process.argv.includes('--resume')});
try{
 assert.equal(process.env.RELEASE_LAB_M10_DEPLOYED,'true');
 const prior=JSON.parse(readFileSync('/dev/shm/kongpilot-release-lab/m9-harness.json','utf8'));
 const admin=h.state.sessions.admin??await h.login('admin',prior.sessions.admin.username,prior.adminPassword);
 for(const label of ['approver','reader'])if(!h.state.sessions[label]){
  const account=prior.accounts[label];assert(account);await h.login(label,account.username,account.password);
 }
 h.state.cid??=prior.cid;const cid=h.state.cid;
 const cluster=(await h.request(admin,`/clusters/${cid}`)).data;
 h.state.originalSourceMode??=cluster.execution_mode;
 h.state.fixtureSourceModeBody??={revision:cluster.revision,execution_mode:'direct'};h.save();
 if(cluster.execution_mode!=='direct')await h.once('m10-source-direct',admin,`/clusters/${cid}`,'PATCH',h.state.fixtureSourceModeBody);
 const source=(await h.once('m10-source-workspace',admin,`/clusters/${cid}/workspaces`,'POST',
  {code:`${h.state.tag}-source`,name:`${h.state.tag} Source`,owner_user_id:admin.user.id,description:'Isolated governance acceptance source'})).data;
 h.state.wid=source.id;h.state.sourceWorkspace=source;h.save();
 const targetCluster=(await h.once('m10-stage-cluster',admin,'/clusters','POST',
  {name:`${h.state.tag} Stage`,environment:'stage',admin_url:'http://stage-kong-admin:8001',proxy_origin:'http://stage-kong:8000',execution_mode:'direct',labels:[h.state.tag]})).data;
 h.state.targetCid=targetCluster.id;h.save();
 await h.once('m10-stage-probe',admin,`/clusters/${targetCluster.id}/probe`,'POST',{});
 const capabilities=(await h.request(admin,`/clusters/${targetCluster.id}/capabilities`)).data;
 assert.equal(capabilities.version,'1.5.1');assert(capabilities.enabled_plugins.includes('key-auth'));
 const target=(await h.once('m10-target-workspace',admin,`/clusters/${targetCluster.id}/workspaces`,'POST',
  {code:`${h.state.tag}-target`,name:`${h.state.tag} Target`,owner_user_id:admin.user.id,description:'Independent physical gateway target'})).data;
 h.state.targetWid=target.id;h.state.targetWorkspace=target;h.save();
 h.state.fixtures??={};
 for(const [side,clusterId,workspace,host,retries,status] of [
  ['source',cid,source,'source.pilot.invalid',0,418],['target',targetCluster.id,target,'stage.pilot.invalid',4,419]
 ]){
  const scoped=suffix=>releaseScope(clusterId,workspace.id,suffix),tags=[h.state.tag,'team:m10-acceptance'];
  const service=(await h.once(`m10-${side}-service`,admin,scoped('entities/services'),'POST',
   {name:`${h.state.tag}-payments`,protocol:'http',host:'echo',port:8080,retries,connect_timeout:side==='source'?2300:5300,read_timeout:side==='source'?3300:6300,write_timeout:side==='source'?4300:7300,tags})).data.entity;
  const route=(await h.once(`m10-${side}-route`,admin,scoped('entities/routes'),'POST',
   {name:`${h.state.tag}-payments-route`,service:{id:service.id},protocols:['http'],hosts:[host],paths:[`/${h.state.tag}/pay`],tags})).data.entity;
  const plugin=(await h.once(`m10-${side}-plugin`,admin,scoped('entities/plugins'),'POST',
   {name:'request-termination',route:{id:route.id},config:{status_code:status,message:'KongPilot isolated governance acceptance'},tags})).data.entity;
  const consumer=(await h.once(`m10-${side}-consumer`,admin,scoped('entities/consumers'),'POST',
   {username:`${h.state.tag}-developer`,tags})).data.entity;
  h.state.fixtureKeys??={};h.state.fixtureKeys[side]??=randomBytes(24).toString('hex');h.save();
  const key=h.state.fixtureKeys[side];
  const credential=(await h.once(`m10-${side}-credential`,admin,scoped(`consumers/${consumer.id}/credentials/key-auth`),'POST',{key,tags})).data.entity;
  const authRoute=(await h.once(`m10-${side}-auth-route`,admin,scoped('entities/routes'),'POST',
   {name:`${h.state.tag}-credential-route`,service:{id:service.id},protocols:['http'],hosts:[host],paths:[`/${h.state.tag}/credential`],tags})).data.entity;
  const authPlugin=(await h.once(`m10-${side}-auth-plugin`,admin,scoped('entities/plugins'),'POST',
   {name:'key-auth',route:{id:authRoute.id},config:{},tags})).data.entity;
  assert.equal(typeof key,'string');assert(!key.includes('REDACTED')&&!key.includes('***'));
  h.state.fixtures[side]={service,route,plugin,consumer,credential,authRoute,authPlugin,key};h.save();
  const input={method:'GET',url:`http://${host}/${h.state.tag}/credential/live`,headers:{apikey:key}};
  await h.poll(async()=>(await h.request(admin,scoped('toolbox/probes'),'POST',
   {routeId:authRoute.id,input,confirmed:true,confirm_name:authRoute.name})).data,r=>r.status===200,'CURRENT_FIXTURE_KEY_MUST_AUTHENTICATE');
 }
 assert.notEqual(h.state.fixtures.source.service.id,h.state.fixtures.target.service.id);
 assert.notEqual(h.state.fixtures.source.key,h.state.fixtures.target.key);
 h.check(true,'two physical Kong 1.5.1 gateways contain matching logical names with different native IDs and working independent API keys');
 h.state.phase='native-fixtures-ready';h.save();
 console.log(JSON.stringify({passed:true,phase:h.state.phase,checks:h.state.checks.length,overallAcceptance:false}));
}catch(error){h.state.phase='native-fixtures-stopped';h.save();h.report(false,'M10_FIXTURE_SETUP_FAILED');console.error(JSON.stringify({passed:false,message:String(error.message).slice(0,500)}));process.exitCode=1;}
