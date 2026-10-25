import{execFileSync}from'node:child_process';import{existsSync}from'node:fs';import{ProductionHarness}from'./lib/production-http-harness.mjs';import{durableProductionJson}from'./lib/production-ui-storage.mjs';
const path='artifacts/Production/root-production-bounded-capacity-fault-actual.json';if(existsSync(path)||process.env.PRODUCTION_CAPACITY_EXCLUSIVE_READY!=='true')throw Error('PRODUCTION_CAPACITY_EXCLUSIVE_REQUIRED');
const h=new ProductionHarness({resume:true});if(!h.state.productionCoreComplete)throw Error('PRODUCTION_CORE_COMPLETE_REQUIRED');
const actor=h.state.sessions.bootstrap;await h.refresh(actor);
const project='kongos-prod-m08-20261012-a3',socket='unix:///dev/shm/kongos-production-ram-m08-20261012-a3/run/docker-production.sock',cid=h.state.scope.cid,wid=h.state.scope.wid;
const target=h.state.origin+`/api/v1/clusters/${cid}/entities/services?workspaceId=${wid}&size=20`,results=[],began=Date.now(),concurrency=10,perWorker=20;
await Promise.all(Array.from({length:concurrency},async()=>{for(let i=0;i<perWorker;i++){const start=Date.now();try{const r=await fetch(target,{headers:{Cookie:actor.cookie},redirect:'manual',signal:AbortSignal.timeout(15000)});await r.arrayBuffer();results.push({status:r.status,elapsedMs:Date.now()-start,requestId:r.headers.get('x-request-id')});}catch{results.push({status:0,elapsedMs:Date.now()-start});}}}));
const elapsedMs=Date.now()-began,sorted=results.map(r=>r.elapsedMs).sort((a,b)=>a-b),percentile=p=>sorted[Math.min(sorted.length-1,Math.floor(sorted.length*p))];
const capacity={concurrency,perWorker,totalRequests:results.length,elapsedMs,readPageSize:20,successful:results.filter(r=>r.status===200).length,limited429:results.filter(r=>r.status===429).length,unexpected:results.filter(r=>![200,429].includes(r.status)).length,p50Ms:percentile(.5),p95Ms:percentile(.95),p99Ms:percentile(.99),requestsPerSecond:results.length*1000/elapsedMs,results,workload:'authenticated BFF bounded Service pages; no write-load SLA claimed'};
const run=args=>{try{return execFileSync('docker',[`--host=${socket}`,...args],{stdio:['ignore','pipe','pipe'],timeout:45000});}catch{throw Error('PRODUCTION_OWNED_FAULT_COMMAND_FAILED');}};
const faults=[];
for(const service of['kong','redis']){
 const name=`${project}-${service}-1`,before=JSON.parse(run(['inspect',name]))[0];if(before.Config.Labels['com.docker.compose.project']!==project||before.State.Health.Status!=='healthy')throw Error('PRODUCTION_OWNED_HEALTHY_FAULT_TARGET_REQUIRED');
 let stopped=false;
 try{
  run(['stop','--time','15',before.Id]);stopped=true;
  const r=await fetch(target,{headers:{Cookie:actor.cookie},redirect:'manual',signal:AbortSignal.timeout(30000)});const payload=await r.json();faults.push({service,originalContainerId:before.Id,status:r.status,errorCode:payload.error?.code,requestId:payload.meta?.requestId??r.headers.get('x-request-id'),passed:r.status===503||r.status===502,writeRequests:0});
 }finally{if(stopped)run(['start',before.Id]);}
 const until=Date.now()+90000;let healthy=false;do{healthy=JSON.parse(run(['inspect',before.Id]))[0].State.Health?.Status==='healthy';if(healthy)break;await new Promise(r=>setTimeout(r,1000));}while(Date.now()<until);
 if(!healthy)throw Error('PRODUCTION_FAULT_TARGET_NOT_HEALTHY_AFTER_RESTART');
 const read=await h.request(actor,`/api/v1/clusters/${cid}/entities/services/${h.state.nativeFixture.service.id}?workspaceId=${wid}`);if(read.data.entity.id!==h.state.nativeFixture.service.id)throw Error('PRODUCTION_FAULT_CHANGED_NATIVE_ID');
 faults.at(-1).recoveredWithOriginalContainer=true;faults.at(-1).originalNativeIdPreserved=true;
}
const report={performedAt:new Date().toISOString(),allPassed:capacity.unexpected===0&&capacity.successful>0&&faults.every(f=>f.passed&&f.recoveredWithOriginalContainer),capacity,faults,originalDevelopmentEnvironmentTouched:false,writeLoadTested:false,commercialSlaCertified:false};durableProductionJson(path,report,true,0o644);console.log(JSON.stringify({allPassed:report.allPassed,requests:capacity.totalRequests,p95Ms:capacity.p95Ms,limited429:capacity.limited429,faults:2}));
