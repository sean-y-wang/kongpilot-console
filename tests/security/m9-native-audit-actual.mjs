import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { lstatSync,readFileSync,writeFileSync,mkdirSync,existsSync } from 'node:fs';
import { dirname,resolve } from 'node:path';
import {knownCompletedOriginal} from './lib/m9-native-audit-worker.mjs';

const repo=resolve(dirname(new URL(import.meta.url).pathname),'../..');
const directory='/dev/shm/kongpilot-release-lab';
const CID='e269f167-53e9-4895-af89-5b1b8835c6ec';
const reportPath=resolve(repo,'artifacts/M9/audit-verification.json');
const privateJSON=name=>{
  const path=`${directory}/${name}`,stat=lstatSync(path);
  assert(stat.isFile()&&!stat.isSymbolicLink()&&stat.uid===process.getuid()&&(stat.mode&0o777)===0o600,'Private original request ledger required');
  assert(stat.size<=32*1024*1024);return JSON.parse(readFileSync(path,'utf8'));
};
const normalizePath=value=>{
  if(typeof value!=='string')throw Error('REQUEST_PATH_REQUIRED');
  const path=(value.startsWith('http')?new URL(value).pathname:value.split('?')[0]).replace(/^\/api\/v1(?=\/)/,'');
  if(!path.startsWith('/')||path.startsWith('//')||path.includes('\\'))throw Error('BFF_REQUEST_PATH_REQUIRED');return path;
};
const classify=packet=>{
  const path=normalizePath(packet.path),method=packet.method;
  if(/^\/auth\//.test(path))return null;
  if(path.endsWith('/toolbox/routes/debug'))return ['route.simulation',['toolbox.route.simulated']];
  if(path.endsWith('/toolbox/probes'))return ['proxy.probe',['toolbox.proxy-probe.intent','toolbox.proxy-probe.result']];
  if(path.endsWith('/toolbox/cache/invalidate'))return ['cache.invalidate',['toolbox.cache.invalidate.requested']];
  if(path.endsWith('/batches/plan'))return packet.body?.action==='workspace-move'?['workspace.migration.plan',['plan']]:['batch.plan',['toolbox.batch.plan']];
  if(/\/drafts(?:\/[a-f0-9-]+)?(?:\/restore)?$/.test(path))return ['draft.metadata',[/\/restore$/.test(path)?'draft.restore':method==='DELETE'?'draft.archive':method==='PATCH'?'draft.update':'draft.create']];
  if(/\/workflows\/[a-f0-9-]+\/(?:approve|reject|cancel|execute)$/.test(path))return ['workflow.'+path.split('/').at(-1),['workflow.'+path.split('/').at(-1)]];
  if(/\/workflows\/[a-f0-9-]+\/reconcile-metadata$/.test(path))return ['workflow.reconcile-migration-metadata',['workflow.reconcile-migration-metadata']];
  if(/\/recycle-bin\/[a-f0-9-]+\/restore$/.test(path))return ['recycle.restore',['restore']];
  if(/\/entities\//.test(path)||/\/credentials\//.test(path))return ['native.'+(method==='POST'?'create':method==='DELETE'?'delete':'update'),[method==='POST'?'create':method==='DELETE'?'delete':'update']];
  if(/\/configuration\//.test(path))return ['configuration.metadata',['configuration.*','snapshot.*']];
  if(/\/workspace-migrations/.test(path))return ['workspace.migration',['migrate','workspace.migrate','plan','workflow.*']];
  if(/^\/iam\//.test(path))return ['iam.metadata',['iam.*']];
  if(/^\/clusters\/[a-f0-9-]+$/.test(path))return ['cluster.metadata',[method==='PATCH'?'update':'create']];
  if(/\/workspaces$/.test(path))return ['workspace.metadata',['create']];
  throw Error('SUCCESSFUL_BUSINESS_REQUEST_NOT_CLASSIFIED');
};

try{
  assert.equal(process.env.RELEASE_LAB_READY,'true');assert.equal(process.env.RELEASE_LAB_AUDIT_READY,'true');
  const verifiedAfter=process.env.RELEASE_LAB_VERIFIED_AFTER;assert(typeof verifiedAfter==='string'&&Number.isFinite(Date.parse(verifiedAfter)));
  const harness=privateJSON('m9-harness.json'),browser=privateJSON('m9-browser-journal.json');
  assert.equal(harness.cid,CID);assert.equal(harness.milestone,'M9');assert(Array.isArray(browser.requests));
  const manifest={milestone:'M9',clusterId:CID,verifiedAfter,requests:[],failedRequests:[],unknownRequests:[],excludedAuthenticationRequests:0};
  for(const [source,packets]of [['native',harness.requests],['browser',browser.requests]])for(const [index,packet]of packets.entries()){
    if(['GET','HEAD'].includes(packet.method))continue;
    const path=normalizePath(packet.path),status=packet.status,state=packet.state??(typeof status==='number'?'response_observed':'response_unknown');
    if(['prepared','response_unknown'].includes(state)||typeof status!=='number'){
      const originalKey=packet.key??packet.idempotencyKey;
      manifest.unknownRequests.push({source,index,method:packet.method,path:path.replace(/[a-f0-9]{8}-[a-f0-9-]{27,}/gi,':id'),state,
        responseResolved:false,authenticationSessionReplaced:packet.resolution?.authSessionReplaced===true,
        originalKeyReplayed:!!originalKey&&packets.filter(value=>(value.key??value.idempotencyKey)===originalKey&&value.path===packet.path&&value.method===packet.method).length>1});
      if(!path.startsWith('/auth/'))throw Error('ORIGINAL_BUSINESS_RESPONSE_UNKNOWN_NO_REPLAY');
      continue;
    }
    let completion;
    if(status<200||status>=300){
      manifest.failedRequests.push({source,index,method:packet.method,path:path.replace(/[a-f0-9]{8}-[a-f0-9-]{27,}/gi,':id'),status,
        ...(typeof packet.errorCode==='string'&&/^[A-Z0-9_]+$/.test(packet.errorCode)?{code:packet.errorCode}:{}),knownNoNativeSend:packet.resolution?.knownNoNativeSend===true,originalRetained:true,
        ...(packet.resolution?.knownNativeComplete?{knownNativeComplete:true,metadataRecovered:packet.resolution.metadataRecovered===true,originalResponseRewritten:false}:{})});
      if(packet.resolution?.knownNativeComplete){
        const proofBytes=readFileSync(resolve(repo,'artifacts/M9/native-migration-v2-known-native-proof.json'));
        completion=knownCompletedOriginal(packet,JSON.parse(proofBytes),createHash('sha256').update(proofBytes).digest('hex'));
      }else continue;
    }
    const category=classify(packet);if(!category){manifest.excludedAuthenticationRequests++;continue;}
    assert.equal(typeof packet.requestId,'string');assert.equal(typeof packet.actorId,'string');assert(Number.isFinite(Date.parse(packet.startedAt)));
    manifest.requests.push({source,index,method:packet.method,requestId:packet.requestId,actorId:packet.actorId,
      clusterId:path.match(/^\/clusters\/([a-f0-9-]{36})(?:\/|$)/)?.[1]??null,
      category:category[0],expectedActions:category[1],startedAt:packet.startedAt,routePath:path,
      ...(category[0]==='workflow.reconcile-migration-metadata'?{workflowId:path.split('/').at(-2)}:{}),
      ...(completion?{knownNativeComplete:completion}:{})});
  }
  // Only minimal request identities enter the API container; no secret ledger is copied.
  const worker=readFileSync(resolve(repo,'tests/security/lib/m9-native-audit-worker.mjs'),'utf8');
  const result=spawnSync('docker',['--host=unix:///var/run/docker.sock','exec','--env','GOMAXPROCS=2','-i','kongos-ram-tool-m08-20261012-a3',
    'docker','--host=unix:///run/docker-production.sock','exec','-i','-e','RELEASE_LAB_READY=true',
    '-e','RELEASE_LAB_CONTAINER=kongpilot-release-lab-console-api-1','kongpilot-release-lab-console-api-1','node','--input-type=module'],
    {env:{...process.env,GOMAXPROCS:'2'},input:worker+'\nawait runAudit('+JSON.stringify(manifest)+');\n',encoding:'utf8',timeout:30000,maxBuffer:4*1024*1024});
  if(result.error)throw Error('OWNED_AUDIT_WORKER_FAILED');
  let report;try{report=JSON.parse(result.stdout);}catch{throw Error('PUBLIC_AUDIT_REPORT_NOT_AVAILABLE');}
  assert.equal(report.milestone,'M9');
  mkdirSync(dirname(reportPath),{recursive:true});
  if(existsSync(reportPath)){let suffix=1;while(existsSync(reportPath.replace('.json',`.attempt-${suffix}.json`)))suffix++;writeFileSync(reportPath.replace('.json',`.attempt-${suffix}.json`),readFileSync(reportPath));}
  writeFileSync(reportPath,JSON.stringify(report,null,2)+'\n');
  process.stdout.write(JSON.stringify({passed:report.passed,checks:report.checks.length,businessRequests:manifest.requests.length,auditRows:report.auditRows,
    historicalShortfalls:report.historicalShortfalls.length,failedOriginalRequests:report.failedOriginalRequests.length,unknownOriginalResponses:report.unknownOriginalRequests.length,originalResponseResolved:false})+'\n');
  if(!report.passed||result.status!==0)process.exitCode=1;
}catch(error){process.stderr.write(JSON.stringify({passed:false,code:/^[A-Z0-9_]+$/.test(error?.message??'')?error.message:error?.code==='ERR_ASSERTION'?'AUDIT_HANDOFF_ASSERTION_FAILED':'AUDIT_TOOL_FAILED',credentialsRecorded:false})+'\n');process.exitCode=1;}
