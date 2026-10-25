import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { M7Harness, M7_COMPOSE, durableJson, sha256 } from './lib/m7-harness.mjs';

if (process.env.M7_DEPLOYMENT_READY !== 'true' || process.env.M7_PRODUCER_DIAGNOSIS_READY !== 'true') throw new Error('M7_ORIGINAL_SAMPLING_READ_ONLY_HANDOFF_REQUIRED');
const h = new M7Harness({ resume: true }); let failure;
const path = 'artifacts/M7/security-producers.json', archive = 'artifacts/M7/security-producers-first-sampling-failure.json';
const marker = 'producerSamplingReadOnlyContinuation', priorPath = 'artifacts/M7/producer-first-sampling-readonly-diagnosis.json';
try {
  const bytes = readFileSync(path), report = JSON.parse(bytes), priorBytes = readFileSync(priorPath), prior = JSON.parse(priorBytes), originalDigest = sha256(JSON.stringify(h.state.requests)), intent = h.state.samplingIntents[0];
  h.check(sha256(bytes) === '9719f854b5d1345241de86407eb8b8c97f8f8879f4b7104b07ed2f11d87a5a2c' &&
    report.testTag === h.state.testTag && report.allPassed === false && report.passed === 21 && report.failed === 1 &&
    h.state.phase === 'stopped-failure' && h.state.requests.length === 267 && h.state.inFlight == null &&
    h.state.requests.every(packet => packet.state === 'response_observed') && h.state.producerSamplingDiagnosis?.state === 'prepared' && !h.state[marker] &&
    sha256(priorBytes) === '678cbbd2fcdf9d7bf7306b44bd01d13906b0879d6a35356f98ebbe99e329b3f5' && prior.allPassed === false,
    'original first sampler failure is retained before one pure read-only diagnostic');
  h.check(intent.state === 'unknown' && intent.samples.length === 0 && intent.cid === 'dff45535-ed8d-4851-b7a6-6376feac7f59' &&
    intent.wid === '4f2f9544-e3f1-4ff9-93ca-4c3b3e5324e5' && intent.type === 'certificates' &&
    intent.id === '9abfa5b8-d34b-4920-88e2-f4058a4ab2dd' && intent.keys.length === 5 &&
    intent.keys[0] === 'e381165a-366f-4bc3-a4d7-869ae6c9645e', 'sampling diagnostic reads only the exact original reserved keys and certificate');
  h.check(sha256(readFileSync(archive)) === sha256(bytes), 'original first producer failure and prior readonly diagnostic failure remain unchanged');
  h.state[marker] = { version: 1, state: 'prepared', at: new Date().toISOString(), originalPacketSha256: originalDigest,
    archive, archiveSha256: sha256(bytes), priorPath, priorSha256: sha256(priorBytes), originalIntentIndex: 0 }; h.save();
  const code = String.raw`
const fs=require('node:fs'),{Client}=require('pg');
let input='';process.stdin.on('data',c=>input+=c);process.stdin.on('end',async()=>{
 let db;try {
  const x=JSON.parse(input),fixed={cid:'dff45535-ed8d-4851-b7a6-6376feac7f59',wid:'4f2f9544-e3f1-4ff9-93ca-4c3b3e5324e5',id:'9abfa5b8-d34b-4920-88e2-f4058a4ab2dd'};
  if(x.cid!==fixed.cid||x.wid!==fixed.wid||x.id!==fixed.id||x.type!=='certificates'||x.keys.length!==5||x.keys[0]!=='e381165a-366f-4bc3-a4d7-869ae6c9645e')throw Error('SCOPE');
  const root='/tmp/kongos-m7-observation-receipts',ds=fs.lstatSync(root);
  if(!ds.isDirectory()||ds.isSymbolicLink()||ds.uid!==process.getuid()||(ds.mode&511)!==448)throw Error('IDENTITY');
  const material=[];
  for(let index=0;index<x.keys.length;index++){
   const key=x.keys[index];if(!/^[a-f0-9-]{36}$/.test(key))throw Error('KEY');
   let fd;try{fd=fs.openSync(root+'/'+key+'.json',fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);}catch(e){if(e.code==='ENOENT'){material.push({index,exists:false});continue;}throw Error('IDENTITY');}
   let r;try{const st=fs.fstatSync(fd);if(!st.isFile()||st.uid!==process.getuid()||(st.mode&511)!==384||st.size>4096)throw Error('IDENTITY');r=JSON.parse(fs.readFileSync(fd,'utf8'));}finally{fs.closeSync(fd);}
   if(r.version!==1||r.clusterId!==x.cid||r.subjectType!==x.type||r.subjectId!==x.id||r.samplingKey!==key||!['reserved','ready'].includes(r.state))throw Error('IDENTITY');
   material.push({index,exists:true,receipt:r});
  }
  const url=new URL(process.env.DATABASE_URL||process.env.CONSOLE_DATABASE_URL);
  const expectedRole=decodeURIComponent(url.username);
  if(expectedRole!=='kongos_app')throw Error('ROLE');
  db=new Client({connectionString:url.toString(),connectionTimeoutMillis:5000,statement_timeout:5000});await db.connect();await db.query('BEGIN READ ONLY');
  const role=(await db.query("SELECT current_user AS role,r.rolsuper,(SELECT count(*)::integer FROM pg_class c WHERE c.relname IN ('event_detection_observations','event_detection_state') AND c.relowner=r.oid) AS owned FROM pg_roles r WHERE r.rolname=current_user")).rows[0];
  if(!role||role.rolsuper||role.owned!==0||role.role!==expectedRole)throw Error('ROLE');
  const current=(await db.query("SELECT c.revision AS cr,c.status AS cs,c.version AS cv,c.admin_url,c.transport_scope,w.revision AS wr,w.status AS ws FROM clusters c JOIN workspaces w ON w.cluster_id=c.id WHERE c.id=$1 AND w.id=$2",[x.cid,x.wid])).rows[0];
  if(!current)throw Error('SCOPE');
  const {transportScopeFor}=require('./dist/infrastructure/kong/transport-scope.js'),transportScope=transportScopeFor(current.admin_url,current.transport_scope);
  const fence=(await db.query("SELECT count(*)::integer AS total,count(*) FILTER(WHERE state IN ('pending','uncertain'))::integer AS unsettled FROM metrics_write_fences WHERE transport_scope=$1",[transportScope])).rows[0];
  const mutations=(await db.query("SELECT count(*)::integer AS unfinished FROM mutation_operations WHERE transport_scope=$1 AND state IN ('pending','running','uncertain')",[transportScope])).rows[0];
  const result=[];
  for(const entry of material){
   if(!entry.exists){result.push({index:entry.index,exists:false});continue;}
   const r=entry.receipt,observationId=typeof r.observationId==='string'&&/^[a-f0-9-]{36}$/.test(r.observationId)?r.observationId:null;
   const row=observationId?(await db.query('SELECT id,cluster_id,workspace_id,subject_type,subject_id,observation_hmac,quality,observed_at,cluster_revision,workspace_revision FROM event_detection_observations WHERE id=$1',[observationId])).rows[0]:null;
   const event=observationId?(await db.query('SELECT id FROM event_records WHERE observation_id=$1',[observationId])).rows[0]:null;
   result.push({index:entry.index,exists:true,state:r.state,observationId,originalHmacAvailable:/^[a-f0-9]{64}$/.test(r.observationHmac||''),observationExists:Boolean(row),
    originalHmacMatches:Boolean(row&&row.observation_hmac===r.observationHmac),typedScopeMatches:Boolean(row&&row.cluster_id===x.cid&&row.workspace_id===x.wid&&row.subject_type===x.type&&row.subject_id===x.id),
    quality:row?.quality??null,observedAt:row?new Date(row.observed_at).toISOString():null,currentRevisionMatches:Boolean(row&&current&&row.cluster_revision===current.cr&&row.workspace_revision===current.wr),eventExists:Boolean(event),eventId:event?.id??null});
  }
  const state=(await db.query('SELECT revision,last_observed_at,last_observation_id FROM event_detection_state WHERE cluster_id=$1 AND workspace_id=$2 AND subject_type=$3 AND subject_id=$4',[x.cid,x.wid,x.type,x.id])).rows[0];
  await db.query('COMMIT');
  let activeSamplerProcesses=0;for(const p of fs.readdirSync('/proc').filter(p=>/^\d+$/.test(p)&&Number(p)!==process.pid)){try{const args=fs.readFileSync('/proc/'+p+'/cmdline','utf8').split('\0');if(args.some(a=>a==='dist/infrastructure/event-observe-test.js'||a.endsWith('/dist/infrastructure/event-observe-test.js'))&&args.includes(x.id)&&args.includes(x.keys.join(',')))activeSamplerProcesses++;}catch{}}
  process.stdout.write(JSON.stringify({ok:true,nonOwnerReadOnly:true,receipts:result,activeSamplerProcesses,subjectState:state?{exists:true,revision:state.revision,lastObservedAt:new Date(state.last_observed_at).toISOString(),lastObservationId:state.last_observation_id}:{exists:false},authorityMetadata:{clusterStatus:current.cs,clusterVersion:current.cv,clusterRevision:current.cr,workspaceStatus:current.ws,workspaceRevision:current.wr,fenceTotal:fence?.total??null,unsettledFences:fence?.unsettled??null,unfinishedMutations:mutations?.unfinished??null}}));
 }catch(e){if(db)await db.query('ROLLBACK').catch(()=>{});process.stdout.write(JSON.stringify({ok:false,errorCode:/^[A-Z0-9_]{1,40}$/.test(e.code||'')?e.code:['SCOPE','IDENTITY','KEY','ROLE'].includes(e.message)?e.message:'DIAGNOSTIC_UNAVAILABLE'}));process.exitCode=1;}finally{if(db)await db.end().catch(()=>{});}
});`;
  let result;
  try { result = JSON.parse(execFileSync('docker', [...M7_COMPOSE, 'exec', '-T', 'console-api', 'node', '-e', code],
    { input: JSON.stringify({ cid: intent.cid, wid: intent.wid, type: intent.type, id: intent.id, keys: intent.keys }), encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'], timeout: 30000 })); }
  catch (error) { try { result = JSON.parse(error.stdout?.toString() ?? ''); } catch { throw new Error('M7_READONLY_DIAGNOSTIC_UNKNOWN'); } }
  h.state[marker].transportReceipt = result; h.save();
  h.public = { diagnosticResult: result, businessWrites: 0, authenticationWrites: 0, nativeTransportWrites: 0, freshAuthorityObservations: 0 };
  h.check(result?.ok === true && result.nonOwnerReadOnly === true && result.receipts.length === 5,
    'original private receipt metadata and exact console rows are read through a nonowner readonly transaction');
  h.check(sha256(JSON.stringify(h.state.requests)) === originalDigest, 'read-only sampling diagnosis preserves all original 267 packets and unknown sampling checkpoint');
  h.state[marker] = { ...h.state[marker], state: 'completed', safeResult: result, unacceptedFirstLineCaptured: false }; h.save();
  h.public = { scope: 'original-reserved-sampling-receipts-and-readonly-console-observations', ...result,
    firstUnacceptedLineCaptured: false, submittedFirstLineStatus: null, originalSamplingStateRetained: 'unknown', businessWrites: 0, authenticationWrites: 0, nativeTransportWrites: 0, freshAuthorityObservations: 0 };
} catch (error) { failure = error; }
if (failure) h.checks.push({ name: failure.safeEvidenceMessage ? failure.message : 'Unexpected readonly sampling diagnosis failure; original private state retained', passed: false });
const report = { performedAt: new Date().toISOString(), milestone: 'M7', testTag: h.state.testTag, allPassed: !failure,
  passed: h.checks.filter(row => row.passed).length, failed: h.checks.filter(row => !row.passed).length, checks: h.checks, ...(h.public ?? {}) };
durableJson('artifacts/M7/producer-first-sampling-readonly-exact-diagnosis.json', report, 0o644, true);
console.log(JSON.stringify({ allPassed: report.allPassed, passed: report.passed, failed: report.failed, businessWrites: 0, authenticationWrites: 0 }));
process.exitCode = failure ? 1 : 0;
