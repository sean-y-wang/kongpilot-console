import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { M7_COMPOSE, M7_REFERENCE, readM7Reference, durableJson, sha256 } from './lib/m7-harness.mjs';

if (process.env.M7_DEPLOYMENT_READY !== 'true' || process.env.M7_PRODUCER_DIAGNOSIS_READY !== 'true') throw new Error('M7_EXACT_REPAIRED_PRODUCER_READONLY_HANDOFF_REQUIRED');
const state = readM7Reference(), intent = state.samplingIntents[1];
const sourcePath = 'artifacts/M7/security-producers-continuation.json', sourceBytes = readFileSync(sourcePath);
const originalReportSha256 = '3ee3b78d6437edd3ff41a322dfe7e66bdb773c230ada609a4a5106a82ac3f589';
if (sha256(sourceBytes) !== originalReportSha256 || state.phase !== 'stopped-failure' || state.requests.length !== 270 || state.inFlight != null || state.requests.some(packet => packet.state !== 'response_observed') ||
  intent?.state !== 'unknown' || intent.samples.length !== 0 || intent.cid !== 'dff45535-ed8d-4851-b7a6-6376feac7f59' || intent.wid !== '4f2f9544-e3f1-4ff9-93ca-4c3b3e5324e5' ||
  intent.type !== 'certificates' || intent.id !== 'dc480bde-b580-4744-89e8-4c1d9f317ab2' || intent.keys.length !== 5 || intent.keys[0] !== 'be9f8242-775d-4bb7-a818-902cfa5fb562') throw new Error('M7_ORIGINAL_REPAIR_FAILURE_TUPLE_REQUIRED');
const archive = 'artifacts/M7/security-producers-after-fence-repair-sampling-failure.json';
if (!existsSync(archive)) {
  durableJson(archive, JSON.parse(sourceBytes), 0o644, true);
  if (sha256(readFileSync(archive)) !== originalReportSha256) throw new Error('M7_FAILURE_ARCHIVE_BYTES_CHANGED');
}
const requestSha256 = sha256(JSON.stringify(state.requests));
state.producerRepairSamplingDiagnosis = { version: 1, state: 'prepared', requestSha256, originalReportSha256, originalIntentIndex: 1, at: new Date().toISOString() }; durableJson(M7_REFERENCE, state);
// Exact previous nonowner read-only adapter; replace only the frozen new tuple.
let code = readFileSync('tests/security/diagnose-m7-producer-sampling.mjs', 'utf8').split('const code = String.raw`')[1].split('`;')[0]
  .replaceAll('9abfa5b8-d34b-4920-88e2-f4058a4ab2dd', intent.id).replaceAll('e381165a-366f-4bc3-a4d7-869ae6c9645e', intent.keys[0]);
code = code.replace('  const state=(await db.query(', `  const counts=(await db.query('SELECT (SELECT count(*)::integer FROM event_detection_observations WHERE cluster_id=$1 AND workspace_id=$2 AND subject_type=$3 AND subject_id=$4) AS observations,(SELECT count(*)::integer FROM event_detection_state WHERE cluster_id=$1 AND workspace_id=$2 AND subject_type=$3 AND subject_id=$4) AS states',[x.cid,x.wid,x.type,x.id])).rows[0];
  let snapshotAccepted=false,snapshotErrorCode=null;
  try{const {ObservationAuthorityService}=require('./dist/modules/event-observers/observation-authority.service.js'),{SecretService}=require('./dist/infrastructure/secret.service.js');
   const reader={one:async(sql,args)=>(await db.query(sql,args)).rows[0]||null,query:async(sql,args)=>(await db.query(sql,args)).rows,exec:async()=>{throw Error('READONLY_WRITE_DENIED')}};
   await new ObservationAuthorityService(reader,new SecretService(),null,null,null).snapshot(x.cid,reader);snapshotAccepted=true;
  }catch(error){const response=typeof error.getResponse==='function'?error.getResponse():null;snapshotErrorCode=/^[A-Z0-9_]{1,80}$/.test(response?.code||error.code||'')?(response?.code||error.code):'SNAPSHOT_READONLY_UNAVAILABLE';}
  const state=(await db.query(`)
  .replace('ok:true,nonOwnerReadOnly:true,receipts:result', 'ok:true,nonOwnerReadOnly:true,typedObservationCount:counts.observations,typedDetectorStateCount:counts.states,snapshotAccepted,snapshotErrorCode,receipts:result');
let result;
try { result = JSON.parse(execFileSync('docker', [...M7_COMPOSE, 'exec', '-T', 'console-api', 'node', '-e', code], { input: JSON.stringify({ cid: intent.cid, wid: intent.wid, type: intent.type, id: intent.id, keys: intent.keys }), encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'], timeout: 30000 })); }
catch (error) { try { result = JSON.parse(error.stdout?.toString() ?? ''); } catch { result = { ok: false, errorCode: 'READONLY_TRANSPORT_UNAVAILABLE' }; } }
state.producerRepairSamplingDiagnosis = { ...state.producerRepairSamplingDiagnosis, state: result.ok ? 'completed' : 'read-only-diagnosis-incomplete', safeResult: result }; durableJson(M7_REFERENCE, state);
const report = { performedAt: new Date().toISOString(), milestone: 'M7', testTag: state.testTag, allPassed: result.ok === true, originalFailureArchive: archive, originalFailureSha256: originalReportSha256,
  originalPacketsUnchanged: sha256(JSON.stringify(state.requests)) === requestSha256, scope: { clusterId: intent.cid, workspaceId: intent.wid, subjectType: intent.type, subjectId: intent.id },
  ...result, originalFirstResponse: intent.receivedResponses[0], samplingStateRetained: 'unknown', businessWrites: 0, authenticationWrites: 0, nativeTransportWrites: 0, freshAuthorityObservations: 0 };
const path = 'artifacts/M7/producer-after-fence-repair-readonly-diagnosis.json'; durableJson(path, report, 0o644, true);
process.stdout.write(JSON.stringify({ path, sha256: sha256(readFileSync(path)), ...result, originalPacketsUnchanged: report.originalPacketsUnchanged, businessWrites: 0, authenticationWrites: 0, freshAuthorityObservations: 0 }) + '\n');
process.exitCode = report.allPassed ? 0 : 1;
