import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {existsSync,readFileSync,writeFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

export const EPOCH_PROJECTION_SQL='SELECT id,cluster_id,node_id,entity_type,entity_id,workspace_id,config_fingerprint,tags_fingerprint,source_pair_hash,valid_from,closed_at FROM metrics_assignment_epochs ORDER BY id LIMIT 10001';
export const EXPIRED_EPOCH_PAIR_SQL=String.raw`SELECT n.id AS new_id,o.id AS old_id,n.valid_from,
 o.close_reason,(o.closed_at=n.valid_from) AS close_matches,(o.verified_until<n.valid_from) AS expired,
 (ROW(o.workspace_id,o.service_id,o.route_id,o.consumer_id,o.business_tags,o.tags_fingerprint,o.config_fingerprint,o.source_pair_hash,o.service_label,o.route_label)
  IS NOT DISTINCT FROM ROW(n.workspace_id,n.service_id,n.route_id,n.consumer_id,n.business_tags,n.tags_fingerprint,n.config_fingerprint,n.source_pair_hash,n.service_label,n.route_label)) AS immutable_equal,
 encode(sha256(convert_to(jsonb_build_array(o.cluster_id,o.node_id,o.entity_type,o.entity_id,o.workspace_id,o.service_id,o.route_id,o.consumer_id,o.business_tags,o.tags_fingerprint,o.config_fingerprint,o.source_pair_hash,o.service_label,o.route_label)::text,'UTF8')),'hex') AS immutable_fingerprint
 FROM metrics_assignment_epochs n JOIN metrics_assignment_epochs o
 ON o.cluster_id=n.cluster_id AND o.node_id=n.node_id AND o.entity_type=n.entity_type AND o.entity_id=n.entity_id
 AND o.closed_at=n.valid_from AND o.valid_from<n.valid_from
 WHERE n.cluster_id=$1 AND n.valid_from BETWEEN ($2::timestamptz-interval '15 seconds') AND $3::timestamptz
 ORDER BY n.valid_from,n.id,o.id LIMIT 257`;

// Time only bounds candidates. Exact sealed hashes, not a timestamp cutoff,
// prove membership in the two original snapshots.
export function reconstructExpiredEpochs(rows,pairs,expected){
  const sha=value=>createHash('sha256').update(JSON.stringify(value)).digest('hex');
  const currentSHA256=sha(rows);
  const fail=reason=>({proved:false,reason,currentCount:rows.length,currentSHA256});
  if(rows.length>10000)return fail('EPOCH_BOUND_EXCEEDED');
  if(rows.length!==expected.afterCount||currentSHA256!==expected.afterSHA256)return fail('CURRENT_SNAPSHOT_DRIFTED');
  if(!Array.isArray(pairs)||pairs.length>256)return fail('PAIR_BOUND_EXCEEDED');
  const groups=new Map();
  for(const pair of pairs){const key=new Date(pair.valid_from).toISOString();if(!groups.has(key))groups.set(key,[]);groups.get(key).push(pair);}
  const matches=[];
  for(const group of groups.values()){
    if(group.length!==7||new Set(group.map(p=>p.new_id)).size!==7||new Set(group.map(p=>p.old_id)).size!==7
      ||group.some(p=>p.new_id===p.old_id||!p.close_matches||!p.expired||!p.immutable_equal||p.close_reason!=='membership_or_proof_changed'
        ||typeof p.immutable_fingerprint!=='string'||!/^[a-f0-9]{64}$/.test(p.immutable_fingerprint)))continue;
    const newIds=new Set(group.map(p=>p.new_id)),oldIds=new Set(group.map(p=>p.old_id));
    if([...newIds].some(id=>oldIds.has(id))||rows.filter(r=>newIds.has(r.id)).length!==7||rows.filter(r=>oldIds.has(r.id)).length!==7)continue;
    const restored=rows.filter(row=>!newIds.has(row.id)).map(row=>oldIds.has(row.id)?{...row,closed_at:null}:row);
    const restoredSHA256=sha(restored);
    if(restored.length===expected.beforeCount&&restoredSHA256===expected.beforeSHA256)
      matches.push({count:restored.length,sha256:restoredSHA256,pairs:group.length});
  }
  if(matches.length!==1)return fail(matches.length?'AMBIGUOUS_RECONSTRUCTION':'BEFORE_HASH_NOT_RECONSTRUCTED');
  return{proved:true,reason:'EXACT_EXPIRED_PROOF_REVALIDATION',currentCount:rows.length,currentSHA256,
    originalCount:matches[0].count,reconstructedBeforeSHA256:matches[0].sha256,uniquePairs:7,
    immutableTuplesEqual:true,strictlyExpired:true,legalCloseBoundary:true,onlyClosedAtRestored:true};
}

function diagnosticRuntime(){
  const{Pool}=require('pg'),fs=require('node:fs');
  const bytes=fs.readFileSync(0);if(bytes.length>4096)process.exit(1);
  const input=JSON.parse(bytes),uuid=value=>typeof value==='string'&&/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(value);
  if(!uuid(input.clusterId)||!Number.isFinite(Date.parse(input.beforeAt))||!Number.isFinite(Date.parse(input.afterAt))
    ||Date.parse(input.afterAt)<Date.parse(input.beforeAt)||!Array.isArray(input.settings)||input.settings.length!==3)process.exit(1);
  (async()=>{const pool=new Pool({connectionString:process.env.DATABASE_URL,connectionTimeoutMillis:5000,query_timeout:10000});let db;
    try{
      db=await pool.connect();await db.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
      await db.query("SET LOCAL TIME ZONE 'UTC'");await db.query("SET LOCAL statement_timeout='10s'");await db.query("SET LOCAL lock_timeout='1s'");
      const role=(await db.query('SELECT rolsuper,rolcreaterole,rolcreatedb,current_setting(\'transaction_read_only\') AS read_only FROM pg_roles WHERE rolname=current_user')).rows[0];
      if(!role||role.rolsuper||role.rolcreaterole||role.rolcreatedb||role.read_only!=='on')throw new Error('RUNTIME_ROLE_INVALID');
      const settings=(await db.query('SELECT cluster_id,credential_generation,catalog_revision FROM metrics_settings ORDER BY cluster_id')).rows;
      const rows=(await db.query(EPOCH_PROJECTION_SQL)).rows;
      if(Buffer.byteLength(JSON.stringify(rows))>8*1024*1024)throw new Error('EPOCH_BOUND_EXCEEDED');
      const currentSHA256=createHash('sha256').update(JSON.stringify(rows)).digest('hex');
      let result={proved:false,reason:'CURRENT_SNAPSHOT_DRIFTED',currentCount:rows.length,currentSHA256};
      if(rows.length===input.expected.afterCount&&currentSHA256===input.expected.afterSHA256){
        const pairs=(await db.query(EXPIRED_EPOCH_PAIR_SQL,[input.clusterId,input.beforeAt,input.afterAt])).rows;
        result=reconstructExpiredEpochs(rows,pairs,input.expected);
      }
      const settingsMatch=JSON.stringify(settings)===JSON.stringify(input.settings);
      let activity=null;
      if(result.proved&&settingsMatch){
        const sql=String.raw`SELECT
         (SELECT count(*)::integer FROM mutation_operations WHERE created_at BETWEEN $1 AND $2 OR updated_at BETWEEN $1 AND $2) AS mutation_rows,
         (SELECT count(*)::integer FROM mutation_operations WHERE remote_started AND (created_at BETWEEN $1 AND $2 OR updated_at BETWEEN $1 AND $2)) AS native_mutation_rows,
         (SELECT count(*)::integer FROM portal_operations WHERE created_at BETWEEN $1 AND $2 OR updated_at BETWEEN $1 AND $2) AS portal_operation_rows,
         (SELECT count(*)::integer FROM workflow_executions WHERE started_at BETWEEN $1 AND $2 OR updated_at BETWEEN $1 AND $2 OR completed_at BETWEEN $1 AND $2) AS execution_rows,
         (SELECT count(*)::integer FROM workflow_steps WHERE started_at BETWEEN $1 AND $2 OR completed_at BETWEEN $1 AND $2) AS workflow_step_rows,
         (SELECT count(*)::integer FROM metrics_write_fences WHERE created_at BETWEEN $1 AND $2 OR settled_at BETWEEN $1 AND $2) AS native_write_fence_rows,
         (SELECT count(*)::integer FROM audit_events WHERE occurred_at BETWEEN $1 AND $2) AS audit_rows,
         (SELECT count(*)::integer FROM audit_events WHERE occurred_at BETWEEN $1 AND $2 AND entity_type NOT IN('authentication','auth_sessions')) AS business_audit_rows`;
        activity=(await db.query(sql,[input.beforeAt,input.afterAt])).rows[0];
      }
      // Readiness legitimately logs authentication/session events; expose their
      // total separately and require every business/native category to be zero.
      const activityEmpty=activity!==null&&Object.entries(activity).filter(([key])=>key!=='audit_rows').every(([,value])=>value===0);
      await db.query('COMMIT');
      const output={...result,settingsMatch,generationsUnchanged:settingsMatch,runtimeNonSuperuser:true,repeatableReadReadOnly:true,
        activity,activityEmpty,allPassed:result.proved&&settingsMatch&&activityEmpty,businessWrites:0,nativeWrites:0};
      const text=JSON.stringify(output);if(Buffer.byteLength(text)>65536)throw new Error('OUTPUT_BOUND_EXCEEDED');process.stdout.write(text);
    }finally{if(db){try{await db.query('ROLLBACK');}catch{}db.release();}await pool.end();}
  })().catch(error=>{const safe=new Set(['RUNTIME_ROLE_INVALID','EPOCH_BOUND_EXCEEDED','OUTPUT_BOUND_EXCEEDED']);
    process.stdout.write(JSON.stringify({allPassed:false,reason:safe.has(error.message)?error.message:'READONLY_DIAGNOSTIC_FAILED',
      ...(typeof error.code==='string'&&/^[0-9A-Z]{5}$/.test(error.code)?{sqlState:error.code}:{}),businessWrites:0,nativeWrites:0}));process.exitCode=1;});
}

export const METRICS_DIAGNOSTIC_PROGRAM="const{createHash}=require('node:crypto');const EPOCH_PROJECTION_SQL="+JSON.stringify(EPOCH_PROJECTION_SQL)
  +';const EXPIRED_EPOCH_PAIR_SQL='+JSON.stringify(EXPIRED_EPOCH_PAIR_SQL)+';const reconstructExpiredEpochs='+reconstructExpiredEpochs.toString()+';('+diagnosticRuntime.toString()+')();';

export function metadataRestoreDiagnosticContext(sealedBytes){
  const sealed=JSON.parse(sealedBytes),before=sealed.before?.foundation?.core,after=sealed.after?.foundation?.core;
  if(createHash('sha256').update(sealedBytes).digest('hex')!=='4c0356e4d11c7676a5db7bf99e8ac292ef90fc41d381d1ad3670af729463f00e'
    ||sealed.allPassed!==false||!Array.isArray(sealed.checks)||sealed.checks.filter(row=>!row.passed).length!==1
    ||sealed.checks.find(row=>!row.passed).name!=='monitoring generations/catalog revisions and immutable epochs unchanged'
    ||!before||!after||!/^[a-f0-9]{64}$/.test(after.api.id)||before.database.epochCount!==2335||after.database.epochCount!==2342
    ||before.database.epochIdentitySHA256!=='a183d84bc9b6e565cc743c975bd5b72954167873277a9fcb0a8993aeb21fae51'
    ||after.database.epochIdentitySHA256!=='056ce1e4958c5719c9cb8b60476a5923b280af85211dd4aa9aefc43019d0144a')throw new Error('SEALED_FAILURE_INVALID');
  const input={clusterId:'d1dfaec8-2a10-4170-8a15-20a600a4bd4f',beforeAt:before.observedAt,afterAt:after.observedAt,
    settings:after.database.settings,expected:{beforeCount:2335,afterCount:2342,beforeSHA256:before.database.epochIdentitySHA256,afterSHA256:after.database.epochIdentitySHA256}};
  return{sealed,input,apiId:after.api.id};
}
export function metadataRestoreMetricsDiagnostic(){
  const sealedPath='artifacts/M6/portal-metadata-restore-repair-continuity.json',output='artifacts/M6/portal-metadata-restore-metrics-readonly-diagnostic.json';
  if(existsSync(output))throw new Error('READONLY_DIAGNOSTIC_ALREADY_RECORDED');
  const sealedBytes=readFileSync(sealedPath),{sealed,input,apiId}=metadataRestoreDiagnosticContext(sealedBytes);
  const startedAt=new Date().toISOString();let result;
  try{
    const env={...process.env};for(const key of ['DOCKER_HOST','DOCKER_CONTEXT','DOCKER_TLS','DOCKER_TLS_VERIFY','DOCKER_CERT_PATH'])delete env[key];
    const raw=execFileSync('docker',['--host=unix:///var/run/docker.sock','exec','-i',apiId,'node','-e',METRICS_DIAGNOSTIC_PROGRAM],
      {env,input:JSON.stringify(input),encoding:'utf8',stdio:['pipe','pipe','pipe'],timeout:15000,maxBuffer:65536});
    result=JSON.parse(raw);
  }catch(error){
    result={allPassed:false,reason:'READONLY_EXECUTION_FAILED',businessWrites:0,nativeWrites:0};
    if(typeof error.stdout==='string'&&Buffer.byteLength(error.stdout)<=65536){try{const safe=JSON.parse(error.stdout);if(safe?.allPassed===false&&typeof safe.reason==='string'&&/^[A-Z_]{1,64}$/.test(safe.reason))result=safe;}catch{}}
  }
  const artifact={stage:'M6',label:'portal-metadata-restore-metrics-readonly-diagnostic',startedAt,endedAt:new Date().toISOString(),
    scope:'One runtime-role READ ONLY transaction; sealed deployment remains failed and unmodified',
    sourceSHA256:createHash('sha256').update(readFileSync(fileURLToPath(import.meta.url))).digest('hex'),
    programSHA256:createHash('sha256').update(METRICS_DIAGNOSTIC_PROGRAM).digest('hex'),
    sealedContinuitySHA256:createHash('sha256').update(sealedBytes).digest('hex'),
    expectedBeforeSHA256:input.expected.beforeSHA256,expectedAfterSHA256:input.expected.afterSHA256,
    materialAndPrivateBytesPreviouslyProved:sealed.checks.filter(row=>/private|material/.test(row.name)).every(row=>row.passed),
    runtimeTransactions:1,builds:0,restarts:0,migrations:0,businessWrites:0,nativeWrites:0,...result};
  const text=JSON.stringify(artifact,null,2)+'\n';if(Buffer.byteLength(text)>65536)throw new Error('OUTPUT_BOUND_EXCEEDED');
  writeFileSync(output,text,{flag:'wx'});console.log(JSON.stringify({allPassed:artifact.allPassed,reason:artifact.reason,currentCount:artifact.currentCount,output}));
  if(!artifact.allPassed)process.exitCode=1;
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  try{if(process.argv.length!==2)throw new Error('ARGUMENTS_INVALID');metadataRestoreMetricsDiagnostic();}
  catch{console.error('READONLY_DIAGNOSTIC_FAILED; raw errors withheld.');process.exitCode=1;}
}
