import { execFileSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';

// Read-only preparation for the two preserved M4 receipts. No encrypted payload,
// names, credentials or native object data are selected by this probe.
const operationIds = ['0def576d-c305-487d-a431-43b861d1d6aa', '7066ab74-a87e-47ec-94a5-dc7271b522c9'];
const compose = ['compose', '--env-file', '.env', '--env-file', '.env.multicluster', '-f', 'docker-compose.yml', '-f', 'deploy/compose/compose.development.yml', '-f', 'deploy/compose/compose.multicluster-test.yml', '--profile', 'multicluster-test'];
const code = `const {Pool}=require('pg');const fs=require('fs');
(async()=>{const ids=JSON.parse(fs.readFileSync(0,'utf8')).operationIds;const pool=new Pool({connectionString:process.env.DATABASE_URL});
try{const operations=(await pool.query('SELECT id,cluster_id,workspace_id,entity_type,entity_id,action,state,remote_started,remote_completed,error_code,created_at,updated_at FROM mutation_operations WHERE id=ANY($1::uuid[]) ORDER BY id',[ids])).rows;
const results=[];
for(const operation of operations){const entries=(await pool.query('SELECT id,cluster_id,workspace_id,root_type,original_id,state,node_count,mutation_id,created_at,updated_at,restored_at,purged_at FROM recycle_entries WHERE mutation_id=$1 OR (cluster_id=$2 AND root_type=$3 AND original_id=$4) ORDER BY created_at LIMIT 51',[operation.id,operation.cluster_id,operation.entity_type,operation.entity_id])).rows;
if(entries.length>50)throw new Error('BOUND_EXCEEDED');
for(const entry of entries){entry.match=entry.mutation_id===operation.id?'mutation_id':'same_cluster_type_original_id';entry.nodeStates=(await pool.query('SELECT entity_type,affected,delete_state,restore_state,count(*)::integer AS count FROM recycle_nodes WHERE entry_id=$1 GROUP BY entity_type,affected,delete_state,restore_state ORDER BY entity_type,affected,delete_state,restore_state',[entry.id])).rows;}
results.push({operation,entries});}
console.log(JSON.stringify(results));}finally{await pool.end();}})().catch(()=>{process.stderr.write('SAFE_ENTRY_PREFLIGHT_FAILED\\n');process.exit(1);});`;
try {
  const operations = JSON.parse(execFileSync('docker', [...compose, 'exec', '-T', 'console-api', 'node', '-e', code], { input: JSON.stringify({ operationIds }), encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'], timeout: 15_000 }));
  const result = { stage: 'M5', observedAt: new Date().toISOString(), kind: 'read-only legacy receipt and relational recycle-node metadata; no encrypted payload selected or decrypted', operations, allSelectedOperationsFound: operations.length === operationIds.length };
  mkdirSync('artifacts/M5', { recursive: true });
  writeFileSync('artifacts/M5/legacy-mutation-entry-preflight.json', JSON.stringify(result, null, 2) + '\n');
  console.log(JSON.stringify(result));
  if (!result.allSelectedOperationsFound) process.exitCode = 1;
} catch { console.error('METRICS_ENTRY_PREFLIGHT_FAILED: no database error or credentials were printed.'); process.exitCode = 1; }
