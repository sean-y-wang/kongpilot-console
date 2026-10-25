import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {createRequire} from 'node:module';

const require=createRequire('/app/apps/console-api/package.json'),{Pool}=require('pg');
assert.equal(process.env.RELEASE_LAB_READY,'true');
assert.equal(process.env.RELEASE_LAB_M11_TARGET_RESULT_DDL_TRIAL_READY,'true');
assert.equal(process.env.RELEASE_LAB_CONTAINER,'kongpilot-release-lab-m11-target-result-ddl-trial');
const role=process.env.M11_RUNTIME_ROLE;
assert(role&&/^[a-z_][a-z\d_]{2,62}$/.test(role));
const sql=readFileSync('/tmp/026_m11_workflow_schedules.sql','utf8');
assert.equal(createHash('sha256').update(sql).digest('hex'),process.env.M11_BUSINESS_DDL_CHECKSUM);
const targetSql=readFileSync('/tmp/027_m11_target_result_observations.sql','utf8');assert.equal(createHash('sha256').update(targetSql).digest('hex'),process.env.M11_TARGET_RESULT_DDL_CHECKSUM);
const immutable=['entity_change_target_result_observations','workflow_executor_delegations','workflow_schedules','workflow_schedule_activations','workflow_schedule_claims',
 'workflow_schedule_leases','workflow_schedule_outcomes','workflow_schedule_events','workflow_execution_origins','workflow_configuration_execution_origins'];
const pool=new Pool({connectionString:process.env.DATABASE_URL??process.env.CONSOLE_DATABASE_URL});
const report={passed:false,sourceOnly:false,productionDeployment:false,overallM11Accepted:false,nativeRequestsSent:0,
 migrationCommitted:false,trialRolledBack:false,checks:[]};
const client=await pool.connect();
try{
 const before=(await client.query('SELECT name,checksum FROM schema_migrations ORDER BY name')).rows;
 assert.equal(before.length,26);assert(!before.some(row=>row.name==='026_m11_workflow_schedules.sql'));
 await client.query('BEGIN');await client.query("SET LOCAL statement_timeout='15000ms'");
 await client.query(sql);await client.query(targetSql);report.checks.push({name:'actual PostgreSQL parses 026 then 027 against original 000–025 schema',passed:true});
 for(const table of immutable){
  await client.query(`REVOKE ALL ON TABLE public.${table} FROM ${role}`);
  await client.query(`GRANT SELECT, INSERT ON TABLE public.${table} TO ${role}`);
 }
 await client.query(`REVOKE ALL ON TABLE public.workflow_schedule_progress FROM ${role}`);
 await client.query(`GRANT SELECT, INSERT, UPDATE ON TABLE public.workflow_schedule_progress TO ${role}`);
 const privileges=await client.query(`SELECT t.table_name,p.privilege,has_table_privilege($1,'public.'||t.table_name,p.privilege) AS allowed
  FROM unnest($2::text[]) AS t(table_name) CROSS JOIN unnest(ARRAY['SELECT','INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER']) AS p(privilege)
  ORDER BY t.table_name,p.privilege`,[role,[...immutable,'workflow_schedule_progress']]);
 for(const row of privileges.rows)assert.equal(row.allowed,['SELECT','INSERT'].includes(row.privilege)||row.table_name==='workflow_schedule_progress'&&row.privilege==='UPDATE');
 report.runtimePrivilegeMatrix=privileges.rows;report.checks.push({name:'ten fact tables append only and progress cannot be deleted',passed:true});
 for(const table of immutable){
  await client.query('SAVEPOINT role_denial');await client.query(`SET LOCAL ROLE ${role}`);
  let denied=false;try{await client.query(`UPDATE public.${table} SET cluster_id=cluster_id WHERE false`);}catch(error){assert.equal(error.code,'42501');denied=true;}
  assert(denied);await client.query('ROLLBACK TO SAVEPOINT role_denial');
 }
 report.checks.push({name:'actual restricted runtime role receives 42501 on immutable UPDATE',passed:true});
 await client.query('SAVEPOINT original_uncertain_guard');
 let originalDenied=false;try{await client.query("UPDATE mutation_operations SET state='succeeded' WHERE id=$1 AND state='uncertain'",['d970379e-2a28-4e92-8498-fe76213ffba5']);}catch(error){assert.equal(error.code,'23514');originalDenied=true;}
 assert(originalDenied);await client.query('ROLLBACK TO SAVEPOINT original_uncertain_guard');report.checks.push({name:'original actual V3 Target uncertain result cannot be marked succeeded without authenticated observation',passed:true});
 await client.query('ROLLBACK');report.trialRolledBack=true;
 const after=(await client.query('SELECT name,checksum FROM schema_migrations ORDER BY name')).rows;assert.deepEqual(after,before);
 const absence=(await client.query("SELECT to_regclass('public.workflow_schedules') AS name")).rows[0];assert.equal(absence.name,null);
 report.originalLedgerUnchanged=true;report.checks.push({name:'DDL, trial grants and all new tables rolled back; original ledger untouched',passed:true});report.passed=true;
}catch(error){report.safeFailure={kind:error.name,code:error.code??null};try{await client.query('SAVEPOINT original_uncertain_guard');
 let originalDenied=false;try{await client.query("UPDATE mutation_operations SET state='succeeded' WHERE id=$1 AND state='uncertain'",['d970379e-2a28-4e92-8498-fe76213ffba5']);}catch(error){assert.equal(error.code,'23514');originalDenied=true;}
 assert(originalDenied);await client.query('ROLLBACK TO SAVEPOINT original_uncertain_guard');report.checks.push({name:'original actual V3 Target uncertain result cannot be marked succeeded without authenticated observation',passed:true});
 await client.query('ROLLBACK');report.trialRolledBack=true;}catch{}process.exitCode=1;
}finally{client.release();await pool.end();console.log(JSON.stringify(report));}
