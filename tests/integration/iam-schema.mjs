import { execFileSync } from 'node:child_process';
import { readFileSync,readdirSync,mkdirSync,writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { randomUUID } from 'node:crypto';

// A disposable database proves real constraints, including deferred commits and the grant view.
const root=resolve('.'),dir=resolve(root,'apps/console-api/src/infrastructure/migrations');
const name=`kongos-iam-schema-${randomUUID().slice(0,8)}`,checks=[];
const ids={c1:'30000000-0000-4000-8000-000000000001',c2:'30000000-0000-4000-8000-000000000002',w1:'30000000-0000-4000-8000-000000000011',w2:'30000000-0000-4000-8000-000000000012',u:'30000000-0000-4000-8000-000000000021',s:'30000000-0000-4000-8000-000000000022',r:'30000000-0000-4000-8000-000000000031',t:'30000000-0000-4000-8000-000000000041',p:'30000000-0000-4000-8000-000000000051',e:'30000000-0000-4000-8000-000000000061'};
function sql(input){return execFileSync('docker',['exec','-i',name,'psql','-h','127.0.0.1','-X','-q','-A','-t','-v','ON_ERROR_STOP=1','-U','postgres'],{input,encoding:'utf8',stdio:['pipe','pipe','pipe']}).trim();}
function check(label,fn){fn();checks.push({name:label,passed:true});}
function eq(query,value){if(sql(query)!==String(value))throw new Error('SQL assertion failed');}
function rejected(statement,code){try{sql(statement);throw new Error('Constraint did not reject invalid data');}catch(error){if(!String(error.stderr??'').includes(code))throw new Error(`Expected constraint ${code}`);}}
try{
 execFileSync('docker',['run','-d','--name',name,'--network','none','-e','POSTGRES_HOST_AUTH_METHOD=trust','postgres:16-alpine'],{stdio:'ignore'});
 for(let i=0;i<50;i++){try{sql('SELECT 1');break;}catch{await new Promise(r=>setTimeout(r,100));if(i===49)throw new Error('Disposable PostgreSQL unavailable');}}
 const files=readdirSync(dir).filter(file=>/^\d+_.*\.sql$/.test(file)).sort();
 for(const file of files.filter(f=>f<'005_'))sql(readFileSync(resolve(dir,file),'utf8'));
 sql(`INSERT INTO users(id,username,password_hash,super_admin) VALUES('${ids.u}','iam-user','synthetic-non-login-hash',false),('${ids.s}','legacy-super','synthetic-non-login-hash',true);
 INSERT INTO clusters(id,name,admin_url) VALUES('${ids.c1}','test-a','http://kong-a:8001'),('${ids.c2}','test-b','http://kong-b:8001');
 INSERT INTO workspaces(id,cluster_id,code,name) VALUES('${ids.w1}','${ids.c1}','pay','pay'),('${ids.w2}','${ids.c2}','ops','ops');`);
 sql(readFileSync(resolve(dir,'005_m4_iam.sql'),'utf8'));
 for(const file of files.filter(f=>f>'005_m4_iam.sql'))sql(readFileSync(resolve(dir,file),'utf8'));
 check('all migrations execute and legacy administrator gets a direct protected binding',()=>eq(`SELECT count(*) FROM user_role_bindings b JOIN roles r ON r.id=b.role_id WHERE b.user_id='${ids.s}' AND r.builtin_kind='super-admin'`,1));
 check('six distinct workspace builtin instances cannot share owners',()=>eq("SELECT count(*) FROM roles WHERE workspace_id IS NOT NULL",6));
 check('readonly builtins have no secret-reading permission',()=>eq("SELECT count(*) FROM role_permissions p JOIN roles r ON r.id=p.role_id WHERE r.builtin_kind IN ('read-only','workspace-read-only') AND p.module='secrets'",0));
 check('workspace builtin permissions always retain exact cluster and workspace ceilings',()=>eq("SELECT count(*) FROM role_permissions p JOIN roles r ON r.id=p.role_id WHERE r.workspace_id IS NOT NULL AND (p.cluster_id IS DISTINCT FROM r.cluster_id OR p.workspace_id IS DISTINCT FROM r.workspace_id)",0));
 check('cross-cluster workspace FK rejects forged ownership',()=>rejected(`INSERT INTO teams(code,name,cluster_id,workspace_id) VALUES('forged','forged','${ids.c1}','${ids.w2}')`,'foreign key constraint'));
 check('workspace role cannot bind another workspace',()=>rejected(`INSERT INTO user_role_bindings(user_id,role_id,cluster_id,workspace_id) SELECT '${ids.u}',id,'${ids.c2}','${ids.w2}' FROM roles WHERE workspace_id='${ids.w1}' AND builtin_kind='workspace-admin'`,'workspace role binding must match'));
 check('super-admin cannot be granted through a team',()=>{
  sql(`INSERT INTO teams(id,code,name) VALUES('${ids.t}','team','team')`);
  rejected(`INSERT INTO team_role_bindings(team_id,role_id) SELECT '${ids.t}',id FROM roles WHERE builtin_kind='super-admin'`,'super-admin cannot be team-bound');
 });
 check('incomplete tag permissions fail at deferred transaction commit',()=>{
  sql(`INSERT INTO roles(id,code,name) VALUES('${ids.r}','tuple-test','tuple-test')`);
  rejected(`BEGIN;INSERT INTO role_permissions(role_id,module,action,scope_type,cluster_id) VALUES('${ids.r}','services','read','tag_group','${ids.c1}');COMMIT;`,'permission values do not match');
 });
 check('tag and typed entity scopes remain separate complete grant rows',()=>{
  sql(`BEGIN;INSERT INTO role_permissions(id,role_id,module,action,scope_type,cluster_id) VALUES('${ids.p}','${ids.r}','services','read','tag_group','${ids.c1}');
  INSERT INTO role_permission_tags(permission_id,logical_tag,physical_tag) VALUES('${ids.p}','team:pay','kos-tag-dGVhbTpwYXk');
  INSERT INTO role_permissions(role_id,module,action,scope_type,cluster_id) VALUES('${ids.r}','routes','delete','entity','${ids.c1}');
  INSERT INTO role_permission_entities(permission_id,entity_type,entity_id) SELECT id,'routes','${ids.e}' FROM role_permissions WHERE role_id='${ids.r}' AND module='routes';
  INSERT INTO user_role_bindings(user_id,role_id,cluster_id,workspace_id) VALUES('${ids.u}','${ids.r}','${ids.c1}','${ids.w1}');COMMIT;`);
  eq(`SELECT count(*) FROM iam_effective_grants WHERE user_id='${ids.u}'`,2);
  eq(`SELECT count(*) FROM iam_effective_grants WHERE user_id='${ids.u}' AND module='services' AND action='delete'`,0);
  eq(`SELECT count(*) FROM iam_effective_grants WHERE user_id='${ids.u}' AND workspace_id='${ids.w1}' AND jsonb_array_length(scope_values)=1`,2);
 });
 check('pairwise inconsistent binding and permission ceilings yield no cross-cluster grant',()=>{
  sql(`INSERT INTO user_role_bindings(user_id,role_id,cluster_id,workspace_id) VALUES('${ids.u}','${ids.r}','${ids.c2}','${ids.w2}')`);
  eq(`SELECT count(*) FROM iam_effective_grants WHERE user_id='${ids.u}' AND cluster_id='${ids.c2}'`,0);
 });
 check('team membership removal immediately removes grants and bumps epoch',()=>{
  const before=Number(sql('SELECT version FROM iam_epoch WHERE singleton'));
  sql(`INSERT INTO team_members(team_id,user_id) VALUES('${ids.t}','${ids.u}');
  INSERT INTO team_role_bindings(team_id,role_id,cluster_id,workspace_id) SELECT '${ids.t}',id,'${ids.c2}','${ids.w2}' FROM roles WHERE builtin_kind='workspace-read-only' AND workspace_id='${ids.w2}';`);
  eq(`SELECT count(*)>0 FROM iam_effective_grants WHERE user_id='${ids.u}' AND binding_source='team' AND workspace_id='${ids.w2}'`,'t');
  sql(`UPDATE team_members SET status='revoked',revoked_at=now(),retention_until=now()+interval '30 days' WHERE team_id='${ids.t}' AND user_id='${ids.u}'`);
  eq(`SELECT count(*) FROM iam_effective_grants WHERE user_id='${ids.u}' AND binding_source='team'`,0);
  if(Number(sql('SELECT version FROM iam_epoch WHERE singleton'))<=before)throw new Error('Epoch did not change');
 });
 check('soft-deleted role code cannot be reused',()=>{
  sql("INSERT INTO roles(code,name,status,deleted_at,retention_until) VALUES('reserved','reserved','deleted',now(),now()+interval '30 days')");
  rejected("INSERT INTO roles(code,name) VALUES('reserved','reuse')",'unique constraint');
 });
 check('all IAM resource deletions are physically blocked',()=>{
  rejected(`DELETE FROM users WHERE id='${ids.u}'`,'must be soft-deleted');
  rejected(`DELETE FROM role_permission_tags WHERE permission_id='${ids.p}'`,'must be soft-deleted');
 });
 check('global audit cannot claim a workspace without its cluster',()=>rejected(`INSERT INTO iam_operations(actor_id,idempotency_key,request_hash,module,action,workspace_id,payload_secret) VALUES('${ids.u}','bad-ws','${'a'.repeat(64)}','roles','write','${ids.w1}','synthetic-ciphertext')`,'check constraint'));
 check('external subjects remain reserved after revocation',()=>{
  sql(`INSERT INTO auth_identities(user_id,provider_type,provider_key,subject,status,revoked_at,retention_until) VALUES('${ids.u}','oidc','provider','subject','revoked',now(),now()+interval '30 days')`);
  rejected(`INSERT INTO auth_identities(user_id,provider_type,provider_key,subject) VALUES('${ids.s}','oidc','provider','subject')`,'unique constraint');
 });
 check('new bootstrap administrator and future workspace receive builtin bindings/instances',()=>{
  sql("INSERT INTO users(id,username,password_hash,super_admin) VALUES(gen_random_uuid(),'new-bootstrap','synthetic-non-login-hash',true);INSERT INTO workspaces(cluster_id,code,name) VALUES('30000000-0000-4000-8000-000000000001','future','future')");
  eq("SELECT count(*) FROM user_role_bindings b JOIN users u ON u.id=b.user_id JOIN roles r ON r.id=b.role_id WHERE u.username='new-bootstrap' AND r.builtin_kind='super-admin'",1);
  eq("SELECT count(*) FROM roles r JOIN workspaces w ON w.id=r.workspace_id WHERE w.code='future'",3);
 });
 check('malformed transport scope is rejected',()=>rejected(`UPDATE clusters SET transport_scope='not-a-hash' WHERE id='${ids.c1}'`,'check constraint'));
 check('IAM success receipt cannot be confused with unresolved commit',()=>rejected(`INSERT INTO iam_operations(actor_id,idempotency_key,request_hash,module,action,state,remote_completed,payload_secret) VALUES('${ids.u}','bad-result','${'a'.repeat(64)}','roles','write','uncertain',true,'synthetic-ciphertext')`,'check constraint'));
 check('derived child navigation accepts only typed upstream/consumer relationships',()=>{
  sql(`INSERT INTO entity_parent_index(cluster_id,child_type,child_id,parent_type,parent_id) VALUES('${ids.c1}','targets','${ids.e}','upstreams','${ids.r}')`);
  eq(`SELECT count(*) FROM entity_parent_index WHERE cluster_id='${ids.c1}' AND child_type='targets'`,1);
 });
 check('target navigation cannot claim a Consumer parent',()=>rejected(`INSERT INTO entity_parent_index(cluster_id,child_type,child_id,parent_type,parent_id) VALUES('${ids.c1}','targets',gen_random_uuid(),'consumers','${ids.r}')`,'check constraint'));
 check('credential navigation cannot claim an Upstream parent',()=>rejected(`INSERT INTO entity_parent_index(cluster_id,child_type,child_id,parent_type,parent_id) VALUES('${ids.c1}','basic-auth',gen_random_uuid(),'upstreams','${ids.r}')`,'check constraint'));
 check('child navigation cannot reference a nonexistent console cluster',()=>rejected(`INSERT INTO entity_parent_index(cluster_id,child_type,child_id,parent_type,parent_id) VALUES(gen_random_uuid(),'jwt',gen_random_uuid(),'consumers','${ids.r}')`,'foreign key constraint'));
 check('native entity types cannot be forged as credential navigation rows',()=>rejected(`INSERT INTO entity_parent_index(cluster_id,child_type,child_id,parent_type,parent_id) VALUES('${ids.c1}','plugins',gen_random_uuid(),'consumers','${ids.r}')`,'check constraint'));
 check('derived navigation contains identifiers only and no secret/config column',()=>eq("SELECT count(*) FROM information_schema.columns WHERE table_name='entity_parent_index' AND column_name IN ('config','password','key','secret','payload')",0));
 mkdirSync(resolve(root,'artifacts/M4'),{recursive:true});writeFileSync(resolve(root,'artifacts/M4/iam-postgres-constraints.json'),JSON.stringify({stage:'M4',database:'disposable PostgreSQL16 (network none)',passed:checks.length,checks},null,2));
 console.log(`IAM PostgreSQL constraints: ${checks.length}/${checks.length} passed`);
}finally{execFileSync('docker',['rm','-f',name],{stdio:'ignore'});}
