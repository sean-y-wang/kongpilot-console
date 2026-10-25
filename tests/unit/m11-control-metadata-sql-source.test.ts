import {createHash} from 'node:crypto';
import {readFileSync,readdirSync} from 'node:fs';
import {resolve} from 'node:path';
import {describe,expect,it} from 'vitest';

const directory=resolve(process.cwd(),'apps/console-api/src/infrastructure/migrations');
const source=readFileSync(resolve(directory,'033_m11_control_metadata_approvals.sql'),'utf8');
const compact=(s:string)=>s.replace(/--[^\n]*/g,'').replace(/\s+/g,' ').trim();
const code=compact(source);
const frozen=[
 ['000_m0.sql','02f171ea1ff6dd64d12840e36681b315cec9665552aa3b8acdf72319a1c2fd96'],
 ['001_m1.sql','ef2e738577ae5321ddfdbd69c315a820e7dfa2bfcbef59176a2a8b9491b3fee6'],
 ['002_m1_index.sql','bd67be44dd80554872943d8ef3bac85757f2790f965e31a9ff996e380b1f7663'],
 ['003_m1_index_cycles.sql','dc695f4006e0839104df4b4108fc4426ca0670d6c7fa4083b1f29032ad751bf6'],
 ['004_m3_workspaces.sql','263301537a1bbbdce62fafe44bc9a40589f6b450c9f4f0c787879a252752d501'],
 ['005_m4_iam.sql','1ab35fdca5b4724af18f1287936c6eced21061ae5605f19b455acabc69f06d22'],
 ['006_m4_child_navigation.sql','d5e89915b7192efcdb32e3a9b729543d44c8691d3cc957fc457b9bc1a42e6c01'],
 ['007_m5_metrics.sql','e301a76f25c74a72e6599e1c735b152b981bd4df20bfc6f57b3b18c2f59887bf'],
 ['008_m6_portal.sql','241444c9f85ea30bc09f6a4a93ded051acc5692317068a1e68814c92d9f520bc'],
 ['009_m6_failed_issue_abandonment.sql','39b2eaf3f0554407114add04aa90a2f197f8cb23b2991077cdc7e018f9dba7fd'],
 ['010_m7_events.sql','32e46c977d121449795cb7af82ce028d6a121e859f452df7fd3534adc06a8a53'],
 ['011_m8_configuration.sql','99131280ca62d17e22093ac31449a5f07c98f76321ea54aef93d028de7ba1b1a'],
 ['012_m9_toolbox.sql','bbd6c5ca35d6e98545ccd61594969e0ccc78acb5e871276499a4418928737631'],
 ['013_m9_cache_key_constraint.sql','65dd6e62f80c3677dd2b357ed584fa79427fb180e5939f60eb236cbf1a365cc5'],
 ['014_m9_configuration_recycle_graphs.sql','f6a0fd59d1311471f9dc9439303a881e59d80d3032be37eef63337c77d8f47c2'],
 ['015_m9_configuration_recycle_workspaces.sql','679d3d498c3c467735221980537d8e163d19385a6034a56ef87f9d44a7a00349'],
 ['016_m9_workspace_migration_workflow.sql','e98a1afa0c42f182ae8b4ad7d2f2f06c0531a5cf07bd7d8c52cf55c4cc1dac38'],
 ['017_m10_governance.sql','677510dd14357029d4e69933c295472c1600e0c31ff7e75a869a52ca82846ec8'],
 ['018_m10_configuration_origins.sql','41c60fea0f26f9e2758acdae2c39a71e7945a27c53ed6159e26bff2574ad92d7'],
 ['019_m11_approval_policy.sql','a78c530fa0eb0078ed196217c8ccb5819afbacb1744611c8769da15e421f0fdb'],
 ['020_m11_durable_entity_intents.sql','d220ee5401d5b704f0dd189ef6d9763d3591fbede52f5cf5a236deddd04cccce'],
 ['021_m11_entity_execution_facts.sql','133756b722dae11085d20e1a419378e821fcae0c66e7a721350344e63b4a2956'],
 ['022_m11_baseline_trigger_alias_fix.sql','8abdc8219e82f3932f0d0bdd7a6c2eddd389e1d29d9fcd6d5e306b50f4f7d5f4'],
 ['023_m11_entity_recycle_facts.sql','9960455dd685da0e528f9f6f2280a4a18b80e812090182742341b9e831ea36eb'],
 ['024_m11_entity_schedules.sql','3b918d1d7f328bfa4c1a5ffa72720ad755dc0aaa11cfa3393dd3b4b297f3955f'],
 ['025_m11_partial_recycle_restore.sql','72b19980dfd3d5cda3370d89a05994f35d557cecf7e8ceb8218315864c419534'],
 ['026_m11_workflow_schedules.sql','a447e5027a9045d2bd72795ed1892de96f1d01a068960cfe03b41f5ca0f46ca4'],
 ['027_m11_target_result_observations.sql','967ee9e56c57ba7be4f4c558c33ed6a5af8a683a316db234443d04375d8c169f'],
 ['028_m11_scheduled_execution_permission.sql','45a3e58fa1dc6ba94408af1abf9090c77e0ecda71c385fc6b09790e5f67a512f'],
 ['029_m11_business_schedule_revisions.sql','1f7beb3f6b2a3beea3edf85c262c5626a3f060e2dcb1b6cfe411999ee0663156'],
 ['030_m11_iam_metadata_approvals.sql','325dccb2f170e56503ad8a2f4ca0b3f1b5598497babed2d3d2842ae863535a65'],
 ['031_m11_target_health_facts.sql','e460c0bb160ec5684c330dbb58e89bde6ec8869673cfa636dc782f5fc89ab3a5'],
 ['032_m11_metrics_setup_approvals.sql','b1fb7d43bf561f422136fb2d8fe5f99598cbd1214467280a9a1035b573f13ff1'],
] as const;

function body(name:string,candidate=source):string {
 const signature=new RegExp(`CREATE FUNCTION ${name}\\(\\)`).exec(candidate);
 if(!signature)throw new Error(`Missing function ${name}`);
 const open=candidate.indexOf('AS $$',signature.index),close=candidate.indexOf('$$;',open+5);
 if(open<0||close<0)throw new Error('Unclosed SQL body');return compact(candidate.slice(open+5,close));
}
function requirePredicates(candidate:string,predicates:readonly string[]):void {
 for(const predicate of predicates)if(!candidate.includes(predicate))throw new Error(`Missing rejection predicate ${predicate}`);
}
function parenthesized(candidate:string,opening:number):{body:string;end:number} {
 let depth=0,quote=false;
 for(let at=opening;at<candidate.length;at++) {
  if(candidate[at]==="'"){if(quote&&candidate[at+1]==="'"){at++;continue;}quote=!quote;}
  if(quote)continue;if(candidate[at]==='(')depth++;
  if(candidate[at]===')'&&--depth===0)return {body:candidate.slice(opening+1,at),end:at+1};
 }throw new Error('Unclosed SQL parentheses');
}
function pieces(candidate:string):string[] {
 const result:string[]=[];let start=0;
 for(let at=0;at<candidate.length;at++) {
  if(candidate[at]==="'"){for(at++;at<candidate.length;at++){if(candidate[at]==="'"&&candidate[at+1]==="'")at++;else if(candidate[at]==="'")break;}}
  else if(candidate[at]==='(')at=parenthesized(candidate,at).end-1;
  else if(candidate[at]===','){result.push(candidate.slice(start,at).trim());start=at+1;}
 }result.push(candidate.slice(start).trim());return result;
}
type Table={columns:Map<string,string>;unique:string[][]};
function actualSchema():Map<string,Table> {
 const schema=new Map<string,Table>();
 const add=(table:Table,part:string)=>{
  const column=/^(\w+)\s+(uuid|text|bigint|integer|smallint|boolean|jsonb|timestamptz)(\[\])?\b/i.exec(part);
  if(column){table.columns.set(column[1],column[2]+(column[3]??''));if(/\b(?:PRIMARY KEY|UNIQUE)\b/.test(part))table.unique.push([column[1]]);}
  else {const key=/^(?:CONSTRAINT\s+\w+\s+)?(?:PRIMARY KEY|UNIQUE)\s*\(([^)]+)\)/i.exec(part);if(key)table.unique.push(key[1].split(',').map(x=>x.trim()));}
 };
 for(const name of readdirSync(directory).filter(n=>/^\d{3}_.*\.sql$/.test(n)&&Number(n.slice(0,3))<=33).sort()) {
  const ddl=readFileSync(resolve(directory,name),'utf8').replace(/--[^\n]*/g,'').replace(/(\$(?:\w+)?\$)[\s\S]*?\1/g,'');
  for(const m of ddl.matchAll(/CREATE TABLE\s+(?:IF NOT EXISTS\s+)?(\w+)\s*\(/gi)){const table={columns:new Map<string,string>(),unique:[] as string[][]};pieces(parenthesized(ddl,m.index!+m[0].length-1).body).forEach(p=>add(table,p));schema.set(m[1],table);}
  for(const m of ddl.matchAll(/ALTER TABLE\s+(\w+)\s+ADD\s+(?:COLUMN\s+)?([^;]+);/gi)){const table=schema.get(m[1]);if(table)add(table,m[2].trim());}
  for(const m of ddl.matchAll(/CREATE UNIQUE INDEX\s+\w+\s+ON\s+(\w+)\s*\(([^;]+)\);/gi)){if(!/\bWHERE\b/i.test(m[2])&&/^[\w\s,]+$/.test(m[2]))schema.get(m[1])?.unique.push(m[2].split(',').map(x=>x.trim()));}
 }return schema;
}
const authorPredicates=[
 's.user_id IS DISTINCT FROM u.id','s.revoked_at IS NOT NULL','s.expires_at<=now()',
 's.credential_epoch IS DISTINCT FROM u.credential_epoch','NEW.credential_epoch IS DISTINCT FROM u.credential_epoch',
 "NEW.permission_version IS DISTINCT FROM (u.id::text||':'||u.permissions_epoch::text||':'||epoch::text)",
 "c.execution_mode<>'approval'","anchor.status<>'active'",'NEW.expires_at>s.expires_at',
 'NEW.before_revision IS DISTINCT FROM c.revision','ds.revision IS DISTINCT FROM NEW.before_revision','target.revision IS DISTINCT FROM NEW.before_revision',
] as const;
const graphPredicates=[
 "w.subject_type IS DISTINCT FROM 'control_metadata_requests'","w.requester_user_id IS DISTINCT FROM i.actor_id",
 "w.execution_mode IS DISTINCT FROM 'approval'",'w.approval_format IS DISTINCT FROM 2','w.plan_revision<=0',
 '(SELECT count(*) FROM workflow_steps WHERE workflow_id=w.id AND plan_revision=w.plan_revision)<>1',"s.handler IS DISTINCT FROM 'control.metadata'",
 "s.dependencies IS DISTINCT FROM '{}'::uuid[]","s.native_requests IS DISTINCT FROM '[]'::jsonb",'s.operation_id IS NOT NULL',
 's.metadata_revision IS DISTINCT FROM i.before_revision','s.metadata_before_hmac IS DISTINCT FROM i.before_config_hmac',
 "s.permission_action IS DISTINCT FROM (CASE WHEN i.operation IN('deactivate','archive') THEN 'delete' ELSE 'write' END)",
] as const;
const completionPredicates=[
 "w.state IS DISTINCT FROM 'succeeded'","e.state IS DISTINCT FROM 'succeeded'","s.state IS DISTINCT FROM 'succeeded'",
 'e.workflow_id IS DISTINCT FROM w.id','s.workflow_id IS DISTINCT FROM w.id',
 'e.cluster_id IS DISTINCT FROM NEW.cluster_id','e.workspace_id IS DISTINCT FROM NEW.workspace_id',
 'e.plan_hash IS DISTINCT FROM NEW.plan_hash','e.plan_revision IS DISTINCT FROM NEW.plan_revision',
 'e.execution_actor_id IS DISTINCT FROM NEW.actor_id','NEW.session_id IS DISTINCT FROM i.authoring_session_id',
 'e.approval_set_id IS NULL','e.approval_set_id IS DISTINCT FROM w.approval_set_id','e.approval_set_hmac IS DISTINCT FROM w.approval_set_hmac',
 'i.resource_id IS DISTINCT FROM NEW.resource_id','i.operation IS DISTINCT FROM NEW.operation','i.before_config_hmac IS DISTINCT FROM NEW.before_config_hmac',
 'i.permission_version IS DISTINCT FROM NEW.before_permission_version',
 'a.workflow_id IS DISTINCT FROM NEW.workflow_id','a.workspace_id IS DISTINCT FROM NEW.workspace_id','a.entity_id IS DISTINCT FROM NEW.resource_id::text',
 "a.action IS DISTINCT FROM 'control.metadata'","a.result IS DISTINCT FROM 'success'",
 'c.revision IS DISTINCT FROM NEW.after_revision','ds.revision IS DISTINCT FROM NEW.after_revision','target.revision IS DISTINCT FROM NEW.after_revision',
] as const;

/** Static source contracts, not PostgreSQL execution, runtime admission or a
 * ledger trial. Root owns actual DDL rollback trials and HTTP acceptance. */
describe('SQL033 control metadata source contracts',()=>{
 it.each(frozen)('retains historical migration %s bytes',(name,hash)=>{
  expect(createHash('sha256').update(readFileSync(resolve(directory,name))).digest('hex')).toBe(hash);
 });
 it('only adds three domain tables and never fabricates an IAM or native ledger',()=>{
  expect([...code.matchAll(/CREATE TABLE (\w+)/g)].map(m=>m[1])).toEqual(['control_change_intents','control_metadata_requests','control_workflow_mutation_facts']);
  expect(code).not.toMatch(/\b(?:INSERT INTO|UPDATE|DELETE FROM)\s+(?:iam_operations|mutation_operations|clusters|data_sources|workspaces|audit_events)\b/);
  expect(code).not.toMatch(/DISABLE TRIGGER|SECURITY DEFINER|CREATE OR REPLACE FUNCTION|GRANT\s|UPDATE\s+pg_/);
 });
 it('preserves all existing kind and subject dictionary members including IAM and monitoring',()=>{
  const previous=compact(readFileSync(resolve(directory,'032_m11_metrics_setup_approvals.sql'),'utf8'));
  for(const constraint of ['workflow_definitions_kind_check','workflows_kind_check','workflows_subject_type_check']) {
   const old=new RegExp(`ADD CONSTRAINT ${constraint} CHECK\\([^;]+`).exec(previous)![0];
   const next=new RegExp(`ADD CONSTRAINT ${constraint} CHECK\\([^;]+`).exec(code)![0];
   const previousMembers=[...old.matchAll(/'([^']+)'/g)].map(m=>m[1]);
   const nextMembers=[...next.matchAll(/'([^']+)'/g)].map(m=>m[1]);
   expect(nextMembers.slice(0,-1)).toEqual(previousMembers);
   expect(nextMembers.at(-1)).toBe(constraint.endsWith('subject_type_check')?'control_metadata_requests':'control-metadata');
  }
 });
 it('delegates only this new kind while preserving the real existing subject function',()=>{
  expect(code).toContain("pg_get_functiondef('m6_validate_workflow_subject()'::regprocedure)");
  expect(code).toContain("IF NEW.kind=''control-metadata'' THEN RETURN NULL;END IF;");
  expect(code.match(/pg_get_functiondef/g)).toHaveLength(1);
  expect(code).not.toContain('CREATE FUNCTION m6_validate_workflow_subject');
 });
 it('encrypts intention and result custody and pins the original immutable submission',()=>{
  expect(code).toContain('material_secret text NOT NULL CHECK(m6_encrypted(material_secret))');
  expect(code).toContain('result_secret text NOT NULL CHECK(m6_encrypted(result_secret))');
  expect(code).toContain('UNIQUE(actor_id,submit_key)');
  expect(code).toContain("r.idempotency_key IS DISTINCT FROM ('control-'||i.id::text)");
  expect(code).not.toMatch(/(?:password|connection_auth|auth_headers|api_key)\s+(?:jsonb|text)/);
 });
 it('binds every new foreign key to actual columns, types and a complete existing unique tuple',()=>{
  const schema=actualSchema();
  for(const match of code.matchAll(/CREATE TABLE (control_\w+)\s*\(/g)) {
   const table=schema.get(match[1])!,definition=parenthesized(code,match.index!+match[0].length-1).body;
   for(const part of pieces(definition)) {
    const fk=/FOREIGN KEY\s*\(([^)]+)\)\s*REFERENCES\s+(\w+)\(([^)]+)\)/.exec(part);
    const inline=/^(\w+)\s+\w+\s+.*?REFERENCES\s+(\w+)\(([^)]+)\)/.exec(part);
    const parsed=fk??inline;if(!parsed)continue;
    const local=parsed[1].split(',').map(s=>s.trim()),remote=parsed[3].split(',').map(s=>s.trim()),target=schema.get(parsed[2]);
    expect(target,`unknown referenced table ${parsed[2]}`).toBeDefined();expect(local.length).toBe(remote.length);
    local.forEach((field,index)=>{expect(table.columns.get(field),`${match[1]}.${field}`).toBeDefined();expect(table.columns.get(field)).toBe(target!.columns.get(remote[index]));});
    expect(target!.unique.some(tuple=>[...tuple].sort().join(',')===[...remote].sort().join(',')),`missing actual unique ${parsed[2]}(${remote})`).toBe(true);
    expect(part).toContain('ON DELETE RESTRICT');
   }
  }
 });
 it('all trigger row-type references resolve against actual historical schema',()=>{
  const schema=actualSchema();
  for(const fn of ['m11_validate_control_intent_author','m11_validate_control_workflow_graph','m11_validate_control_mutation_fact']) {
   const fnBody=body(fn),variables=new Map<string,string>();
   for(const m of fnBody.matchAll(/(\w+)\s+(\w+)%ROWTYPE/g))variables.set(m[1],m[2]);
   for(const [variable,table] of variables) {
    expect(schema.has(table)).toBe(true);
    for(const reference of fnBody.matchAll(new RegExp(`\\b${variable}\\.(\\w+)`,'g')))expect(schema.get(table)!.columns.has(reference[1]),`unknown ${variable}.${reference[1]}`).toBe(true);
   }
  }
 });
 it('the real current SID, epochs, old approval mode and actual original target are mandatory',()=>{
  expect(()=>requirePredicates(body('m11_validate_control_intent_author'),authorPredicates)).not.toThrow();
 });
 it.each(authorPredicates)('rejects removal of the author binding %s',predicate=>{
  expect(()=>requirePredicates(body('m11_validate_control_intent_author').replace(predicate,'false'),authorPredicates)).toThrow(/Missing rejection/);
 });
 it('dedicated V2 metadata Native0 graph is exact',()=>{
  expect(()=>requirePredicates(body('m11_validate_control_workflow_graph'),graphPredicates)).not.toThrow();
  expect(body('m11_validate_control_workflow_graph')).toContain("w.subject_type='control_metadata_requests' OR EXISTS");
  expect(body('m11_validate_control_workflow_graph')).toContain("historical.native_requests IS DISTINCT FROM '[]'::jsonb OR historical.operation_id IS NOT NULL");
  expect(code).toContain('plan_revision integer NOT NULL CHECK(plan_revision>0)');
 });
 it.each(graphPredicates)('rejects removal of the fixed plan guard %s',predicate=>{
  expect(()=>requirePredicates(body('m11_validate_control_workflow_graph').replace(predicate,'false'),graphPredicates)).toThrow(/Missing rejection/);
 });
 it('complete actual original W/E/s, exact approval set, revision readback and audit are mandatory',()=>{
  expect(()=>requirePredicates(body('m11_validate_control_mutation_fact'),completionPredicates)).not.toThrow();
 });
 it.each(completionPredicates)('rejects removal of the completion binding %s',predicate=>{
  expect(()=>requirePredicates(body('m11_validate_control_mutation_fact').replace(predicate,'false'),completionPredicates)).toThrow(/Missing rejection/);
 });
 it('requires after revision to be original plus one including true create revision one',()=>{
  expect(code).toContain('CHECK(after_revision=before_revision+1)');
  expect(code).toContain("CHECK((operation='create' AND before_revision=0) OR(operation<>'create' AND before_revision>0))");
  expect(code).toContain("resource='clusters' AND resource_id=cluster_id AND operation IN('update','deactivate')");
 });
 it('checks actual soft deletion and restored state while allowing only the original mode or scope change',()=>{
  const completion=body('m11_validate_control_mutation_fact');
  requirePredicates(completion,["NEW.operation='deactivate' AND(c.deleted_at IS NULL OR c.status IS DISTINCT FROM 'disabled')",
   "NEW.operation='deactivate' AND(ds.deleted_at IS NULL OR ds.enabled)",
   "NEW.operation='archive' AND(target.status IS DISTINCT FROM 'deleted' OR target.deleted_at IS NULL OR target.retention_until IS NULL OR target.is_default)",
   "NEW.operation IN('create','restore') AND(target.status IS DISTINCT FROM 'active'",
   "IF NOT(NEW.resource='workspaces' AND NEW.resource_id=NEW.workspace_id AND NEW.operation IN('update','archive'))"]);
  const clusterBranch=completion.slice(completion.indexOf("IF NEW.resource='clusters' THEN"),completion.indexOf("IF NEW.resource='data-sources' THEN"));
  expect(clusterBranch).toContain("ELSE IF c.deleted_at IS NOT NULL OR c.status='disabled' OR c.execution_mode IS DISTINCT FROM 'approval'");
  expect(clusterBranch.slice(0,clusterBranch.indexOf('ELSE'))).not.toContain("c.execution_mode IS DISTINCT FROM 'approval'");
 });
 it('checks requests, workflow and steps at commit and never claims success without a receipt',()=>{
  for(const table of ['control_metadata_requests','workflows','workflow_steps'])expect(code).toContain(`ON ${table} DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m11_validate_control_workflow_graph()`);
  expect(code).toContain('AFTER INSERT ON control_workflow_mutation_facts DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m11_validate_control_mutation_fact()');
  expect(body('m11_validate_control_workflow_graph')).toContain("IF w.state='succeeded' AND NOT EXISTS(SELECT 1 FROM control_workflow_mutation_facts");
 });
 it('all evidence tables are append-only and this PUBLIC revoke is not a runtime-role grant check',()=>{
  expect(code).toContain("ARRAY['control_change_intents','control_metadata_requests','control_workflow_mutation_facts']");
  expect(code).toContain('BEFORE UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION m8_immutable()');
  expect(code).toContain('BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION m8_immutable()');
  expect(code).toContain('REVOKE UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER ON %I FROM PUBLIC');
 });
 it('has balanced expression parentheses and protects CASE expressions in PL/pgSQL IF',()=>{
  const expressions=source.replace(/--[^\n]*/g,'').replace(/'(?:''|[^'])*'/g,"''");let depth=0;
  for(const char of expressions){if(char==='(')depth++;if(char===')')depth--;expect(depth).toBeGreaterThanOrEqual(0);}expect(depth).toBe(0);
  expect(code).not.toMatch(/\bIS (?:NOT )?DISTINCT FROM CASE\b|(?:<>|=) CASE\b/);
  expect(source.match(/\$\$/g)).toHaveLength(10);
 });
});
