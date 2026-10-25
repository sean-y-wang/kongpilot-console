import {describe,expect,it} from 'vitest';
import {readFileSync,readdirSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import {join} from 'node:path';

/** Source assembly/patch preservation tests only. The read-only reconstruction
 * models which version of the named function is installed after 000-035;
 * it does not execute pg_get_functiondef, SQL or any runtime migration. */
const dir=fileURLToPath(new URL('../../apps/console-api/src/infrastructure/migrations/',import.meta.url));
const sql=readFileSync(join(dir,'036_m11_health_baseline_alias_repair.sql'),'utf8');
const definitions: {name:string;body:string}[]=[];
for(const name of readdirSync(dir).filter(x=>/^\d+_.*\.sql$/.test(x)&&Number(x.slice(0,3))<=35).sort()){
 const source=readFileSync(join(dir,name),'utf8'),match=source.match(/CREATE(?: OR REPLACE)? FUNCTION m11_validate_baseline_graph\(\) RETURNS trigger LANGUAGE plpgsql AS \$\$([\s\S]*?)\$\$;/);
 if(match)definitions.push({name,body:match[1]});
}
const latest=definitions.at(-1)!;
function literal(name:string):string {
 const pattern=new RegExp(`${name} text := \\$${name}\\$([\\s\\S]*?)\\$${name}\\$;`),match=sql.match(pattern);
 if(!match)throw Error(`Missing repair literal ${name}`);return match[1];
}
const candidateBefore=literal('candidate_before'),candidateAfter=literal('candidate_after'),previousBefore=literal('previous_before'),previousAfter=literal('previous_after');
const occurrences=(whole:string,part:string)=>whole.split(part).length-1;
function patch(original:string):string {
 if(occurrences(original,candidateBefore)!==1||occurrences(original,previousBefore)!==1||!original.includes('FROM entity_change_target_health_baselines h')
  ||!original.includes('o entity_change_baseline_objects%ROWTYPE')||!original.includes('FOR o IN SELECT * FROM entity_change_baseline_objects')
  ||original.includes('baseline_candidate_object_036')||original.includes('baseline_previous_object_036'))throw Error('Exact SQL031 guards required');
 const repaired=original.replace(candidateBefore,candidateAfter).replace(previousBefore,previousAfter);
 if(repaired===original||repaired.includes(candidateBefore)||repaired.includes(previousBefore)||repaired.includes('FROM entity_change_baseline_objects o WHERE')||repaired.includes('FROM entity_change_baseline_objects old WHERE')
  ||repaired.replace(candidateAfter,candidateBefore).replace(previousAfter,previousBefore)!==original)throw Error('Unexpected validator drift');
 return repaired;
}
describe('SQL036 surgical repair of health baseline SQL031 aliases',()=>{
 it('reconstructs the actual 021 -> 022 -> 031 definition chain through SQL035',()=>{
  expect(definitions.map(x=>x.name)).toEqual(['021_m11_entity_execution_facts.sql','022_m11_baseline_trigger_alias_fix.sql','031_m11_target_health_facts.sql']);
  expect(latest.name).toBe('031_m11_target_health_facts.sql');expect(latest.body).toContain('FROM entity_change_baseline_objects o WHERE o.baseline_id=b.id');
  expect(definitions[1].body).not.toContain('FROM entity_change_baseline_objects o WHERE');expect(definitions[1].body).not.toContain('FROM entity_change_baseline_objects old WHERE');
 });
 it('replaces both unique conflicting SQL aliases without renaming the PL/pgSQL FOR object record',()=>{
  const repaired=patch(latest.body);expect(repaired).not.toContain('FROM entity_change_baseline_objects o WHERE');expect(repaired).not.toContain('FROM entity_change_baseline_objects old WHERE');
  expect(repaired).toContain('o entity_change_baseline_objects%ROWTYPE');expect(repaired).toContain('FOR o IN SELECT * FROM entity_change_baseline_objects');
  expect(repaired).toContain('item=b.object_manifest->(o.object_order-1)');expect(repaired).toContain('FOREACH dep IN ARRAY o.dependencies LOOP');
  expect(occurrences(repaired,candidateAfter)).toBe(1);expect(occurrences(repaired,previousAfter)).toBe(1);
 });
 it('changes only alias identifier references within each complete subquery',()=>{
  expect(candidateBefore.replace('entity_change_baseline_objects o WHERE','entity_change_baseline_objects baseline_candidate_object_036 WHERE').replace(/\bo\./g,'baseline_candidate_object_036.')).toBe(candidateAfter);
  expect(previousBefore.replace('entity_change_baseline_objects old WHERE','entity_change_baseline_objects baseline_previous_object_036 WHERE').replace(/\bold\./g,'baseline_previous_object_036.')).toBe(previousAfter);
  const repaired=patch(latest.body);expect(repaired.replace(candidateAfter,candidateBefore).replace(previousAfter,previousBefore)).toBe(latest.body);
 });
 it('retains every old immutable manifest, completeness, dependency, source window and health check/error',()=>{
  const repaired=patch(latest.body),outside=(s:string,candidate:string,previous:string)=>s.replace(candidate,'<exact-candidate-subquery>').replace(previous,'<exact-previous-subquery>');
  expect(outside(repaired,candidateAfter,previousAfter)).toBe(outside(latest.body,candidateBefore,previousBefore));
  for(const check of ['b.observed_from<s.issued_at OR b.observed_until>s.expires_at','jsonb_array_length(b.object_manifest)<>n','cardinality(o.dependencies)','ord>=o.object_order',
   "item->>'provenanceHmac' IS DISTINCT FROM o.provenance_hmac","o.present=(p.method<>'POST' OR p.mutation_action IN('mark_healthy','mark_unhealthy'))",'FROM entity_change_target_health_baselines h',
   "p.method='POST' AND p.native_type='targets' AND p.permission_action='write' AND p.parent_id IS NOT NULL",'p.original_native_id IS NULL AND p.credential_kind IS NULL','h.native_id=p.native_id AND h.upstream_id=p.parent_id AND h.before_hmac=p.before_hmac',
   "p.original_native_id IS NOT NULL AND p.mutation_action<>'restore'"]){
   const expected=check.replace('o.present=', 'baseline_candidate_object_036.present=');expect(repaired).toContain(expected);
  }
  const raises=(s:string)=>s.match(/RAISE EXCEPTION '[^']*' USING ERRCODE='23514'/g);expect(raises(repaired)).toEqual(raises(latest.body));
 });
 it.each(['021','022'])('refuses stale %s function material instead of dropping newer health guards',prefix=>{expect(()=>patch(definitions.find(x=>x.name.startsWith(prefix))!.body)).toThrow();});
 it.each(['candidate missing','previous missing','candidate duplicate','previous duplicate','health missing','record missing','loop missing','already repaired'])('fails closed on %s input',variant=>{
  let source=latest.body;if(variant==='candidate missing')source=source.replace(candidateBefore,'');if(variant==='previous missing')source=source.replace(previousBefore,'');
  if(variant==='candidate duplicate')source+=candidateBefore;if(variant==='previous duplicate')source+=previousBefore;if(variant==='health missing')source=source.replace('FROM entity_change_target_health_baselines h','FROM wrong_health_table h');
  if(variant==='record missing')source=source.replace('o entity_change_baseline_objects%ROWTYPE','o record');if(variant==='loop missing')source=source.replace('FOR o IN SELECT * FROM entity_change_baseline_objects','FOR o IN SELECT * FROM wrong_table');if(variant==='already repaired')source=patch(source);
  expect(()=>patch(source)).toThrow();
 });
 it('uses the live definition and controlled byte-exact replacements without DROP, constraint disabling or conflict-mode bypass',()=>{
  expect(sql).toContain("pg_get_functiondef('public.m11_validate_baseline_graph()'::regprocedure)");expect(sql).toContain('EXECUTE repaired;');
  expect(sql).toContain("length(definition)-length(replace(definition,candidate_before,''))<>length(candidate_before)");expect(sql).toContain("length(definition)-length(replace(definition,previous_before,''))<>length(previous_before)");
  expect(sql).toContain('replace(replace(repaired,candidate_after,candidate_before),previous_after,previous_before) IS DISTINCT FROM definition');
  const code=sql.replace(/--[^\n]*/g,'');expect(code).not.toMatch(/\bDROP\b|DISABLE\s+TRIGGER|session_replication_role|variable_conflict|SET\s+CONSTRAINTS|ALTER\s+TABLE|DELETE\s+FROM|UPDATE\s+\w+/i);
 });
});
