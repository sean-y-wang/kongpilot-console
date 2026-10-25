import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {describe,expect,it} from 'vitest';

/** SOURCE schema contract only. Root must separately compile/run migration031
 * under real PostgreSQL roles and test deferred constraints/transaction rollback. */
const read=(name:string)=>readFileSync(new URL('../../apps/console-api/src/infrastructure/migrations/'+name,import.meta.url),'utf8'),
  parent=read('021_m11_entity_execution_facts.sql'),sql=read('031_m11_target_health_facts.sql'),code=sql.replace(/--[^\n]*/g,''),
  oldGraph=parent.slice(parent.indexOf('CREATE FUNCTION m11_validate_baseline_graph()'),parent.indexOf('CREATE CONSTRAINT TRIGGER entity_change_baselines_complete')),
  newGraph=sql.slice(sql.indexOf('CREATE OR REPLACE FUNCTION m11_validate_baseline_graph()'));
describe('SQL031 bounded non-reversible Target health facts',()=>{
  it('keeps accepted SQL021 unchanged and changes no existing rows or triggers',()=>{
    expect(createHash('sha256').update(parent).digest('hex')).toBe('133756b722dae11085d20e1a419378e821fcae0c66e7a721350344e63b4a2956');
    expect(code).not.toMatch(/\b(?:DROP|DISABLE|ENABLE)\s+(?:TABLE|TRIGGER|CONSTRAINT)|session_replication_role|SECURITY DEFINER|SET ROLE|current_setting|set_config/);
    expect(code).not.toMatch(/\b(?:UPDATE|INSERT INTO|DELETE FROM|TRUNCATE)\s+(?:entity_change_baselines|entity_change_baseline_objects|entity_change_packet_attempts|entity_change_packet_events|mutation_operations)\b/);
  });
  it('retains the entire old graph manifest, capture-window and dependency checks before packet coverage',()=>{
    const prefix=(text:string)=>text.slice(text.indexOf(' DECLARE'),text.indexOf(' IF EXISTS(SELECT 1 FROM entity_change_intent_packets'));
    expect(prefix(newGraph)).toBe(prefix(oldGraph));
    expect(newGraph).toContain("AND o.present=(p.method<>'POST' OR p.mutation_action IN('mark_healthy','mark_unhealthy'))");
    expect(newGraph).toContain("OR(p.original_native_id IS NOT NULL AND p.mutation_action<>'restore' AND NOT EXISTS(SELECT 1 FROM entity_change_baseline_objects old WHERE old.baseline_id=b.id AND old.affected AND old.present");
  });
  it('requires typed health facts instead of merely allowing any provenance hash',()=>{
    expect(code).toContain('CREATE TABLE entity_change_target_health_baselines');
    expect(code).toContain('PRIMARY KEY(baseline_id,packet_key),UNIQUE(baseline_id,object_key)');
    expect(code).toContain('FOREIGN KEY(baseline_id,object_key) REFERENCES entity_change_baseline_objects(baseline_id,object_key) ON DELETE RESTRICT');
    expect(newGraph).toContain("OR(p.mutation_action IN('mark_healthy','mark_unhealthy') AND NOT EXISTS(SELECT 1 FROM entity_change_target_health_baselines h");
    expect(newGraph).toContain('h.before_hmac=p.before_hmac');expect(newGraph).toContain('h.native_id=p.native_id AND h.upstream_id=p.parent_id');
    expect(code).not.toMatch(/ALTER TABLE entity_change_baseline_objects|DROP FUNCTION/);
  });
  it.each(['p.material_hmac IS DISTINCT FROM b.material_hmac','p.change_digest IS DISTINCT FROM b.change_digest',
    'p.packet_manifest_hmac IS DISTINCT FROM b.packet_manifest_hmac','NEW.cluster_id IS DISTINCT FROM b.cluster_id','NEW.workspace_id IS DISTINCT FROM b.workspace_id',
    'NEW.object_manifest_hmac IS DISTINCT FROM b.object_manifest_hmac','NEW.native_id IS DISTINCT FROM p.native_id','NEW.native_id IS DISTINCT FROM o.native_id',
    'NEW.upstream_id IS DISTINCT FROM p.parent_id','NEW.upstream_id IS DISTINCT FROM o.parent_id','NEW.before_hmac IS DISTINCT FROM p.before_hmac',
    'NEW.before_hmac IS DISTINCT FROM o.before_hmac','NEW.provenance_hmac IS DISTINCT FROM o.provenance_hmac'])('rejects identity mismatch %s',condition=>{
    expect(code).toContain(condition);
  });
  it('keeps health strictly node-local, bodyless POST and never declares override recoverable',()=>{
    expect(code).toContain("health text NOT NULL CHECK(health IN('HEALTHY','UNHEALTHY'))");
    expect(code).toContain('override_recoverable boolean NOT NULL DEFAULT false CHECK(override_recoverable=false)');
    expect(code).toContain("p.native_type<>'targets' OR p.method<>'POST' OR p.permission_action<>'write'");
    expect(code).toContain("p.mutation_action NOT IN('mark_healthy','mark_unhealthy') OR p.original_native_id IS NOT NULL OR p.credential_kind IS NOT NULL");
    expect(code).toContain("parent.native_type='upstreams'");expect(code).toContain('parent.native_id=NEW.upstream_id AND parent.present AND parent.object_order<o.object_order');
    expect(code).not.toContain('HEALTHCHECKS_OFF');expect(code).not.toContain('native_status');
  });
  it('uses append-only facts and grants no additional runtime powers',()=>{
    expect(code).toContain('BEFORE UPDATE OR DELETE ON entity_change_target_health_baselines');
    expect(code).toContain('BEFORE TRUNCATE ON entity_change_target_health_baselines');expect(code.match(/EXECUTE FUNCTION m8_immutable\(\)/g)).toHaveLength(2);
    expect(code).toContain('REVOKE UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER ON entity_change_target_health_baselines FROM PUBLIC');
    expect(code).not.toMatch(/\bGRANT\b|auth_sessions|kong_database|kong_db/);
  });
});
