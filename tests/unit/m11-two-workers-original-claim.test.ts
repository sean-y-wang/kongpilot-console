import {describe,it,expect} from 'vitest';
import {randomUUID} from 'node:crypto';
import {readFileSync} from 'node:fs';
// Pure manifest/counter validation only. No Nest/runtime/container/SQL/native
// code is executed or replaced by a fake worker in these source regressions.
import {validateM11TwoWorkerManifest,assertM11TwoWorkerDue,validateM11TwoWorkerTick} from '../integration/m11-two-workers-original-claim.mjs';
const manifest=()=>({version:1,milestone:'M11',capsule:'a',clusterId:randomUUID(),workspaceId:randomUUID(),scheduleId:randomUUID(),workflowId:randomUUID(),notBefore:new Date().toISOString()});
describe('M11 two original-worker capsule source safeguards',()=>{
  it('accepts only an exact readonly own-schedule manifest and freezes the copy',()=>{
    const m=manifest(),copy=validateM11TwoWorkerManifest(m);expect(copy).toEqual(m);expect(copy).not.toBe(m);expect(Object.isFrozen(copy)).toBe(true);
    for(const extra of [{actor:{id:randomUUID()}},{sessionId:randomUUID()},{claimId:randomUUID()},{approved:true},{dueIds:[m.scheduleId]},{workerHandle:{}}])expect(()=>validateM11TwoWorkerManifest({...m,...extra})).toThrow('M11_TWO_WORKER_MANIFEST_INVALID');
    for(const patch of [{version:2},{milestone:'M10'},{capsule:'c'},{scheduleId:'copied'},{notBefore:'2026-10-13T12:00:00Z'}])expect(()=>validateM11TwoWorkerManifest({...m,...patch})).toThrow();
  });
  it('accepts actual empty/own due observations but never filters away a foreign schedule',()=>{
    const id=randomUUID();expect(()=>assertM11TwoWorkerDue([],id)).not.toThrow();expect(()=>assertM11TwoWorkerDue([id],id)).not.toThrow();
    for(const due of [[randomUUID()],[id,randomUUID()],[id,id],null,{id}])expect(()=>assertM11TwoWorkerDue(due,id)).toThrow('M11_TWO_WORKER_FOREIGN_DUE_ID');
  });
  it('validates bounded original counters without turning a blocked result into native success evidence',()=>{
    for(const result of [{checked:0,claimed:0,completed:0,blocked:0,busy:false},{checked:1,claimed:1,completed:1,blocked:0,busy:false},{checked:1,claimed:0,completed:0,blocked:1,busy:false},{checked:1,claimed:1,completed:0,blocked:1,busy:false}])expect(validateM11TwoWorkerTick(result)).toEqual(result);
    const original={checked:1,claimed:1,completed:1,blocked:0,busy:false};
    for(const changed of [{busy:true},{checked:2},{claimed:2},{completed:2},{checked:0},{claimed:0},{blocked:-1},{blocked:0.5},{nativeStatus:201},{checked:NaN}])expect(()=>validateM11TwoWorkerTick({...original,...changed})).toThrow();
  });
  it('retains the bootstrap order, one original tick, and no repository/claim/session substitutions',()=>{
    const source=readFileSync('tests/integration/m11-two-workers-original-claim.mjs','utf8');
    expect(source.indexOf('app.get(NativeKongPolicyService).install()')).toBeLessThan(source.indexOf('await app.init()'));
    expect(source).toContain("createRequire('/app/apps/console-api/package.json')");expect(source).toContain('repository.listDue(25)');expect(source.match(/await worker\.tick\(\)/g)).toHaveLength(1);
    expect(source).toContain('Math.min(1000,dueAt-Date.now())');expect(source).toContain('60000');expect(source).toContain('await app.close()');
    expect(source).not.toMatch(/repository\.listDue\s*=|worker\.tick\s*=|\.acquireDueClaim\(|runActor\(|runHttp\(|runSystemRead\(|bindHttpActor\(|INSERT INTO|UPDATE entity_change|setSystemTime/);
  });
});
