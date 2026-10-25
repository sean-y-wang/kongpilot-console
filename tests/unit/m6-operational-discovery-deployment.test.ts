import{describe,it,expect}from'vitest';
import{operationalDiscoveryChecks}from'../../deploy/scripts/verify-operational-discovery-api-repair.mjs';
const base=()=>({api:{id:'same'},apiStartedAt:'old',services:[{name:'other',startedAt:'retained'}],statics:{console:{a:'bytes'},portal:{b:'bytes'}},materials:{a:{sha256:'same'}},migrations:[{name:'000.sql',checksum:'same',applied_at:'old'}],sourceMigrations:[{name:'000.sql',checksum:'same'}],sourceSHA256:'source',compiledSHA256:'old',runtimeCompiledSHA256:'old'});
describe('minimal API operational discovery deployment boundaries',()=>{
 it('allows API process/compiled bytes alone while avoiding metrics/catalog requirements',()=>{const before=base(),after={...base(),apiStartedAt:'new',compiledSHA256:'new',runtimeCompiledSHA256:'new'};expect(operationalDiscoveryChecks(before,after).every(r=>r.passed)).toBe(true);});
 it('rejects any other service restart',()=>{const before=base(),after={...base(),apiStartedAt:'new',services:[{name:'other',startedAt:'changed'}]};expect(operationalDiscoveryChecks(before,after)[1].passed).toBe(false);});
 it('rejects static/material/migration changes',()=>{const before=base(),after={...base(),apiStartedAt:'new',statics:{console:{a:'changed'}},materials:{a:{sha256:'changed'}},migrations:[]};const c=operationalDiscoveryChecks(before,after);expect(c[2].passed).toBe(false);expect(c[3].passed).toBe(false);expect(c[4].passed).toBe(false);});
});
