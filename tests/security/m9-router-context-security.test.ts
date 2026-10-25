import { afterEach, describe, expect, it, vi } from 'vitest';
import { randomUUID } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { boundedRegexMatches, cidrContains, resolvePluginChain, simulateRoutes } from '../../apps/console-api/src/modules/toolbox/route-matcher';
import { routeDebugInput } from '../../apps/console-api/src/modules/toolbox/toolbox-input';
afterEach(()=>vi.restoreAllMocks());

describe('M9 diagnostics do not invent complete authentication context',()=>{
  it.each(['sourceIp','destinationIp'])('rejects IPv6 zone identifiers in %s before CIDR matching can throw',field=>{
    expect(()=>routeDebugInput({method:'GET',url:'https://example.com/v1/users',headers:{},[field]:'fe80::1%eth0'})).toThrow(expect.objectContaining({response:{code:'INVALID_ROUTE_DEBUG_IP'}}));
    expect(cidrContains('fe80::/10','fe80::1%eth0')).toBe(false);
  });
  it('returns a partial plugin chain when Consumer authentication may override a global instance',()=>{
    const rid=randomUUID(),sid=randomUUID(),cid=randomUUID(),global={id:randomUUID(),name:'rate-limiting'},consumer={id:randomUUID(),name:'rate-limiting',consumer:{id:cid},route:{id:rid}};
    const unresolved=resolvePluginChain([global,consumer],rid,sid);
    expect(unresolved.complete).toBe(false);
    expect(unresolved.reasonCodes).toEqual(['CONSUMER_CONTEXT_MISSING']);
    expect(unresolved.executionOrder.map(row=>row.id)).toEqual([global.id]);
    const resolved=resolvePluginChain([global,consumer],rid,sid,cid);
    expect(resolved.complete).toBe(true);expect(resolved.reasonCodes).toEqual([]);
    expect(resolved.executionOrder.map(row=>row.id)).toEqual([consumer.id]);
  });
  it('keeps disabled and unrelated-route Consumer instances outside the completeness decision',()=>{
    const rid=randomUUID(),sid=randomUUID(),cid=randomUUID();
    const plugins=[{id:randomUUID(),name:'rate-limiting',consumer:{id:cid},route:{id:randomUUID()}},{id:randomUUID(),name:'rate-limiting',consumer:{id:cid},service:{id:randomUUID()}},{id:randomUUID(),name:'rate-limiting',consumer:{id:cid},enabled:false}];
    expect(resolvePluginChain(plugins,rid,sid)).toMatchObject({complete:true,reasonCodes:[],executionOrder:[]});
  });
  it('distinguishes an unknown execution priority from missing Consumer context',()=>{
    const result=resolvePluginChain([{id:randomUUID(),name:'synthetic-custom-plugin'},{id:randomUUID(),name:'rate-limiting',consumer:{id:randomUUID()}}],randomUUID(),randomUUID());
    expect(result.complete).toBe(false);expect(result.reasonCodes).toEqual(['CONSUMER_CONTEXT_MISSING','PLUGIN_PRIORITY_UNKNOWN']);
  });
  // These escapes have PCRE1 semantics that JavaScript either changes or
  // cannot reproduce. The real isolated native engine must return a known
  // match/no-match; unavailable engines must not make these cases pass.
  it.each([
    ['\\A/v1/users',true],['/v1/users\\z',true],['/v1/users\\Z',true],
    ['/v1/\\N',true],['/v1/[[:digit:]]+',false],['/v1/\\p{L}+',true],['/v1/\\P{N}+',true],
    ['/v1/\\h+',false],['/v1/\\H+',true],['/v1/\\v+',false],['/v1/\\V+',true],
    ['/v1/\\x{41}',false],['/v1/\\o{101}',false],
  ] as const)('uses native PCRE1 escape semantics without JavaScript fallback: %s',async(pattern,matched)=>{
    expect((await boundedRegexMatches([pattern],'/v1/users'))[pattern]).toEqual({match:matched});
    const result=await simulateRoutes([{id:randomUUID(),protocols:['https'],paths:[pattern]}],routeDebugInput({method:'GET',url:'https://example.com/v1/users',headers:{}}));
    expect(result.complete).toBe(true);expect(result.regexEngine).toContain('PCRE1 8.45');
    expect(result.candidates[0].warnings).toEqual([]);expect(result.candidates[0].matched).toBe(matched);
  });
  it('keeps an undefined PCRE back-reference unsupported instead of silently using JavaScript literals',async()=>{
    const pattern='/v1/\\g{1}';
    expect(new RegExp(pattern).test('/v1/g')).toBe(true);
    expect((await boundedRegexMatches([pattern],'/v1/users'))[pattern]).toEqual({unsupported:true,reason:'PCRE_COMPILE_ERROR'});
    const result=await simulateRoutes([{id:randomUUID(),protocols:['https'],paths:[pattern]}],routeDebugInput({method:'GET',url:'https://example.com/v1/users',headers:{}}));
    expect(result.complete).toBe(false);expect(result.route).toBeNull();
    expect(result.candidates[0].warnings).toEqual(expect.arrayContaining(['PCRE_COMPILE_ERROR','PCRE_PATTERN_UNSUPPORTED']));
  });
  it('keeps regex work within one 64-pattern batch and marks overflow partial even with a known plain match',async()=>{
    const paths=Array.from({length:65},(_,index)=>`/v1/(?:resource-${index})`),root={id:randomUUID(),protocols:['https'],paths:['/v1/users',...paths]};
    const result=await simulateRoutes([root],routeDebugInput({method:'GET',url:'https://example.com/v1/users',headers:{}}));
    expect(result.complete).toBe(false);expect(result.reasonCodes).toContain('REGEX_CALL_BUDGET_EXHAUSTED');expect(result.simulationBudget).toMatchObject({regexCallLimit:64,regexCalls:64,examinedRoutes:1});
    const raw=await boundedRegexMatches(paths,'/v1/resource-64');expect(raw[paths[64]]).toEqual({unsupported:true,reason:'PCRE_PATTERN_BUDGET'});
  });
  it('keeps unsupported regex alternatives partial even when a plain path also matches',async()=>{
    const result=await simulateRoutes([{id:randomUUID(),paths:['/v1/users','/v1/(?:']}],routeDebugInput({method:'GET',url:'https://example.com/v1/users',headers:{}}));
    expect(result.complete).toBe(false);expect(result.route).toBeNull();
    expect(result.candidates[0].warnings).toEqual(expect.arrayContaining(['PCRE_COMPILE_ERROR','PCRE_PATTERN_UNSUPPORTED']));
  });
  it('does not charge plain paths against the regex budget and safely handles large path arrays without argument spreading',async()=>{
    const paths=Array.from({length:140000},()=>'/public'),root={id:randomUUID(),protocols:['https'],paths};
    const result=await simulateRoutes([root],routeDebugInput({method:'GET',url:'https://example.com/public/resource',headers:{}}));
    expect(result.complete).toBe(true);expect(result.route?.id).toBe(root.id);expect(result.simulationBudget.regexCalls).toBe(0);
  });
  it('stops after the total monotonic deadline without starting additional worker waves',async()=>{
    vi.spyOn(performance,'now').mockReturnValueOnce(100).mockReturnValue(2101);
    const result=await simulateRoutes([{id:randomUUID(),paths:['/v1/(?:users)']}],routeDebugInput({method:'GET',url:'https://example.com/v1/users',headers:{}}));
    expect(result.complete).toBe(false);expect(result.reasonCodes).toContain('SIMULATION_DEADLINE_EXCEEDED');expect(result.candidates).toEqual([]);expect(result.simulationBudget.regexCalls).toBe(0);
  });
  it('bounds route scanning itself at 1000 while reporting an incomplete inventory',async()=>{
    const roots=Array.from({length:1001},(_,index)=>({id:randomUUID(),protocols:['https'],paths:[`/resource-${index}/`]}));
    const result=await simulateRoutes(roots,routeDebugInput({method:'GET',url:'https://example.com/resource-0/item',headers:{}}));
    expect(result.complete).toBe(false);expect(result.reasonCodes).toContain('CAPTURE_BUDGET_EXHAUSTED');expect(result.candidates).toHaveLength(1000);expect(result.simulationBudget).toMatchObject({regexCalls:0,routeLimit:1000});
  });
});
