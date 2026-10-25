import { afterEach, describe, expect, it, vi } from 'vitest';
import { randomUUID } from 'node:crypto';
import { assertPublicDraft, cacheKey, routeDebugInput } from '../../apps/console-api/src/modules/toolbox/toolbox-input';
import { boundedRegexMatches, cidrContains, resolvePluginChain, simulateRoutes } from '../../apps/console-api/src/modules/toolbox/route-matcher';
import { toolboxBatchTarget, validateBatchSelection } from '../../apps/console-api/src/modules/toolbox/batch-plan';
import { validateProxyOrigin } from '../../apps/console-api/src/modules/toolbox/proxy-probe';
import { toolboxReceiptComplete, toolboxReceiptPath } from '../../apps/console-web/src/features/m9.model';
import { safeRecoveryReferences } from '../../apps/console-web/src/api/workspace-scope';

type RegexRankingFixture={matches:Record<string,{match?:boolean;unsupported?:boolean;reason?:string}>;calls:Array<{patterns:string[];path:string;timeoutMs:number}>;};
const regexWorkers=vi.hoisted(()=>({fixture:undefined as RegexRankingFixture|undefined,realConstructions:0,realExits:[] as Promise<void>[]}));
vi.mock('../../apps/console-api/src/modules/toolbox/pcre1-engine',async importOriginal=>{
 const actual=await importOriginal<typeof import('../../apps/console-api/src/modules/toolbox/pcre1-engine')>();
 return {...actual,boundedPcre1Matches:(patterns:string[],path:string,timeoutMs:number)=>{
  const fixture=regexWorkers.fixture;if(!fixture)return actual.boundedPcre1Matches(patterns,path,timeoutMs);
  fixture.calls.push({patterns,path,timeoutMs});return Promise.resolve(fixture.matches);
 }};
});
vi.mock('node:child_process',async importOriginal=>{
 const actual=await importOriginal<typeof import('node:child_process')>();
 return {...actual,spawn:(...args:Parameters<typeof actual.spawn>)=>{
  const child=actual.spawn(...args);if(String(args[0]).endsWith('/kongpilot-pcre1')){regexWorkers.realConstructions++;regexWorkers.realExits.push(new Promise<void>(resolve=>child.once('close',()=>resolve())));}return child;
 }};
});
afterEach(async()=>{
  regexWorkers.fixture=undefined;
  // A bounded response can precede SIGKILL close; wait for genuine child exits
  // so the previous case cannot occupy this case's four native slots.
  await Promise.all(regexWorkers.realExits.splice(0));vi.unstubAllEnvs();
});
const route=(fields:Record<string,unknown>={})=>({id:randomUUID(),protocols:['https'],paths:['/'],created_at:1,...fields});
const request=(fields:Record<string,unknown>={})=>routeDebugInput({method:'GET',url:'https://api.example.com/v1/users',headers:{},...fields});
// Ranking assumes these explicitly known regex outcomes. The production worker
// deadline must not turn an OS scheduling delay into a ranking assertion failure.
// Other tests use the genuine native process, including deadline/capacity failures.
async function simulateRanking(routes:Parameters<typeof simulateRoutes>[0],input:Parameters<typeof simulateRoutes>[1],matches:RegexRankingFixture['matches']){
  expect(regexWorkers.fixture).toBeUndefined();
  const fixture:RegexRankingFixture={matches,calls:[]};regexWorkers.fixture=fixture;
  try{
    const result=await simulateRoutes(routes,input);
    expect(fixture.calls).toEqual([{patterns:Object.keys(matches),path:new URL(input.url).pathname,timeoutMs:250}]);
    return result;
  }finally{regexWorkers.fixture=undefined;}
}

describe('Kong 1.5 traditional route simulation',()=>{
  it('counts AND conditions before category bits, regex priority and path length',async()=>{
    const one=route({paths:['/v1'],regex_priority:999}),two=route({methods:['GET'],hosts:['api.example.com'],paths:['/']});
    expect((await simulateRoutes([one,two],request())).route?.id).toBe(two.id);
  });
  it('ranks HOST category above URI within equal condition counts',async()=>{
    const host=route({hosts:['api.example.com'],paths:null}),path=route({paths:['/v1/users']});
    expect((await simulateRoutes([path,host],request())).route?.id).toBe(host.id);
  });
  it('prefers exact hosts over wildcard hosts in one category',async()=>{
    const wildcard=route({hosts:['*.example.com'],paths:['/v1/users'],regex_priority:999}),exact=route({hosts:['api.example.com'],paths:['/']});
    expect((await simulateRoutes([wildcard,exact],request())).route?.id).toBe(exact.id);
  });
  it('supports OR values per header and AND across header fields',async()=>{
    const a=route({headers:{'X-Team':['pay','orders'],'x-region':['cn']}});
    expect((await simulateRoutes([a],request({headers:{'x-team':'pay','X-Region':'cn'}}))).route?.id).toBe(a.id);
    expect((await simulateRoutes([a],request({headers:{'x-team':'pay','x-region':'us'}}))).route).toBeNull();
  });
  it('prefers regex routes and applies regex_priority before plain URI length',async()=>{
    const plain=route({paths:['/v1/users']}),regex=route({paths:['/v1/[a-z]+'],regex_priority:1});
    expect((await simulateRanking([plain,regex],request(),{'/v1/[a-z]+':{match:true}})).route?.id).toBe(regex.id);
  });
  it('uses the longest plain prefix, then older created_at',async()=>{
    const short=route({paths:['/']}),long=route({paths:['/v1'],created_at:2}),older=route({paths:['/v1'],created_at:1});
    expect((await simulateRoutes([short,long,older],request())).route?.id).toBe(older.id);
  });
  it.each([
    {paths:['/x','/this-is-a-very-long-unrelated-path']},
    {paths:['/this-is-a-very-long-unrelated-path','/x']},
  ])('ranks only the matching plain prefix from a multi-path route: %j',async({paths})=>{
    const unrelated=route({paths}),specific=route({paths:['/x/sub']}),result=await simulateRoutes([unrelated,specific],request({url:'https://api.example.com/x/sub'}));
    expect(result.route?.id).toBe(specific.id);expect(result.complete).toBe(true);
  });
  it('selects the longest among all actual matching prefixes regardless of path-array order',async()=>{
    const multiple=route({paths:['/x','/unrelated/long/path','/x/sub']}),shorter=route({paths:['/x/s']}),result=await simulateRoutes([shorter,multiple],request({url:'https://api.example.com/x/sub'}));
    expect(result.route?.id).toBe(multiple.id);expect(result.complete).toBe(true);
  });
  it('does not give an unmatched regex the priority of the matching plain path in the same route',async()=>{
    const mixed=route({paths:['/x','/never/[a-z]+']}),specific=route({paths:['/x/sub']}),result=await simulateRanking([mixed,specific],request({url:'https://api.example.com/x/sub'}),{'/never/[a-z]+':{match:false}});
    expect(result.route?.id).toBe(specific.id);expect(result.complete).toBe(true);expect(result.reasonCodes).not.toContain('BOUNDED_JS_REGEX_NOT_PCRE');expect(result.regexEngine).toContain('PCRE1 8.45');
  });
  it('ranks a matched regex as a single regex path without borrowing a matching plain-prefix length',async()=>{
    const newerMixed=route({paths:['/x/[a-z]+','/x/sub'],created_at:2}),olderRegex=route({paths:['/x/[a-z]+'],created_at:1}),result=await simulateRanking([newerMixed,olderRegex],request({url:'https://api.example.com/x/sub'}),{'/x/[a-z]+':{match:true}});
    expect(result.route?.id).toBe(olderRegex.id);expect(result.complete).toBe(true);
  });
  it('rejects a regex-only nonmatch even when its regex_priority exceeds every matching route',async()=>{
    const nonmatch=route({paths:['/different/[a-z]+'],regex_priority:999}),prefix=route({paths:['/x']}),result=await simulateRanking([nonmatch,prefix],request({url:'https://api.example.com/x/sub'}),{'/different/[a-z]+':{match:false}});
    expect(result.route?.id).toBe(prefix.id);expect(result.candidates.find(candidate=>candidate.id===nonmatch.id)?.reasons).toContain('PATH_MISMATCH');expect(result.complete).toBe(true);
  });
  it('retains regex_priority for actual regex matches before created_at',async()=>{
    const low=route({paths:['/x/(sub|other)'],regex_priority:1,created_at:1}),high=route({paths:['/an-unrelated-long-plain-prefix','/x/[a-z]+'],regex_priority:2,created_at:2}),result=await simulateRanking([low,high],request({url:'https://api.example.com/x/sub'}),{'/x/(sub|other)':{match:true},'/x/[a-z]+':{match:true}});
    expect(result.route?.id).toBe(high.id);expect(result.complete).toBe(true);
  });
  it('retains matched-regex precedence over a plain path with higher regex_priority',async()=>{
    const regex=route({paths:['/x/[a-z]+'],regex_priority:0}),plain=route({paths:['/x/sub'],regex_priority:999}),result=await simulateRanking([plain,regex],request({url:'https://api.example.com/x/sub'}),{'/x/[a-z]+':{match:true}});
    expect(result.route?.id).toBe(regex.id);expect(result.complete).toBe(true);
  });
  it('keeps an unverified regex branch visibly partial even when its plain alternative matches',async()=>{
    const unverified=route({paths:['/x','/x/(?>sub|other)']}),specific=route({paths:['/x/sub']}),result=await simulateRanking([unverified,specific],request({url:'https://api.example.com/x/sub'}),{'/x/(?>sub|other)':{unsupported:true,reason:'PCRE_ENGINE_BUSY'}});
    expect(result.route?.id).toBe(specific.id);expect(result.complete).toBe(false);
    expect(result.candidates.find(candidate=>candidate.id===unverified.id)?.warnings).toContain('PCRE_PATTERN_UNSUPPORTED');expect(result.reasonCodes).toContain('UNSUPPORTED_OR_MISSING_CONTEXT');
  });
  it('preserves prefix semantics without inventing a path-segment boundary',async()=>{
    const short=route({paths:['/x']}),prefix=route({paths:['/x/sub','/a-much-longer-unmatched-prefix']}),result=await simulateRoutes([short,prefix],request({url:'https://api.example.com/x/submarine'}));
    expect(result.route?.id).toBe(prefix.id);expect(result.complete).toBe(true);
  });
  it('does not let an unmatched extension break equal-prefix created_at ordering at the shorter boundary',async()=>{
    const mixed=route({paths:['/x/sub','/x'],created_at:2}),older=route({paths:['/x'],created_at:1}),result=await simulateRoutes([mixed,older],request({url:'https://api.example.com/x'}));
    expect(result.route?.id).toBe(older.id);expect(result.complete).toBe(true);
  });
  it('reports unresolved priority ties and missing SNI context',async()=>{
    const tied=await simulateRoutes([route(),route()],request());expect(tied.complete).toBe(false);expect(tied.reasonCodes).toContain('ROUTE_PRIORITY_TIE');
    const missing=await simulateRoutes([route({snis:['api.example.com']})],request());expect(missing.route).toBeNull();expect(missing.complete).toBe(false);
  });
  it('supports IPv4/IPv6 CIDR and source-port AND matching',async()=>{
    expect(cidrContains('192.0.2.0/24','192.0.2.15')).toBe(true);expect(cidrContains('192.0.2.0/24','198.51.100.1')).toBe(false);
    expect(cidrContains('2001:db8::/32','2001:db8:10::1')).toBe(true);expect(cidrContains('2001:db8::/32','2001:db9::1')).toBe(false);
    const r=route({sources:[{ip:'192.0.2.0/24',port:443}]});expect((await simulateRoutes([r],request({sourceIp:'192.0.2.1',sourcePort:443}))).route?.id).toBe(r.id);
    expect((await simulateRoutes([r],request({sourceIp:'192.0.2.1',sourcePort:80}))).route).toBeNull();
  });
  it('matches PCRE atomic groups with the actual anchored native engine',async()=>{
    const r=route({paths:['/v1/(?>users|groups)']}),result=await simulateRoutes([r],request());expect(result.complete).toBe(true);expect(result.route?.id).toBe(r.id);expect(result.candidates[0].warnings).toEqual([]);expect(result.regexProfile).toMatchObject({version:'8.45',jit:false,anchored:true});
  });
  it('retains the regex-call cap and reports unexamined mixed paths as partial',async()=>{
    const mixed=route({paths:Array.from({length:65},(_,index)=>`/other-${index}/[a-z]+`)}),plain=route({paths:['/x']}),result=await simulateRoutes([mixed,plain],request({url:'https://api.example.com/x/sub'}));
    expect(result.route?.id).toBe(plain.id);expect(result.complete).toBe(false);expect(result.reasonCodes).toContain('REGEX_CALL_BUDGET_EXHAUSTED');
    expect(result.candidates.find(candidate=>candidate.id===mixed.id)?.warnings).toContain('PCRE_PATTERN_UNSUPPORTED');
    expect(result.regexBudgetMs).toBe(250);expect(result.simulationBudget).toMatchObject({deadlineMs:2000,regexCallLimit:64,regexCalls:64,routeLimit:1000,examinedRoutes:2});
  });
  it('retains the route cap without claiming that an omitted longer prefix was considered',async()=>{
    const visible=route({paths:['/x']}),omitted=route({paths:['/x/sub']}),result=await simulateRoutes([visible,...Array.from({length:999},()=>route({paths:['/elsewhere']})),omitted],request({url:'https://api.example.com/x/sub'}));
    expect(result.route?.id).toBe(visible.id);expect(result.complete).toBe(false);expect(result.reasonCodes).toContain('CAPTURE_BUDGET_EXHAUSTED');
    expect(result.candidates.some(candidate=>candidate.id===omitted.id)).toBe(false);expect(result.simulationBudget.examinedRoutes).toBe(1000);
  });
  it('bounds pathological backtracking in a real native child without blocking the API thread',async()=>{
    expect(regexWorkers.fixture).toBeUndefined();const before=regexWorkers.realConstructions;
    const result=await boundedRegexMatches(['/(a+)+$'],'/'+'a'.repeat(3500)+'!',80);expect(result['/(a+)+$'].unsupported).toBe(true);
    expect(regexWorkers.realConstructions-before).toBe(1);
  },5000);
  it('selects the most specific plugin configuration before execution priorities',()=>{
    const rid=randomUUID(),sid=randomUUID(),cid=randomUUID(),global={id:randomUUID(),name:'rate-limiting',enabled:true},specific={id:randomUUID(),name:'rate-limiting',enabled:true,route:{id:rid},service:{id:sid},consumer:{id:cid}},auth={id:randomUUID(),name:'key-auth',enabled:true,service:{id:sid}};
    const chain=resolvePluginChain([global,specific,auth],rid,sid,cid);expect(chain.executionOrder.map(p=>p.name)).toEqual(['key-auth','rate-limiting']);expect(chain.selectionPrecedence.find(p=>p.id===specific.id)?.rank).toBe(1);expect(chain.selectionPrecedence.find(p=>p.id===global.id)?.selected).toBe(false);
  });
  it('runs pre-function first while retaining a JSON-safe infinite-priority label',()=>{
    const rid=randomUUID(),sid=randomUUID(),chain=resolvePluginChain([{id:randomUUID(),name:'key-auth'},{id:randomUUID(),name:'pre-function'}],rid,sid);
    expect(chain.executionOrder.map(p=>p.name)).toEqual(['pre-function','key-auth']);expect(chain.complete).toBe(true);expect(JSON.stringify(chain.executionOrder)).not.toContain('Infinity');expect(chain.executionOrder[0].priorityLabel).toBeTruthy();
  });
  it('bounds concurrent native engines instead of spawning an unbounded process workload',async()=>{
    expect(regexWorkers.fixture).toBeUndefined();const before=regexWorkers.realConstructions;
    const active=Array.from({length:4},()=>boundedRegexMatches(['/(a+)+$'],'/'+'a'.repeat(3500)+'!',500));
    try{
      expect(regexWorkers.realConstructions-before).toBe(4);
      expect((await boundedRegexMatches(['/v1/users'],'/v1/users'))['/v1/users'].unsupported).toBe(true);
      const regex=route({paths:['/x/[a-z]+']}),plain=route({paths:['/x/sub']}),result=await simulateRoutes([plain,regex],request({url:'https://api.example.com/x/sub'}));
      expect(result.route?.id).toBe(plain.id);expect(result.complete).toBe(false);
      expect(result.reasonCodes).toContain('UNSUPPORTED_OR_MISSING_CONTEXT');
      expect(result.candidates.find(candidate=>candidate.id===regex.id)?.warnings).toContain('PCRE_PATTERN_UNSUPPORTED');
      expect(regexWorkers.realConstructions-before).toBe(4);
    }finally{await Promise.all(active);}
  },5000);
});
describe('bounded inputs and selected batch closures',()=>{
  it.each(['../services','foo/bar','foo%2fbar','','token-secret','key?offset=all','keyauth_credentials:synthetic-api-key','basicauth_credentials:synthetic-user','hmacauth_credentials:synthetic-user'])('rejects cache path and secret steering: %s',value=>expect(()=>cacheKey(value)).toThrow());
  it.each([{password:'synthetic'}, {key:'synthetic'}, {config:{private_key:'synthetic'}}, {host:'http://user:pass@example.com'}, {headers:{Authorization:'synthetic'}}, {ownerId:randomUUID()}])('rejects secret or ownership fields in drafts',value=>expect(()=>assertPublicDraft(value)).toThrow());
  it('keeps false and zero values in public drafts',()=>{const value={tls_verify:false,retries:0,host:'api.example.com'};expect(()=>assertPublicDraft(value)).not.toThrow();expect(value).toEqual({tls_verify:false,retries:0,host:'api.example.com'});});
  it('permits transient authentication headers but rejects controls, query secrets, malformed IPs and mass assignment',()=>{
    expect(request({headers:{Authorization:'Bearer synthetic'}}).headers.authorization).toBe('Bearer synthetic');
    for(const field of [{headers:{'X-Test':'bad\u0000value'}},{headers:{'X-Test':'bad\r\nvalue'}},{url:'http://x.example/?token=synthetic'},{sourceIp:'123.456.1.1'},{approved:true}])expect(()=>request(field)).toThrow();
  });
  it('validates origins independently of the routing Host and blocks Admin/database ports',()=>{
    vi.stubEnv('OUTBOUND_ALLOWED_HOSTS','kong,gateway.example.com');
    expect(validateProxyOrigin('http://kong:8000','http://kong:8001')).toBe('http://kong:8000');
    for(const url of ['http://kong:8001','http://kong:5432','http://kong:6379','http://kong:8000/path','http://user:password@kong:8000'])expect(()=>validateProxyOrigin(url,'http://kong:8001')).toThrow();
  });
  it('keeps plugin false, rejects duplicate IDs and reserved workspace tags',()=>{
    const id=randomUUID();expect(validateBatchSelection({action:'plugin-enabled',roots:[{type:'plugins',id}],enabled:false}).enabled).toBe(false);
    expect(()=>validateBatchSelection({action:'delete',roots:[{type:'services',id},{type:'services',id}]})).toThrow();
    expect(()=>validateBatchSelection({action:'tags',roots:[{type:'services',id}],tags:['workspace:foreign']})).toThrow();
  });
  it('removes only the selected service and owned routes/plugins, preserving unrelated objects',()=>{
    const wid=randomUUID(),serviceId=randomUUID(),otherId=randomUUID(),routeId=randomUUID(),pluginId=randomUUID();
    const object=(type:string,id:string,payload:any)=>({objectKey:`${type}:${id}`,entityType:type,nativeId:id,objectWorkspaceId:wid,payload:{id,...payload},affected:true,referenceOnly:false,dependencies:[]});
    const graph:any={scope:{workspaceId:wid},schemas:{},objects:[object('services',serviceId,{}),object('services',otherId,{}),object('routes',routeId,{service:{id:serviceId}}),object('plugins',pluginId,{route:{id:routeId}})]};
    const target=toolboxBatchTarget(graph,validateBatchSelection({action:'delete',roots:[{type:'services',id:serviceId}]}),{[wid]:'default'});
    expect(target.objects.map(o=>o.nativeId)).toEqual([otherId]);
  });
});
describe('original operation recovery',()=>{
  it('binds completion to the original user, cluster, workspace, key and real fact type',()=>{
    const actor=randomUUID(),cid=randomUUID(),wid=randomUUID(),key=randomUUID(),recovery:any={kind:'toolbox',clusterId:cid,workspaceId:wid,idempotencyKey:key};
    const result={id:randomUUID(),actorId:actor,clusterId:cid,workspaceId:wid,idempotencyKey:key,kind:'cache-invalidate',state:'succeeded',remoteStarted:true,remoteCompleted:true};
    expect(toolboxReceiptComplete(result,recovery,actor)).toBe(true);
    for(const changes of [{actorId:randomUUID()},{workspaceId:randomUUID()},{idempotencyKey:randomUUID()},{remoteCompleted:false},{kind:'draft-metadata'}])expect(toolboxReceiptComplete({...result,...changes},recovery,actor)).toBe(false);
    expect(toolboxReceiptPath(recovery)).toContain(`/clusters/${cid}/toolbox/operations/by-key/${key}?workspaceId=${wid}`);
  });
  it('retains a toolbox unknown request across reload without storing payloads or credentials',()=>{
    const actor=randomUUID(),cid=randomUUID(),wid=randomUUID(),key=randomUUID();const refs=safeRecoveryReferences([{actor_id:actor,cid,wid,idempotencyKey:key,kind:'toolbox',scope:'workspace',state:'uncertain',created_at:new Date().toISOString(),payload:{password:'synthetic'}}],actor);
    expect(refs).toHaveLength(1);expect(JSON.stringify(refs)).not.toContain('password');
  });
});
