import { describe, expect, it } from 'vitest';
import { randomUUID } from 'node:crypto';
import { nativeWorkflowImpact, workflowRelatedRoutes, workflowTrafficMeasurement, workflowTrafficQueryPlan, workflowVitalsQuery, WORKFLOW_IMPACT_ROUTE_LIMIT } from '../../apps/console-api/src/modules/workflows/workflow-impact';

const cid=randomUUID(),wid=randomUUID(),service=randomUUID(),route=randomUUID();
const packet=(type:string,nativeId:string,before:any,body:any,method='PATCH')=>({key:randomUUID(),order:1,nativeType:type,nativeId,before,body,method,mutationAction:method==='DELETE'?'delete':'update'});
function prepared(packets:any[],prerequisites:any[]=[],graphs:any[]=[]):any{return{clusterId:cid,workspaceId:wid,packets,prerequisites,
  metadataObligations:graphs.map(graph=>({kind:'recycle-archive',graph})),recovery:{state:'baseline-required',blockerCodes:[]}};}
function graph(complete=true):any{return{purpose:'recycle',complete,rootKey:`services:${service}`,nodes:[{key:`services:${service}`,type:'services',id:service,data:{id:service}},
  {key:`routes:${route}`,type:'routes',id:route,data:{id:route,name:'owned-route',service:{id:service},headers:{authorization:['private-header']},secret:'private-graph'}}]};}
function overview(value:number|null=12,availability='available',complete=true):any{return{clusterId:cid,workspaceId:wid,scope:'workspace',evaluationAt:'2026-10-13T00:05:00.000Z',
  cards:{qps:{value,availability}},quality:{complete,reasonCodes:complete?[]:['METRICS_SOURCE_QUERY_FAILED']}};}
describe('M11 workflow impact pure business projection',()=>{
  it('lists changed routes and both old/new Service associations without disclosing native config',()=>{
    const other=randomUUID(),material=prepared([packet('routes',route,{id:route,name:'before',service:{id:service},headers:{Authorization:['secret']}},{name:'after',service:{id:other},paths:['/private-path']})]);
    const related=workflowRelatedRoutes(material);expect(related.coverage).toBe('direct_routes');expect(related.items).toEqual([{id:route,name:'after',serviceIds:[service,other].sort()}]);
    expect(JSON.stringify(related)).not.toMatch(/Authorization|secret|private-path|headers|paths/);
  });
  it('merges a Route PATCH without silently removing an unchanged Service relation',()=>{
    const material=prepared([packet('routes',route,{id:route,name:'before',service:{id:service}},{name:'after'})]);expect(workflowRelatedRoutes(material).items[0].serviceIds).toEqual([service]);
  });
  it('does not present an unenumerated Service update as zero related Routes',()=>{
    const material=prepared([packet('services',service,{id:service,name:'pay'},{host:'new.internal'})]),related=workflowRelatedRoutes(material);
    expect(related).toMatchObject({items:[],coverage:'not_captured',reasonCodes:['SERVICE_ROUTE_COLLECTION_NOT_CAPTURED']});
  });
  it('accepts complete sealed Service closure and rejects incomplete enumeration claims',()=>{
    const p=packet('services',service,{id:service},null,'DELETE');
    expect(workflowRelatedRoutes(prepared([p],[],[graph(true)]))).toMatchObject({coverage:'complete_service_closure',items:[{id:route,name:'owned-route'}]});
    expect(workflowRelatedRoutes(prepared([p],[],[graph(false)]))).toMatchObject({coverage:'partial',reasonCodes:['SERVICE_ROUTE_COLLECTION_NOT_CAPTURED']});
  });
  it.each(['consumers','upstreams','targets','certificates','key-auth'])('leaves %s route closure explicitly uncaptured',type=>{
    expect(workflowRelatedRoutes(prepared([packet(type,randomUUID(),null,{})]))).toMatchObject({coverage:'not_captured',reasonCodes:['RELATED_ROUTES_NOT_CAPTURED']});
  });
  it('uses only captured route-binding identities and does not equate global plugin scope with a workspace',()=>{
    const p=packet('plugins',randomUUID(),{route:{id:route}},{config:{secret:'private-plugin'}}),prerequisite={type:'routes',nativeId:route,absent:false,before:{id:route,name:'named',service:{id:service}}};
    expect(workflowRelatedRoutes(prepared([p],[prerequisite])).items).toEqual([{id:route,name:'named',serviceIds:[service]}]);
    const global=workflowRelatedRoutes(prepared([packet('plugins',randomUUID(),null,{name:'cors'})]));expect(global.coverage).toBe('not_captured');expect(global.reasonCodes).toContain('GLOBAL_PLUGIN_ROUTE_RELATIONS_NOT_CAPTURED');
  });
  it('deduplicates routes and marks bounded display truncation instead of asserting full closure',()=>{
    const g=graph();g.nodes=[g.nodes[0],...Array.from({length:WORKFLOW_IMPACT_ROUTE_LIMIT+1},()=>({type:'routes',id:randomUUID(),data:{service:{id:service}}}))];
    const result=workflowRelatedRoutes(prepared([packet('services',service,{id:service},null,'DELETE')],[],[g]));expect(result.items).toHaveLength(WORKFLOW_IMPACT_ROUTE_LIMIT);expect(result.truncated).toBe(true);expect(result.coverage).toBe('partial');
  });
  it('persists planning facts while reserving current execution/rollback capabilities for the live summary',()=>{
    const material=prepared([packet('services',service,{id:service},{host:'new.internal'})]),impact=nativeWorkflowImpact(material,{type:'entity_change_intents',id:randomUUID()},1,true);
    expect(impact).toMatchObject({nativeRequests:0,nativeRequestsScope:'metadata_wrapper',plannedNativePackets:1,objectCount:1,traffic:null,trafficAvailability:'unavailable',trafficReasonCode:'WORKFLOW_TRAFFIC_NOT_QUERIED'});
    expect(impact).not.toHaveProperty('executionAvailable');expect(impact.rollback).not.toContain('尚未启用');expect(impact.rollback).toContain('当前工单能力');
  });
  it('refuses malformed IDs or excessive inputs rather than deriving public relationships from arbitrary data',()=>{
    expect(()=>workflowRelatedRoutes(prepared([packet('routes','foreign-name',{},{} )]))).toThrow('WORKFLOW_IMPACT_MATERIAL_INVALID');
    expect(()=>workflowRelatedRoutes(prepared(Array.from({length:1001},()=>packet('routes',route,{},{}))))).toThrow();
  });
});
describe('M11 Vitals impact query plan and truthful availability',()=>{
  it('uses explicit scoped UUID selectors and keeps overlapping Service/Route measurements separate',()=>{
    const material=prepared([packet('services',service,{id:service},{}),packet('routes',route,{id:route,service:{id:service}}, {})]),plan=workflowTrafficQueryPlan(material);
    expect(plan.aggregation).toBe('separate');expect(plan.targets).toEqual(expect.arrayContaining([{type:'services',id:service},{type:'routes',id:route}]));
    const target={type:'routes' as const,id:route},query=workflowVitalsQuery(plan,target,'2026-10-13T00:00:00.000Z','2026-10-13T00:05:00.000Z');
    expect(query).toEqual({workspaceId:wid,scope:'workspace',routeId:route,start:'2026-10-13T00:00:00.000Z',end:'2026-10-13T00:05:00.000Z'});
    expect(JSON.stringify(query)).not.toMatch(/labels|promql|serviceName|consumer|host/);
    expect(()=>workflowVitalsQuery(plan,{type:'routes',id:randomUUID()},query.start!,query.end!)).toThrow();
  });
  it('bounds provider queries and reports uncaptured credential scope without broadening to workspace totals',()=>{
    const large=workflowTrafficQueryPlan(prepared(Array.from({length:9},()=>packet('routes',randomUUID(),null,{}))));expect(large.targets).toHaveLength(8);expect(large.reasonCodes).toContain('WORKFLOW_TRAFFIC_QUERY_BUDGET');
    const credential=workflowTrafficQueryPlan(prepared([packet('key-auth',randomUUID(),null,{consumer:{id:randomUUID()}})]));expect(credential.targets).toEqual([]);expect(credential.reasonCodes).toContain('WORKFLOW_TRAFFIC_SCOPE_NOT_CAPTURED');
  });
  it.each(['unavailable','insufficient_samples','unsupported','partial'])('preserves null for %s instead of inventing zero QPS',availability=>{
    const plan=workflowTrafficQueryPlan(prepared([packet('routes',route,{id:route},{})])),target=plan.targets[0],query=workflowVitalsQuery(plan,target,'2026-10-13T00:00:00Z','2026-10-13T00:05:00Z');
    expect(workflowTrafficMeasurement(plan,target,overview(null,availability),query).qps).toEqual({value:null,availability});
  });
  it('accepts measured zero, refuses incomplete/infinite/negative samples and fences cluster/workspace/selectors',()=>{
    const plan=workflowTrafficQueryPlan(prepared([packet('routes',route,{id:route},{})])),target=plan.targets[0],query=workflowVitalsQuery(plan,target,'2026-10-13T00:00:00Z','2026-10-13T00:05:00Z');
    expect(workflowTrafficMeasurement(plan,target,overview(0),query).qps).toEqual({value:0,availability:'available'});
    expect(workflowTrafficMeasurement(plan,target,overview(10,'available',false),query).qps).toEqual({value:null,availability:'partial'});
    for(const value of [Infinity,-1,NaN])expect(workflowTrafficMeasurement(plan,target,overview(value),query).qps).toEqual({value:null,availability:'unavailable'});
    expect(()=>workflowTrafficMeasurement(plan,target,{...overview(),workspaceId:randomUUID()},query)).toThrow();
    expect(()=>workflowTrafficMeasurement(plan,target,{...overview(),clusterId:randomUUID()},query)).toThrow();
    expect(()=>workflowTrafficMeasurement(plan,target,overview(),{...query,routeId:undefined})).toThrow();
  });
});
