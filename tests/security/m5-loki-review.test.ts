import { beforeEach, describe, expect, it, vi } from 'vitest';
import { currentLokiAssignments, fixedLogql } from '../../apps/console-api/src/modules/vitals/providers/logql';
import { LokiProvider } from '../../apps/console-api/src/modules/vitals/providers/loki.provider';
import { MetricsQueryBudget } from '../../apps/console-api/src/modules/vitals/providers/query-budget';
import { outboundJson } from '../../apps/console-api/src/infrastructure/kong/outbound';
vi.mock('../../apps/console-api/src/infrastructure/kong/outbound',()=>({outboundJson:vi.fn()}));
const transport=vi.mocked(outboundJson);
const cid='721bfeda-dc12-4d7a-b33e-06b2879a7ead',wid='a109e333-40a0-4965-966b-6b810f54e9b6',otherWid='42f6fe90-aae7-451d-80bf-0e8fbc319fa4';
const sid='14368d69-dd76-46f6-b490-583893b13cba',rid='cd7ce64b-e7b0-4b39-9086-c55b7b5f8d9e',uid='f4095396-0771-4b02-9f09-2739a1809c0d';
const pairEpoch='40246f11-52ee-43c2-8ca9-71976d078848',consumerEpoch='de3aa362-52b1-4b94-b2f1-1715d6203853',otherEpoch='6d5a920e-e5d6-4b9b-a731-0759b7a21191';
const now=Date.parse('2026-10-10T12:00:00.000Z'),start=now-300000,window={start:new Date(start).toISOString(),end:new Date(now).toISOString(),step:15,rateWindowSeconds:60};
const source:any={id:sid,name:'registered-logs',type:'loki',baseUrl:'http://registered-loki:3100',auth:null,revision:1};
function pair(extra:any={}){return {epoch_id:pairEpoch,cluster_id:cid,node_id:'a'.repeat(64),entity_type:'routes',entity_id:rid,workspace_id:wid,service_id:sid,route_id:rid,consumer_id:null,tags:[],valid_from:new Date(start-60000).toISOString(),verified_until:new Date(now+15000).toISOString(),closed_at:null,quality:'verified',...extra};}
function consumer(extra:any={}){return {...pair(),epoch_id:consumerEpoch,entity_type:'consumers',entity_id:uid,service_id:null,route_id:null,consumer_id:uid,...extra};}
function scope(extra:any={}):any{return {workspaceId:wid,mode:'workspace',version:'v1',wholeCluster:false,epochs:[pair()],consumerPairEpochs:[],serviceNames:new Map([[sid,'display-service']]),consumerNames:new Map([[uid,'display-consumer']]),...extra};}
const body=(rows:any[],type='matrix')=>({status:200,body:{status:'success',data:{resultType:type,result:rows}}});
beforeEach(()=>{transport.mockReset();transport.mockImplementation(async(_base,path,_method,_body,params)=>{
 const query=String(params?.query);if(path.endsWith('query'))return body(query.includes('sum by(consumer_id)')?[{metric:{consumer_id:uid},value:[now/1000,'2']}]:[{metric:{service_id:sid},value:[now/1000,'2']}],'vector');
 return body([{metric:query.includes('sum by(code)')?{code:'200'}:query.includes('bytes_ingress')?{type:'ingress'}:{},values:[[start/1000,'0'],[now/1000,'2']]}]);
});});
describe('M5 independent exact LogQL scope, collector schema and provider failures',()=>{
 it('requires exact CID/workspace/node/Service/Route/current epoch conjunctions without business-label inference',()=>{
  const queries=fixedLogql(cid,scope(),window);for(const expected of ['job="kongos-collector"',`cluster_id="${cid}"`,`workspace_id="${wid}"`,`node_id="${'a'.repeat(64)}"`,`service_id="${sid}"`,`route_id="${rid}"`,`epoch_id="${pairEpoch}"`])expect(queries.status).toContain(expected);
  expect(queries.status).not.toContain('team:');expect(queries.latency('upstream',0.95)).toContain('latency_upstream_ms');expect(queries.bandwidth).toContain('bytes_ingress');expect(queries.bandwidth).toContain('bytes_egress');expect(queries.nodes).toBe('');
 });
 it('only pairs authorized Consumers with current traffic epochs in their own workspace and node',()=>{
  const foreign=pair({epoch_id:otherEpoch,workspace_id:otherWid,node_id:'b'.repeat(64)}),selected=scope({mode:'cluster',epochs:[consumer()],consumerPairEpochs:[pair(),foreign]});
  const query=fixedLogql(cid,selected,window).consumers;expect(query).toContain(`consumer_id="${uid}" and consumer_epoch_id="${consumerEpoch}"`);expect(query).toContain(`workspace_id="${wid}"`);expect(query).not.toContain(`workspace_id="${otherWid}"`);
  expect(fixedLogql(cid,scope({epochs:[consumer()],consumerPairEpochs:[pair({node_id:'b'.repeat(64)})]}),window).consumers).toContain('epoch_id=~"a^"');
 });
 it('rejects client expression injection, crossCID, closed epochs and wrong workspace before any transport',async()=>{
  for(const patch of [{epoch_id:'x"} | json'}, {cluster_id:otherWid}, {closed_at:new Date().toISOString()}, {workspace_id:otherWid}, {node_id:'not-a-scope'}, {route_id:sid}]){
   const selected=scope({epochs:[pair(patch)]});expect(()=>currentLokiAssignments(cid,selected)).toThrow();await expect(new LokiProvider().evaluate(source,cid,selected,window,new MetricsQueryBudget(),true)).rejects.toBeDefined();
  }expect(transport).not.toHaveBeenCalled();expect(()=>fixedLogql(cid,scope(),{...window,rateWindowSeconds:1})).toThrow();expect(()=>fixedLogql(cid,scope(),window).latency('token',0.5)).toThrow();
 });
 it('does not query anything or produce synthetic zero when the collector channel is disabled',async()=>{
  const result=await new LokiProvider().evaluate(source,cid,scope(),window,new MetricsQueryBudget(),false);expect(transport).not.toHaveBeenCalled();expect(result.series.qps.every(point=>point.value===null)).toBe(true);expect(result.reasonCodes).toContain('LOKI_COLLECTOR_NOT_ENABLED');
 });
 it('uses the registered endpoint, bounded fixed API paths, real milliseconds and no node query even for whole-cluster readers',async()=>{
  const result=await new LokiProvider().evaluate(source,cid,scope({wholeCluster:true}),window,new MetricsQueryBudget(),true);expect(transport).toHaveBeenCalledTimes(12);expect(result.series.qps[0].value).toBe(0);expect(result.series.latencyUpstreamP95.at(-1)?.value).toBe(2);expect(result.nodes).toEqual([]);
  for(const call of transport.mock.calls){expect(call[0]).toBe(source.baseUrl);expect(call[1]).toMatch(/^\/loki\/api\/v1\/query(?:_range)?$/);expect(call[4].query).not.toContain('up{');}
 });
 it('computes Consumer TopN from current matching pair epochs and stays within the cumulative13-call budget',async()=>{
  const result=await new LokiProvider().evaluate(source,cid,scope({epochs:[pair(),consumer()],consumerPairEpochs:[pair()]}),window,new MetricsQueryBudget(),true);expect(transport).toHaveBeenCalledTimes(13);expect(result.topN.consumers).toEqual([{id:uid,name:'display-consumer',value:2}]);
 });
 it('preserves null rate-boundary gaps after a migration and omits newly opened TopN identities',async()=>{
  const selected=scope({epochs:[pair({valid_from:new Date(now-30000).toISOString()})]});const result=await new LokiProvider().evaluate(source,cid,selected,window,new MetricsQueryBudget(),true);expect(result.series.qps.every(point=>point.value===null)).toBe(true);expect(result.topN.services).toEqual([]);expect(result.reasonCodes).toContain('LOKI_CURRENT_EPOCH_WINDOW_INCOMPLETE');
 });
 it('refuses duplicate status/direction rows and upstream failures instead of double-counting a partial result',async()=>{
  transport.mockResolvedValue(body([{metric:{code:'200'},values:[[start/1000,'1']]},{metric:{code:'200'},values:[[start/1000,'1']]}]));await expect(new LokiProvider().evaluate(source,cid,scope(),window,new MetricsQueryBudget(),true)).rejects.toMatchObject({response:{code:'INVALID_METRICS_RESPONSE'}});
  transport.mockResolvedValue({status:502,body:{message:'SYNTHETIC-SECRET-ERROR'}});await expect(new LokiProvider().evaluate(source,cid,scope(),window,new MetricsQueryBudget(),true)).rejects.toMatchObject({response:{code:'INVALID_METRICS_RESPONSE'}});
 });
});
