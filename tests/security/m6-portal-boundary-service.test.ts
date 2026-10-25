import 'reflect-metadata';
import { beforeAll, describe, expect, it, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { NotFoundException, ForbiddenException } from '@nestjs/common';
import { PortalAuthBoundaryService } from '../../apps/console-api/src/modules/portal-boundary/portal-auth-boundary.service';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { publicationProofAad } from '../../apps/console-api/src/modules/portal/portal-proof';

const ids=Array.from({length:140},(_,n)=>`10000000-0000-4000-8000-${String(n+1).padStart(12,'0')}`);
const [cid,wid,pid,sid,rid,kid,aid,consumerId,grantId,workflowId,executionId,operationId]=ids;
const scope='a'.repeat(64),group=`kos-portal-api-${pid}`,tag='kos-ws-pay',permit={};
beforeAll(()=>{process.env.CONSOLE_ENCRYPTION_KEY='78'.repeat(32);});
const rawSchema=(name:string)=>JSON.parse(readFileSync(new URL(`../fixtures/kong-1.5.1/${name}.json`,import.meta.url),'utf8'));
function fixture(){
 const secrets=new SecretService(),service={id:sid,protocol:'http',host:'example.test',port:80,tags:[tag]},route={id:rid,protocols:['http','https'],service:{id:sid},tags:[tag]};
 const key={id:kid,name:'key-auth',enabled:true,protocols:['http','https'],consumer:null,route:null,service:{id:sid},tags:[tag],config:{key_names:['apikey'],anonymous:null}};
 const acl={id:aid,name:'acl',enabled:true,protocols:['http','https'],consumer:null,route:null,service:{id:sid},tags:[tag],config:{whitelist:[group],blacklist:null}};
 const proof:any={version:1,clusterId:cid,workspaceId:wid,publicationId:pid,publicationRevision:1,transportScope:scope,
  clusterRevision:1,workspaceRevision:1,executionMode:'direct',workflowId,executionId,planRevision:1,planHash:'b'.repeat(64),verifiedAt:new Date().toISOString(),
  serviceId:sid,aclGroup:group,aclPluginId:aid,keyAuthPluginId:kid,service,aclPlugin:acl,keyAuthPlugin:key,schemas:{},definitions:{}};
 const row:any={id:pid,cluster_id:cid,workspace_id:wid,transport_scope:scope,state:'published',published_revision:1,revision:1,
  service_id:sid,acl_group:group,key_auth_plugin_id:kid,acl_plugin_id:aid,publication_id:pid,publication_revision:1,
  proof_workflow_id:workflowId,workflow_execution_id:executionId,workflow_plan_revision:1,workflow_plan_hash:proof.planHash,
  proof_execution_state:'succeeded',proof_workflow_state:'succeeded',proof_workflow_kind:'portal-publication',
  publication_proof_secret:secrets.encrypt(proof,publicationProofAad(cid,wid,pid,1)),publication_proof_hmac:secrets.fingerprint(proof)};
 const history={publications:[row],grants:[] as any[],credentials:[] as any[]};
 const graph={services:[service],routes:[route],plugins:[key,acl]};let captureCallback:(()=>void)|undefined;
 const db:any={query:vi.fn(async(sql:string,params:any[])=>{
  expect(params).toEqual([scope]);
  const source=sql.includes('FROM portal_publications p')?history.publications:sql.includes('SELECT c.*')?history.credentials:history.grants;
  return structuredClone(source);
 })};
 const context:any={runPortalBoundaryRead:vi.fn(async(p:any,paths:string[],fn:any)=>{expect(p).toBe(permit);expect(paths).not.toContain('/consumers');return fn();}),runInternalRead:vi.fn(async(_cid:string,purpose:string,fn:any,limits:any)=>{expect(purpose).toBe('entity-preflight');expect(limits.paths.every((p:string)=>/^\/(schemas|plugins\/schema)\//.test(p))).toBe(true);return fn();})};
 const kong:any={list:vi.fn(async(_cid:string,path:string)=>{
  captureCallback?.();return {items:structuredClone(path.endsWith('/acls')?[{id:ids[13],group,consumer:{id:consumerId}}]:(graph as any)[path.slice(1)]),nextCursor:null};
 }),request:vi.fn(async(_cid:string,_method:string,path:string)=>{
  if(path===`/consumers/${consumerId}`)return {id:consumerId};throw new NotFoundException();
 }),schema:vi.fn(async(_cid:string,type:string)=>rawSchema(`schema-${type}`)),pluginSchema:vi.fn(async(_cid:string,name:string)=>rawSchema(`plugin-schema-${name}`))};
 const workspaces:any={listScope:vi.fn(async(c:string,w:string)=>{expect(c).toBe(cid);expect(w).toBe(wid);return {tag};}),matches:(_scope:any,next:any)=>next.tags?.filter((value:string)=>value.startsWith('kos-ws-')).join(',')===tag};
 const approved:any={assertNativeWrite:vi.fn(async()=>{throw new ForbiddenException();})};
 const boundary=new PortalAuthBoundaryService(db,secrets,kong,context,workspaces,approved);
 const packet=(extra:any={})=>({clusterId:cid,workspaceId:wid,transportScope:scope,operationId,method:'PATCH',canonicalPath:`/services/${sid}`,mutationAction:'update',before:service,body:{host:'next.example.test'},...extra});
 const grant=(state='active')=>({id:grantId,cluster_id:cid,workspace_id:wid,transport_scope:scope,publication_id:pid,consumer_id:consumerId,acl_group:group,acl_id:ids[13],state});
 return {boundary,secrets,history,graph,db,kong,context,approved,packet,grant,row,onCapture:(fn:()=>void)=>{captureCallback=fn;}};
}

// Database/transport data are fixtures. This suite exercises the actual final
// boundary and real AEAD/HMAC proof decoder. Private permit provenance has a
// separate actual ExecutionContext suite; this fixture does not test minting.
describe('M6 final-send Portal boundary service',()=>{
 it('captures complete private graphs and accepts a safe Service change',async()=>{
  const f=fixture();await f.boundary.assertBeforeNativeSend(f.packet(),permit as any);
  expect(f.kong.list.mock.calls.map(call=>call[1])).toEqual(['/services','/routes','/plugins']);
  expect(f.db.query.mock.calls.every(call=>call[1][0]===scope)).toBe(true);
 });
 it.each(['basic-auth','key-auth','jwt','oauth2','hmac-auth','acls'])('protects every %s child of a historically revoked Portal Consumer',async kind=>{
  const f=fixture();f.history.publications=[];f.history.grants=[f.grant('revoked')];
  await expect(f.boundary.assertBeforeNativeSend(f.packet({canonicalPath:`/consumers/${consumerId}/${kind}`,method:'POST',body:{id:ids[14]},mutationAction:'restore',parentId:consumerId,credentialKind:kind}),permit as any)).rejects.toMatchObject({response:{code:'PORTAL_MANAGED_OBJECT'}});
  expect(f.kong.list).not.toHaveBeenCalled();expect(f.approved.assertNativeWrite).toHaveBeenCalledOnce();
 });
 it('uses captured physical scope across cluster aliases and remapped history',async()=>{
  const f=fixture();f.history.publications=[];f.history.grants=[f.grant('revoked')];
  await expect(f.boundary.assertBeforeNativeSend(f.packet({clusterId:ids[15],canonicalPath:`/consumers/${consumerId.toUpperCase()}`,body:{username:'bypass'}}),permit as any)).rejects.toMatchObject({response:{code:'PORTAL_MANAGED_OBJECT'}});
  expect(f.db.query.mock.calls.every(call=>call[1][0]===scope)).toBe(true);
 });
 it('does not trust HTTP-style workflow IDs, flags or copied handles',async()=>{
  const f=fixture();f.history.grants=[f.grant()];
  await expect(f.boundary.assertBeforeNativeSend(f.packet({canonicalPath:`/consumers/${consumerId}/key-auth`,method:'POST',body:{id:ids[14],approved:true,workflowId,capability:{}},parentId:consumerId}),permit as any)).rejects.toMatchObject({response:{code:'PORTAL_MANAGED_OBJECT'}});
 });
 it.each(['key-auth','acls'])('prevents recreating a historical %s UUID under a different Consumer',async kind=>{
  const f=fixture();f.history.publications=[];f.history.grants=[f.grant('revoked')];f.history.credentials=[{kong_id:ids[18],grant_id:grantId,state:'revoked'}];
  const oldId=kind==='acls'?ids[13]:ids[18];
  await expect(f.boundary.assertBeforeNativeSend(f.packet({canonicalPath:`/consumers/${ids[19]}/${kind}`,method:'POST',body:{id:oldId},parentId:ids[19]}),permit as any)).rejects.toMatchObject({response:{code:'PORTAL_MANAGED_OBJECT'}});
  expect(f.kong.list).not.toHaveBeenCalled();
 });
 it.each(['POST','PATCH'])('prevents %s reserved Portal membership on an unrelated Consumer',async method=>{
  const f=fixture();await expect(f.boundary.assertBeforeNativeSend(f.packet({canonicalPath:`/consumers/${ids[19]}/acls${method==='PATCH'?`/${ids[20]}`:''}`,method,
   body:{group},before:method==='PATCH'?{id:ids[20],group:'other-team'}:undefined,parentId:ids[19]}),permit as any)).rejects.toMatchObject({response:{code:'PORTAL_MANAGED_OBJECT'}});
  expect(f.kong.list).not.toHaveBeenCalled();
 });
 it('reserves membership even after an unpublished zero-key publication is retired',async()=>{
  const f=fixture();f.history.publications=[];
  await expect(f.boundary.assertBeforeNativeSend(f.packet({canonicalPath:`/consumers/${ids[19]}/acls`,method:'POST',body:{group},parentId:ids[19]}),permit as any)).rejects.toMatchObject({response:{code:'PORTAL_MANAGED_OBJECT'}});
 });
 it('allows the audited removal of externally introduced rogue membership',async()=>{
  const f=fixture();await f.boundary.assertBeforeNativeSend(f.packet({canonicalPath:`/consumers/${ids[19]}/acls/${ids[20]}`,method:'DELETE',body:undefined,before:{id:ids[20],group},parentId:ids[19]}),permit as any);
  expect(f.approved.assertNativeWrite).not.toHaveBeenCalled();
 });
 it('requires the exact private approved step for a managed packet and still checks authentication',async()=>{
  const f=fixture();f.history.grants=[f.grant()];f.approved.assertNativeWrite.mockResolvedValueOnce(undefined);
  await f.boundary.assertBeforeNativeSend(f.packet({canonicalPath:`/consumers/${consumerId}/key-auth`,method:'POST',body:{id:ids[14]},parentId:consumerId}),permit as any);
  expect(f.kong.request).toHaveBeenCalledWith(cid,'GET',`/consumers/${consumerId}`);
  expect(f.kong.list.mock.calls.map(call=>call[1])).toContain(`/consumers/${consumerId}/acls`);
 });
 it('retains zero-key publication protection after the final grant is revoked',async()=>{
  const f=fixture();f.history.grants=[f.grant('revoked')];
  await expect(f.boundary.assertBeforeNativeSend(f.packet({canonicalPath:`/plugins/${kid}`,before:f.graph.plugins[0],body:{enabled:false}}),permit as any)).rejects.toMatchObject({status:403});
 });
 it.each(['key-auth','acl'])('allows a safe direct republish %s configuration through the ordinary native gate',async name=>{
  const f=fixture();f.history.grants=[f.grant()];const plugin=f.graph.plugins.find(row=>row.name===name)!;
  await f.boundary.assertBeforeNativeSend(f.packet({canonicalPath:`/plugins/${plugin.id}`,before:plugin,body:{enabled:true,config:structuredClone(plugin.config)}}),permit as any);
  expect(f.approved.assertNativeWrite).not.toHaveBeenCalled();
  expect(f.kong.list.mock.calls.map(call=>call[1])).toContain(`/consumers/${consumerId}/acls`);
 });
 it('releases retired authentication risks while retaining historical ownership',async()=>{
  const f=fixture();f.history.publications=[];f.history.grants=[f.grant('revoked')];
  await f.boundary.assertBeforeNativeSend(f.packet(),permit as any);expect(f.kong.list).not.toHaveBeenCalled();
 });
 it('releases only SQL-proven never-issued risk while permanently protecting its reserved native UUIDs',async()=>{
  const f=fixture();f.history.publications=[];f.history.grants=[{...f.grant('disabled'),reservation_released_at:new Date().toISOString()}];
  await f.boundary.assertBeforeNativeSend(f.packet(),permit as any);expect(f.kong.list).not.toHaveBeenCalled();
  await expect(f.boundary.assertBeforeNativeSend(f.packet({canonicalPath:`/consumers/${consumerId}`,method:'POST',body:{id:consumerId}}),permit as any)).rejects.toMatchObject({response:{code:'PORTAL_MANAGED_OBJECT'}});
 });
 it('does not interpret a merely disabled reservation as SQL-proven risk release',async()=>{
  const f=fixture();f.history.grants=[f.grant('disabled')];
  await f.boundary.assertBeforeNativeSend(f.packet(),permit as any);
  expect(f.kong.list.mock.calls.map(call=>call[1])).toContain(`/consumers/${consumerId}/acls`);
 });
 it.each(['proof','parent','binding'])('rejects invalid %s publication evidence',async kind=>{
  const f=fixture();if(kind==='proof')f.row.publication_proof_hmac='c'.repeat(64);if(kind==='parent')f.row.proof_execution_state='uncertain';if(kind==='binding')f.row.key_auth_plugin_id=ids[17];
  await expect(f.boundary.assertBeforeNativeSend(f.packet(),permit as any)).rejects.toMatchObject({response:{code:'PORTAL_PUBLICATION_PROOF_INVALID'}});expect(f.kong.list).not.toHaveBeenCalled();
 });
 it('rejects metadata changed during a native capture await',async()=>{
  const f=fixture();f.onCapture(()=>{f.row.revision++;});
  await expect(f.boundary.assertBeforeNativeSend(f.packet(),permit as any)).rejects.toMatchObject({response:{code:'PORTAL_AUTH_GRAPH_CHANGED'}});
 });
 it('rejects a changed native before object rather than approving stale graph data',async()=>{
  const f=fixture();f.graph.services[0].host='changed-outside';
  await expect(f.boundary.assertBeforeNativeSend(f.packet({before:{...f.graph.services[0],host:'original'}}),permit as any)).rejects.toMatchObject({response:{code:'PORTAL_AUTH_GRAPH_CHANGED'}});
 });
 it('prevents published Service workspace migration',async()=>{
  const f=fixture();await expect(f.boundary.assertBeforeNativeSend(f.packet({body:{tags:['kos-ws-ops']},mutationAction:'migrate'}),permit as any)).rejects.toMatchObject({response:{code:'PORTAL_PUBLISHED_WORKSPACE_IMMUTABLE'}});
 });
 it('prevents rebinding a published Route to another Service',async()=>{
  const f=fixture();await expect(f.boundary.assertBeforeNativeSend(f.packet({canonicalPath:`/routes/${rid}`,before:f.graph.routes[0],body:{service:{id:ids[17]}}}),permit as any)).rejects.toMatchObject({response:{code:'PORTAL_PUBLISHED_BINDING_IMMUTABLE'}});
 });
 it('resolves omitted Plugin defaults from actual recorded 1.5 schemas, without changing wire body',async()=>{
  const f=fixture(),body={id:ids[16],name:'correlation-id',service:{id:sid},config:{},tags:[tag]};
  await f.boundary.assertBeforeNativeSend(f.packet({method:'POST',canonicalPath:'/plugins',body,before:undefined,mutationAction:'create'}),permit as any);
  expect(f.kong.schema).toHaveBeenCalledWith(cid,'plugins');expect(f.kong.pluginSchema).toHaveBeenCalledWith(cid,'correlation-id');expect(body).not.toHaveProperty('enabled');expect(body).not.toHaveProperty('protocols');
 });
 it('rejects incomplete data and excessive derived Consumer read paths',async()=>{
  const f=fixture();f.history.grants=ids.slice(20,84).map(id=>({...f.grant(),id,consumer_id:id,state:'pending'}));
  await expect(f.boundary.assertBeforeNativeSend(f.packet(),permit as any)).rejects.toMatchObject({response:{code:'PORTAL_AUTH_GRAPH_BUDGET'}});expect(f.kong.list).not.toHaveBeenCalled();
 });
 it('does not misclassify unrelated certificate packets as authentication changes',async()=>{
  const f=fixture();await f.boundary.assertBeforeNativeSend(f.packet({canonicalPath:`/certificates/${ids[17]}`}),permit as any);expect(f.db.query).not.toHaveBeenCalled();
 });
 it.each([`/services/${sid}/routes`,`/routes/${rid}/service`,`/plugins/${kid}/service`])('fails closed for an unnormalized relation write %s',async path=>{
  const f=fixture();await expect(f.boundary.assertBeforeNativeSend(f.packet({canonicalPath:path,method:'POST'}),permit as any)).rejects.toMatchObject({response:{code:'PORTAL_AUTH_NATIVE_PATH_UNSUPPORTED'}});expect(f.db.query).not.toHaveBeenCalled();
 });
});

describe('M6 actual graph verification during metadata-only issuance recovery',()=>{
 function recoveryFixture(){
  const f=fixture();
  f.history.grants=[{...f.grant('pending'),workflow_id:workflowId}];
  f.context.currentIssueActivationRecovery=vi.fn(async()=>({clusterId:cid,workspaceId:wid,workflowId,executionId,transportScope:scope}));
  f.context.runPortalRecoveryBoundaryRead=vi.fn(async(paths:string[],fn:any,limits:any)=>{
   expect(paths).toEqual(['/services','/routes','/plugins',`/consumers/${consumerId}`,`/consumers/${consumerId}/acls`]);
   expect(limits).toEqual({maxCalls:250,maxPages:100,maxRecords:10000,maxBytes:32*1024*1024,timeoutMs:120000});
   return fn();
  });
  return f;
 }
 it('observes all physical lists and owned ACLs without prospective packet, native permit or schema access',async()=>{
  const f=recoveryFixture();await f.boundary.assertCurrentIssueRecoveryBoundary();
  expect(f.kong.list.mock.calls.map(call=>call[1])).toEqual(['/services','/routes','/plugins',`/consumers/${consumerId}/acls`]);
  expect(f.kong.request.mock.calls).toEqual([[cid,'GET',`/consumers/${consumerId}`]]);
  expect(f.context.currentIssueActivationRecovery).toHaveBeenCalledTimes(2);
  expect(f.context.runPortalBoundaryRead).not.toHaveBeenCalled();expect(f.approved.assertNativeWrite).not.toHaveBeenCalled();
  expect(f.kong.schema).not.toHaveBeenCalled();expect(f.kong.pluginSchema).not.toHaveBeenCalled();
 });
 it.each(['workflow','cluster','workspace'])('rejects a different %s subject before capture',async dimension=>{
  const f=recoveryFixture(),row=f.history.grants[0];row[`${dimension}_id`]=ids[35];
  await expect(f.boundary.assertCurrentIssueRecoveryBoundary()).rejects.toMatchObject({response:{code:'PORTAL_RECOVERY_SUBJECT_MISMATCH'}});
  expect(f.kong.list).not.toHaveBeenCalled();expect(f.kong.request).not.toHaveBeenCalled();
 });
 it('rejects current unsafe plugin priority even though the original publication was proven',async()=>{
  const f=recoveryFixture();f.graph.plugins.push({...f.graph.plugins[0],id:ids[35],route:{id:rid},config:{key_names:['apikey'],anonymous:ids[36]}} as any);
  await expect(f.boundary.assertCurrentIssueRecoveryBoundary()).rejects.toMatchObject({status:403});
  expect(f.context.runPortalRecoveryBoundaryRead).toHaveBeenCalledOnce();
 });
 it('retains original published proof integrity and fails before remote observation when corrupt',async()=>{
  const f=recoveryFixture();f.row.publication_proof_hmac='c'.repeat(64);
  await expect(f.boundary.assertCurrentIssueRecoveryBoundary()).rejects.toMatchObject({response:{code:'PORTAL_PUBLICATION_PROOF_INVALID'}});
  expect(f.kong.list).not.toHaveBeenCalled();expect(f.kong.request).not.toHaveBeenCalled();
  expect(f.context.runPortalBoundaryRead).not.toHaveBeenCalled();expect(f.approved.assertNativeWrite).not.toHaveBeenCalled();
 });
 it('fails on changed physical ownership during capture instead of accepting the stale grant proof',async()=>{
  const f=recoveryFixture();f.onCapture(()=>{f.history.grants[0].revision=(f.history.grants[0].revision??0)+1;});
  await expect(f.boundary.assertCurrentIssueRecoveryBoundary()).rejects.toMatchObject({response:{code:'PORTAL_AUTH_GRAPH_CHANGED'}});
 });
 it('rechecks live recovery authority after all native awaits',async()=>{
  const f=recoveryFixture();f.context.currentIssueActivationRecovery.mockRejectedValueOnce(new ForbiddenException({code:'SESSION_EXPIRED'}));
  await expect(f.boundary.assertCurrentIssueRecoveryBoundary()).rejects.toMatchObject({response:{code:'SESSION_EXPIRED'}});
  expect(f.kong.list).not.toHaveBeenCalled();
  const g=recoveryFixture();g.context.currentIssueActivationRecovery.mockResolvedValueOnce({clusterId:cid,workspaceId:wid,workflowId,executionId,transportScope:scope})
   .mockRejectedValueOnce(new ForbiddenException({code:'SESSION_EXPIRED'}));
  await expect(g.boundary.assertCurrentIssueRecoveryBoundary()).rejects.toMatchObject({response:{code:'SESSION_EXPIRED'}});
  expect(g.kong.list).toHaveBeenCalled();
 });
 it('rejects repeated pagination cursors and incomplete lists without pretending a partial graph is complete',async()=>{
  const f=recoveryFixture();f.kong.list.mockImplementation(async()=>({items:[],nextCursor:'same'}));
  await expect(f.boundary.assertCurrentIssueRecoveryBoundary()).rejects.toMatchObject({response:{code:'PORTAL_AUTH_GRAPH_INCOMPLETE'}});
  expect(f.kong.list).toHaveBeenCalledTimes(2);
 });
});
