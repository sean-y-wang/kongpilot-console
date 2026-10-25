import 'reflect-metadata';
import { describe, expect, it, vi } from 'vitest';
import { AuthorizationService } from '../../apps/console-api/src/modules/authorization/authorization.service';
import { KongExecutionContextService } from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import { normalizePermission } from '../../apps/console-api/src/modules/iam/iam-policy';
import { encodeTag } from '../../apps/console-api/src/infrastructure/kong/tags';
import { permissionModule, type EffectiveGrant } from '../../apps/console-api/src/common/authorization.types';
import { frozenChangePermits } from '../../apps/console-api/src/modules/entities/entity-change-subject-policy';
import type { PreparedEntityChange } from '../../apps/console-api/src/modules/entities/entity-change.types';
import { payWorkspaceId as wid, opsWorkspaceId as otherWid, workspaceFixture } from '../unit/workspace-test-fixture';

const cid='d7f71f42-26c0-435f-b9d5-33f951d20447', otherCid='999cde21-5a17-4c2c-b526-2b884689e5cf';
const uid='b064c239-d385-47bc-a45a-f58757f78d72', sid='bf616dbf-6dc8-43e6-8e51-0c3bd73d423d';
const entityId='07c941af-e0c9-4e27-93be-4e04dc9decc6';
const actor={id:uid,username:'portal-manager',superAdmin:false};
const workflowEntityTypes=['services','routes','consumers','plugins','upstreams','certificates','ca_certificates','snis','targets','key-auth','basic-auth','jwt','oauth2','hmac-auth','acls'];
const grant=(extra:Partial<EffectiveGrant>={}):EffectiveGrant=>({module:'portal',action:'read',cluster_id:cid,workspace_id:wid,
 scope_type:'workspace',scope_values:[wid],...extra});

// Current SQL/session rows and gateway responses are fixtures. Actual Authz,
// workspace, grant and request-context policies are used without policy stubs.
function fixture(initial:EffectiveGrant[]=[grant()]){
 let rows=initial, epoch=1, sessionActive=true, clusterActive=true;
 const user={...actor,super_admin:false,status:'active',credential_epoch:1,permissions_epoch:1};
 const workspace=workspaceFixture(cid), execution=new KongExecutionContextService();
 const db:any={one:vi.fn(async(sql:string,params:any[]=[])=>{
  if(sql.includes('FROM users'))return params[0]===uid&&user.status==='active'?user:null;
  if(sql.includes('FROM auth_sessions'))return sessionActive?{id:sid}:null;
  if(sql.includes('FROM iam_epoch'))return {version:epoch};
  if(sql.includes('FROM clusters'))return clusterActive&&[cid,otherCid].includes(params[0])?{id:params[0]}:null;
  throw new Error('unexpected fixture SQL');
 }),query:vi.fn(async(sql:string)=>sql.includes('iam_effective_grants')?structuredClone(rows):[{id:cid},{id:otherCid}])};
 const kong:any={request:vi.fn()};
 const authz=new AuthorizationService(db,workspace.resolver,kong,execution);
 const run=<T>(fn:()=>Promise<T>)=>execution.runHttp({},async()=>{
  execution.bindHttpActor(actor,sid);const close=execution.captureHttpCloser();
  try{return await execution.runActor({actor,clusterId:cid,workspaceId:wid},fn);}finally{close();}
 });
 return {authz,workspace,db,kong,user,run,replace:(next:EffectiveGrant[])=>{rows=next;epoch++;},
  revoke:()=>{sessionActive=false;},removeCluster:()=>{clusterActive=false;},changeEpoch:()=>{epoch++;}};
}

describe('M6 operational authorization and pure metadata',()=>{
 it.each(['portal','developers','applications','workflows'])('allows minimal tenant discovery for %s without native read',async module=>{
  const f=fixture([grant({module})]);
  await f.run(async()=>{
   const caps=await f.authz.capabilities(actor);
   expect(caps.clusters).toEqual([cid]);expect(caps.modules.clusters.read).toBe(true);
   expect(caps.modules.workspaces.read).toBe(true);expect(caps.modules.services.read).toBe(false);
   await f.authz.assertCluster(actor,cid,'clusters','read');
   await f.authz.assertCluster(actor,cid,'workspaces','read',wid);
   const ownWorkspace=f.workspace.rows.find(row=>row.id===wid)!;
   const otherWorkspace=f.workspace.rows.find(row=>row.id===otherWid)!;
   // Discovery must authorize the actual row and list projection, not only
   // the coarse module capability; WorkflowDetail waits for this real WID.
   await f.authz.assertEntity(actor,cid,'workspaces','read',ownWorkspace,wid);
   expect(await f.authz.filterEntities(actor,cid,'workspaces',[
    ownWorkspace,otherWorkspace,{...ownWorkspace,id:otherWid,cluster_id:otherCid},
   ])).toEqual([ownWorkspace]);
   await expect(f.authz.assertEntity(actor,cid,'workspaces','read',otherWorkspace,otherWid)).rejects.toMatchObject({status:403});
   await expect(f.authz.assertEntity(actor,otherCid,'workspaces','read',{...ownWorkspace,cluster_id:otherCid},wid)).rejects.toMatchObject({status:403});
   await expect(f.authz.filterEntities(actor,otherCid,'workspaces',[{...ownWorkspace,cluster_id:otherCid}])).rejects.toMatchObject({status:403});
   await expect(f.authz.assertEntity(actor,cid,'workspaces','write',ownWorkspace,wid)).rejects.toMatchObject({status:403});
   await expect(f.authz.assertCluster(actor,cid,'services','read',wid)).rejects.toMatchObject({status:403});
   await expect(f.authz.assertCluster(actor,otherCid,'clusters','read')).rejects.toMatchObject({status:403});
  });expect(f.kong.request).not.toHaveBeenCalled();
 });
 it.each(['read','write','delete','approve'])('requires the exact %s row for whole-workspace metadata',async action=>{
  const f=fixture([grant({action:action as any})]);
  await f.run(async()=>{
   expect(await f.authz.hasWholeWorkspace(actor,cid,wid,'portal',action)).toBe(true);
   expect(await f.authz.hasWholeWorkspace(actor,cid,wid,'developers',action)).toBe(false);
   for(const other of ['read','write','delete','approve'].filter(value=>value!==action))
    expect(await f.authz.hasWholeWorkspace(actor,cid,wid,'portal',other)).toBe(false);
  });
 });
 it.each(['tag_group','entity'])('never promotes %s to a whole-workspace metadata grant',async scope=>{
  const f=fixture([grant({scope_type:scope as any,scope_values:scope==='tag_group'?[encodeTag('team:pay')]:[{entity_type:'services',entity_id:entityId}]})]);
  await f.run(async()=>{
   expect(await f.authz.hasWholeWorkspace(actor,cid,wid,'portal','read')).toBe(false);
   await expect(f.authz.assertWholeWorkspace(actor,cid,wid,'portal','read')).rejects.toMatchObject({status:403});
  });
 });
 it('does not assemble module/action/workspace authority from separate rows',async()=>{
  const f=fixture([grant({module:'developers',action:'write'}),grant({module:'portal',action:'write',workspace_id:otherWid,scope_values:[otherWid]}),grant()]);
  expect(await f.run(()=>f.authz.hasWholeWorkspace(actor,cid,wid,'portal','write'))).toBe(false);
 });
 it('accepts a complete global row while retaining assignment ceilings',async()=>{
  const f=fixture([grant({scope_type:'global',scope_values:[]})]);
  await f.run(async()=>{
   expect(await f.authz.hasWholeWorkspace(actor,cid,wid,'portal','read')).toBe(true);
   expect(await f.authz.hasWholeWorkspace(actor,cid,otherWid,'portal','read')).toBe(false);
  });
 });
 it('preserves disabled metadata history but refuses disabled writes even for a platform actor',async()=>{
  const f=fixture([grant({action:'write'}),grant()]);f.workspace.rows.find(row=>row.id===wid)!.status='disabled';f.user.super_admin=true;
  await f.run(async()=>{
   expect(await f.authz.hasWholeWorkspace(actor,cid,wid,'portal','read')).toBe(true);
   expect(await f.authz.hasWholeWorkspace(actor,cid,wid,'portal','write')).toBe(false);
  });
 });
 it('refuses a deleted tenant and a missing cluster',async()=>{
  const f=fixture();f.workspace.rows.find(row=>row.id===wid)!.status='deleted';
  await expect(f.run(()=>f.authz.hasWholeWorkspace(actor,cid,wid,'portal','read'))).rejects.toMatchObject({status:404});
  f.removeCluster();await expect(f.run(()=>f.authz.hasWholeWorkspace(actor,cid,wid,'portal','read'))).rejects.toMatchObject({status:404});
 });
 it('rejects a permission epoch change after the workspace SQL await',async()=>{
  const f=fixture();f.workspace.db.one.mockImplementationOnce(async()=>{f.changeEpoch();return f.workspace.rows.find(row=>row.id===wid)!;});
  await expect(f.run(()=>f.authz.hasWholeWorkspace(actor,cid,wid,'portal','read'))).rejects.toMatchObject({status:403});
 });
 it('checks the current session rather than a stale actor projection',async()=>{
  const f=fixture();await f.run(async()=>{
   expect(await f.authz.hasWholeWorkspace(actor,cid,wid,'portal','read')).toBe(true);f.revoke();
   await expect(f.authz.hasWholeWorkspace(actor,cid,wid,'portal','read')).rejects.toMatchObject({status:401});
  });
 });
 it('keeps typed Portal scopes limited to services/routes without granting native configuration',async()=>{
  for(const type of ['services','routes']){
   const value=normalizePermission(grant({module:'portal',scope_type:'entity',scope_values:[{entity_type:type,entity_id:entityId}]}),{cluster_id:cid,workspace_id:wid});
   const f=fixture([value]), actual={id:entityId,name:'scoped',tags:['kos-ws-pay']};
   await f.run(async()=>{
    await f.authz.assertScopedResource(actor,cid,'portal','read',type,actual,wid);
    for(const action of ['read','write','delete'])
     await expect(f.authz.assertCluster(actor,cid,type,action,wid)).rejects.toMatchObject({status:403});
   });
   expect(f.kong.request).not.toHaveBeenCalled();
  }
  for(const type of [...workflowEntityTypes.slice(2),'vaults','keys','key-sets','event-hooks','clustering'])
   expect(()=>normalizePermission(grant({module:'portal',scope_type:'entity',scope_values:[{entity_type:type,entity_id:entityId}]}),{cluster_id:cid,workspace_id:wid})).toThrow();
 });
 it.each(workflowEntityTypes)('supports M11 typed %s workflow grants without native CRUD or cross-scope authority',async type=>{
  const actual={id:entityId,name:'scoped',tags:['kos-ws-pay']};
  for(const action of ['read','write','delete','approve'] as const){
   const value=normalizePermission(grant({module:'workflows',action,scope_type:'entity',scope_values:[{entity_type:type,entity_id:entityId}]}),{cluster_id:cid,workspace_id:wid});
   const f=fixture([value]);
   await f.run(async()=>{
    const caps=await f.authz.capabilities(actor);
    expect(caps.modules.workflows[action]).toBe(true);
    for(const nativeAction of ['read','write','delete'] as const){
     expect(caps.modules[permissionModule(type)][nativeAction]).toBe(false);
     await expect(f.authz.assertCluster(actor,cid,type,nativeAction,wid)).rejects.toMatchObject({status:403});
    }
    expect(caps.modules.secrets.read).toBe(false);
    // The generic operational-resource API covers the eight core entities.
    // Child identity checks use the M11 frozen-subject policy below instead.
    if(workflowEntityTypes.indexOf(type)<8){
     await f.authz.assertScopedResource(actor,cid,'workflows',action,type,actual,wid);
     for(const [scopeCid,scopeWid,scopeType,entity] of [
      [otherCid,wid,type,actual], [cid,otherWid,type,actual],
      [cid,wid,type,{...actual,id:uid}], [cid,wid,type==='services'?'routes':'services',actual],
     ] as const)
      await expect(f.authz.assertScopedResource(actor,scopeCid,'workflows',action,scopeType,entity,scopeWid)).rejects.toMatchObject({status:403});
    }
   });
   expect(f.kong.request).not.toHaveBeenCalled();
  }
  const readGrant=normalizePermission(grant({module:'workflows',scope_type:'entity',scope_values:[{entity_type:type,entity_id:entityId}]}),{cluster_id:cid,workspace_id:wid});
  // This policy takes only CID/WID from already authenticated compiler material;
  // the fixture tests grant separation, not a client-created execution permit.
  const material={clusterId:cid,workspaceId:wid} as PreparedEntityChange;
  const node={type,data:actual}, graph=new Map([[`${type}:${entityId}`,node]]);
  expect(frozenChangePermits([readGrant],material,graph,node,'workflows','read')).toBe(true);
  for(const action of ['read','write','delete'] as const)
   expect(frozenChangePermits([readGrant],material,graph,node,'native',action)).toBe(false);
  expect(frozenChangePermits([readGrant],material,graph,node,'workflows','write')).toBe(false);
  for(const wrong of [{...material,clusterId:otherCid},{...material,workspaceId:otherWid}])
   expect(frozenChangePermits([readGrant],wrong,graph,node,'workflows','read')).toBe(false);
  expect(frozenChangePermits([readGrant],material,new Map(),{...node,data:{...actual,id:uid}},'workflows','read')).toBe(false);
  expect(frozenChangePermits([readGrant],material,new Map(),{...node,type:type==='services'?'routes':'services'},'workflows','read')).toBe(false);
 });
 it.each(['vaults','keys','key-sets','event-hooks','clustering'])('rejects unsupported %s workflow entity scopes',type=>{
  expect(()=>normalizePermission(grant({module:'workflows',scope_type:'entity',scope_values:[{entity_type:type,entity_id:entityId}]}),{cluster_id:cid,workspace_id:wid})).toThrow();
 });
});
