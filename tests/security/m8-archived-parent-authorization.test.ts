import 'reflect-metadata';
import {describe,it,expect,vi} from 'vitest';
import {randomUUID} from 'node:crypto';
import {ForbiddenException,NotFoundException,ServiceUnavailableException} from '@nestjs/common';
import {AuthorizationService} from '../../apps/console-api/src/modules/authorization/authorization.service';
import {KongExecutionContextService} from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import {encodeTag} from '../../apps/console-api/src/infrastructure/kong/tags';
import type {EffectiveGrant} from '../../apps/console-api/src/common/authorization.types';
import type {GraphNode} from '../../apps/console-api/src/modules/recycle-bin/graph-capturer.service';
import {workspaceFixture,payWorkspaceId,opsWorkspaceId} from '../unit/workspace-test-fixture';

const cid=randomUUID(),foreignCid=randomUUID(),uid=randomUUID(),sid=randomUUID(),pay=encodeTag('team:pay'),ops=encodeTag('team:ops');
const actor={id:uid,username:'source-test',superAdmin:false};
const grant=(module:string,action:any='write',scope:any='workspace',values:any[]=[payWorkspaceId]):EffectiveGrant=>({module,action,scope_type:scope,scope_values:values,cluster_id:cid,workspace_id:payWorkspaceId});
function node(type:string,extra:any={},parents:GraphNode[]=[],affected=true):GraphNode{
 const id=randomUUID();return{key:`${type}:${id}`,type,id,path:`/${type}/${id}`,data:{id,tags:['kos-ws-pay',pay],...extra},affected,dependencies:parents.map(parent=>parent.key),restorable:true};
}
function fixture(initial:EffectiveGrant[]){
 let grants=initial,epoch=1,activeSession=true;
 const remote=new Map<string,any>(),failures=new Map<string,Error>(),workspace=workspaceFixture(cid),execution=new KongExecutionContextService();
 const db:any={one:vi.fn(async(sql:string,p:any[])=>sql.includes('FROM users')?{id:uid,username:actor.username,super_admin:false,credential_epoch:1,permissions_epoch:1}:sql.includes('FROM auth_sessions')?activeSession?{id:sid}:null:sql.includes('FROM iam_epoch')?{version:epoch}:sql.includes('FROM clusters')&&p[0]===cid?{id:cid}:null),query:vi.fn(async()=>structuredClone(grants))};
 const kong:any={request:vi.fn(async(_cid:string,method:string,path:string)=>{expect(method).toBe('GET');if(failures.has(path))throw failures.get(path);if(!remote.has(path))throw new NotFoundException();return structuredClone(remote.get(path));})};
 const authz=new AuthorizationService(db,workspace.resolver,kong,execution);
 const run=<T>(fn:()=>Promise<T>)=>execution.runHttp({},async()=>{execution.bindHttpActor(actor,sid);const close=execution.captureHttpCloser();try{return await execution.runActor({actor,clusterId:cid,workspaceId:payWorkspaceId},fn);}finally{close();}});
 return{authz,kong,remote,failures,run,workspace,revoke:()=>{activeSession=false;},setGrants:(next:EffectiveGrant[])=>{grants=next;epoch++;}};
}
const check=(f:ReturnType<typeof fixture>,child:GraphNode,graph:GraphNode[],action='write',wid=payWorkspaceId,cluster=cid)=>f.run(()=>f.authz.assertArchivedEntity(actor,cluster,child.type,action,child.data,wid,graph));

describe('M8 actual current authorization for server-archived absent parents',()=>{
 it.each(['key-auth','basic-auth','jwt','oauth2','hmac-auth','acls'])('permits archived %s only through its deleted authorized Consumer',async(type)=>{
  const parent=node('consumers',{username:'archived'}),child=node(type,{consumer:{id:parent.id}},[parent]),f=fixture([grant('consumers')]);
  await expect(check(f,child,[parent,child])).resolves.toBeUndefined();expect(f.kong.request).toHaveBeenCalledWith(cid,'GET',`/consumers/${parent.id}`);
  await expect(f.run(()=>f.authz.assertEntity(actor,cid,type,'write',child.data,payWorkspaceId))).rejects.toMatchObject({status:404});
 });
 it('permits an archived Target through a deleted Upstream without changing ordinary child reads',async()=>{
  const parent=node('upstreams',{name:'archived'}),child=node('targets',{upstream:{id:parent.id},target:'127.0.0.1:80'},[parent]),f=fixture([grant('upstreams')]);await expect(check(f,child,[parent,child])).resolves.toBeUndefined();
 });
 it('retains Service inheritance through an absent Route for a bound Plugin',async()=>{
  const service=node('services',{name:'archived'}),route=node('routes',{service:{id:service.id}},[service]),plugin=node('plugins',{name:'cors',route:{id:route.id}},[route]),f=fixture([grant('services')]);
  await expect(check(f,plugin,[service,route,plugin])).resolves.toBeUndefined();
 });
 it('retains only necessary Service read inherited from an authorized archived Route',async()=>{
  const service=node('services',{name:'shared'},[],false),route=node('routes',{service:{id:service.id}},[service]),f=fixture([grant('routes','write','entity',[{entity_type:'routes',entity_id:route.id}])]);
  f.remote.set(`/services/${service.id}`,service.data);await expect(check(f,service,[service,route],'read')).resolves.toBeUndefined();
  await expect(check(f,service,[service,route],'write')).rejects.toMatchObject({status:403});
 });
 it('does not reuse archived Route grants after moving a currently shared Service',async()=>{
  const service=node('services',{name:'shared'},[],false),route=node('routes',{service:{id:service.id}},[service]),f=fixture([grant('routes','read','entity',[{entity_type:'routes',entity_id:route.id}])]);
  f.remote.set(`/services/${service.id}`,{...service.data,tags:['kos-ws-ops',pay]});await expect(check(f,service,[service,route],'read')).rejects.toMatchObject({status:403});
 });
 it('checks current shared-object business tags rather than accepting its historical matching tag',async()=>{
  const service=node('services',{name:'shared'},[],false),f=fixture([grant('services','read','tag_group',[pay])]);
  f.remote.set(`/services/${service.id}`,{...service.data,tags:['kos-ws-pay',ops]});await expect(check(f,service,[service],'read')).rejects.toMatchObject({status:403});
 });
 it('uses current shared-parent tags and refuses a parent moved to another workspace',async()=>{
  const parent=node('consumers',{username:'shared'},[],false),child=node('key-auth',{consumer:{id:parent.id}},[parent]),f=fixture([grant('consumers')]);
  f.remote.set(`/consumers/${parent.id}`,{...parent.data,tags:['kos-ws-ops',pay]});await expect(check(f,child,[parent,child])).rejects.toMatchObject({status:403});
 });
 it('refuses an absent unaffected dependency rather than authorizing its archived identity',async()=>{
  const parent=node('consumers',{},[],false),child=node('jwt',{consumer:{id:parent.id}},[parent]),f=fixture([grant('consumers')]);await expect(check(f,child,[parent,child])).rejects.toMatchObject({status:404});
 });
 it.each([new ForbiddenException(),new ServiceUnavailableException(),new Error('synthetic network failure')])('never treats denied or failed parent reads as absence',async(error)=>{
  const parent=node('consumers'),child=node('jwt',{consumer:{id:parent.id}},[parent]),f=fixture([grant('consumers')]);f.failures.set(`/consumers/${parent.id}`,error);await expect(check(f,child,[parent,child])).rejects.toBe(error);
 });
 it('refuses a reused affected parent ID whose configuration or tags changed',async()=>{
  const parent=node('consumers',{username:'archived'}),child=node('jwt',{consumer:{id:parent.id}},[parent]),f=fixture([grant('consumers')]);
  for(const data of [{...parent.data,username:'replacement'},{...parent.data,tags:['kos-ws-pay',ops]}]){f.remote.set(`/consumers/${parent.id}`,data);await expect(check(f,child,[parent,child])).rejects.toMatchObject({response:{code:'ARCHIVED_PARENT_CHANGED'}});}
  f.remote.set(`/consumers/${parent.id}`,{...parent.data,created_at:5,updated_at:6});await expect(check(f,child,[parent,child])).resolves.toBeUndefined();
 });
 it('retains child tag requirements under inherited Consumer tag grants',async()=>{
  const parent=node('consumers'),child=node('jwt',{consumer:{id:parent.id},tags:['kos-ws-pay',ops]},[parent]),f=fixture([grant('consumers','write','tag_group',[pay])]);await expect(check(f,child,[parent,child])).rejects.toMatchObject({status:403});
 });
 it('retains exact typed child allowlists and rejects sibling credentials',async()=>{
  const parent=node('consumers'),child=node('jwt',{consumer:{id:parent.id}},[parent]),sibling=node('jwt',{consumer:{id:parent.id}},[parent]),f=fixture([grant('consumers','write','entity',[{entity_type:'jwt',entity_id:child.id}])]);
  await expect(check(f,child,[parent,child,sibling])).resolves.toBeUndefined();await expect(check(f,sibling,[parent,child,sibling])).rejects.toMatchObject({status:403});
 });
 it('does not convert read-only or revoked grants into restoration authority',async()=>{
  const parent=node('consumers'),child=node('jwt',{consumer:{id:parent.id}},[parent]),f=fixture([grant('consumers','read')]);await expect(check(f,child,[parent,child])).rejects.toMatchObject({status:403});
  f.setGrants([grant('consumers')]);await check(f,child,[parent,child]);f.setGrants([]);await expect(check(f,child,[parent,child])).rejects.toMatchObject({status:403});
 });
 it('rejects revoked sessions and foreign cluster/workspace ceilings',async()=>{
  const parent=node('consumers'),child=node('jwt',{consumer:{id:parent.id}},[parent]),f=fixture([grant('consumers')]);await expect(check(f,child,[parent,child],'write',opsWorkspaceId)).rejects.toMatchObject({status:403});
  await expect(check(f,child,[parent,child],'write',payWorkspaceId,foreignCid)).rejects.toMatchObject({status:403});f.revoke();await expect(check(f,child,[parent,child])).rejects.toMatchObject({status:401});
 });
 it('rejects graph substitution, omitted dependency edges and duplicate identities before parent reads',async()=>{
  const parent=node('consumers'),child=node('jwt',{consumer:{id:parent.id}},[parent]),f=fixture([grant('consumers')]);
  for(const graph of [[child],[parent,{...child,dependencies:[]}],[parent,child,{...parent}],[parent,{...child,data:{...child.data,id:randomUUID()}}]])await expect(check(f,child,graph)).rejects.toMatchObject({status:403});expect(f.kong.request).not.toHaveBeenCalled();
 });
 it('fails if grants change during a missing-parent read and does not reuse the earlier permission snapshot',async()=>{
  const parent=node('consumers'),child=node('jwt',{consumer:{id:parent.id}},[parent]),f=fixture([grant('consumers')]);f.kong.request.mockImplementationOnce(async()=>{f.setGrants([]);throw new NotFoundException();});await expect(check(f,child,[parent,child])).rejects.toMatchObject({status:403});
 });
 it('keeps migration projections dependent on an existing parent',async()=>{
  const parent=node('consumers'),child=node('jwt',{consumer:{id:parent.id}},[parent]),f=fixture([grant('consumers')]);await expect(f.run(()=>f.authz.assertMigrationEntity(actor,cid,'jwt','write',child.data,payWorkspaceId,[parent]))).rejects.toMatchObject({status:404});
 });
});
