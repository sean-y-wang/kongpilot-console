import {describe,expect,it} from 'vitest';
import {hasObservedAbsenceWitness,isKongPointNotFound} from '../../apps/console-api/src/modules/workflows/workflow-read-absence-witness';
const cid='c',wid='w',parent='p',entityId='e',key=(r:any)=>`${r.clusterId}:${r.workspaceId}:${r.path}`;
const root:any={clusterId:cid,workspaceId:wid,path:'/consumers/e',kind:'point',entityType:'consumers',entityId,allowAbsent:true};
const collection:any={clusterId:cid,workspaceId:wid,path:'/consumers',kind:'collection',entityType:'consumers'};
describe('absence witness requires actual provider-owned EOF or parent observation',()=>{
 it('requires explicit true EOF and no matching id in an accepted root collection',()=>{
  const cursors=new Map([[key(collection),{complete:true,ids:new Set<string>()}]]);
  expect(hasObservedAbsenceWitness(root,[root,collection],new Set([key(collection)]),new Set(),cursors)).toBe(true);
  expect(hasObservedAbsenceWitness(root,[root,collection],new Set(),new Set(),cursors)).toBe(false);
  cursors.get(key(collection))!.ids.add(entityId);expect(hasObservedAbsenceWitness(root,[root,collection],new Set([key(collection)]),new Set(),cursors)).toBe(false);
 });
 it.each(['clusterId','workspaceId','entityType','path'])('does not borrow another %s collection',field=>{
  const changed={...collection,[field]:'foreign'};
  expect(hasObservedAbsenceWitness(root,[root,changed],new Set([key(changed)]),new Set(),new Map([[key(changed),{complete:true,ids:new Set()}]]))).toBe(false);
 });
 it('requires a declared matching parent point accepted as present for a nested point',()=>{
  const point:any={clusterId:cid,workspaceId:wid,path:`/consumers/${parent}/key-auth/${entityId}`,kind:'point',entityType:'keyauth_credentials',entityId,parentId:parent,allowAbsent:true};
  const p:any={clusterId:cid,workspaceId:wid,path:`/consumers/${parent}`,kind:'point',entityType:'consumers',entityId:parent};
  expect(hasObservedAbsenceWitness(point,[point,p],new Set(),new Set([key(p)]),new Map())).toBe(true);
  expect(hasObservedAbsenceWitness(point,[point,p],new Set(),new Set(),new Map())).toBe(false);
  expect(hasObservedAbsenceWitness({...point,parentId:'foreign'},[point,p],new Set(),new Set([key(p)]),new Map())).toBe(false);
 });
 it('requires both the future-parent authenticated point absence and its root true EOF',()=>{
  const point:any={clusterId:cid,workspaceId:wid,path:`/consumers/${parent}/key-auth/${entityId}`,kind:'point',entityType:'keyauth_credentials',entityId,parentId:parent,allowAbsent:true};
  const p:any={clusterId:cid,workspaceId:wid,path:`/consumers/${parent}`,kind:'point',entityType:'consumers',entityId:parent,allowAbsent:true};
  const cursors=new Map([[key(collection),{complete:true,ids:new Set<string>()}]]),eof=new Set([key(collection)]),absent=new Set([key(p)]);
  expect(hasObservedAbsenceWitness(point,[point,p,collection],eof,new Set(),cursors,absent)).toBe(true);
  expect(hasObservedAbsenceWitness(point,[point,p,collection],eof,new Set(),cursors,new Set())).toBe(false);
  expect(hasObservedAbsenceWitness(point,[point,{...p,allowAbsent:false},collection],eof,new Set(),cursors,absent)).toBe(false);
  cursors.get(key(collection))!.ids.add(parent);expect(hasObservedAbsenceWitness(point,[point,p,collection],eof,new Set(),cursors,absent)).toBe(false);
 });
 it.each([null,[],false,{}, {id:'e'},{data:[],next:null},{message:'Forbidden'},{message:'Not found',fields:{}},{message:'上游返回非 JSON 响应'}])('cannot read response %j as a Kong 1.5 point NotFound',response=>expect(isKongPointNotFound(response)).toBe(false));
 it('recognizes the actual Kong 1.5 point NotFound shape only',()=>expect(isKongPointNotFound({message:'Not found'})).toBe(true));
});
