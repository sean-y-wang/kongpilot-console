import {randomUUID} from 'node:crypto';
import {describe,expect,it} from 'vitest';
import {portalActivationReadPaths,portalEntityParentReadPaths} from '../../apps/console-api/src/modules/workflows/workflow-portal-activation-read';
function fixture(){
 const cid=randomUUID(),wid=randomUUID(),consumer=randomUUID(),acl=randomUUID(),key=randomUUID(),actor=randomUUID(),workflow=randomUUID(),grant=randomUUID();
 const native=(type:string,id:string,parent?:string)=>({id:randomUUID(),kind:'native',nativeRequests:[{method:'POST',nativeType:type,nativeId:id,canonicalPath:parent?`/consumers/${parent}/${type}`:`/${type}`,parentId:parent}]});
 const step={id:randomUUID(),kind:'metadata',handler:'portal.credential.activate',entityId:grant,nativeRequests:[]};
 const plan:any={kind:'portal-credential-issue',clusterId:cid,workspaceId:wid,workflowId:workflow,scheduling:{executorId:actor},subject:{id:grant},steps:[native('consumers',consumer),native('acls',acl,consumer),native('key-auth',key,consumer),step]};
 const proof:any={kind:'metadata',stepId:step.id,execution:{workflowId:workflow,actorId:actor,clusterId:cid,workspaceId:wid,origin:'scheduled-workflow',sessionId:null}};
 const path=`/consumers/${consumer}/key-auth/${key}`;
 return{cid,wid,consumer,acl,key,step,plan,proof,path,read:()=>portalActivationReadPaths(plan,proof,cid,path)};
}
describe('Portal activation support selects exact sealed Native points',()=>{
 it('selects the Consumer parent before its original credential',()=>{
  const f=fixture();expect(f.read()).toEqual([`/consumers/${f.consumer}`,f.path]);expect(Object.isFrozen(f.read())).toBe(true);
  expect(portalActivationReadPaths(f.plan,f.proof,f.cid,`/consumers/${f.consumer}`)).toEqual([`/consumers/${f.consumer}`]);
 });
 it.each(['workflowId','actorId','clusterId','workspaceId','origin','sessionId'])('denies foreign execution %s',field=>{
  const f=fixture();f.proof.execution[field]='foreign';expect(f.read).toThrow();
 });
 it.each(['kind','stepId'])('denies foreign approved step %s',field=>{
  const f=fixture();f.proof[field]='foreign';expect(f.read).toThrow();
 });
 it.each(['handler','entityId','kind'])('denies changed original activation %s',field=>{
  const f=fixture();(f.step as any)[field]='foreign';expect(f.read).toThrow();
 });
 it.each(['/consumers','/services','/schemas/consumers','/cache','/consumers/foreign/key-auth/foreign'])('denies unsealed support path %s',path=>{
  const f=fixture();expect(()=>portalActivationReadPaths(f.plan,f.proof,f.cid,path)).toThrow();
 });
 it('denies a foreign cluster, a different plan kind or a non-POST request',()=>{
  const f=fixture();expect(()=>portalActivationReadPaths(f.plan,f.proof,randomUUID(),f.path)).toThrow();
  f.plan.steps[2].nativeRequests[0].method='DELETE';expect(f.read).toThrow();
  f.plan.kind='configuration_v2';expect(f.read).toThrow();
 });
});
describe('Portal EntityService parent support selects only the sealed credential parent',()=>{
 function parentFixture(kind='key-auth'){
  const f=fixture(),step=f.plan.steps[kind==='acls'?1:2];
  Object.assign(step,{entityType:'credentials',mutationAction:'create',parentId:f.consumer,credentialKind:kind});
  f.plan.generated={consumerId:f.consumer};
  Object.assign(f.proof,{kind:'native',stepId:step.id});
  const path=`/consumers/${f.consumer}`;
  return{...f,step,path,read:()=>portalEntityParentReadPaths(f.plan,f.proof,f.cid,path)};
 }
 it.each(['acls','key-auth'])('keeps the exact %s parent point and no other resource',kind=>{
  const f=parentFixture(kind);expect(f.read()).toEqual([f.path]);expect(Object.isFrozen(f.read())).toBe(true);
 });
 it.each(['workflowId','actorId','clusterId','workspaceId','origin','sessionId'])('denies foreign execution %s',field=>{
  const f=parentFixture();f.proof.execution[field]='foreign';expect(f.read).toThrow();
 });
 it.each(['kind','stepId'])('denies foreign private step %s',field=>{
  const f=parentFixture();f.proof[field]='foreign';expect(f.read).toThrow();
 });
 it.each(['kind','entityType','mutationAction','parentId','credentialKind'])('denies changed step %s',field=>{
  const f=parentFixture();f.step[field]='foreign';expect(f.read).toThrow();
 });
 it.each(['method','parentId','nativeType','canonicalPath'])('denies changed sealed request %s',field=>{
  const f=parentFixture();f.step.nativeRequests[0][field]='foreign';expect(f.read).toThrow();
 });
 it.each(['/consumers','/schemas/consumers','/cache','/consumers/foreign','/consumers/foreign/key-auth'])('denies unbound path %s',path=>{
  const f=parentFixture();expect(()=>portalEntityParentReadPaths(f.plan,f.proof,f.cid,path)).toThrow();
 });
 it('denies different allocated parent, plan kind, cluster and additional requests',()=>{
  const f=parentFixture();expect(()=>portalEntityParentReadPaths(f.plan,f.proof,randomUUID(),f.path)).toThrow();
  f.plan.generated.consumerId=randomUUID();expect(f.read).toThrow();f.plan.generated.consumerId=f.consumer;
  f.plan.kind='configuration_v2';expect(f.read).toThrow();f.plan.kind='portal-credential-issue';
  f.step.nativeRequests.push({...f.step.nativeRequests[0]});expect(f.read).toThrow();
 });
});
