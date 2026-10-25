import { describe,expect,it } from 'vitest';
import { describeConsoleApi } from '../../apps/console-api/src/common/openapi';
function api(){const operation=()=>({responses:{'200':{description:'ok'}}});return describeConsoleApi({openapi:'3.0.0',info:{title:'test',version:'1'},paths:{
 '/api/v1/portal/auth/login':{post:operation()},'/api/v1/portal/auth/register':{post:operation()},'/api/v1/portal/auth/me':{get:operation(),patch:operation()},
 '/api/v1/portal/tenants':{get:operation()},'/api/v1/portal/tenants/{slug}':{get:operation()},'/api/v1/portal/publications':{get:operation()},'/api/v1/portal/catalog':{get:operation()},'/api/v1/portal/operations/by-key/{key}':{get:operation()},
 '/api/v1/clusters/{clusterId}/portal/settings':{patch:operation()},'/api/v1/clusters/{clusterId}/workflows/{id}/approve':{post:operation()},'/api/v1/clusters/{clusterId}/workflows/{id}/reconcile-metadata':{post:operation()},
 '/api/v1/clusters/{clusterId}/workflows/{id}/abandon-rejected-issue':{post:operation()},'/api/v1/auth/login':{post:operation()}}} as any);}
describe('M6 Swagger identity and workflow contracts',()=>{
 it('documents Portal cookie independently from Console authentication',()=>{
  const doc=api();expect(doc.components!.securitySchemes!.portalCookie).toMatchObject({type:'apiKey',in:'cookie',name:'kongos_portal_access'});
  expect(doc.paths['/api/v1/portal/auth/me'].get!.security).toEqual([{portalCookie:[]}]);expect(doc.paths['/api/v1/clusters/{clusterId}/portal/settings'].patch!.security).toEqual([{cookie:[]}]);
 });
 it('does not falsely require a login for public catalog or registration',()=>{
  const doc=api();for(const [path,method]of [['/api/v1/portal/tenants','get'],['/api/v1/portal/publications','get'],['/api/v1/portal/catalog','get'],['/api/v1/portal/auth/register','post']]as const)expect(doc.paths[path][method]!.security).toEqual([]);
  expect(doc.paths['/api/v1/portal/tenants/{slug}'].get!.parameters).toBeUndefined();
 });
 it('keeps operation receipts authenticated and tenant scoped',()=>{
  const op=api().paths['/api/v1/portal/operations/by-key/{key}'].get!;expect(op.security).toEqual([{portalCookie:[]}]);expect(op.parameters).toEqual(expect.arrayContaining([expect.objectContaining({name:'clusterId',in:'query',required:true}),expect.objectContaining({name:'workspaceId',required:true})]));
 });
 it('documents exact Portal CSRF on anonymous and authenticated writes',()=>{
  const doc=api();for(const [path,method]of [['/api/v1/portal/auth/register','post'],['/api/v1/portal/auth/me','patch']]as const){const headers=doc.paths[path][method]!.parameters!;expect(headers).toContainEqual(expect.objectContaining({name:'X-Portal-CSRF',required:true}));expect(headers).not.toContainEqual(expect.objectContaining({name:'X-CSRF-Token'}));}
 });
 it('includes explicit tenant scope in Portal login but not Console login',()=>{
  const doc=api(),body=(path:string)=>(doc.paths[path].post!.requestBody as any).content['application/json'].schema;
  expect(body('/api/v1/portal/auth/login').required).toEqual(['clusterId','workspaceId','username','password']);expect(body('/api/v1/auth/login').required).toEqual(['username','password']);
 });
 it('requires current revision, sealed plan hash and explicit workflow confirmation',()=>{
  const doc=api();expect((doc.paths['/api/v1/clusters/{clusterId}/workflows/{id}/approve'].post!.requestBody as any).content['application/json'].schema).toEqual({$ref:'#/components/schemas/WorkflowDecision'});
  expect(doc.components!.schemas!.WorkflowDecision).toMatchObject({additionalProperties:false,required:['revision','planHash','confirmed','confirm_name']});
 });
 it('documents metadata recovery with exact original execution and key rather than native entity inputs',()=>{
  const doc=api(),op=doc.paths['/api/v1/clusters/{clusterId}/workflows/{id}/reconcile-metadata'].post!;
  expect((op.requestBody as any).content['application/json'].schema).toEqual({$ref:'#/components/schemas/IssueMetadataRecovery'});
  expect(doc.components!.schemas!.IssueMetadataRecovery).toMatchObject({additionalProperties:false,required:['revision','planHash','executionId','confirmed','confirm_name'],properties:{confirm_name:{enum:['portal-credential-issue']},executionId:{format:'uuid'}}});
  expect(op.parameters).toContainEqual(expect.objectContaining({name:'workspaceId',in:'query',required:true}));
  expect(op.parameters).toContainEqual(expect.objectContaining({name:'X-Idempotency-Key',required:true,description:expect.stringContaining('原执行')}));
  expect(op.security).toEqual([{cookie:[]}]);expect(op.description).toContain('不重发原生请求');
 });
 it('documents rejected issue closure as confirmed metadata only and preserves the failed execution',()=>{
  const doc=api(),op=doc.paths['/api/v1/clusters/{clusterId}/workflows/{id}/abandon-rejected-issue'].post!;
  expect((op.requestBody as any).content['application/json'].schema).toEqual({$ref:'#/components/schemas/RejectedIssueAbandonment'});
  expect(doc.components!.schemas!.RejectedIssueAbandonment).toMatchObject({additionalProperties:false,required:['revision','planHash','executionId','confirmed','confirm_name'],properties:{confirmed:{enum:[true]},executionId:{format:'uuid'}}});
  expect(op.security).toEqual([{cookie:[]}]);
  expect(op.parameters).toContainEqual(expect.objectContaining({name:'workspaceId',in:'query',required:true}));
  expect(op.parameters).toContainEqual(expect.objectContaining({name:'X-Idempotency-Key',required:true,description:expect.stringContaining('原执行')}));
  expect(op.description).toContain('原执行仍为 failed');expect(op.description).toContain('不重发原生请求');
 });
 it('describes Portal metadata separately from native entity configuration and requires durable mutation keys',()=>{
  const doc=api();for(const path of ['/api/v1/portal/auth/me','/api/v1/clusters/{clusterId}/portal/settings']){
   const op=doc.paths[path].patch!;
   expect((op.requestBody as any).content['application/json'].schema).toEqual({$ref:'#/components/schemas/PortalInput'});
   expect(op.parameters).toContainEqual(expect.objectContaining({name:'X-Idempotency-Key',required:true}));
  }
  expect(doc.paths['/api/v1/clusters/{clusterId}/workflows/{id}/approve'].post!.parameters).toContainEqual(expect.objectContaining({name:'X-Idempotency-Key',required:true}));
  expect(doc.paths['/api/v1/portal/auth/register'].post!.parameters).toContainEqual(expect.objectContaining({name:'X-Idempotency-Key',required:false}));
 });
});
