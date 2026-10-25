import { describe,expect,it } from 'vitest';
import { normalizePermission,resolveAssignedGrants } from '../../apps/console-api/src/modules/iam/iam-policy';
import { encodeTag } from '../../apps/console-api/src/infrastructure/kong/tags';
const c1='30000000-0000-4000-8000-000000000001',c2='30000000-0000-4000-8000-000000000002',w1='30000000-0000-4000-8000-000000000011',w2='30000000-0000-4000-8000-000000000012',entityId='30000000-0000-4000-8000-000000000061';
const global={cluster_id:null,workspace_id:null};
describe('IAM complete grants and delegation input boundaries',()=>{
 it('encodes only logical business tags, deduplicates values, and never mutates input',()=>{
  const input={module:'services',action:'write',scope_type:'tag_group',cluster_id:c1,workspace_id:w1,scope_values:['team:pay','team:pay','owner:ops']};
  const grant=normalizePermission(input,global);expect(grant.scope_values).toEqual([encodeTag('team:pay'),encodeTag('owner:ops')]);expect(input.scope_values).toEqual(['team:pay','team:pay','owner:ops']);
 });
 it.each(['workspace:pay','kos-ws-pay','kos-tag-dGVhbTpwYXk'])('rejects reserved or pre-encoded scope tag %s',tag=>{
  expect(()=>normalizePermission({module:'services',action:'read',scope_type:'tag_group',cluster_id:c1,scope_values:[tag]},global)).toThrow();
 });
 it('rejects empty restricted scopes and ignores no field during mass-assignment validation',()=>{
  for(const scope_type of ['tag_group','entity'])expect(()=>normalizePermission({module:'services',action:'read',scope_type,cluster_id:c1,scope_values:[]},global)).toThrow();
  expect(()=>normalizePermission({module:'services',action:'read',scope_type:'global',scope_values:[],super_admin:true},global)).toThrow();
 });
 it('requires typed entity IDs in the same permission module, including child types',()=>{
  expect(normalizePermission({module:'upstreams',action:'delete',scope_type:'entity',cluster_id:c1,scope_values:[{entity_type:'targets',entity_id:entityId}]},global).scope_values).toHaveLength(1);
  expect(normalizePermission({module:'consumers',action:'write',scope_type:'entity',cluster_id:c1,scope_values:[{entity_type:'basic-auth',entity_id:entityId}]},global).scope_values).toHaveLength(1);
  expect(normalizePermission({module:'secrets',action:'read',scope_type:'entity',cluster_id:c1,scope_values:[{entity_type:'basic-auth',entity_id:entityId}]},global).scope_values).toHaveLength(1);
  expect(normalizePermission({module:'annotations',action:'write',scope_type:'entity',cluster_id:c1,scope_values:[{entity_type:'services',entity_id:entityId}]},global).scope_values).toHaveLength(1);
  expect(()=>normalizePermission({module:'annotations',action:'write',scope_type:'entity',cluster_id:c1,scope_values:[{entity_type:'basic-auth',entity_id:entityId}]},global)).toThrow();
  expect(()=>normalizePermission({module:'routes',action:'read',scope_type:'entity',cluster_id:c1,scope_values:[{entity_type:'services',entity_id:entityId}]},global)).toThrow();
  expect(()=>normalizePermission({module:'services',action:'read',scope_type:'entity',cluster_id:c1,scope_values:[entityId]},global)).toThrow();
 });
 it('requires exact workspace values and forbids a workspace role from owning global permission',()=>{
  const owner={cluster_id:c1,workspace_id:w1};
  expect(()=>normalizePermission({module:'services',action:'read',scope_type:'workspace',cluster_id:c1,workspace_id:w1,scope_values:[w2]},owner)).toThrow();
  expect(()=>normalizePermission({module:'services',action:'read',scope_type:'global',scope_values:[]},owner)).toThrow();
 });
 it('intersects complete rows independently, drops disjoint permissions, and retains narrowed global scope',()=>{
  const grants=[normalizePermission({module:'services',action:'read',scope_type:'global',scope_values:[]},global),normalizePermission({module:'routes',action:'delete',scope_type:'entity',cluster_id:c2,scope_values:[{entity_type:'routes',entity_id:entityId}]},global)];
  expect(resolveAssignedGrants(grants,global,{cluster_id:c1,workspace_id:w1})).toEqual([{...grants[0],cluster_id:c1,workspace_id:w1}]);
  expect(grants[0].cluster_id).toBeNull();
 });
 it('does not broaden a role owner ceiling or convert tag/entity into workspace/global scope',()=>{
  const owner={cluster_id:c1,workspace_id:w1},grant=normalizePermission({module:'services',action:'read',scope_type:'tag_group',cluster_id:c1,workspace_id:w1,scope_values:['team:pay']},owner);
  expect(resolveAssignedGrants([grant],owner,owner)[0].scope_type).toBe('tag_group');
  expect(()=>resolveAssignedGrants([grant],owner,{cluster_id:c1,workspace_id:null})).toThrow();
 });
});
