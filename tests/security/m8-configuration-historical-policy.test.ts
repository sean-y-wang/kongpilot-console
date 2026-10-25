import {describe,it,expect} from 'vitest';
import type {EffectiveGrant} from '../../apps/console-api/src/common/authorization.types';
import {historicalConfigurationAllowed as allows} from '../../apps/console-api/src/modules/configuration/configuration-history-policy';
import {graph,id} from '../unit/m8-config-transfer.fixture';

const cid=id(101),wid=id(100);
const grant=(module:string,action:EffectiveGrant['action']='read',extra:Partial<EffectiveGrant>={}):EffectiveGrant=>({module,action,scope_type:'workspace',scope_values:[wid],cluster_id:cid,workspace_id:wid,...extra});
describe('current grant checks over a private historical configuration graph',()=>{
  it('requires the exact cluster and workspace even for a global grant',()=>{
    const g=graph(),s=g.objects[0];expect(allows([grant('services')],cid,s,g.objects)).toBe(true);
    expect(allows([grant('services')],id(999),s,g.objects)).toBe(false);
    expect(allows([grant('services','read',{workspace_id:id(998),scope_type:'global',scope_values:[]})],cid,s,g.objects)).toBe(false);
  });
  it('does not combine the module, operation or scope of separate rows',()=>{
    const g=graph(),s=g.objects[0];expect(allows([grant('services','write'),grant('routes')],cid,s,[s])).toBe(false);
    expect(allows([grant('services','read',{scope_type:'entity',scope_values:[{entity_type:'routes',entity_id:s.nativeId}]})],cid,s,g.objects)).toBe(false);
  });
  it('inherits service write/delete into its routes, but does not invent route read',()=>{
    const g=graph(),r=g.objects[1];expect(allows([grant('services','write')],cid,r,g.objects,'write')).toBe(true);
    expect(allows([grant('services','delete')],cid,r,g.objects,'delete')).toBe(true);
    expect(allows([grant('services')],cid,r,g.objects)).toBe(false);
  });
  it('grants the service read only from a real same-workspace route FK',()=>{
    const g=graph(),s=g.objects[0],r=g.objects[1];const a=grant('routes','write',{scope_type:'entity',scope_values:[{entity_type:'routes',entity_id:r.nativeId}]});
    expect(allows([a],cid,s,g.objects)).toBe(true);
    expect(allows([a],cid,s,[s])).toBe(false);
    r.objectWorkspaceId=id(900);expect(allows([a],cid,s,g.objects)).toBe(false);
  });
  it('requires grants for every plugin binding and never uses a plugin grant to bypass them',()=>{
    const g=graph(),p=g.objects[3];expect(allows([grant('plugins')],cid,p,g.objects)).toBe(false);
    expect(allows([grant('services'),grant('routes')],cid,p,g.objects)).toBe(false);
    expect(allows([grant('services'),grant('routes'),grant('consumers')],cid,p,g.objects)).toBe(true);
    const consumer=g.objects[2];consumer.objectWorkspaceId=id(999);expect(allows([grant('services'),grant('routes'),grant('consumers')],cid,p,g.objects)).toBe(false);
  });
  it('permits only read of a global plugin through this historical view',()=>{
    const g=graph(),p=g.objects[3];p.payload.service=null;p.payload.route=null;p.payload.consumer=null;
    expect(allows([grant('plugins')],cid,p,g.objects)).toBe(true);
    expect(allows([grant('plugins','write')],cid,p,g.objects,'write')).toBe(false);
  });
  it('checks physical tag ceilings on both child and sealed parent',()=>{
    const g=graph(),r=g.objects[1],s=g.objects[0],tag='kos-tag-cGF5';const a=grant('services','write',{scope_type:'tag_group',scope_values:[tag]});
    s.ownershipTags=[tag];r.ownershipTags=[tag];expect(allows([a],cid,r,g.objects,'write')).toBe(true);
    r.ownershipTags=[];expect(allows([a],cid,r,g.objects,'write')).toBe(false);
    r.ownershipTags=[tag];s.ownershipTags=[];expect(allows([a],cid,r,g.objects,'write')).toBe(false);
  });
  it('inherits credential/target reads only through the actual same-scope parent',()=>{
    const g=graph(),c=g.objects.find(o=>o.credentialKind==='key-auth')!,t=g.objects.find(o=>o.entityType==='targets')!;
    const a=grant('consumers','read',{scope_type:'entity',scope_values:[{entity_type:'consumers',entity_id:c.parentId!}]}),b=grant('upstreams','read',{scope_type:'entity',scope_values:[{entity_type:'upstreams',entity_id:t.parentId!}]});
    expect(allows([a],cid,c,g.objects)).toBe(true);
    expect(allows([b],cid,t,g.objects)).toBe(true);
    expect(allows([a],cid,c,[c])).toBe(false);
    expect(allows([a],cid,c,g.objects.filter(o=>o.entityType!=='consumers'))).toBe(false);
  });
  it('keeps typed child ID exceptions distinct from their parent and other credential kinds',()=>{
    const g=graph(),c=g.objects.find(o=>o.credentialKind==='key-auth')!;
    const a=grant('consumers','read',{scope_type:'entity',scope_values:[{entity_type:'key-auth',entity_id:c.nativeId}]});
    expect(allows([a],cid,c,[c])).toBe(true);expect(allows([a],cid,{...c,credentialKind:'jwt'},[c])).toBe(false);
    expect(allows([a],cid,g.objects[2],g.objects)).toBe(false);
  });
});
