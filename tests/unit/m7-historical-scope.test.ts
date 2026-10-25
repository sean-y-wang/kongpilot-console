import { describe,expect,it,vi } from 'vitest';
import type { EffectiveGrant } from '../../apps/console-api/src/common/authorization.types';
import { historicalAllows,type HistoricalScope } from '../../apps/console-api/src/modules/authorization/historical-scope-policy';
import { normalizePermission } from '../../apps/console-api/src/modules/iam/iam-policy';
import { AuthorizationService } from '../../apps/console-api/src/modules/authorization/authorization.service';

const cid='11111111-1111-4111-8111-111111111111',wid='22222222-2222-4222-8222-222222222222',other='33333333-3333-4333-8333-333333333333',id='44444444-4444-4444-8444-444444444444',uid='55555555-5555-4555-8555-555555555555';
const grant=(scope_type:EffectiveGrant['scope_type'],scope_values:EffectiveGrant['scope_values'],extra:Partial<EffectiveGrant>={}):EffectiveGrant=>({module:'audit',action:'read',cluster_id:cid,workspace_id:null,scope_type,scope_values,...extra});
const scope=(before:string[]|null,after:string[]|null):HistoricalScope=>({version:1,quality:'verified',module:'services',nativeType:'services',nativeId:id,
 before:before===null?null:{workspaceId:wid,physicalTags:before},after:after===null?null:{workspaceId:wid,physicalTags:after}});
function allowed(grants:EffectiveGrant[],s:HistoricalScope){return historicalAllows({user:{superAdmin:false},grants},'audit',{clusterId:cid,workspaceId:wid,scope:s});}

describe('M7 immutable historical complete-grant policy',()=>{
 it('does not combine two tag grants across transfer sides',()=>{
  expect(allowed([grant('tag_group',['old']),grant('tag_group',['new'])],scope(['old'],['new']))).toBe(false);
  expect(allowed([grant('tag_group',['old','new'])],scope(['old'],['new']))).toBe(true);
 });
 it('uses the real existing side on create/delete, including an explicitly empty tag set',()=>{
  expect(allowed([grant('tag_group',['mine'])],scope(null,['mine']))).toBe(true);
  expect(allowed([grant('tag_group',['mine'])],scope(['mine'],null))).toBe(true);
  expect(allowed([grant('tag_group',['mine'])],scope([],['mine']))).toBe(false);
 });
 it('does not use root WID to conceal a cross-workspace after side',()=>{
  const s=scope(['mine'],['mine']);s.after!.workspaceId=other;
  expect(allowed([grant('workspace',[wid],{workspace_id:wid})],s)).toBe(false);
  expect(allowed([grant('tag_group',['mine'],{workspace_id:wid})],s)).toBe(false);
  expect(allowed([grant('tag_group',['mine'])],s)).toBe(true);
 });
 it('requires module, action, CID, typed identity and reserved tag policy together',()=>{
  const s=scope(null,['mine','kos-ws-default']);
  for(const g of [grant('tag_group',['mine'],{module:'events'}),grant('tag_group',['mine'],{action:'write'}),grant('tag_group',['mine'],{cluster_id:other}),grant('entity',[{entity_type:'routes',entity_id:id}]),grant('tag_group',['kos-ws-default'])])expect(allowed([g],s)).toBe(false);
  expect(allowed([grant('entity',[{entity_type:'services',entity_id:id}])],s)).toBe(true);
 });
 it('keeps unknown rows out of whole-workspace grants and null scope out of cluster grants',()=>{
  const s={...scope(null,null),quality:'legacy_unknown' as const};
  expect(allowed([grant('workspace',[wid],{workspace_id:wid})],s)).toBe(false);
  expect(allowed([grant('global',[])],s)).toBe(true);
  expect(historicalAllows({user:{superAdmin:false},grants:[grant('global',[])]},'audit',{clusterId:null,workspaceId:null,scope:s})).toBe(false);
  expect(historicalAllows({user:{superAdmin:false},grants:[grant('global',[],{cluster_id:null})]},'audit',{clusterId:null,workspaceId:null,scope:s})).toBe(true);
 });
 it('metadata subjects do not turn tag/entity native grants into whole-workspace authority',()=>{
  const s=scope(null,['mine']);delete s.nativeType;delete s.nativeId;s.subject={type:'notification_channels',id};
  expect(allowed([grant('tag_group',['mine']),grant('entity',[{entity_type:'services',entity_id:id}])],s)).toBe(false);
  expect(allowed([grant('workspace',[wid],{workspace_id:wid})],s)).toBe(true);
 });
 it.each(['audit','events','notifications'])('allows %s typed historical grant but never shared channel entity',module=>{
  const input={module,action:'read',scope_type:'entity',cluster_id:cid,workspace_id:wid,scope_values:[{entity_type:'key-auth',entity_id:id}]};
  expect(normalizePermission(input,{cluster_id:cid,workspace_id:wid}).scope_values).toEqual(input.scope_values);
  expect(()=>normalizePermission({...input,scope_values:[{entity_type:'notification_channels',entity_id:id}]},{cluster_id:cid,workspace_id:wid})).toThrow();
 });
 it.each(['audit','events','notifications'])('permits %s-only workspace discovery without any Kong/native read',async module=>{
  const g=grant('entity',[{entity_type:'services',entity_id:id}],{module,workspace_id:wid});
  const db={one:vi.fn(async(sql:string)=>sql.includes('FROM clusters')?{id:cid}:null)},workspaces={get:vi.fn(async()=>({id:wid,cluster_id:cid,status:'active'}))},kong={request:vi.fn()},execution={peek:vi.fn()};
  const auth=new AuthorizationService(db as any,workspaces as any,kong as any,execution as any);
  vi.spyOn(auth,'snapshot').mockResolvedValue({user:{id:uid,username:'operator',superAdmin:false},grants:[g],version:'current'});
  await auth.assertEntity({id:uid,username:'operator',superAdmin:false},cid,'workspaces','read',{id:wid,cluster_id:cid},wid);
  await expect(auth.assertEntity({id:uid,username:'operator',superAdmin:false},cid,'services','read',{id,tags:[]},wid)).rejects.toThrow();
  expect(kong.request).not.toHaveBeenCalled();
 });
});
