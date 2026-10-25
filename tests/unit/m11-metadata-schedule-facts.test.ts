import {describe,expect,it} from 'vitest';
import {loadMetadataScheduleFacts} from '../../apps/console-api/src/modules/workflows/metadata-schedule.facts';
import {assertMetadataScheduleExecution} from '../../apps/console-api/src/modules/workflows/metadata-schedule.guard';

const now=Date.parse('2026-10-24T02:30:00Z'),iso=(m:number)=>new Date(now+m*60_000).toISOString();
const owner='0b3a7c1e-2d4f-4a6b-8c9d-0e1f2a3b4c5d',cid='1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d',wid='2a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d',
  wf='3a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d',subject='1c2d3e4f-5a6b-4c7d-9e8f-0a1b2c3d4e5f';
const material='m'.repeat(64),sealHmac='a'.repeat(64);
const seal=(m:{materialHmac:string})=>m.materialHmac===material?sealHmac:'b'.repeat(64);
const stored=(o:{kind?:string;subjectType?:string}={})=>({
  draft:{binding:{clusterId:cid,workspaceId:wid,workflowId:wf,kind:o.kind??'control-metadata',subjectType:o.subjectType??'control_metadata_requests',subjectId:subject,
    requester:{type:'console',id:owner,credentialEpoch:'7'}},
    delegation:{kind:o.kind??'control-metadata',subjectType:o.subjectType??'control_metadata_requests',subjectId:subject,ownerId:owner,
      ownerCredentialEpoch:'7',subjectSealHmac:sealHmac,expiresAt:iso(60)},
    spec:{windowStart:iso(-20),notBefore:iso(-10),windowEnd:iso(30)}},
  plan:{kind:o.kind??'control-metadata',executionMode:'approval',approvalRequired:true}}) as never;

function db(rows:{user?:Record<string,unknown>|null;request?:Record<string,unknown>|null;entity?:Record<string,unknown>|null}={}){
  const calls:string[]=[];
  return{calls,sql:{async one(q:string){calls.push(q);
    if(q.includes('iam_epoch'))return{version:294};
    if(q.includes('FROM users'))return rows.user===undefined?{status:'active',deleted_at:null,force_password_change:false,credential_epoch:7,permissions_epoch:3}:rows.user;
    if(q.includes('control_metadata_requests')||q.includes('iam_metadata_requests')||q.includes('workflow_policy_requests')||q.includes('governance_metadata_requests'))
      return rows.request===undefined?{material_hmac:material,workflow_id:wf,cluster_id:cid,workspace_id:wid}:rows.request;
    if(q.includes('config_snapshots')||q.includes('portal_settings')||q.includes('portal_developers')||q.includes('notification_channels'))
      return rows.entity===undefined?{id:subject,revision:1,cluster_id:cid,workspace_id:wid}:rows.entity;
    return null;}}};
}
const entityHmac=(row:Readonly<Record<string,unknown>>)=>row.revision===1?material:'x'.repeat(64);
const load=(d:ReturnType<typeof db>,o:{kind?:string;subjectType?:string;write?:boolean;entity?:boolean}={})=>
  loadMetadataScheduleFacts(d.sql as never,{stored:stored(o),sealedPermissionVersion:`${owner}:3:294`,
    hasDomainWrite:async()=>o.write??true,seal,entityMaterialHmac:o.entity?entityHmac:undefined});
const verdict=async(d:ReturnType<typeof db>,o:{kind?:string;subjectType?:string;write?:boolean;entity?:boolean}={})=>{
  try{assertMetadataScheduleExecution({...await load(d,o),claim:{state:'claimed',attempt:1}},now);return 'ok';}
  catch(e){return (e as {code:string}).code;}};

describe('metadata schedule facts loader (SQL041 remaining kinds)',()=>{
  it('request-style control-metadata facts pass write-time recheck',async()=>expect(await verdict(db())).toBe('ok'));
  it('entity-style configuration-metadata facts pass with entityMaterialHmac',async()=>
    expect(await verdict(db(),{kind:'configuration-metadata',subjectType:'config_snapshots',entity:true})).toBe('ok'));
  it('locks iam_epoch then owner FOR SHARE before subject',async()=>{const d=db();await load(d);
    expect(d.calls[0]).toMatch(/iam_epoch.*FOR SHARE/);
    expect(d.calls.findIndex(q=>/FROM users.*FOR SHARE/.test(q))).toBeLessThan(d.calls.findIndex(q=>q.includes('control_metadata_requests')));});
  it.each([
    ['deleted owner',{user:{status:'active',deleted_at:'2026-10-01',force_password_change:false,credential_epoch:7,permissions_epoch:3}},'METADATA_SCHEDULE_REQUESTER_INACTIVE'],
    ['forced password',{user:{status:'active',deleted_at:null,force_password_change:true,credential_epoch:7,permissions_epoch:3}},'METADATA_SCHEDULE_REQUESTER_INACTIVE'],
    ['missing owner',{user:null},'METADATA_SCHEDULE_REQUESTER_INACTIVE'],
    ['rotated credential',{user:{status:'active',deleted_at:null,force_password_change:false,credential_epoch:8,permissions_epoch:3}},'METADATA_SCHEDULE_EPOCH_CHANGED'],
    ['permissions epoch',{user:{status:'active',deleted_at:null,force_password_change:false,credential_epoch:7,permissions_epoch:4}},'METADATA_SCHEDULE_PERMISSION_CHANGED'],
    ['material changed',{request:{material_hmac:'n'.repeat(64),workflow_id:wf,cluster_id:cid,workspace_id:wid}},'METADATA_SCHEDULE_SUBJECT_CHANGED'],
    ['rebound workflow',{request:{material_hmac:material,workflow_id:subject,cluster_id:cid,workspace_id:wid}},'METADATA_SCHEDULE_SUBJECT_CHANGED'],
    ['other workspace',{request:{material_hmac:material,workflow_id:wf,cluster_id:cid,workspace_id:owner}},'METADATA_SCHEDULE_SUBJECT_CHANGED'],
    ['request gone',{request:null},'METADATA_SCHEDULE_SUBJECT_CHANGED'],
  ] as const)('rejects %s',async(_n,rows,code)=>expect(await verdict(db(rows as never))).toBe(code));
  it('revoked domain write is rejected',async()=>expect(await verdict(db(),{write:false})).toBe('METADATA_SCHEDULE_PERMISSION_REVOKED'));
  it('entity-style without entityMaterialHmac fails closed',async()=>{
    expect(await verdict(db(),{kind:'configuration-metadata',subjectType:'config_snapshots'})).toBe('METADATA_SCHEDULE_SUBJECT_CHANGED');});
  it('refuses non-metadata schedules before SQL',async()=>{const d=db();
    expect(await verdict(d,{kind:'configuration_v2' as never,subjectType:'config_snapshots'})).toBe('METADATA_SCHEDULE_KIND');
    expect(d.calls).toHaveLength(0);});
  it.each([
    ['iam-metadata','iam_metadata_requests'],
    ['governance-metadata','governance_metadata_requests'],
    ['workflow-policy-metadata','workflow_policy_requests'],
  ] as const)('%s request-style positive',async(kind,subjectType)=>expect(await verdict(db(),{kind,subjectType})).toBe('ok'));
  it.each([
    ['portal-metadata','portal_settings'],
    ['portal-developer-review','portal_developers'],
    ['event-metadata','notification_channels'],
  ] as const)('%s entity-style positive',async(kind,subjectType)=>
    expect(await verdict(db(),{kind,subjectType,entity:true})).toBe('ok'));
});
