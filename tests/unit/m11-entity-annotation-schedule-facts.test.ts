import {describe,expect,it} from 'vitest';
import {loadEntityAnnotationScheduleFacts} from '../../apps/console-api/src/modules/workflows/entity-annotation-schedule.facts';
import {assertEntityAnnotationExecution} from '../../apps/console-api/src/modules/workflows/entity-annotation-schedule.guard';

const now=Date.parse('2026-10-23T12:30:00Z'),iso=(m:number)=>new Date(now+m*60_000).toISOString();
const owner='0b3a7c1e-2d4f-4a6b-8c9d-0e1f2a3b4c5d',cid='1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d',wid='2a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d',
  wf='3a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d',subject='1c2d3e4f-5a6b-4c7d-9e8f-0a1b2c3d4e5f',seal=(m:{materialHmac:string})=>m.materialHmac==='m'.repeat(64)?'a'.repeat(64):'b'.repeat(64);
const stored=(o:{kind?:string}={})=>({
  draft:{binding:{clusterId:cid,workspaceId:wid,workflowId:wf,kind:o.kind??'entity-annotation',subjectType:'entity_annotation_requests',subjectId:subject,requester:{type:'console',id:owner,credentialEpoch:'7'}},
    delegation:{kind:o.kind??'entity-annotation',subjectType:'entity_annotation_requests',subjectId:subject,ownerId:owner,ownerCredentialEpoch:'7',subjectSealHmac:'a'.repeat(64),expiresAt:iso(60)},
    spec:{windowStart:iso(-20),notBefore:iso(-10),windowEnd:iso(30)}},
  plan:{kind:o.kind??'entity-annotation',executionMode:'approval',approvalRequired:true}}) as never;
function db(rows:{user?:Record<string,unknown>|null;request?:Record<string,unknown>|null}={}){
  const calls:string[]=[];
  return{calls,sql:{async one(q:string){calls.push(q);
    if(q.includes('iam_epoch'))return{version:294};
    if(q.includes('FROM users'))return rows.user===undefined?{status:'active',deleted_at:null,force_password_change:false,credential_epoch:7,permissions_epoch:3}:rows.user;
    if(q.includes('entity_annotation_requests'))return rows.request===undefined?{material_hmac:'m'.repeat(64),workflow_id:wf,cluster_id:cid,workspace_id:wid}:rows.request;
    return null;}}};
}
const load=(d:ReturnType<typeof db>,o:{kind?:string;write?:boolean}={})=>loadEntityAnnotationScheduleFacts(d.sql as never,{stored:stored(o),sealedPermissionVersion:`${owner}:3:294`,hasAnnotationWrite:async()=>o.write??true,seal});
const verdict=async(d:ReturnType<typeof db>,o:{kind?:string;write?:boolean}={})=>{try{assertEntityAnnotationExecution({...await load(d,o),claim:{state:'claimed',attempt:1}},now);return 'ok';}catch(e){return (e as {code:string}).code;}};

describe('entity-annotation schedule facts loader (SQL041)',()=>{
  it('current SQL facts pass the write-time recheck',async()=>expect(await verdict(db())).toBe('ok'));
  it('locks iam_epoch then the owner row FOR SHARE before reading the subject',async()=>{const d=db();await load(d);
    expect(d.calls[0]).toMatch(/iam_epoch.*FOR SHARE/);expect(d.calls.findIndex(q=>/FROM users.*FOR SHARE/.test(q))).toBeLessThan(d.calls.findIndex(q=>q.includes('entity_annotation_requests')));});
  it.each([
    ['deleted owner',{user:{status:'active',deleted_at:'2026-10-01',force_password_change:false,credential_epoch:7,permissions_epoch:3}},'ANNOTATION_SCHEDULE_REQUESTER_INACTIVE'],
    ['forced password change',{user:{status:'active',deleted_at:null,force_password_change:true,credential_epoch:7,permissions_epoch:3}},'ANNOTATION_SCHEDULE_REQUESTER_INACTIVE'],
    ['missing owner',{user:null},'ANNOTATION_SCHEDULE_REQUESTER_INACTIVE'],
    ['rotated credential',{user:{status:'active',deleted_at:null,force_password_change:false,credential_epoch:8,permissions_epoch:3}},'ANNOTATION_SCHEDULE_EPOCH_CHANGED'],
    ['permissions epoch moved',{user:{status:'active',deleted_at:null,force_password_change:false,credential_epoch:7,permissions_epoch:4}},'ANNOTATION_SCHEDULE_PERMISSION_CHANGED'],
    ['annotation material changed',{request:{material_hmac:'n'.repeat(64),workflow_id:wf,cluster_id:cid,workspace_id:wid}},'ANNOTATION_SCHEDULE_SUBJECT_CHANGED'],
    ['request re-bound to another workflow',{request:{material_hmac:'m'.repeat(64),workflow_id:subject,cluster_id:cid,workspace_id:wid}},'ANNOTATION_SCHEDULE_SUBJECT_CHANGED'],
    ['request in another workspace',{request:{material_hmac:'m'.repeat(64),workflow_id:wf,cluster_id:cid,workspace_id:owner}},'ANNOTATION_SCHEDULE_SUBJECT_CHANGED'],
    ['request gone',{request:null},'ANNOTATION_SCHEDULE_SUBJECT_CHANGED'],
  ] as const)('rejects %s',async(_n,rows,code)=>expect(await verdict(db(rows as never))).toBe(code));
  it('revoked annotation write is rejected',async()=>expect(await verdict(db(),{write:false})).toBe('ANNOTATION_SCHEDULE_PERMISSION_REVOKED'));
  it('refuses non-annotation schedules before any SQL',async()=>{const d=db();expect(await verdict(d,{kind:'configuration_v2'})).toBe('ANNOTATION_SCHEDULE_KIND');expect(d.calls).toHaveLength(0);});
});
