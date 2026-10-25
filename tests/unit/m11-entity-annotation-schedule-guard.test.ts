import {describe,expect,it} from 'vitest';
import {assertEntityAnnotationExecution,assertEntityAnnotationScheduleAdmission,type EntityAnnotationExecutionRecheck,type EntityAnnotationScheduleAdmission} from '../../apps/console-api/src/modules/workflows/entity-annotation-schedule.guard';

const now=Date.parse('2026-10-23T12:00:00Z'),iso=(m:number)=>new Date(now+m*60_000).toISOString();
const owner='0b3a7c1e-2d4f-4a6b-8c9d-0e1f2a3b4c5d',seal='a'.repeat(64);
const admission=(o:Partial<EntityAnnotationScheduleAdmission>={}):EntityAnnotationScheduleAdmission=>({kind:'entity-annotation',executionMode:'approval',approvalRequired:true,
  subjectType:'entity_annotation_requests',subjectId:'1c2d3e4f-5a6b-4c7d-9e8f-0a1b2c3d4e5f',requester:{type:'console',id:owner,credentialEpoch:'7'},ownerId:owner,ownerCredentialEpoch:'7',
  subjectSealHmac:seal,windowStart:iso(5),notBefore:iso(10),windowEnd:iso(60),expiresAt:iso(120),...o});
const recheck=(o:Partial<EntityAnnotationExecutionRecheck>={},c:Partial<EntityAnnotationExecutionRecheck['current']>={}):EntityAnnotationExecutionRecheck=>({admission:admission(),
  sealedPermissionVersion:`${owner}:3:294`,currentSubjectSealHmac:seal,claim:{state:'claimed',attempt:1},
  current:{userActive:true,credentialEpoch:'7',permissionsEpoch:'3',iamEpoch:'294',hasAnnotationWrite:true,...c},...o});
const code=(fn:()=>void)=>{try{fn();return 'ok';}catch(e){return (e as {code:string}).code;}};

describe('entity-annotation schedule admission (SQL041 TS mirror)',()=>{
  it('admits an approval-mode Console schedule',()=>expect(code(()=>assertEntityAnnotationScheduleAdmission(admission(),now))).toBe('ok'));
  it.each([
    ['direct mode',{executionMode:'direct'},'ANNOTATION_SCHEDULE_APPROVAL_ONLY'],
    ['no approval',{approvalRequired:false},'ANNOTATION_SCHEDULE_APPROVAL_ONLY'],
    ['other kind',{kind:'configuration_v2'},'ANNOTATION_SCHEDULE_KIND'],
    ['wrong subject',{subjectType:'configuration_jobs'},'ANNOTATION_SCHEDULE_SUBJECT'],
    ['developer requester',{requester:{type:'developer',id:owner,credentialEpoch:'7'}},'ANNOTATION_SCHEDULE_CONSOLE_ONLY'],
    ['owner substitution',{ownerId:'2b3a7c1e-2d4f-4a6b-8c9d-0e1f2a3b4c5d'},'ANNOTATION_SCHEDULE_OWNER'],
    ['epoch mismatch',{ownerCredentialEpoch:'8'},'ANNOTATION_SCHEDULE_EPOCH'],
    ['bad seal',{subjectSealHmac:'A'.repeat(64)},'ANNOTATION_SCHEDULE_SEAL'],
    ['window past expiry',{windowEnd:iso(130)},'ANNOTATION_SCHEDULE_WINDOW'],
    ['not_before outside window',{notBefore:iso(60)},'ANNOTATION_SCHEDULE_WINDOW'],
    ['already-ended window',{windowStart:iso(-30),notBefore:iso(-20),windowEnd:iso(-1)},'ANNOTATION_SCHEDULE_WINDOW'],
  ] as const)('rejects %s',(_n,o,c)=>expect(code(()=>assertEntityAnnotationScheduleAdmission(admission(o as never),now))).toBe(c));
});

describe('entity-annotation execution recheck before write',()=>{
  const at=now+15*60_000;
  it('allows the exact due, claimed, still-authorized execution',()=>expect(code(()=>assertEntityAnnotationExecution(recheck(),at))).toBe('ok'));
  it('rejects before not_before',()=>expect(code(()=>assertEntityAnnotationExecution(recheck(),now))).toBe('ANNOTATION_SCHEDULE_NOT_DUE'));
  it('rejects after window end (expiry)',()=>expect(code(()=>assertEntityAnnotationExecution(recheck(),now+60*60_000))).toBe('ANNOTATION_SCHEDULE_EXPIRED'));
  it('rejects a double claim / retry',()=>{
    expect(code(()=>assertEntityAnnotationExecution(recheck({claim:{state:'claimed',attempt:2}}),at))).toBe('ANNOTATION_SCHEDULE_CLAIM');
    expect(code(()=>assertEntityAnnotationExecution(recheck({claim:{state:'succeeded',attempt:1}}),at))).toBe('ANNOTATION_SCHEDULE_CLAIM');
  });
  it('rejects a disabled requester',()=>expect(code(()=>assertEntityAnnotationExecution(recheck({},{userActive:false}),at))).toBe('ANNOTATION_SCHEDULE_REQUESTER_INACTIVE'));
  it('rejects a rotated credential epoch',()=>expect(code(()=>assertEntityAnnotationExecution(recheck({},{credentialEpoch:'8'}),at))).toBe('ANNOTATION_SCHEDULE_EPOCH_CHANGED'));
  it('rejects a changed permission or IAM epoch',()=>{
    expect(code(()=>assertEntityAnnotationExecution(recheck({},{permissionsEpoch:'4'}),at))).toBe('ANNOTATION_SCHEDULE_PERMISSION_CHANGED');
    expect(code(()=>assertEntityAnnotationExecution(recheck({},{iamEpoch:'295'}),at))).toBe('ANNOTATION_SCHEDULE_PERMISSION_CHANGED');
  });
  it('rejects a revoked annotation permission',()=>expect(code(()=>assertEntityAnnotationExecution(recheck({},{hasAnnotationWrite:false}),at))).toBe('ANNOTATION_SCHEDULE_PERMISSION_REVOKED'));
  it('rejects a tampered subject seal',()=>{
    expect(code(()=>assertEntityAnnotationExecution(recheck({currentSubjectSealHmac:'b'.repeat(64)}),at))).toBe('ANNOTATION_SCHEDULE_SUBJECT_CHANGED');
    expect(code(()=>assertEntityAnnotationExecution(recheck({currentSubjectSealHmac:'a'.repeat(63)}),at))).toBe('ANNOTATION_SCHEDULE_SUBJECT_CHANGED');
  });
});
