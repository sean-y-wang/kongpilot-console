import {describe,expect,it} from 'vitest';
import {METADATA_SCHEDULE_SUBJECTS,assertMetadataScheduleAdmission,assertMetadataScheduleExecution,type MetadataExecutionRecheck,type MetadataScheduleAdmission} from '../../apps/console-api/src/modules/workflows/metadata-schedule.guard';

const now=Date.parse('2026-10-23T12:00:00Z'),iso=(m:number)=>new Date(now+m*60_000).toISOString();
const owner='0b3a7c1e-2d4f-4a6b-8c9d-0e1f2a3b4c5d',seal='a'.repeat(64);
const code=(fn:()=>void)=>{try{fn();return 'ok';}catch(e){return (e as {code:string}).code;}};
const kinds=Object.keys(METADATA_SCHEDULE_SUBJECTS) as (keyof typeof METADATA_SCHEDULE_SUBJECTS)[];
const allSubjects=[...new Set(Object.values(METADATA_SCHEDULE_SUBJECTS).flat()),'configuration_jobs','portal_application_grants'];

describe('SQL041 metadata schedule guards (all nine kinds)',()=>{
  it('covers exactly the nine metadata kinds',()=>expect(kinds).toHaveLength(9));
  for(const kind of kinds){
    const subjectType=METADATA_SCHEDULE_SUBJECTS[kind][0];
    const admission=(o:Partial<MetadataScheduleAdmission>={}):MetadataScheduleAdmission=>({kind,executionMode:'approval',approvalRequired:true,subjectType,
      subjectId:'1c2d3e4f-5a6b-4c7d-9e8f-0a1b2c3d4e5f',requester:{type:'console',id:owner,credentialEpoch:'7'},ownerId:owner,ownerCredentialEpoch:'7',
      subjectSealHmac:seal,windowStart:iso(5),notBefore:iso(10),windowEnd:iso(60),expiresAt:iso(120),...o});
    const recheck=(o:Partial<MetadataExecutionRecheck>={},c:Partial<MetadataExecutionRecheck['current']>={}):MetadataExecutionRecheck=>({admission:admission(),
      sealedPermissionVersion:`${owner}:3:294`,currentSubjectSealHmac:seal,claim:{state:'claimed',attempt:1},
      current:{userActive:true,credentialEpoch:'7',permissionsEpoch:'3',iamEpoch:'294',hasDomainWrite:true,...c},...o});
    it(`${kind}: admission accepts only its own subjects, approval mode and the same Console owner/epoch`,()=>{
      for(const st of allSubjects)expect(code(()=>assertMetadataScheduleAdmission(admission({subjectType:st}),now))).toBe((METADATA_SCHEDULE_SUBJECTS[kind] as readonly string[]).includes(st)?'ok':'METADATA_SCHEDULE_SUBJECT');
      expect(code(()=>assertMetadataScheduleAdmission(admission({executionMode:'direct'}),now))).toBe('METADATA_SCHEDULE_APPROVAL_ONLY');
      expect(code(()=>assertMetadataScheduleAdmission(admission({requester:{type:'developer',id:owner,credentialEpoch:'7'}}),now))).toBe('METADATA_SCHEDULE_CONSOLE_ONLY');
      expect(code(()=>assertMetadataScheduleAdmission(admission({ownerId:'2b3a7c1e-2d4f-4a6b-8c9d-0e1f2a3b4c5d'}),now))).toBe('METADATA_SCHEDULE_OWNER');
      expect(code(()=>assertMetadataScheduleAdmission(admission({ownerCredentialEpoch:'8'}),now))).toBe('METADATA_SCHEDULE_EPOCH');
      expect(code(()=>assertMetadataScheduleAdmission(admission({windowEnd:iso(-1)}),now))).toBe('METADATA_SCHEDULE_WINDOW');
    });
    it(`${kind}: execution rechecks due/expiry, claim, revocation, epoch and tampered seal`,()=>{
      const at=now+15*60_000;
      expect(code(()=>assertMetadataScheduleExecution(recheck(),at))).toBe('ok');
      expect(code(()=>assertMetadataScheduleExecution(recheck(),now))).toBe('METADATA_SCHEDULE_NOT_DUE');
      expect(code(()=>assertMetadataScheduleExecution(recheck(),now+61*60_000))).toBe('METADATA_SCHEDULE_EXPIRED');
      expect(code(()=>assertMetadataScheduleExecution(recheck({claim:{state:'claimed',attempt:2}}),at))).toBe('METADATA_SCHEDULE_CLAIM');
      expect(code(()=>assertMetadataScheduleExecution(recheck({},{userActive:false}),at))).toBe('METADATA_SCHEDULE_REQUESTER_INACTIVE');
      expect(code(()=>assertMetadataScheduleExecution(recheck({},{credentialEpoch:'8'}),at))).toBe('METADATA_SCHEDULE_EPOCH_CHANGED');
      expect(code(()=>assertMetadataScheduleExecution(recheck({},{iamEpoch:'295'}),at))).toBe('METADATA_SCHEDULE_PERMISSION_CHANGED');
      expect(code(()=>assertMetadataScheduleExecution(recheck({},{hasDomainWrite:false}),at))).toBe('METADATA_SCHEDULE_PERMISSION_REVOKED');
      expect(code(()=>assertMetadataScheduleExecution(recheck({currentSubjectSealHmac:'b'.repeat(64)}),at))).toBe('METADATA_SCHEDULE_SUBJECT_CHANGED');
    });
  }
  it('rejects non-metadata kinds',()=>{
    expect(code(()=>assertMetadataScheduleAdmission({kind:'configuration_v2'} as MetadataScheduleAdmission,now))).toBe('METADATA_SCHEDULE_KIND');
  });
});
