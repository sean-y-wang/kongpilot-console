import {describe,expect,it} from 'vitest';
import {executeMetadataSchedule,type MetadataScheduleExecutorPorts,type MetadataScheduleTx} from '../../apps/console-api/src/modules/workflows/metadata-schedule.executor';

const now=Date.parse('2026-10-24T02:30:00Z'),iso=(m:number)=>new Date(now+m*60_000).toISOString();
const owner='0b3a7c1e-2d4f-4a6b-8c9d-0e1f2a3b4c5d',seal='a'.repeat(64),id='3d2c1b0a-9f8e-4d7c-8b6a-5f4e3d2c1b0a';
type Current={userActive:boolean;credentialEpoch:string;permissionsEpoch:string;iamEpoch:string;hasDomainWrite:boolean};
function store(o:{current?:Partial<Current>;seal?:string;windowEnd?:string;notBefore?:string;attempt?:number;applyThrows?:Error;kind?:string}={}){
  const committed={claims:0,applies:0,outcomes:[] as {state:string;code:string|null}[]};let locked=false;
  const ports:MetadataScheduleExecutorPorts={
    async transaction(fn){if(locked)throw new Error('nested');locked=true;const tx:MetadataScheduleTx={id:Symbol('tx')};const staged={claims:0,applies:0,outcomes:[] as typeof committed.outcomes};(tx as any).staged=staged;
      try{const r=await fn(tx);committed.claims+=staged.claims;committed.applies+=staged.applies;committed.outcomes.push(...staged.outcomes);return r;}finally{locked=false;}},
    async claim(_s,tx){if(committed.claims>0)return null;(tx as any).staged.claims++;return{state:'claimed',attempt:o.attempt??1};},
    async load(){const kind=o.kind??'control-metadata';const subjectType=({
      'control-metadata':'control_metadata_requests','iam-metadata':'iam_metadata_requests','governance-metadata':'governance_metadata_requests',
      'workflow-policy-metadata':'workflow_policy_requests','configuration-metadata':'config_snapshots','portal-metadata':'portal_settings',
      'portal-developer-review':'portal_developers','event-metadata':'notification_channels'} as Record<string,string>)[kind]??'control_metadata_requests';
      return{admission:{kind,executionMode:'approval',approvalRequired:true,subjectType,subjectId:'1c2d3e4f-5a6b-4c7d-9e8f-0a1b2c3d4e5f',
      requester:{type:'console',id:owner,credentialEpoch:'7'},ownerId:owner,ownerCredentialEpoch:'7',subjectSealHmac:seal,
      windowStart:iso(-20),notBefore:o.notBefore??iso(-10),windowEnd:o.windowEnd??iso(30),expiresAt:iso(60)},
      sealedPermissionVersion:`${owner}:3:294`,currentSubjectSealHmac:o.seal??seal,
      current:{userActive:true,credentialEpoch:'7',permissionsEpoch:'3',iamEpoch:'294',hasDomainWrite:true,...o.current}};},
    async apply(_s,tx){if(o.applyThrows)throw o.applyThrows;(tx as any).staged.applies++;},
    async recordOutcome(_s,outcome,tx){(tx as any).staged.outcomes.push(outcome);},
    now:()=>now,
  };
  return{ports,committed};
}

describe('metadata scheduled executor (SQL041 remaining kinds)',()=>{
  it('applies exactly once and records success',async()=>{const s=store();
    expect(await executeMetadataSchedule(id,s.ports)).toEqual({state:'succeeded',code:null});
    expect(s.committed).toEqual({claims:1,applies:1,outcomes:[{state:'succeeded',code:null}]});});
  it.each([
    ['expired window',{windowEnd:iso(-1)},'METADATA_SCHEDULE_EXPIRED'],
    ['not yet due',{notBefore:iso(5)},'METADATA_SCHEDULE_NOT_DUE'],
    ['revoked domain write',{current:{hasDomainWrite:false}},'METADATA_SCHEDULE_PERMISSION_REVOKED'],
    ['permissions epoch moved',{current:{permissionsEpoch:'4'}},'METADATA_SCHEDULE_PERMISSION_CHANGED'],
    ['IAM epoch moved',{current:{iamEpoch:'295'}},'METADATA_SCHEDULE_PERMISSION_CHANGED'],
    ['credential epoch rotated',{current:{credentialEpoch:'8'}},'METADATA_SCHEDULE_EPOCH_CHANGED'],
    ['requester disabled',{current:{userActive:false}},'METADATA_SCHEDULE_REQUESTER_INACTIVE'],
    ['tampered subject seal',{seal:'b'.repeat(64)},'METADATA_SCHEDULE_SUBJECT_CHANGED'],
    ['malformed subject seal',{seal:'zz'},'METADATA_SCHEDULE_SUBJECT_CHANGED'],
    ['replayed claim attempt',{attempt:2},'METADATA_SCHEDULE_CLAIM'],
  ] as const)('fails %s terminally without writing',async(_n,o,code)=>{const s=store(o as never);
    expect(await executeMetadataSchedule(id,s.ports)).toEqual({state:'failed',code});
    expect(s.committed.applies).toBe(0);expect(s.committed.outcomes).toEqual([{state:'failed',code}]);});
  it('a second claim never writes again',async()=>{const s=store();
    await executeMetadataSchedule(id,s.ports);
    expect(await executeMetadataSchedule(id,s.ports)).toEqual({state:'not-claimed',code:'METADATA_SCHEDULE_CLAIM_BLOCKED'});
    expect(s.committed).toEqual({claims:1,applies:1,outcomes:[{state:'succeeded',code:null}]});});
  it('unknown apply failure rolls back the claim and records no outcome',async()=>{const s=store({applyThrows:new Error('db down')});
    await expect(executeMetadataSchedule(id,s.ports)).rejects.toThrow('db down');
    expect(s.committed).toEqual({claims:0,applies:0,outcomes:[]});});
  it.each(['iam-metadata','governance-metadata','workflow-policy-metadata','configuration-metadata','portal-metadata','portal-developer-review','event-metadata'] as const)(
    'positive path for %s',async(kind)=>{const s=store({kind});
      expect(await executeMetadataSchedule(id,s.ports)).toEqual({state:'succeeded',code:null});});
});
