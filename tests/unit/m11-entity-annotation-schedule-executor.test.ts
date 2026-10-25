import {describe,expect,it} from 'vitest';
import {executeEntityAnnotationSchedule,type EntityAnnotationScheduleExecutorPorts,type EntityAnnotationScheduleTx} from '../../apps/console-api/src/modules/workflows/entity-annotation-schedule.executor';

const now=Date.parse('2026-10-23T12:30:00Z'),iso=(m:number)=>new Date(now+m*60_000).toISOString();
const owner='0b3a7c1e-2d4f-4a6b-8c9d-0e1f2a3b4c5d',seal='a'.repeat(64),id='3d2c1b0a-9f8e-4d7c-8b6a-5f4e3d2c1b0a';
type Current={userActive:boolean;credentialEpoch:string;permissionsEpoch:string;iamEpoch:string;hasAnnotationWrite:boolean};
/** In-memory store with real transactional semantics: writes inside a failed transaction are discarded. */
function store(o:{current?:Partial<Current>;seal?:string;windowEnd?:string;notBefore?:string;attempt?:number;applyThrows?:Error}={}){
  const committed={claims:0,applies:0,outcomes:[] as {state:string;code:string|null}[]};let locked=false;
  const ports:EntityAnnotationScheduleExecutorPorts={
    async transaction(fn){if(locked)throw new Error('nested');locked=true;const tx:EntityAnnotationScheduleTx={id:Symbol('tx')};const staged={claims:0,applies:0,outcomes:[] as typeof committed.outcomes};(tx as any).staged=staged;
      try{const r=await fn(tx);committed.claims+=staged.claims;committed.applies+=staged.applies;committed.outcomes.push(...staged.outcomes);return r;}finally{locked=false;}},
    async claim(_s,tx){if(committed.claims>0)return null;(tx as any).staged.claims++;return{state:'claimed',attempt:o.attempt??1};},
    async load(){return{admission:{kind:'entity-annotation',executionMode:'approval',approvalRequired:true,subjectType:'entity_annotation_requests',subjectId:'1c2d3e4f-5a6b-4c7d-9e8f-0a1b2c3d4e5f',
      requester:{type:'console',id:owner,credentialEpoch:'7'},ownerId:owner,ownerCredentialEpoch:'7',subjectSealHmac:seal,
      windowStart:iso(-20),notBefore:o.notBefore??iso(-10),windowEnd:o.windowEnd??iso(30),expiresAt:iso(60)},
      sealedPermissionVersion:`${owner}:3:294`,currentSubjectSealHmac:o.seal??seal,
      current:{userActive:true,credentialEpoch:'7',permissionsEpoch:'3',iamEpoch:'294',hasAnnotationWrite:true,...o.current}};},
    async apply(_s,tx){if(o.applyThrows)throw o.applyThrows;(tx as any).staged.applies++;},
    async recordOutcome(_s,outcome,tx){(tx as any).staged.outcomes.push(outcome);},
    now:()=>now,
  };
  return{ports,committed};
}

describe('entity-annotation scheduled executor (SQL041)',()=>{
  it('applies exactly once and records success',async()=>{const s=store();
    expect(await executeEntityAnnotationSchedule(id,s.ports)).toEqual({state:'succeeded',code:null});
    expect(s.committed).toEqual({claims:1,applies:1,outcomes:[{state:'succeeded',code:null}]});});
  it.each([
    ['expired window',{windowEnd:iso(-1)},'ANNOTATION_SCHEDULE_EXPIRED'],
    ['not yet due',{notBefore:iso(5)},'ANNOTATION_SCHEDULE_NOT_DUE'],
    ['revoked annotation permission',{current:{hasAnnotationWrite:false}},'ANNOTATION_SCHEDULE_PERMISSION_REVOKED'],
    ['permissions epoch moved',{current:{permissionsEpoch:'4'}},'ANNOTATION_SCHEDULE_PERMISSION_CHANGED'],
    ['IAM epoch moved',{current:{iamEpoch:'295'}},'ANNOTATION_SCHEDULE_PERMISSION_CHANGED'],
    ['credential epoch rotated',{current:{credentialEpoch:'8'}},'ANNOTATION_SCHEDULE_EPOCH_CHANGED'],
    ['requester disabled',{current:{userActive:false}},'ANNOTATION_SCHEDULE_REQUESTER_INACTIVE'],
    ['tampered subject seal',{seal:'b'.repeat(64)},'ANNOTATION_SCHEDULE_SUBJECT_CHANGED'],
    ['malformed subject seal',{seal:'zz'},'ANNOTATION_SCHEDULE_SUBJECT_CHANGED'],
    ['replayed claim attempt',{attempt:2},'ANNOTATION_SCHEDULE_CLAIM'],
  ] as const)('fails %s terminally without writing',async(_n,o,code)=>{const s=store(o as never);
    expect(await executeEntityAnnotationSchedule(id,s.ports)).toEqual({state:'failed',code});
    expect(s.committed.applies).toBe(0);expect(s.committed.outcomes).toEqual([{state:'failed',code}]);});
  it('a second (double) claim of the same occurrence never writes again',async()=>{const s=store();
    await executeEntityAnnotationSchedule(id,s.ports);
    expect(await executeEntityAnnotationSchedule(id,s.ports)).toEqual({state:'not-claimed',code:'ANNOTATION_SCHEDULE_CLAIM_BLOCKED'});
    expect(s.committed).toEqual({claims:1,applies:1,outcomes:[{state:'succeeded',code:null}]});});
  it('unknown apply failure rolls back the claim and records no outcome',async()=>{const s=store({applyThrows:new Error('db down')});
    await expect(executeEntityAnnotationSchedule(id,s.ports)).rejects.toThrow('db down');
    expect(s.committed).toEqual({claims:0,applies:0,outcomes:[]});});
});
