import {timingSafeEqual} from 'node:crypto';

/** SQL041 slice 1: pure, fail-closed guards for entity-annotation business
 * schedules. This module installs no worker. The generic services keep their
 * kind allow-lists unchanged until the annotation executor is wired in, so an
 * entity-annotation schedule cannot run before every guard below is enforced.
 * Mirrors workflow_executor_delegations_metadata_subject_check and
 * m11_business_origin_permission (SQL028/041). */
export const ENTITY_ANNOTATION_SCHEDULED_KIND='entity-annotation' as const;
export const ENTITY_ANNOTATION_SUBJECT_TYPE='entity_annotation_requests' as const;

export class EntityAnnotationScheduleRejected extends Error{
  constructor(readonly code:string){super(code);this.name='EntityAnnotationScheduleRejected';}
}
const reject=(code:string):never=>{throw new EntityAnnotationScheduleRejected(code);};
const uuid=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const epoch=/^(0|[1-9]\d{0,18})$/;
const hex64=/^[a-f0-9]{64}$/;

export interface EntityAnnotationScheduleAdmission{
  readonly kind:string;readonly executionMode:string;readonly approvalRequired:boolean;
  readonly subjectType:string;readonly subjectId:string;
  readonly requester:Readonly<{type:string;id:string;credentialEpoch:string}>;
  readonly ownerId:string;readonly ownerCredentialEpoch:string;
  readonly subjectSealHmac:string;
  readonly windowStart:string;readonly notBefore:string;readonly windowEnd:string;readonly expiresAt:string;
}
/** Checked when the schedule is admitted into a plan, before the first approval. */
export function assertEntityAnnotationScheduleAdmission(a:EntityAnnotationScheduleAdmission,now:number):void{
  if(a.kind!==ENTITY_ANNOTATION_SCHEDULED_KIND)reject('ANNOTATION_SCHEDULE_KIND');
  if(a.executionMode!=='approval'||a.approvalRequired!==true)reject('ANNOTATION_SCHEDULE_APPROVAL_ONLY');
  if(a.subjectType!==ENTITY_ANNOTATION_SUBJECT_TYPE||!uuid.test(a.subjectId))reject('ANNOTATION_SCHEDULE_SUBJECT');
  if(a.requester?.type!=='console')reject('ANNOTATION_SCHEDULE_CONSOLE_ONLY');
  if(!uuid.test(a.requester.id)||a.requester.id!==a.ownerId)reject('ANNOTATION_SCHEDULE_OWNER');
  if(!epoch.test(a.requester.credentialEpoch)||a.requester.credentialEpoch!==a.ownerCredentialEpoch)reject('ANNOTATION_SCHEDULE_EPOCH');
  if(!hex64.test(a.subjectSealHmac))reject('ANNOTATION_SCHEDULE_SEAL');
  const [ws,nb,we,ex]=[a.windowStart,a.notBefore,a.windowEnd,a.expiresAt].map(v=>typeof v==='string'?Date.parse(v):NaN);
  if([ws,nb,we,ex].some(Number.isNaN)||ws>nb||nb>=we||we>ex||we<=now)reject('ANNOTATION_SCHEDULE_WINDOW');
}

export interface EntityAnnotationExecutionRecheck{
  readonly admission:EntityAnnotationScheduleAdmission;
  /** Value sealed at approval: `${userId}:${permissionsEpoch}:${iamEpoch}`. */
  readonly sealedPermissionVersion:string;
  /** HMAC recomputed now over the current annotation request material. */
  readonly currentSubjectSealHmac:string;
  readonly current:Readonly<{userActive:boolean;credentialEpoch:string;permissionsEpoch:string;iamEpoch:string;hasAnnotationWrite:boolean}>;
  readonly claim:Readonly<{state:string;attempt:number}>;
}
/** Checked inside the executor transaction, immediately before the write. */
export function assertEntityAnnotationExecution(r:EntityAnnotationExecutionRecheck,now:number):void{
  const a=r.admission;
  if(a.kind!==ENTITY_ANNOTATION_SCHEDULED_KIND||a.executionMode!=='approval'||a.requester?.type!=='console')reject('ANNOTATION_SCHEDULE_KIND');
  const nb=Date.parse(a.notBefore),we=Date.parse(a.windowEnd),ex=Date.parse(a.expiresAt);
  if(!(now>=nb))reject('ANNOTATION_SCHEDULE_NOT_DUE');
  if(!(now<we)||!(now<ex))reject('ANNOTATION_SCHEDULE_EXPIRED');
  if(r.claim.state!=='claimed'||r.claim.attempt!==1)reject('ANNOTATION_SCHEDULE_CLAIM');
  const c=r.current;
  if(c.userActive!==true)reject('ANNOTATION_SCHEDULE_REQUESTER_INACTIVE');
  if(c.credentialEpoch!==a.ownerCredentialEpoch)reject('ANNOTATION_SCHEDULE_EPOCH_CHANGED');
  if(`${a.ownerId}:${c.permissionsEpoch}:${c.iamEpoch}`!==r.sealedPermissionVersion)reject('ANNOTATION_SCHEDULE_PERMISSION_CHANGED');
  if(c.hasAnnotationWrite!==true)reject('ANNOTATION_SCHEDULE_PERMISSION_REVOKED');
  const s=Buffer.from(r.currentSubjectSealHmac,'utf8'),t=Buffer.from(a.subjectSealHmac,'utf8');
  if(!hex64.test(r.currentSubjectSealHmac)||s.length!==t.length||!timingSafeEqual(s,t))reject('ANNOTATION_SCHEDULE_SUBJECT_CHANGED');
}
