import {timingSafeEqual} from 'node:crypto';

/** SQL041 slice 2: pure, fail-closed guards for all nine metadata business
 * schedule kinds. Mirrors workflow_executor_delegations_metadata_subject_check
 * and m11_business_origin_permission. Installs no worker: the generic services
 * keep their kind allow-lists until per-kind executors are wired in. */
export const METADATA_SCHEDULE_SUBJECTS={
  'entity-annotation':['entity_annotation_requests'],
  'control-metadata':['control_metadata_requests'],
  'configuration-metadata':['config_snapshots','config_snapshot_schedules','configuration_gitops_runs'],
  'governance-metadata':['governance_metadata_requests'],
  'workflow-policy-metadata':['workflow_policy_requests'],
  'iam-metadata':['iam_metadata_requests'],
  'portal-metadata':['portal_settings','portal_developers','portal_applications','portal_publications','portal_content'],
  'portal-developer-review':['portal_developers'],
  'event-metadata':['notification_channels','event_subscriptions','event_deliveries'],
} as const satisfies Record<string,readonly string[]>;
export type MetadataScheduledKind=keyof typeof METADATA_SCHEDULE_SUBJECTS;
export const isMetadataScheduledKind=(k:unknown):k is MetadataScheduledKind=>typeof k==='string'&&Object.prototype.hasOwnProperty.call(METADATA_SCHEDULE_SUBJECTS,k);

export class MetadataScheduleRejected extends Error{
  constructor(readonly code:string){super(code);this.name='MetadataScheduleRejected';}
}
const reject=(code:string):never=>{throw new MetadataScheduleRejected(code);};
const uuid=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const epoch=/^(0|[1-9]\d{0,18})$/;
const hex64=/^[a-f0-9]{64}$/;

export interface MetadataScheduleAdmission{
  readonly kind:string;readonly executionMode:string;readonly approvalRequired:boolean;
  readonly subjectType:string;readonly subjectId:string;
  readonly requester:Readonly<{type:string;id:string;credentialEpoch:string}>;
  readonly ownerId:string;readonly ownerCredentialEpoch:string;
  readonly subjectSealHmac:string;
  readonly windowStart:string;readonly notBefore:string;readonly windowEnd:string;readonly expiresAt:string;
}
export function assertMetadataScheduleAdmission(a:MetadataScheduleAdmission,now:number):void{
  if(!isMetadataScheduledKind(a.kind))reject('METADATA_SCHEDULE_KIND');
  if(a.executionMode!=='approval'||a.approvalRequired!==true)reject('METADATA_SCHEDULE_APPROVAL_ONLY');
  const allowed:readonly string[]=METADATA_SCHEDULE_SUBJECTS[a.kind as MetadataScheduledKind];
  if(!allowed.includes(a.subjectType)||!uuid.test(a.subjectId))reject('METADATA_SCHEDULE_SUBJECT');
  if(a.requester?.type!=='console')reject('METADATA_SCHEDULE_CONSOLE_ONLY');
  if(!uuid.test(a.requester.id)||a.requester.id!==a.ownerId)reject('METADATA_SCHEDULE_OWNER');
  if(!epoch.test(a.requester.credentialEpoch)||a.requester.credentialEpoch!==a.ownerCredentialEpoch)reject('METADATA_SCHEDULE_EPOCH');
  if(!hex64.test(a.subjectSealHmac))reject('METADATA_SCHEDULE_SEAL');
  const [ws,nb,we,ex]=[a.windowStart,a.notBefore,a.windowEnd,a.expiresAt].map(v=>typeof v==='string'?Date.parse(v):NaN);
  if([ws,nb,we,ex].some(Number.isNaN)||ws>nb||nb>=we||we>ex||we<=now)reject('METADATA_SCHEDULE_WINDOW');
}

export interface MetadataExecutionRecheck{
  readonly admission:MetadataScheduleAdmission;
  /** `${userId}:${permissionsEpoch}:${iamEpoch}` sealed at approval. */
  readonly sealedPermissionVersion:string;
  readonly currentSubjectSealHmac:string;
  /** hasDomainWrite: the kind-specific write permission, resolved now. */
  readonly current:Readonly<{userActive:boolean;credentialEpoch:string;permissionsEpoch:string;iamEpoch:string;hasDomainWrite:boolean}>;
  readonly claim:Readonly<{state:string;attempt:number}>;
}
export function assertMetadataScheduleExecution(r:MetadataExecutionRecheck,now:number):void{
  const a=r.admission;
  if(!isMetadataScheduledKind(a.kind)||a.executionMode!=='approval'||a.requester?.type!=='console')reject('METADATA_SCHEDULE_KIND');
  if(!(METADATA_SCHEDULE_SUBJECTS[a.kind as MetadataScheduledKind] as readonly string[]).includes(a.subjectType))reject('METADATA_SCHEDULE_SUBJECT');
  const nb=Date.parse(a.notBefore),we=Date.parse(a.windowEnd),ex=Date.parse(a.expiresAt);
  if(!(now>=nb))reject('METADATA_SCHEDULE_NOT_DUE');
  if(!(now<we)||!(now<ex))reject('METADATA_SCHEDULE_EXPIRED');
  if(r.claim.state!=='claimed'||r.claim.attempt!==1)reject('METADATA_SCHEDULE_CLAIM');
  const c=r.current;
  if(c.userActive!==true)reject('METADATA_SCHEDULE_REQUESTER_INACTIVE');
  if(c.credentialEpoch!==a.ownerCredentialEpoch)reject('METADATA_SCHEDULE_EPOCH_CHANGED');
  if(`${a.ownerId}:${c.permissionsEpoch}:${c.iamEpoch}`!==r.sealedPermissionVersion)reject('METADATA_SCHEDULE_PERMISSION_CHANGED');
  if(c.hasDomainWrite!==true)reject('METADATA_SCHEDULE_PERMISSION_REVOKED');
  const s=Buffer.from(r.currentSubjectSealHmac,'utf8'),t=Buffer.from(a.subjectSealHmac,'utf8');
  if(!hex64.test(r.currentSubjectSealHmac)||s.length!==t.length||!timingSafeEqual(s,t))reject('METADATA_SCHEDULE_SUBJECT_CHANGED');
}
