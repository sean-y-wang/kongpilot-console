import {METADATA_SCHEDULE_SUBJECTS,type MetadataScheduledKind} from './metadata-schedule.guard';

/** Per-kind SQL subject loaders for scheduled metadata executors.
 * Request-style rows expose material_hmac (or payload_hmac). Entity-style rows
 * seal over {id,revision,cluster_id,workspace_id}. Callers still supply
 * hasDomainWrite inside the original scheduled namespace. */
export type MetadataSubjectSealSource =
  | Readonly<{style:'request';table:string;materialColumn:'material_hmac'|'payload_hmac'}>
  | Readonly<{style:'entity';table:string}>;

export const METADATA_SUBJECT_SEAL_SOURCE:Readonly<Record<string,MetadataSubjectSealSource>> = Object.freeze({
  entity_annotation_requests:{style:'request',table:'entity_annotation_requests',materialColumn:'material_hmac'},
  control_metadata_requests:{style:'request',table:'control_metadata_requests',materialColumn:'material_hmac'},
  iam_metadata_requests:{style:'request',table:'iam_metadata_requests',materialColumn:'material_hmac'},
  workflow_policy_requests:{style:'request',table:'workflow_policy_requests',materialColumn:'material_hmac'},
  governance_metadata_requests:{style:'request',table:'governance_metadata_requests',materialColumn:'payload_hmac'},
  config_snapshots:{style:'entity',table:'config_snapshots'},
  config_snapshot_schedules:{style:'entity',table:'config_snapshot_schedules'},
  configuration_gitops_runs:{style:'entity',table:'configuration_gitops_runs'},
  portal_settings:{style:'entity',table:'portal_settings'},
  portal_developers:{style:'entity',table:'portal_developers'},
  portal_applications:{style:'entity',table:'portal_applications'},
  portal_publications:{style:'entity',table:'portal_publications'},
  portal_content:{style:'entity',table:'portal_content'},
  notification_channels:{style:'entity',table:'notification_channels'},
  event_subscriptions:{style:'entity',table:'event_subscriptions'},
  event_deliveries:{style:'entity',table:'event_deliveries'},
});

/** Feature module used by Root whole-workspace grant checks for scheduled reads. */
export const METADATA_SCHEDULE_FEATURE:Readonly<Record<MetadataScheduledKind,string>> = Object.freeze({
  'entity-annotation':'annotations',
  'control-metadata':'clusters',
  'configuration-metadata':'snapshots',
  'governance-metadata':'governance',
  'workflow-policy-metadata':'workflows',
  'iam-metadata':'users',
  'portal-metadata':'portal',
  'portal-developer-review':'developers',
  'event-metadata':'events',
});

export const METADATA_SCHEDULE_KINDS = Object.freeze(Object.keys(METADATA_SCHEDULE_SUBJECTS) as MetadataScheduledKind[]);

export function metadataSubjectSealSource(subjectType:string):MetadataSubjectSealSource{
  const src=METADATA_SUBJECT_SEAL_SOURCE[subjectType];
  if(!src)throw new Error(`METADATA_SCHEDULE_SUBJECT_SOURCE:${subjectType}`);
  return src;
}
