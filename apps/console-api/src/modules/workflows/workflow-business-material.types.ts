import type { WorkflowPlanV1 } from './workflow.types';
import type { WorkflowBusinessSubjectSealV1 } from './workflow-schedule.contract';
import type { WorkflowScheduledConfigurationMaterial } from './workflow-scheduled-configuration-origin.types';
import type { GovernanceInventory } from '../governance/governance-inventory.types';
import type { PortalPublicationProofV1 } from '../portal/portal-proof';
import type { WorkflowScheduleCandidateReadInput, WorkflowScheduleCandidateReadResource } from './workflow-schedule-candidate-read.types';

/** BFF-private plaintext. Neither these material records nor their digests
 * mint an actor, scheduled namespace, approval, SID or native capability. */
export interface WorkflowBusinessPortalMaterial {
 readonly kind: 'portal-credential-issue' | 'portal-credential-rotate' | 'portal-credential-revoke';
 readonly grant: Readonly<Record<string, any>>;
 readonly credential: Readonly<Record<string, any>>;
 /** Prior active credential for rotate; same as credential for revoke; null for issue. */
 readonly previousCredential: Readonly<Record<string, any>> | null;
 readonly application: Readonly<Record<string, any>>;
 readonly publication: Readonly<Record<string, any>>;
 readonly developer: Readonly<Record<string, any>>;
 readonly publicationProof: Readonly<PortalPublicationProofV1>;
 readonly publicationProofRow: Readonly<Record<string, any>>;
 readonly plan: Readonly<WorkflowPlanV1>;
 readonly subjectSeal: Readonly<WorkflowBusinessSubjectSealV1>;
}
export interface WorkflowBusinessPromotionMaterial {
 readonly configurationLineage:Readonly<{importJobId:string;importPlanId:string;authorityExpiresAt:string;expiresAt:string;planExpiresAt:string}>;
 readonly row: Readonly<Record<string, any>>;
 readonly comparison: Readonly<Record<string, any>>;
 readonly source: Readonly<GovernanceInventory>;
 readonly target: Readonly<GovernanceInventory>;
 readonly sourceNativeFingerprints: Readonly<Record<string, string>>;
 readonly targetNativeFingerprints: Readonly<Record<string, string>>;
 readonly selection: Readonly<Record<string, any>>;
 readonly recovery: Readonly<Record<string, any>> | null;
}
export interface WorkflowBusinessConfigurationMaterial extends WorkflowScheduledConfigurationMaterial {
 readonly kind: 'configuration_v2';
 readonly promotion: Readonly<WorkflowBusinessPromotionMaterial> | null;
}
export interface WorkflowBusinessAnnotationMaterial {
 readonly kind: 'entity-annotation';
 readonly request: Readonly<Record<string, any>>;
 readonly intent: Readonly<Record<string, any>>;
 readonly plan: Readonly<WorkflowPlanV1>;
 readonly subjectSeal: Readonly<WorkflowBusinessSubjectSealV1>;
}
export interface WorkflowBusinessMetadataMaterial {
 readonly kind: 'control-metadata'|'configuration-metadata'|'governance-metadata'|'workflow-policy-metadata'|'iam-metadata'|'portal-metadata'|'portal-developer-review'|'event-metadata';
 readonly subjectType: string;
 readonly request: Readonly<Record<string, any>> | null;
 readonly entity: Readonly<Record<string, any>> | null;
 readonly plan: Readonly<WorkflowPlanV1>;
 readonly subjectSeal: Readonly<WorkflowBusinessSubjectSealV1>;
}
export type WorkflowBusinessMaterial = WorkflowBusinessConfigurationMaterial | WorkflowBusinessPortalMaterial | WorkflowBusinessAnnotationMaterial | WorkflowBusinessMetadataMaterial;
export function isPortalCredentialBusinessMaterial(m: Readonly<WorkflowBusinessMaterial>): m is WorkflowBusinessPortalMaterial {
  return m.kind === 'portal-credential-issue' || m.kind === 'portal-credential-rotate' || m.kind === 'portal-credential-revoke';
}

export interface WorkflowBusinessReadObservation {
 readonly resource: Readonly<WorkflowScheduleCandidateReadResource>;
 readonly response: unknown;
 readonly status: number;
}
/** Root invokes the fixed GET provider inside runResponseScope, then verifies
 * the current raw observations before returning a candidate/validation read.
 * This scope owns only read witnesses; it cannot create execution authority. */
export interface WorkflowBusinessCompleteReadInput extends WorkflowScheduleCandidateReadInput {}
