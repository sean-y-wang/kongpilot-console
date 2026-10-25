/** A distinct material domain. This data shape never grants execution authority. */
export const CONFIGURATION_DURABLE_DOMAIN = 'durable-configuration-v1' as const;
export interface DurableConfigurationEnvelope {
  readonly domain: typeof CONFIGURATION_DURABLE_DOMAIN;
  readonly envelopeVersion: 1;
  readonly issueId: string;
  readonly clusterId: string;
  readonly workspaceId: string;
  readonly jobId: string;
  readonly ownerId: string;
  readonly authoringSessionId: string;
  readonly credentialEpoch: number;
  readonly permissionVersion: string;
  readonly issuedAt: string;
  /** One-time issuance deadline; never a future execution capability expiry. */
  readonly admissionExpiresAt: string;
  readonly expiresAt: string;
  readonly policy: Readonly<{definitionId: string; version: number; hash: string; intentTtlHours: number}>;
  /** Historical provenance only; these IDs are not an execution source. */
  readonly provenance: Readonly<{jobId: string; planId: string; planRevision: number; planHash: string; kind: 'import' | 'rollback'}>;
  readonly baseline: Readonly<{snapshotId: string; version: number; manifestHmac: string}>;
  readonly recipeHmac: string;
  readonly schemaHmac: string;
  readonly scopeHmac: string;
  readonly plan: Readonly<{planId: string; planRevision: number; planHash: string; stepsHmac: string; sourceManifestHmac: string; baselineManifestHmac: string}>;
}
export interface DurableConfigurationLocator {
  readonly domain: typeof CONFIGURATION_DURABLE_DOMAIN;
  readonly envelopeVersion: 1;
  readonly issueId: string;
  readonly clusterId: string;
  readonly workspaceId: string;
  readonly jobId: string;
  readonly planId: string;
  readonly planRevision: number;
  readonly planHash: string;
}
/** Both fields must be compared with the immutable persistent binding. */
export interface DurableConfigurationSeal {
  readonly ciphertext: string;
  readonly materialHmac: string;
}
