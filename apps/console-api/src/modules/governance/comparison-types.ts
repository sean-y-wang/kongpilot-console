import type { CapturedSchemaBundle, ConfigurationCredentialKind, ConfigurationEntityType, ConfigurationRecovery, ConfigurationScope } from '../configuration/configuration.types';

/** Pure compiler material. None of these fields or flags conveys authorization. */
export interface ComparisonObject {
  entityType: ConfigurationEntityType;
  nativeId: string;
  payload: Record<string, unknown>;
  parentId?: string | null;
  credentialKind?: ConfigurationCredentialKind | null;
  objectWorkspaceId?: string;
  sensitiveFields?: readonly string[];
  referenceOnly?: boolean;
  managedBoundary?: 'none' | 'portal' | 'metrics';
  certificate?: { fingerprint?: string; state: 'valid' | 'invalid'; expiresAt?: string; expired?: boolean };
  /** Private credential imports consume the actual complete M8 recovery body. */
  recovery?: ConfigurationRecovery;
}

export interface ComparisonInventory {
  scope: ConfigurationScope;
  objects: readonly ComparisonObject[];
  schemas: Readonly<Record<string, unknown>>;
  pluginSchemas: Readonly<Record<string, unknown>>;
  enabledPlugins: readonly string[];
  version: string;
  adapterVersion?: string;
  completeness: 'complete' | 'incomplete';
  projection: boolean;
  consistency?: 'console_fenced_best_effort' | 'changed' | 'unverified';
  observedFrom?: string;
  observedUntil?: string;
}

export interface ComparisonPolicy {
  /** Exact source/target native identity to a human supplied, non-secret logical alias. */
  identityAliases?: Readonly<Record<string, string>>;
  includeEnvironmentFields?: boolean;
  includeSecrets?: boolean;
  includeCredentials?: boolean;
  credentialKinds?: readonly ConfigurationCredentialKind[];
}

export type FieldExclusionReason = 'metadata' | 'workspace_tag' | 'environment' | 'secret' | 'credential' | 'certificate_material' | 'unknown_plugin' | 'managed_boundary';
export interface FieldExclusion { objectKey: string; field: string; reason: FieldExclusionReason; }
export interface ComparisonIssue { code: string; objectKey?: string; field?: string; }
export interface LogicalObject {
  logicalKey: string;
  objectKey: string;
  nativeId: string;
  entityType: ConfigurationEntityType;
  credentialKind?: ConfigurationCredentialKind | null;
  identityKind: 'named' | 'alias' | 'anonymous_signature' | 'certificate_fingerprint' | 'binding';
  parentLogicalKey?: string;
  /** Private input to diff/compile; never return directly from a controller. */
  payload: Record<string, unknown>;
  referenceFields: Readonly<Record<string, string | readonly string[]>>;
  sensitiveFields: readonly string[];
}
export interface LogicalGraph {
  scope: ConfigurationScope;
  objects: readonly LogicalObject[];
  exclusions: readonly FieldExclusion[];
  issues: readonly ComparisonIssue[];
  complete: boolean;
  /** Includes omitted dependency identities, never omitted payload or secret values. */
  identities: Readonly<Record<string, string>>;
}

export interface DriftFieldChange { path: string; action: 'add' | 'remove' | 'replace'; before?: unknown; after?: unknown; redacted: boolean; }
export interface DriftObjectChange {
  logicalKey: string;
  entityType: ConfigurationEntityType;
  action: 'source_only' | 'target_only' | 'changed';
  sourceNativeId?: string;
  targetNativeId?: string;
  fields: readonly DriftFieldChange[];
}
export interface DriftThreshold { maxChangedObjects: number; maxChangedFields?: number; }
export interface DriftOptions {
  sourcePolicy?: ComparisonPolicy;
  targetPolicy?: ComparisonPolicy;
  threshold?: DriftThreshold;
  previousFingerprint?: string | null;
  /** Required for secret-aware comparisons; supplied by the server keyed digest owner. */
  fingerprint?: (value: unknown) => string;
}
export interface DriftResult {
  completeness: 'complete' | 'incomplete';
  changes: readonly DriftObjectChange[];
  issues: readonly ComparisonIssue[];
  exclusions: { source: readonly FieldExclusion[]; target: readonly FieldExclusion[] };
  counts: { sourceOnly: number; targetOnly: number; changed: number; unchanged: number; changedObjects: number; changedFields: number };
  threshold: { evaluated: boolean; exceeded: boolean; notify: boolean };
  /** Internal persistence key; secret-aware mode requires a keyed digest. */
  fingerprint: string | null;
}

export interface PromoteOptions extends ComparisonPolicy {
  targetWorkspaceCode: string;
  targetWorkspaceCodesById?: Readonly<Record<string, string>>;
  selectedServiceIds?: readonly string[];
  selectedObjectKeys?: readonly string[];
  /** Exact authorized source identity -> existing target native ID; never arbitrary foreign ID. */
  mapping?: Readonly<Record<string, string>>;
  /** Field values are explicit target environment inputs, validated against target schemas. */
  fieldOverrides?: Readonly<Record<string, Readonly<Record<string, unknown>>>>;
  /** Separate secret recovery input from public redacted inventory. Root must authorize it. */
  privateSourceObjects?: readonly ComparisonObject[];
  /** Server-owned allocation; a DTO callback or preallocated source UUID is not accepted by HTTP. */
  allocateNativeId?: (logicalKey: string) => string;
}
export interface PromoteMapping { sourceObjectKey: string; logicalKey: string; targetNativeId: string; action: 'existing' | 'create'; }
export interface PromoteCompilation {
  state: 'ready' | 'blocked';
  mode: 'merge';
  document: Readonly<Record<string, unknown>> | null;
  yaml: string | null;
  selectedObjectKeys: readonly string[];
  mappings: readonly PromoteMapping[];
  exclusions: readonly FieldExclusion[];
  blockers: readonly ComparisonIssue[];
  basicPasswordIntents: Readonly<Record<string, 'replace'>>;
}

export class GovernanceComparisonError extends Error {
  constructor(readonly code: string, readonly field?: string) { super(code); this.name = 'GovernanceComparisonError'; }
}
export function comparisonFail(code: string, field?: string): never { throw new GovernanceComparisonError(code, field); }

export function comparisonSchemas(inventory: ComparisonInventory): CapturedSchemaBundle {
  return { entities: inventory.schemas, plugins: inventory.pluginSchemas, enabledPlugins: inventory.enabledPlugins,
    kongVersion: inventory.version, adapterVersion: inventory.adapterVersion ?? 'kong-1.5', schemaHmac: 'comparison-not-authority' };
}
