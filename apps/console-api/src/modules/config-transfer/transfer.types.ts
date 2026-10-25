import type { CaptureGraph, CapturedSchemaBundle, CaptureObject, ConfigPlan, ConfigurationEntityType, ConfigurationCredentialKind, ConfigurationScope } from '../configuration/configuration.types';

/** These values are private compiler inputs, never authorization proofs or public DTOs. */
export interface ParsedDeckDocument {
  readonly formatVersion: '1.1'; readonly document: Readonly<Record<string, unknown>>;
  readonly bytes: number; readonly nodes: number;
}
export interface TransferObject {
  readonly objectKey: string; readonly entityType: ConfigurationEntityType; readonly nativeId: string;
  readonly parentType?: ConfigurationEntityType; readonly parentId?: string;
  readonly credentialKind?: ConfigurationCredentialKind; readonly payload: Record<string, unknown>;
  readonly objectWorkspaceId: string;
  readonly dependencies: readonly string[]; readonly sourcePath: string;
  readonly passwordIntent?: 'keep' | 'replace';
}
export interface NormalizedTransferGraph {
  readonly scope: ConfigurationScope; readonly schemas: CapturedSchemaBundle;
  readonly objects: readonly TransferObject[];
  readonly workspaceCodesById: Readonly<Record<string, string>>;
  readonly semantics: 'merge' | 'complete';
}
export interface NormalizeOptions {
  readonly scope: ConfigurationScope; readonly workspaceCode: string;
  readonly workspaceCodesById?: Readonly<Record<string, string>>;
  /** Frozen once by the caller. Keys are structural paths, e.g. services[0].routes[0]. */
  readonly allocatedNativeIds?: Readonly<Record<string, string>>;
  readonly basicPasswordIntents?: Readonly<Record<string, 'keep' | 'replace'>>;
  readonly references?: CaptureGraph;
}
export interface TransferChange {
  readonly objectKey: string; readonly entityType: ConfigurationEntityType; readonly nativeId: string;
  readonly parentType?: ConfigurationEntityType | null; readonly parentId?: string | null;
  readonly credentialKind?: ConfigurationCredentialKind | null;
  readonly action: 'create' | 'update' | 'delete'; readonly before: CaptureObject | null;
  readonly after: TransferObject | null; readonly effectivePayload: Record<string, unknown> | null;
  readonly writePayload: Record<string, unknown> | null; readonly dependencies: readonly string[];
  readonly blockerCodes: readonly string[]; readonly patch: readonly unknown[];
  readonly clearMap: readonly string[];
}
export interface DeckFormatOmission { readonly objectKey: string; readonly jsonPointer: string; readonly reason: 'deck11_optional_null'; }
export interface Deck11Export { readonly yaml: string; readonly formatOmissions: readonly DeckFormatOmission[]; }
export interface TransferDiff {
  readonly scope: ConfigurationScope; readonly mode: ConfigPlan['mode']; readonly baseline: CaptureGraph;
  readonly target: NormalizedTransferGraph; readonly changes: readonly TransferChange[];
  readonly unchangedCount: number; readonly referenceCount: number; readonly blockerCodes: readonly string[];
  readonly recoveryComplete: boolean;
}
export interface DiffOptions {
  readonly mode?: ConfigPlan['mode']; readonly syncConfirmed?: boolean;
  /** Root verifies this fresh graph rather than treating the old snapshot as current before. */
  readonly rollbackBaselineVerified?: boolean;
}
export interface CompileOptions {
  readonly sourceManifestHmac: string; readonly baselineManifestHmac: string; readonly expiresAt: string;
  readonly stepIds: Readonly<Record<string, string>>;
  /** A caller-owned keyed digest. The compiler never initializes SecretService or reads env. */
  readonly fingerprint: (value: unknown) => string;
  readonly redact: (value: unknown) => unknown;
  /** Target updates append a newly preallocated physical record instead of reviving an old ID. */
  readonly allocatedTargetIds?: Readonly<Record<string, string>>;
}
export class ConfigTransferError extends Error {
  constructor(readonly code: string, readonly path?: string) {
    super(code); this.name = 'ConfigTransferError';
  }
}
export function transferFail(code: string, path?: string): never { throw new ConfigTransferError(code, path); }
