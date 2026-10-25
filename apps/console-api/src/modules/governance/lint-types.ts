import type { GovernanceInventory } from './governance-inventory.types';
/** Pure analysis inputs. None of these structures grant database or Kong authority. */
export const GOVERNANCE_NATIVE_TYPES = ['services', 'routes', 'consumers', 'plugins', 'upstreams', 'targets', 'certificates', 'ca_certificates', 'snis'] as const;
export type GovernanceNativeType = typeof GOVERNANCE_NATIVE_TYPES[number];
export type LintSeverity = 'error' | 'warn' | 'info';
export type LintScalar = string | number | boolean | null;
export type LintPredicate =
  | { readonly all: readonly LintPredicate[] }
  | { readonly any: readonly LintPredicate[] }
  | { readonly not: LintPredicate }
  | ({ readonly path?: string } & (
    | { readonly op: 'required' }
    | { readonly op: 'exists'; readonly value?: boolean }
    | { readonly op: 'type'; readonly value: 'string' | 'number' | 'integer' | 'boolean' | 'array' | 'record' | 'null' }
    | { readonly op: 'enum'; readonly values: readonly LintScalar[] }
    | { readonly op: 'equals' | 'includes'; readonly value: LintScalar }
    | { readonly op: 'min' | 'max'; readonly value: number }
    | { readonly op: 'length'; readonly min?: number; readonly max?: number }
    | { readonly op: 'tags_contains'; readonly value: string; readonly match?: 'exact' | 'prefix' }
    | { readonly op: 'https_only' }
    | { readonly op: 'reference_exists'; readonly entityType: GovernanceNativeType; readonly by?: 'id' | 'name' }
    | { readonly op: 'matches'; readonly pattern: string }
  ));
export interface GovernanceLintRule {
  readonly code: string;
  readonly given: { readonly entityTypes: readonly GovernanceNativeType[]; readonly path?: string; readonly where?: LintPredicate };
  readonly then: LintPredicate;
  readonly severity: LintSeverity;
  readonly description: string;
  readonly enabled: boolean;
}
export interface LintObject {
  readonly entityType: GovernanceNativeType;
  readonly nativeId: string;
  readonly payload: Readonly<Record<string, unknown>>;
  readonly parentId?: string | null;
  readonly objectWorkspaceId?: string;
  readonly annotations?: { readonly state: 'readable' | 'not_authorized' | 'absent'; readonly description?: string | null; readonly ownerUserId?: string | null };
  readonly sensitiveFields?: readonly string[];
  readonly referenceOnly?: boolean;
  readonly selected?: boolean;
}
export interface LintCollectionCoverage {
  readonly entityType: GovernanceNativeType;
  readonly parentId?: string | null;
  readonly complete: boolean;
  /** Only cluster-complete collections prove that a foreign native ID is absent. */
  readonly extent: 'cluster' | 'workspace' | 'services' | 'projection';
}
export interface LintReferenceObservation {
  readonly entityType: GovernanceNativeType;
  readonly nativeId: string;
  readonly state: 'present' | 'absent' | 'forbidden' | 'unavailable';
  /** An absent observation is a current, authorized native GET404, not a filtered list gap. */
  readonly authoritative?: boolean;
}
export interface GovernanceLintContext {
  readonly objects: readonly LintObject[];
  readonly collections: readonly LintCollectionCoverage[];
  readonly referenceObservations?: readonly LintReferenceObservation[];
  readonly completeness: 'complete' | 'incomplete';
  readonly projection: boolean;
  readonly schemas?: Readonly<Partial<Record<GovernanceNativeType, unknown>>>;
  readonly pluginSchemas?: Readonly<Record<string, unknown>>;
  readonly enabledPlugins?: readonly string[];
  readonly scope?: { readonly kind: 'cluster' | 'workspace' | 'services'; readonly clusterId: string; readonly workspaceId: string };
}
export type GovernanceFixCode = 'owner_tag_add' | 'route_https_only' | 'service_timeouts_set' | 'entity_rename'
  | 'reference_replace_or_clear' | 'unused_certificate_archive' | 'baseline_plugin_configure' | 'annotation_description_set';
export interface LintFinding {
  readonly code: string;
  readonly ruleCode: string;
  readonly severity: LintSeverity;
  readonly status: 'confirmed' | 'potential' | 'not_evaluated';
  readonly entityType: GovernanceNativeType | null;
  readonly nativeId: string | null;
  readonly field: string | null;
  readonly description: string;
  readonly reasonCodes: readonly string[];
  readonly relatedObjects?: readonly { readonly entityType: GovernanceNativeType; readonly nativeId: string }[];
  readonly fixCodes: readonly GovernanceFixCode[];
}
export interface LintRuleResult {
  readonly ruleCode: string;
  readonly evaluatedObjects: number;
  readonly failedObjects: number;
  readonly notEvaluatedObjects: number;
  readonly skippedObjects: number;
  readonly state: 'evaluated' | 'partial' | 'disabled';
}
export interface GovernanceAnalysisBudget {
  readonly operationLimit: number;
  readonly operations: number;
  readonly deadlineMs: number;
  readonly findingLimit: number;
  readonly regexCaseLimit: number;
  readonly regexCases: number;
  readonly exhausted: boolean;
}
export interface GovernanceAnalysisResult {
  readonly findings: readonly LintFinding[];
  readonly ruleResults: readonly LintRuleResult[];
  readonly complete: boolean;
  readonly reasonCodes: readonly string[];
  readonly budget: GovernanceAnalysisBudget;
}
export interface GovernanceAnalysisOptions {
  readonly operationLimit?: number;
  readonly deadlineMs?: number;
  readonly findingLimit?: number;
  readonly regexCaseLimit?: number;
}
export class GovernanceLintError extends Error {
  constructor(readonly code: string, readonly path?: string) { super(code); this.name = 'GovernanceLintError'; }
}

/** Narrow projection adapter; no transport/private material or authority is copied. */
export function lintContextFromInventory(inventory: GovernanceInventory): GovernanceLintContext {
  return {
    objects: inventory.objects, schemas: inventory.schemas, pluginSchemas: inventory.pluginSchemas, enabledPlugins: inventory.enabledPlugins,
    scope: { kind: inventory.scope.kind, clusterId: inventory.scope.clusterId, workspaceId: inventory.scope.workspaceId },
    completeness: inventory.completeness, projection: inventory.projection,
    collections: Object.entries(inventory.coverage).flatMap(([key, coverage]) => {
      const [entityType, parentId] = key.split(':');
      if (!(GOVERNANCE_NATIVE_TYPES as readonly string[]).includes(entityType)) return [];
      return [{ entityType: entityType as GovernanceNativeType, parentId: parentId || undefined,
        complete: coverage.state === 'complete' && coverage.eof, extent: coverage.extent }];
    }),
  };
}
