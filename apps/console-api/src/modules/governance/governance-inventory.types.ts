import type { EntityActor } from '../entities/entities.types';

export const GOVERNANCE_ENTITY_TYPES = ['services','routes','consumers','plugins','upstreams','certificates','ca_certificates','snis'] as const;
export type GovernanceEntityType = typeof GOVERNANCE_ENTITY_TYPES[number];
export interface GovernanceScope {
  clusterId: string; workspaceId: string; kind: 'cluster'|'workspace'|'services'; rootIds: string[]; transportScope: string;
}
export interface GovernanceCaptureInput { scope: GovernanceScope['kind']; serviceIds?: string[]; workspaceId?: string; module?: 'governance'|'drift'|'promote'; }
export interface GovernanceCoverage {
  state: 'complete'|'projected'|'incomplete'|'not_authorized'; extent: 'cluster'|'workspace'|'services'|'projection';
  eof: boolean; pages: number; records: number; reasonCodes: string[];
}
export interface GovernanceInventoryObject {
  entityType: GovernanceEntityType|'targets'; nativeId: string; payload: Record<string,unknown>; parentId?: string;
  objectWorkspaceId?: string; sensitiveFields: string[]; referenceOnly?: boolean; selected?: boolean;
  annotations?: { state: 'readable'|'not_authorized'|'absent'; description?: string; ownerUserId?: string|null };
  certificate?: { fingerprint?: string; expiresAt?: string; expired?: boolean; state: 'valid'|'invalid' };
  scopeReason?: string;
  managedBoundary?: 'none'|'portal'|'metrics';
}
export interface GovernanceInventory {
  id: string; scope: GovernanceScope; objects: GovernanceInventoryObject[];
  schemas: Record<string,unknown>; pluginSchemas: Record<string,unknown>; enabledPlugins: string[]; version: string;
  coverage: Record<string,GovernanceCoverage>; completeness: 'complete'|'incomplete'; projection: boolean;
  consistency: 'console_fenced_best_effort'; observedFrom: string; observedUntil: string;
  usage: {calls:number;pages:number;records:number;bytes:number}; reasonCodes: string[];
}
declare const governanceReadBrand: unique symbol;
export type GovernanceReadHandle = Readonly<{[governanceReadBrand]:true}>;
export interface GovernanceScheduleLocator {
  scheduleId:string; clusterId:string; workspaceId:string; ownerUserId:string; version:number; revision:number; scheduledAt:string;
  runId:string; leaseGeneration:number;
}
export interface GovernanceAuthorityDescription {
  actor: EntityActor; scope: GovernanceScope; projection:boolean; permittedTypes: readonly GovernanceEntityType[];
  permissionVersion:string; expiresAt:number;
  version:string;
}
