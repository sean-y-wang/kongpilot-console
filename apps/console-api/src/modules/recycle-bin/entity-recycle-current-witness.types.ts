import type { PreparedEntityChange, EntityChangePacket } from '../entities/entity-change.types';
import type { EntityExecutionSourceByOrigin } from '../workflows/entity-change-schedule.contract';
import type { PreparedRecycleObligation } from './entity-prepared-recycle-writer.types';

declare const currentWitnessBrand:unique symbol;
export type EntityRecycleCurrentWitnessHandle=Readonly<{[currentWitnessBrand]:true}>;
export interface EntityRecycleOriginalCompletion {
 readonly nodeKey:string;readonly packet:Readonly<EntityChangePacket>;readonly operationId:string;readonly responseHmac:string;readonly response:unknown;
 readonly source:'committed-original-receipt'|'current-original-response';
}
/** Only a once-installed private Coordinator can resolve this descriptor from
 * its ORIGINAL handle. It is expected material, never a current observation. */
export interface EntityRecycleCurrentDescriptor {
 readonly source:EntityExecutionSourceByOrigin;readonly prepared:Readonly<PreparedEntityChange>;
 readonly obligation:PreparedRecycleObligation;readonly packets:readonly Readonly<EntityChangePacket>[];
 readonly packet:Readonly<EntityChangePacket>;readonly nodeKey:string;
 readonly completed:readonly Readonly<EntityRecycleOriginalCompletion>[];
}
export interface EntityRecycleCurrentNode {
 readonly key:string;readonly originalId:string;readonly type:string;readonly parentId:string|null;readonly affected:boolean;readonly data:Readonly<Record<string,any>>;
}
/** Every node here is from a fresh actual SDK GET, never the archive or POST
 * result. Expected historical/proposed views remain separate. */
export interface EntityRecycleCurrentWitness {
 readonly descriptor:Readonly<EntityRecycleCurrentDescriptor>;
 readonly nodes:readonly Readonly<EntityRecycleCurrentNode>[];readonly absent:readonly string[];
 readonly phase:'before-native'|'after-native';readonly wholeGraphObserved:boolean;
 readonly monotonicDeadline:number;
 readonly observationHmac:string;readonly observedFrom:string;readonly observedUntil:string;
 readonly configurationVerification:'verified';readonly functionalVerification:'pending';
}
export interface EntityRecycleCurrentWitnessDelegate {
 describe(originalPacket:object,phase:'before-native'|'after-native'):Promise<Readonly<EntityRecycleCurrentDescriptor>>;
 assertLive(originalPacket:object):void;
}
export interface EntityRecycleCurrentWitnessReader {
 resolve(handle:EntityRecycleCurrentWitnessHandle):Readonly<EntityRecycleCurrentWitness>;
}
