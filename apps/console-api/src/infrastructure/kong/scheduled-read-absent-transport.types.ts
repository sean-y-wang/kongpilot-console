import type { KongPolicyTicket } from './execution-context.service';

/** Evidence authenticated from one actual SDK transport response. A copied
 * DTO never replaces its opaque original proof or private request ticket. */
export interface ScheduledReadAbsentTransportFact {
 readonly clusterId:string;readonly transportScope:string;readonly clusterRevision:number;
 readonly method:'GET';readonly path:string;readonly query:Readonly<Record<string,string|number>>;
 readonly status:404;readonly response:unknown;
}
export interface ScheduledReadAbsentTransportObserver {
 verifyTransport(originalTicket:KongPolicyTicket,originalTransportProof:object):Readonly<ScheduledReadAbsentTransportFact>;
}
/** Root Context owns this original token/observation association. It is valid
 * only during observation of the genuine transport 404 and mints no Native
 * permission. Numbers and caller-shaped response facts are not observations. */
export interface ScheduledReadAbsentObservationVerifier {
 verifyOriginalResponse(originalRequestToken:object,originalObservation:object):Readonly<{status:404;response:unknown}>;
}
