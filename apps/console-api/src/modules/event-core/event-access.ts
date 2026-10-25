import type {AuthUser} from '../../common/auth';
import type {DbService} from '../../infrastructure/db.service';
import type {DeliveryClaim,DetectorObservationInput,EventRecord,EventOperationAudit} from './event.types';
export const EVENT_ACCESS=Symbol('EVENT_ACCESS');
export const EVENT_OPERATION_AUDIT=Symbol('EVENT_OPERATION_AUDIT');
export const EVENT_OBSERVATION_AUTHORITY=Symbol('EVENT_OBSERVATION_AUTHORITY');
export type {EventOperationAudit};
export interface DeliveryAuthorityProof {readonly actorId:string;readonly permissionVersion:string;readonly channelRevision:number;readonly subscriptionRevision:number|null;readonly credentialGeneration:number;readonly sourceProofDigest:string}
export interface ObservationAuthority {assertCurrent(input:DetectorObservationInput,tx:DbService):Promise<void>}
export interface EventAccess {
 permissionVersion(actor:AuthUser):Promise<string>;
 assertSourceRead(actor:AuthUser,event:EventRecord,module:'events'|'notifications'|'audit'):Promise<void>;
 canSourceRead(actor:AuthUser,event:EventRecord,module:'events'|'notifications'):Promise<boolean>;
 assertWholeWorkspace(actor:AuthUser,cid:string,wid:string,module:'events'|'notifications',action:'read'|'write'|'delete'):Promise<void>;
 assertDeliveryCurrent(claim:DeliveryClaim):Promise<DeliveryAuthorityProof>;
 assertNotificationOwner(actor:AuthUser,ownerId:string,cid:string|null,wid:string|null,action:'read'|'write'|'delete'):Promise<void>;
 assertObservationCurrent(input:DetectorObservationInput,tx:DbService):Promise<void>;
}
