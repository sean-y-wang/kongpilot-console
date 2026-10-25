import type {AuthUser} from '../../common/auth';

export const CONFIGURATION_DECK_ACCESS='CONFIGURATION_DECK_ACCESS';
export const CONFIGURATION_DECK_REPOSITORY='CONFIGURATION_DECK_REPOSITORY';
export const DECK_ENTITIES=['services','routes','consumers','plugins','certificates','ca_certificates','snis','upstreams'] as const;
export const DECK_CREDENTIAL_PATHS={ 'key-auths':'key-auth','basic-auths':'basic-auth','jwts':'jwt','hmac-auths':'hmac-auth','oauth2':'oauth2','acls':'acls' } as const;
export type DeckEntity=typeof DECK_ENTITIES[number];
export type DeckCredential=typeof DECK_CREDENTIAL_PATHS[keyof typeof DECK_CREDENTIAL_PATHS];
export type DeckPurpose='read'|'write';
export interface DeckSessionLocator {
 id:string;clusterId:string;workspaceId:string;transportScope:string;actorId:string;sessionId:string;jobId:string;
 purpose:DeckPurpose;credentialEpoch:number;permissionVersion:string;revision:number;expiresAt:string;
 planId?:string;planRevision?:number;planHash?:string;
}
/** Handle identity is owned by Root/Storage. These objects are never accepted
 * from HTTP or used as an approved execution capability by this module. */
export interface DeckAuthority {
 readonly handle:unknown;readonly user:AuthUser;readonly sessionId:string;readonly locator:DeckSessionLocator;
}
export interface DeckPage {items:Record<string,unknown>[];nextCursor:string|null;}
export interface DeckReadRequest {type:DeckEntity|DeckCredential|'targets';parentId?:string;size:100;cursor?:string;tags?:string;}
export interface DeckPacket {
 readonly method:'GET'|'POST'|'PUT'|'PATCH'|'DELETE';readonly path:string;
 readonly kind:'root'|'entity'|'targets'|'credential'|'global-credential'|'unsupported-discovery';readonly type:string;
 readonly id?:string;readonly parentId?:string;readonly collection:boolean;
 readonly query:Readonly<{size:number;offset?:string;tags?:string}>;
 readonly body?:Readonly<Record<string,unknown>>;readonly bodyHmac?:string;
}
export interface DeckSessionIssue {jobId:string;purpose:DeckPurpose;planId?:string;planRevision?:number;planHash?:string;}
export interface DeckIssueAuthority {readonly handle:unknown;readonly user:AuthUser;readonly sessionId:string;readonly clusterId:string;readonly workspaceId:string;readonly jobId:string;readonly purpose:DeckPurpose;readonly credentialEpoch:number;readonly expiresAt:string;}
/** Actual implementations must be installed by ConfigurationCore/Root, never
 * by an optional provider, HTTP callback, fake actor or default-allow stub. */
export interface DeckConfigurationAccess {
 authorizeDeckSessionIssue(input:DeckSessionIssue,actor:{user:AuthUser;sessionId:string;clusterId:string;workspaceId?:string;requestId:string}):Promise<DeckIssueAuthority>;
 acquireDeckSession(locator:DeckSessionLocator):Promise<DeckAuthority>;
 assertDeckCurrent(authority:DeckAuthority|DeckIssueAuthority,phase:'request'|'response'):Promise<void>;
 readDeckRoot(authority:DeckAuthority):Promise<{version:string}>;
 /** Root measures actual native usage (including hidden reads/retries) and
  * atomically charges the shared session budget before returning a page.
  * Manifest-backed reads still charge their bounded returned payload budget. */
 readDeckCollection(authority:DeckAuthority,input:DeckReadRequest):Promise<DeckPage>;
 readDeckEntity(authority:DeckAuthority,input:{type:string;id:string;parentId?:string}):Promise<Record<string,unknown>>;
 /** Select exactly one ready immutable packet/step and delegate to the real
  * Entity/Recycle/Mutation execution. PUT is not a native upsert permission. */
 executeDeckPacket(authority:DeckAuthority,input:DeckPacket):Promise<{status:200|201|204;entity?:Record<string,unknown>}>;
 authorizeDeckSessionRevoke(actor:{user:AuthUser;sessionId:string;clusterId:string;workspaceId?:string;requestId:string},id:string):Promise<DeckAuthority>;
}
export interface DeckSessionRepository {
 locateDeckSession(input:{id:string;tokenHash:string}):Promise<DeckSessionLocator|null>;
 issueDeckSession(handle:unknown,input:DeckSessionIssue&{expiresAt:string;credentialEpoch:number}):Promise<{id:string;token:string;expiresAt:string}>;
 readDeckSession(handle:unknown,input:{id:string;token:string;purpose:DeckPurpose}):Promise<DeckSessionLocator>;
 revokeDeckSession(handle:unknown,id:string,revision:number):Promise<unknown>;
 chargeDeckSessionBudget(handle:unknown,id:string,delta:{pages:number;records:number;bytes:number;calls?:number}):Promise<void>;
}
