import type {LookupAddress} from 'node:dns';

export type DeliveryProviderType='webhook'|'email'|'slack'|'feishu';
export type DeliveryChannelAuth={type:'none'}|{type:'bearer';token:string}|{type:'basic';username:string;password:string}|{type:'feishu-signature';secret:string};
export interface DeliveryChannelInput {type:DeliveryProviderType;endpoint?:string|{recipients:string[]};auth?:DeliveryChannelAuth;options?:Record<string,never>}
export interface DeliverySafeSummary {destinationHost:string|null;maskedDestination:string;authConfigured:boolean;recipientCount?:number}
export interface ValidatedDeliveryChannel {
 readonly type:DeliveryProviderType;
 readonly endpoint:{url:string}|{recipients:readonly string[]};
 readonly auth:DeliveryChannelAuth;
 readonly optionsSafe:Readonly<Record<string,never>>;
 readonly safeSummary:DeliverySafeSummary;
}
export interface DeliveryProviderDescriptor {type:DeliveryProviderType;label:string;available:boolean;reasonCode?:string;authTypes:readonly DeliveryChannelAuth['type'][]}
export interface DeliverySmtpConfig {
 host:string;port:number;mode:'starttls'|'implicit-tls';servername:string;from:string;
 username?:string;password?:string;ca?:string;
}
export interface DeliveryPolicyOptions {
 allowedAuthorities:readonly string[];protectedHosts:readonly string[];
 smtp?:DeliverySmtpConfig;httpsCa?:string;
 testReceivers?:Readonly<Record<string,readonly string[]>>;
 ownAddresses?:readonly string[];
 lookupAll?:(host:string)=>Promise<LookupAddress[]>;
}
export interface DeliveryDestination {readonly hostname:string;readonly port:number;readonly addresses:readonly LookupAddress[];readonly pinned:LookupAddress}
export interface DeliverySendFence {prepareSend:()=>Promise<void>;beforeSend:()=>void;signal:AbortSignal;onSendStarted:()=>void}
export interface TransportDeliveryOutcome {outcome:'succeeded'|'failed'|'uncertain';sendStarted:boolean;httpStatus?:number;durationMs:number;errorCode?:string;retryable:boolean;retryAfterMs?:number}
export interface DeliveryEnvelope {version:1;eventId:string;deliveryId:string;clusterId:string;workspaceId:string;occurredAt:string;eventType:string;phase:string;result:string;summary:string;sourceId?:string}
export const DELIVERY_POLICY_OPTIONS=Symbol('DELIVERY_POLICY_OPTIONS');
