import { BadRequestException } from '@nestjs/common';
export const PORTAL_COOKIE_PATH='/api/v1/portal';
export const PORTAL_COOKIES={access:'kongos_portal_access',refresh:'kongos_portal_refresh',csrf:'kongos_portal_csrf'} as const;
export interface PortalScope {clusterId:string;workspaceId:string}
export interface PortalDeveloperView extends PortalScope {
  id:string;username:string;email:string;displayName:string;
  status:'pending'|'active'|'disabled'|'rejected'|'deleted';revision:number;mustChangePassword:boolean;createdAt:string;
}
export interface PortalPrincipal extends PortalScope {readonly kind:'portal_developer';readonly developerId:string;readonly sessionId:string;readonly credentialEpoch:number}
export interface PortalRequestContext {requestId?:string;ip?:string;userAgent?:string;idempotencyKey?:string}
export interface PortalOriginProof {readonly origin:string}
export interface PortalAuthResult {developer:PortalDeveloperView;accessToken:string;refreshToken:string;csrfToken:string;expiresAt:string}
export interface PortalMetadataMutation {module:'applications'|'credentials'|'profile'|'password';action:string;targetId?:string;payload:unknown;context:PortalRequestContext}
export interface PortalOperationView extends PortalScope {
  id:string;state:'running'|'succeeded'|'failed'|'uncertain';module:string;action:string;targetId:string|null;
  remoteStarted:boolean;remoteCompleted:boolean;errorCode:string|null;safeResult:unknown;createdAt:string;updatedAt:string;
}
export const PORTAL_UUID=/^[a-f\d]{8}-[a-f\d]{4}-[1-8][a-f\d]{3}-[89ab][a-f\d]{3}-[a-f\d]{12}$/i;
export function portalScope(value:unknown):PortalScope {
  if(!value||typeof value!=='object'||Array.isArray(value)||!PORTAL_UUID.test((value as any).clusterId??'')||!PORTAL_UUID.test((value as any).workspaceId??''))
    throw new BadRequestException({code:'INVALID_PORTAL_SCOPE',message:'门户集群和工作区必须明确指定'});
  return {clusterId:(value as any).clusterId,workspaceId:(value as any).workspaceId};
}
export function portalExact(value:unknown,keys:readonly string[]):Record<string,any> {
  if(!value||typeof value!=='object'||Array.isArray(value)||Object.keys(value).some(key=>!keys.includes(key)))
    throw new BadRequestException({code:'INVALID_PORTAL_PAYLOAD',message:'门户请求包含不允许的字段'});
  if(Buffer.byteLength(JSON.stringify(value))>128*1024)throw new BadRequestException({code:'PORTAL_PAYLOAD_TOO_LARGE',message:'门户请求超过大小限制'});
  return value as Record<string,any>;
}
export function portalRevision(value:unknown):number {
  if(!Number.isInteger(value)||Number(value)<1||Number(value)>2147483647)throw new BadRequestException({code:'INVALID_REVISION',message:'需要有效的数据修订号'});
  return Number(value);
}
