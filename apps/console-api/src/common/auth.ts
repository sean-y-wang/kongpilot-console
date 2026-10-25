import { SetMetadata } from '@nestjs/common';
export const PUBLIC_ROUTE = 'kongos.public';
export const SUPER_ADMIN_ROUTE = 'kongos.superAdmin';
export const Public = () => SetMetadata(PUBLIC_ROUTE, true);
export const RequireSuperAdmin = () => SetMetadata(SUPER_ADMIN_ROUTE, true);
export interface AuthUser {
 id:string; username:string; superAdmin:boolean; permissions?:unknown[];
 displayName?:string; locale?:string; timezone?:string; revision?:number;
 forcePasswordChange?:boolean; permissionsVersion?:string;
 capabilities?:import('./authorization.types').ConsoleCapabilities;
}
