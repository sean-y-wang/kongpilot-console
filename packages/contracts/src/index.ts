export type EntityType = 'services'|'routes'|'consumers'|'plugins'|'upstreams'|'certificates'|'ca_certificates'|'snis';
export type ExecutionMode = 'direct'|'approval';
export interface Page<T> { items:T[]; nextCursor:string|null; size:number; total?:number|null; }
export interface ApiEnvelope<T> { data:T; meta:{requestId:string}; }
export interface Cluster { id:string; name:string; environment:string; admin_url:string; labels:string[]; execution_mode:ExecutionMode; status:string; version:string|null; capabilities:Record<string,unknown>; enabled_plugins:string[]; last_probed_at:string|null; }
export interface Workspace {id:string;cluster_id:string;code:string;name:string;owner_user_id:string|null;description:string;status:'active'|'disabled'|'deleted';is_default:boolean;revision:number;deleted_at:string|null;created_at:string;updated_at:string;}
export type WorkspaceMigrationState='planned'|'running'|'partial'|'succeeded'|'failed'|'expired';
export type WorkspaceMigrationStepState='pending'|'succeeded'|'failed'|'uncertain';
export interface WorkspaceMigrationRoot {type:EntityType|'targets'|'credentials';id:string;parent_id?:string;credential_kind?:'key-auth'|'basic-auth'|'jwt'|'oauth2'|'hmac-auth'|'acls';}
export interface WorkspaceMigrationPlan {id:string;cluster_id:string;source_workspace_id:string;target_workspace_id:string;target_workspace_name:string;state:WorkspaceMigrationState;plan_hash:string;expires_at:string;operation_id:string|null;affected:Array<{key:string;type:string;id:string;name:string;before_tags:string[];after_tags:string[];status:WorkspaceMigrationStepState;inherited_only:boolean;source_workspace_id:string;target_workspace_id:string}>;references:Array<{type:string;id:string;name:string;workspace_id:string|null;affected:boolean}>;conflicts:Array<{code:string;message:string;objects:string[]}>;budget:{pages:number;records:number;nodes:number};warnings:string[];}
export * from './kong-capabilities';
