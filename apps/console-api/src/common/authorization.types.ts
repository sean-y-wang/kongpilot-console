/** A grant is evaluated as a complete row. Never union independent dimensions. */
export const PERMISSION_MODULES = [
  'services','routes','consumers','plugins','upstreams','certificates','ca_certificates','snis',
  'clusters','data-sources','workspaces','annotations','overview','mutations','recycle-bin','secrets',
  'users','teams','roles','permissions','monitoring','portal','developers','applications',
  'audit','events','notifications','snapshots','gitops','toolbox','batches','drafts',
  'governance','lint','drift','promote','workflows',
] as const;
export const PERMISSION_ACTIONS = ['read','write','delete','approve'] as const;
export type PermissionAction = typeof PERMISSION_ACTIONS[number];
export type PermissionModule = typeof PERMISSION_MODULES[number];
export type ScopeType = 'global'|'workspace'|'tag_group'|'entity';
export interface EntityScopeValue { entity_type:string; entity_id:string }
export interface EffectiveGrant {
  user_id?:string; role_id?:string; role_code?:string; permission_id?:string;
  binding_id?:string; binding_source?:'user'|'team';
  cluster_id:string|null; workspace_id:string|null;
  module:string; action:PermissionAction; scope_type:ScopeType;
  /** tag_group: encoded physical strings; entity: typed IDs; workspace: workspace UUIDs. */
  scope_values:Array<string|EntityScopeValue>;
}
export interface ConsoleCapabilities {
  modules:Record<string,Record<PermissionAction,boolean>>;
  grants:EffectiveGrant[];
  clusters:string[];
  platformAdmin:boolean;
}

export function permissionModule(value:string):string {
  if(['targets'].includes(value))return 'upstreams';
  if(['credentials','key-auth','basic-auth','jwt','oauth2','hmac-auth','acls',
      'keyauth_credentials','basicauth_credentials','jwt_secrets','oauth2_credentials','hmacauth_credentials'].includes(value))return 'consumers';
  if(['recycle_entries','recycle_nodes','recycle_bin'].includes(value))return 'recycle-bin';
  if(['workspace_migration','workspace_migrations','workspace-migrations','workspace_migration_plans'].includes(value))return 'workspaces';
  if(value==='data_sources'||value==='data_source')return 'data-sources';
  if(value==='cluster')return 'clusters';
  if(value==='mutation_operations')return 'mutations';
  if(value==='entity_annotations')return 'annotations';
  return value;
}

export function permissionAction(value:string):PermissionAction {
  if(value==='read'||value==='approve')return value;
  if(value==='delete'||value==='purge')return 'delete';
  return 'write';
}
