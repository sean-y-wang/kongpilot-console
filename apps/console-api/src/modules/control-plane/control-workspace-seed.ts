import {ForbiddenException} from '@nestjs/common';
import type {DbService} from '../../infrastructure/db.service';
import {immutableJson} from '../../infrastructure/kong/immutable-json';

/** Exact SQL005 workspace bootstrap policy. The roles are unassigned; this
 * seed changes the global epoch but does not grant the actor new privileges. */
export const CONTROL_WORKSPACE_SEED_MODULES=Object.freeze(['services','routes','consumers','plugins','upstreams','certificates','ca_certificates','snis','clusters','data-sources','workspaces','annotations','overview','mutations','recycle-bin','secrets','users','teams','roles','permissions','monitoring','portal','developers','applications','audit','events','notifications','snapshots','gitops','toolbox','batches','drafts','governance','lint','drift','promote','workflows']);
export const CONTROL_WORKSPACE_SEED_ROLES=Object.freeze(['workspace-super-admin','workspace-admin','workspace-read-only']);
export const CONTROL_WORKSPACE_SEED_PERMISSIONS=immutableJson(CONTROL_WORKSPACE_SEED_ROLES.flatMap(role=>CONTROL_WORKSPACE_SEED_MODULES.flatMap(module=>{
 if(['clusters','data-sources','users'].includes(module)||module==='secrets'&&role!=='workspace-super-admin')return [];
 return ['read','write','delete','approve'].filter(action=>(role!=='workspace-read-only'||action==='read')&&(role!=='workspace-admin'||action!=='approve')&&(module!=='secrets'||action==='read'))
  .map(action=>({role,module,action}));
})));
export const CONTROL_WORKSPACE_SEED_EPOCH_DELTA=3+CONTROL_WORKSPACE_SEED_PERMISSIONS.length;

/** This is an integrity check, not a grant provider. The caller is the fixed
 * original completion path; plain rows or a copied result mint no authority. */
export async function verifyControlWorkspaceSeed(tx:DbService,cid:string,wid:string):Promise<void> {
 const deny=()=>new ForbiddenException({code:'CONTROL_WORKSPACE_SEED_CHANGED'}),roles=await tx.query<any>('SELECT * FROM roles WHERE cluster_id=$1 AND workspace_id=$2 ORDER BY builtin_kind',[cid,wid]);
 if(roles.length!==3||roles.some(r=>!CONTROL_WORKSPACE_SEED_ROLES.includes(r.builtin_kind)||r.code!==r.builtin_kind||r.name!==r.builtin_kind||r.cluster_id!==cid||r.workspace_id!==wid
  ||r.protected!==true||r.status!=='active'||r.revision!==1||r.deleted_at!=null||r.retention_until!=null)||new Set(roles.map(r=>r.builtin_kind)).size!==3)throw deny();
 const ids=roles.map(r=>r.id),permissions=await tx.query<any>('SELECT * FROM role_permissions WHERE role_id=ANY($1::uuid[]) ORDER BY role_id,module,action',[ids]),byId=new Map(roles.map(r=>[r.id,r.builtin_kind]));
 const expected=new Set(CONTROL_WORKSPACE_SEED_PERMISSIONS.map(p=>`${p.role}:${p.module}:${p.action}`)),seen=new Set<string>();
 if(permissions.length!==expected.size)throw deny();
 for(const p of permissions){const key=`${byId.get(p.role_id)}:${p.module}:${p.action}`;
  if(!expected.has(key)||seen.has(key)||p.scope_type!=='workspace'||p.cluster_id!==cid||p.workspace_id!==wid||p.status!=='active'||p.revision!==1||p.revoked_at!=null||p.retention_until!=null)throw deny();seen.add(key);
 }
 const extra=await tx.one<any>(`SELECT EXISTS(SELECT 1 FROM user_role_bindings WHERE role_id=ANY($1::uuid[]))
  OR EXISTS(SELECT 1 FROM team_role_bindings WHERE role_id=ANY($1::uuid[]))
  OR EXISTS(SELECT 1 FROM role_permission_tags WHERE permission_id=ANY($2::uuid[]))
  OR EXISTS(SELECT 1 FROM role_permission_entities WHERE permission_id=ANY($2::uuid[])) AS present`,[ids,permissions.map(p=>p.id)]);
 if(!extra||extra.present!==false)throw deny();
}
