import 'reflect-metadata';
import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {randomUUID} from 'node:crypto';
import {createRequire} from 'node:module';
import {RequestMethod} from '@nestjs/common';
import {AuthorizationService} from '../../apps/console-api/src/modules/authorization/authorization.service';
import {WorkspaceResolverService} from '../../apps/console-api/src/modules/workspaces/workspace-resolver.service';
import {PortalAdminService} from '../../apps/console-api/src/modules/portal/portal-admin.service';
import {PortalAdminController} from '../../apps/console-api/src/modules/portal/portal.controller';
import {SecretService} from '../../apps/console-api/src/infrastructure/secret.service';
const {PATH_METADATA,METHOD_METADATA}=createRequire(new URL('../../apps/console-api/package.json',import.meta.url))('@nestjs/common/constants');

// Actual authorization and resolver policies, with an explicit metadata store.
// The synthetic repository supplies facts; it does not decide permissions.
function fixture(modules=['applications','developers','portal','workflows']){
 const cid=randomUUID(),wid=randomUUID(),otherWid=randomUUID(),uid=randomUUID(),sid=randomUUID(),developerId=randomUUID(),appId=randomUUID(),pubId=randomUUID();
 const stamp='2026-10-11T01:00:00.000Z',marker='PRIVATE_CREDENTIAL_CANARY';
 const users=new Map<string,any>([[uid,{id:uid,username:'reader',super_admin:false,status:'active',deleted_at:null,permissions_epoch:1,credential_epoch:1,force_password_change:false,revision:1}]]);
 let epoch=1,sessionValid=true,afterRead:undefined|((kind:string)=>void),grantFailure=false;
 const workspace={id:wid,cluster_id:cid,code:'pay',name:'Payments',description:'',status:'active',is_default:false,revision:1,deleted_at:null};
 const workspaces=[workspace,{...workspace,id:otherWid,code:'other'}];
 let grants=modules.map(module=>({module,action:'read',cluster_id:cid,workspace_id:wid,scope_type:'workspace',scope_values:[wid]}));
 let frame:any={actor:{id:uid},sessionId:sid};
 const app:any={id:appId,cluster_id:cid,workspace_id:wid,developer_id:developerId,name:'Retained application',description:'Safe description',status:'active',revision:2,created_at:stamp,key_secret:marker,consumer_id:randomUUID(),configuration:{password:marker}};
 const developer:any={id:developerId,cluster_id:cid,workspace_id:wid,username:'developer',email:'developer@example.test',display_name:'Developer',status:'disabled',revision:3,must_change_password:true,created_at:stamp,password_hash:marker,session_token:marker};
 const applications=[app],developers=[developer];
 const grantRows:any[]=[0,1].map(index=>({id:randomUUID(),cluster_id:cid,workspace_id:wid,application_id:appId,developer_id:developerId,publication_id:pubId,publication_name:'API',state:index?'disabled':'active',current_generation:index?0:1,revision:1,reservation_released_at:index?stamp:null,created_at:stamp,workflow_id:randomUUID(),key_secret:marker,consumer_id:randomUUID(),acl_id:randomUUID()}));
 const requestRows:any[]=['portal-credential-issue','portal-credential-rotate','portal-credential-revoke'].map(kind=>({id:randomUUID(),cluster_id:cid,workspace_id:wid,subject_type:'portal_application_grants',subject_id:grantRows[0].id,application_id:appId,grant_id:grantRows[0].id,publication_id:pubId,kind,state:'succeeded',revision:3,execution_mode:'direct',approval_required:true,created_at:stamp,expires_at:'2026-10-12T01:00:00.000Z',plan_hash:marker,payload_secret:marker,native_id:randomUUID()}));
 grantRows[0].workflow_id=requestRows[2].id; // Current revoke pointer cannot erase prior issue/rotate history.
 const dataQueries:string[]=[];
 const finish=(kind:string,result:any)=>{const copy=structuredClone(result);afterRead?.(kind);return copy;};
 const db:any={
  one:vi.fn(async(sql:string,p:any[]=[])=>{
   if(sql.includes('FROM users')){const row=users.get(p[0]);return row?.status==='active'&&!row.deleted_at?structuredClone(row):null;}
   if(sql.includes('FROM auth_sessions'))return sessionValid&&p[0]===sid&&p[1]===frame.actor.id?{id:sid}:null;
   if(sql.includes('FROM iam_epoch'))return{version:epoch};
   if(sql.includes('FROM clusters'))return p[0]===cid?{id:cid}:null;
   if(sql.includes('FROM workspaces'))return structuredClone(workspaces.find(w=>w.cluster_id===p[0]&&w.id===p[1])??null);
   if(sql.includes('FROM portal_applications')){dataQueries.push(sql);return finish('application',applications.find(a=>a.cluster_id===p[0]&&a.workspace_id===p[1]&&a.id===p[2])??null);}
   if(sql.includes('FROM portal_developers')){dataQueries.push(sql);return finish('developer',developers.find(a=>a.cluster_id===p[0]&&a.workspace_id===p[1]&&a.id===p[2])??null);}
   throw new Error('UNEXPECTED_METADATA_READ');
  }),
  query:vi.fn(async(sql:string,p:any[]=[])=>{
   if(sql.includes('FROM iam_effective_grants')){if(grantFailure)throw new Error('AUTHORITY_DATABASE_UNAVAILABLE');return structuredClone(grants);}
   dataQueries.push(sql);
   if(sql.includes('FROM portal_application_grants g')){
    const rows=grantRows.filter(g=>g.cluster_id===p[0]&&g.workspace_id===p[1]&&g.application_id===p[2]&&g.developer_id===p[3]&&(p[4]===null||g.state===p[4]));
    return finish('grants',rows.slice(p[6],p[6]+p[5]));
   }
   if(sql.includes('FROM workflows w')){
    expect(sql).toContain("w.subject_type='portal_application_grants'");expect(sql).toContain('w.subject_id=g.id');expect(sql).not.toContain('g.workflow_id');
    const rows=requestRows.filter(w=>w.cluster_id===p[0]&&w.workspace_id===p[1]&&w.subject_type==='portal_application_grants'&&grantRows.some(g=>g.id===w.subject_id&&g.cluster_id===w.cluster_id&&g.workspace_id===w.workspace_id)&&(p[2]===null||w.application_id===p[2])&&(p[3]===null||applications.find(a=>a.id===w.application_id)?.developer_id===p[3])&&['portal-credential-issue','portal-credential-rotate','portal-credential-revoke'].includes(w.kind)&&(p[4]===null||w.state===p[4]));
    return finish('requests',rows.slice(p[6],p[6]+p[5]));
   }
   if(sql.includes('FROM portal_applications'))return finish('applications',applications.filter(a=>a.cluster_id===p[0]&&a.workspace_id===p[1]&&(p[2]===null||a.status===p[2])).slice(p[5],p[5]+p[4]));
   if(sql.includes('FROM portal_developers'))return finish('developers',developers.filter(a=>a.cluster_id===p[0]&&a.workspace_id===p[1]&&(p[2]===null||a.status===p[2])).slice(p[5],p[5]+p[4]));
   throw new Error('UNEXPECTED_METADATA_QUERY');
  }),exec:vi.fn(async()=>{throw new Error('METADATA_WRITE_FORBIDDEN');}),transaction:vi.fn(async()=>{throw new Error('METADATA_TRANSACTION_FORBIDDEN');})
 };
 const native:any={service:vi.fn(async()=>{throw new Error('NATIVE_READ_FORBIDDEN');}),collection:vi.fn(async()=>{throw new Error('NATIVE_READ_FORBIDDEN');})};
 const authz=new AuthorizationService(db,new WorkspaceResolverService(db),native,{peek:()=>frame}as any),resolver=new WorkspaceResolverService(db);
 const effects:any={execute:vi.fn(),assertSubject:vi.fn(),append:vi.fn()};
 const service=new PortalAdminService(db,new SecretService(),authz,effects,effects,effects,resolver,effects,effects,effects,effects,native,effects);
 const actor:any={user:{id:uid,username:'reader',superAdmin:false},workspaceId:wid};
 return{service,db,authz,cid,wid,otherWid,uid,sid,app,developer,appId,developerId,grantRows,requestRows,workspace,actor,marker,dataQueries,native,effects,
  query:{workspaceId:wid},setAfter:(fn:typeof afterRead)=>{afterRead=fn;},setGrants:(v:any[])=>{grants=v;},getGrants:()=>grants,
  bump:()=>{epoch++;},revokeSession:()=>{sessionValid=false;},disableUser:()=>{users.get(uid).status='disabled';},failAuthority:()=>{grantFailure=true;},
  otherActor:()=>{const id=randomUUID();users.set(id,{...users.get(uid),id,username:'other'});frame={actor:{id},sessionId:sid};return{...actor,user:{...actor.user,id}};}};
}
beforeEach(()=>{vi.stubEnv('CONSOLE_ENCRYPTION_KEY','ac'.repeat(32));vi.stubEnv('CURSOR_SIGNING_KEY','SyntheticPortalAdminCursor2026!');});afterEach(()=>vi.unstubAllEnvs());

describe('M6 actual portal admin read boundary',()=>{
 it('applications-only reader gets safe root and denied relationship capabilities without extra reads',async()=>{const f=fixture(['applications']),r=await f.service.application(f.cid,f.appId,f.query,f.actor);expect(r.entity.capabilities).toEqual({readGrants:false,readRequests:false});expect(JSON.stringify(r)).not.toContain(f.marker);expect(f.dataQueries).toHaveLength(1);expect(f.native.service).not.toHaveBeenCalled();expect(f.effects.execute).not.toHaveBeenCalled();expect(f.db.exec).not.toHaveBeenCalled();});
 it('developer detail needs only its complete module grant and excludes authentication material',async()=>{const f=fixture(['developers']),r=await f.service.developer(f.cid,f.developerId,f.query,f.actor);expect(r.entity).toMatchObject({status:'disabled',mustChangePassword:true,email:'developer@example.test'});expect(JSON.stringify(r)).not.toContain(f.marker);});
 for(const state of ['disabled','deleted'])it(`retains ${state} app relationships in a disabled workspace`,async()=>{const f=fixture();f.app.status=state;f.workspace.status='disabled';expect((await f.service.application(f.cid,f.appId,f.query,f.actor)).entity.state).toBe(state==='deleted'?'archived':state);expect((await f.service.applicationGrants(f.cid,f.appId,f.query,f.actor)).items).toHaveLength(2);expect((await f.service.applicationRequests(f.cid,f.appId,f.query,f.actor)).items).toHaveLength(3);expect(f.effects.assertSubject).not.toHaveBeenCalled();});
 for(const module of ['portal','workflows'])it(`does not combine foreign/tag/action grants into ${module} relation read`,async()=>{const f=fixture(['applications']),base={cluster_id:f.cid,workspace_id:f.wid,scope_values:[f.wid],scope_type:'workspace'};f.setGrants([...f.getGrants(),{...base,module,action:'write'},{...base,module,action:'read',workspace_id:f.otherWid,scope_values:[f.otherWid]},{...base,module,action:'read',scope_type:'tag_group',scope_values:['team~pay']}]);const call=module==='portal'?f.service.applicationGrants.bind(f.service):f.service.applicationRequests.bind(f.service);await expect(call(f.cid,f.appId,f.query,f.actor)).rejects.toMatchObject({status:403});expect(f.dataQueries).toHaveLength(0);});
 it('grants disclose reservation closure and counters without native IDs, workflow pointers or ciphertext',async()=>{const f=fixture(),r=await f.service.applicationGrants(f.cid,f.appId,f.query,f.actor);expect(r.items[1]).toMatchObject({generation:0,reservationReleased:true});for(const field of ['consumer_id','acl_id','key_secret','workflowId','workflow_id'])expect(JSON.stringify(r)).not.toContain(field);expect(JSON.stringify(r)).not.toContain(f.marker);});
 it('reads immutable subject history after the mutable grant pointer moves to revoke',async()=>{const f=fixture(),r=await f.service.applicationRequests(f.cid,f.appId,f.query,f.actor);expect(r.items.map((w:any)=>w.kind)).toEqual(['portal-credential-issue','portal-credential-rotate','portal-credential-revoke']);expect(JSON.stringify(r)).not.toContain(f.marker);});
 it('workspace request alias needs workflows read alone and excludes unrelated workflows',async()=>{const f=fixture(['workflows']);f.requestRows.push({...f.requestRows[0],id:randomUUID(),kind:'portal-metadata'});const r=await f.service.requests(f.cid,f.query,f.actor);expect(r.items).toHaveLength(3);expect(f.dataQueries).toHaveLength(1);expect(f.dataQueries[0]).toContain('FROM workflows w');});
 for(const method of ['developer','application','developers','applications','requests']as const)it(`${method} rejects missing or contradictory workspace before metadata lookup`,async()=>{const f=fixture(),call=(q:any)=>['developer','application'].includes(method)?(f.service[method]as any)(f.cid,method==='developer'?f.developerId:f.appId,q,f.actor):(f.service[method]as any)(f.cid,q,f.actor);await expect(call({})).rejects.toMatchObject({status:400});await expect(call({workspaceId:f.otherWid})).rejects.toMatchObject({status:403});expect(f.dataQueries).toHaveLength(0);expect(f.db.exec).not.toHaveBeenCalled();});
 it('an object ID from another scope never authorizes a detail read',async()=>{const f=fixture();f.app.workspace_id=f.otherWid;await expect(f.service.application(f.cid,f.appId,f.query,f.actor)).rejects.toMatchObject({status:404});});
 it('capability database failures propagate instead of returning misleading false capabilities',async()=>{const f=fixture();f.setAfter(kind=>{if(kind==='application')f.failAuthority();});await expect(f.service.application(f.cid,f.appId,f.query,f.actor)).rejects.toThrow('AUTHORITY_DATABASE_UNAVAILABLE');});
 for(const kind of ['grants','requests','developers','applications']as const)it(`${kind} denies a grant revoked while its data query is awaited`,async()=>{const f=fixture();f.setAfter(read=>{if(read===kind){f.setGrants([]);f.bump();}});const call=kind==='grants'?()=>f.service.applicationGrants(f.cid,f.appId,f.query,f.actor):kind==='requests'?()=>f.service.applicationRequests(f.cid,f.appId,f.query,f.actor):()=>f.service[kind](f.cid,f.query,f.actor);await expect(call()).rejects.toMatchObject({status:403});});
 for(const fault of ['epoch','session','user']as const)it(`root detail refuses late ${fault} invalidation`,async()=>{const f=fixture();f.setAfter(kind=>{if(kind==='developer'){if(fault==='epoch')f.bump();if(fault==='session')f.revokeSession();if(fault==='user')f.disableUser();}});await expect(f.service.developer(f.cid,f.developerId,f.query,f.actor)).rejects.toMatchObject({status:fault==='epoch'?403:401});});
 for(const fault of ['actor','epoch','state','size','kind','app','workspace']as const)it(`relationship cursor cannot cross ${fault}`,async()=>{const f=fixture(),page=await f.service.applicationGrants(f.cid,f.appId,{...f.query,size:1},f.actor);expect(page.nextCursor).toBeTruthy();let actor=f.actor,query:any={...f.query,size:1,cursor:page.nextCursor},id=f.appId;if(fault==='actor')actor=f.otherActor();if(fault==='epoch')f.bump();if(fault==='state')query.state='disabled';if(fault==='size')query.size=2;if(fault==='app'){id=randomUUID();f.app.id=id;}if(fault==='workspace')query.workspaceId=f.otherWid;const call=fault==='kind'?()=>f.service.applicationRequests(f.cid,id,query,actor):()=>f.service.applicationGrants(f.cid,id,query,actor);await expect(call()).rejects.toMatchObject({status:fault==='workspace'?403:400});});
 for(const query of [{state:['active']},{state:'all'},{size:['20']},{size:'1e2'},{cursor:['bad']}])it(`rejects noncanonical relationship query ${JSON.stringify(query)}`,async()=>{const f=fixture();await expect(f.service.applicationGrants(f.cid,f.appId,{...f.query,...query},f.actor)).rejects.toMatchObject({status:400});});
 it('registers five exact console GET routes without adding public native/reveal routes',()=>{expect(Reflect.getMetadata(PATH_METADATA,PortalAdminController)).toBe('clusters/:clusterId/portal');for(const[method,path]of Object.entries({developer:'developers/:id',application:'applications/:id',applicationGrants:'applications/:id/grants',applicationRequests:'applications/:id/requests',requests:'requests'})){const handler=(PortalAdminController.prototype as any)[method];expect(Reflect.getMetadata(PATH_METADATA,handler)).toBe(path);expect(Reflect.getMetadata(METHOD_METADATA,handler)).toBe(RequestMethod.GET);}});
});
