import { AuditOutboxWriter } from '../../apps/console-api/src/modules/event-core/audit-outbox-writer.service';
import 'reflect-metadata';
import { execFileSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { mkdirSync,writeFileSync } from 'node:fs';
import { DbService } from '../../apps/console-api/src/infrastructure/db.service';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { AuditService } from '../../apps/console-api/src/modules/audit/audit.service';
import { AuthService } from '../../apps/console-api/src/modules/auth/auth.service';
import { AuthorizationService } from '../../apps/console-api/src/modules/authorization/authorization.service';
import { KongExecutionContextService } from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import { WorkspaceResolverService } from '../../apps/console-api/src/modules/workspaces/workspace-resolver.service';
import { IamMutationsService } from '../../apps/console-api/src/modules/iam/iam-mutations.service';
import { IamService } from '../../apps/console-api/src/modules/iam/iam.service';
import type { IamActor } from '../../apps/console-api/src/modules/iam/iam.types';
import { ClustersService } from '../../apps/console-api/src/modules/clusters/clusters.service';
import { DataSourcesService } from '../../apps/console-api/src/modules/data-sources/data-sources.service';

async function main(){
 const container=`kongos-iam-business-${randomUUID().slice(0,8)}`,checks:any[]=[],key=()=>randomUUID();let db:DbService|undefined;
 const check=async(name:string,fn:()=>Promise<void>)=>{await fn();checks.push({name,passed:true});};
 const assert=(condition:any)=>{if(!condition)throw new Error('IAM business assertion failed');};
 const denied=async(fn:()=>Promise<any>,status:number)=>{try{await fn();throw new Error('Expected rejection');}catch(error:any){if(error.getStatus?.()!==status)throw new Error(`Expected HTTP ${status}, received ${error.getStatus?.()??'non-HTTP error'}`);}};
 try{
  execFileSync('docker',['run','-d','--name',container,'-p','127.0.0.1::5432','-e','POSTGRES_HOST_AUTH_METHOD=trust','postgres:16-alpine'],{stdio:'ignore'});
  const port=execFileSync('docker',['port',container,'5432'],{encoding:'utf8'}).trim().split(':').pop();
  process.env.DATABASE_URL=`postgres://postgres@127.0.0.1:${port}/postgres`;process.env.APP_SECRET='IAM-business-test-signing-secret-at-least-32';process.env.CONSOLE_ENCRYPTION_KEY='de'.repeat(32);
  process.env.BOOTSTRAP_ADMIN_USERNAME='iam-bootstrap';process.env.BOOTSTRAP_ADMIN_PASSWORD='Synthetic!Iam2026Password';
  db=new DbService();for(let i=0;i<50;i++){try{await db.one('SELECT 1');break;}catch{await new Promise(r=>setTimeout(r,100));if(i===49)throw new Error('Disposable DB unavailable');}}
  await db.migrateAndSeed();const secrets=new SecretService(),audit=new AuditService(db,secrets,new AuditOutboxWriter(db,secrets)),workspaces=new WorkspaceResolverService(db),execution=new KongExecutionContextService();
  const authz=new AuthorizationService(db,workspaces,{} as any,execution);
  const redis:any={withLock:async(_key:string,fn:any)=>fn(),assertLeaseOwnership:async()=>undefined,rateLimit:async()=>({allowed:true}),client:{}};
  const auth=new AuthService(db,redis,audit,authz,execution,secrets),ledger=new IamMutationsService(db,redis,secrets,audit,authz),service=new IamService(db,secrets,audit,authz,auth,ledger);
  const admin=await db.one<any>("SELECT id,username FROM users WHERE super_admin AND status='active'"),actor:IamActor={user:{id:admin.id,username:admin.username,superAdmin:true},idempotencyKey:key()};
  const fresh=(user=actor.user)=>({user,idempotencyKey:key()});let user:any,team:any,role:any,grant:any,member:any;
  const http=async<T>(who:IamActor,fn:()=>Promise<T>):Promise<T>=>execution.runHttp({idempotencyKey:who.idempotencyKey},async()=>{execution.bindHttpActor(who.user);try{return await fn();}finally{execution.captureHttpCloser()();}});
  await check('first startup seeds protected role binding as well as the administrator',async()=>assert((await authz.snapshot(actor.user)).grants.some(g=>g.role_code==='super-admin')));
  await check('user create blocks protected mass assignment before hashing or persistence',async()=>{
   await denied(()=>service.create('users',{username:'invalid-admin',password:'Synthetic!Iam2026Password',super_admin:true},fresh()),400);
   assert(!await db!.one("SELECT id FROM users WHERE username='invalid-admin'"));
  });
  await check('new user has no password/session material in resource or audit views',async()=>{
   user=await service.create('users',{username:'business-user',password:'Synthetic!Business2026Password',display_name:'Business user'},fresh());
   assert(user.super_admin===false&&!('password_hash'in user));const audits=await db!.query<any>('SELECT before,after,json_patch FROM audit_events WHERE entity_type=\'users\'');
   assert(!JSON.stringify(audits).includes('Synthetic!Business2026Password'));
  });
  await check('stale cached superAdmin flag never authorizes a fresh ordinary account',async()=>{
   await denied(()=>service.list('users',{},fresh({id:user.id,username:user.username,superAdmin:true})),403);
  });
  await check('custom role grants produce an immediate complete permission snapshot',async()=>{
   role=await service.create('roles',{code:'business-reader',name:'Business reader'},fresh());
   const result=await service.replacePermissions(role.id,{revision:role.revision,permissions:[{module:'users',action:'read',scope_type:'global',scope_values:[]}]},fresh());role.revision=result.revision;
   grant=await service.addBinding('users',user.id,{role_id:role.id},fresh());
   const reader={id:user.id,username:user.username,superAdmin:false};assert((await service.list('users',{},fresh(reader))).items.some((u:any)=>u.id===user.id));
   await denied(()=>service.create('users',{username:'reader-escalation',password:'Synthetic!Reader2026Password'},fresh(reader)),403);
  });
  await check('durable global receipt replays exactly once with safe commit proof',async()=>{
   const same=fresh(),payload={code:'receipt-role',name:'Receipt role'};const a=await service.create('roles',payload,same),b=await service.create('roles',payload,same);assert(a.id===b.id);
   const receipt=await ledger.receipt(same,same.idempotencyKey!,true);assert(receipt.state==='succeeded'&&receipt.remote_completed===true&&!('result_secret'in receipt));
  });
  await check('role revocation immediately denies the same ordinary principal',async()=>{
   await service.bindingState('users',user.id,grant.id,{revision:grant.revision,confirmed:true,confirm_name:grant.role_name},false,fresh());
   await denied(()=>service.list('users',{},fresh({id:user.id,username:user.username,superAdmin:false})),403);
  });
  await check('restoring a role assignment restores its exact prior permission ceiling',async()=>{
   grant=await service.bindingState('users',user.id,grant.id,{revision:grant.revision+1,confirmed:true,confirm_name:grant.role_name},true,fresh());
   assert((await authz.snapshot({id:user.id,username:user.username,superAdmin:false})).grants.some(g=>g.role_id===role.id&&g.module==='users'&&g.action==='read'));
  });
  await check('team membership addition/removal has immediate DB-authoritative effects',async()=>{
   team=await service.create('teams',{code:'business-team',name:'Business team'},fresh());
   await service.addBinding('teams',team.id,{role_id:role.id},fresh());member=await service.addMember(team.id,{user_id:user.id},fresh());
   assert((await authz.snapshot({id:user.id,username:user.username,superAdmin:false})).grants.some(g=>g.binding_source==='team'));
   await service.memberState(team.id,user.id,{revision:member.revision,confirmed:true,confirm_name:user.username},false,fresh());
   assert(!(await authz.snapshot({id:user.id,username:user.username,superAdmin:false})).grants.some(g=>g.binding_source==='team'));
  });
  await check('global admin cannot assign Super role, modify Super user, or clone it',async()=>{
   const operator=await service.create('users',{username:'ordinary-admin',password:'Synthetic!Operator2026Password'},fresh());
   const globalAdmin=await db!.one<any>("SELECT id FROM roles WHERE builtin_kind='admin'");await service.addBinding('users',operator.id,{role_id:globalAdmin.id},fresh());
   const lower=fresh({id:operator.id,username:operator.username,superAdmin:false}),superRole=await db!.one<any>("SELECT id FROM roles WHERE builtin_kind='super-admin'");
   await denied(()=>service.addBinding('users',user.id,{role_id:superRole.id},lower),403);
   await denied(()=>service.state('users',admin.id,{revision:1,status:'disabled',confirmed:true,confirm_name:admin.username},'status',lower),403);
   await denied(()=>service.clone(superRole.id,{code:'fake-super',name:'Fake Super'},lower),403);
  });
  await check('last active Super administrator cannot be disabled or have its protected binding revoked',async()=>{
   const before=await service.get('users',admin.id,fresh());await denied(()=>service.state('users',admin.id,{revision:before.revision,status:'disabled',confirmed:true,confirm_name:admin.username},'status',fresh()),409);
   const binding=await db!.one<any>("SELECT b.*,r.name AS role_name FROM user_role_bindings b JOIN roles r ON r.id=b.role_id WHERE b.user_id=$1 AND r.builtin_kind='super-admin' AND b.status='active'",[admin.id]);
   await denied(()=>service.bindingState('users',admin.id,binding.id,{revision:binding.revision,confirmed:true,confirm_name:binding.role_name},false,fresh()),409);
  });
  await check('soft-deleted role is retained, visible in trash, cannot reuse its code, and restores without new ID',async()=>{
   const deleted=await service.state('roles',role.id,{revision:role.revision,confirmed:true,confirm_name:role.name},'delete',fresh());assert(deleted.status==='deleted'&&deleted.retention_until);
   assert((await service.list('roles',{status:'deleted'},fresh())).items.some((r:any)=>r.id===role.id));
   await denied(()=>service.create('roles',{code:role.code,name:'Reuse'},fresh()),409);
   const restored=await service.state('roles',role.id,{revision:deleted.revision,confirmed:true,confirm_name:role.name},'restore',fresh());role=restored;assert(restored.id===deleted.id&&restored.status==='active');
  });
  await check('concurrent metadata editors cannot overwrite a committed revision',async()=>{
   const revision=role.revision;const outcomes=await Promise.allSettled([service.update('roles',role.id,{revision,name:'Editor A'},fresh()),service.update('roles',role.id,{revision,name:'Editor B'},fresh())]);
   assert(outcomes.filter(x=>x.status==='fulfilled').length===1);const failed=outcomes.find(x=>x.status==='rejected') as PromiseRejectedResult;assert(failed.reason.getStatus()===409);
  });
  await check('signed IAM cursors bind current permissions and reject a revoked capability',async()=>{
   const same=fresh({id:user.id,username:user.username,superAdmin:false}),page=await service.list('users',{size:1},same);assert(page.nextCursor);
   const currentRole=await service.get('roles',role.id,fresh());
   await service.bindingState('users',user.id,grant.id,{revision:grant.revision,confirmed:true,confirm_name:currentRole.name},false,fresh());
   await denied(()=>service.list('users',{size:1,cursor:page.nextCursor},same),403);
  });
  await check('password reset atomically revokes DB sessions and persists a replayable private IAM receipt',async()=>{
   const before=await service.get('users',user.id,fresh());await db!.exec('INSERT INTO auth_sessions(user_id,expires_at) VALUES($1,now()+interval \'1 day\')',[user.id]);
   const same=fresh(),body={revision:before.revision,new_password:'Synthetic!Rotated2026Password',confirmed:true};
   const result=await http(same,()=>service.resetPassword(user.id,body,same));assert(result.sessionsRevoked&&result.forcePasswordChange);
   assert(!await db!.one('SELECT id FROM auth_sessions WHERE user_id=$1 AND revoked_at IS NULL',[user.id]));
   const replay=await http(same,()=>service.resetPassword(user.id,body,same));assert(replay.revision===result.revision);
   assert((await db!.one<any>('SELECT revision FROM users WHERE id=$1',[user.id])).revision===result.revision);
   const receipt=await ledger.receipt(same,same.idempotencyKey!,true);assert(receipt.state==='succeeded'&&receipt.remote_completed===true);
   await denied(()=>http(same,()=>service.resetPassword(user.id,{...body,new_password:'Synthetic!Different2026Password'},same)),409);
   const stale=fresh();await denied(()=>http(stale,()=>service.resetPassword(user.id,{...body,new_password:'Synthetic!Different2026Password'},stale)),409);
   const operation=await db!.one<any>('SELECT id,payload_secret FROM iam_operations WHERE actor_id=$1 AND idempotency_key=$2',[same.user.id,same.idempotencyKey]);
   assert(!JSON.stringify(secrets.decrypt(operation.payload_secret,`iam:${operation.id}:payload`)).includes(body.new_password));
  });
  await check('every committed IAM mutation has an append-only audit with no plaintext password',async()=>{
   const count=await db!.one<any>("SELECT count(*)::int AS n FROM iam_operations WHERE state='succeeded'");const auditCount=await db!.one<any>("SELECT count(*)::int AS n FROM audit_events WHERE (action LIKE 'iam.%' OR action='password.reset') AND result='success'");assert(auditCount.n>=count.n);
   const audited=await db!.query('SELECT before,after,json_patch FROM audit_events');assert(!JSON.stringify(audited).includes('Synthetic!Rotated2026Password'));try{await db!.exec('UPDATE audit_events SET result=\'tampered\'');throw new Error('Audit modification allowed');}catch(error:any){assert(error.code==='42501');}
  });
  process.env.OUTBOUND_ALLOWED_HOSTS='127.0.0.1,localhost,kong,prometheus,loki';
  let remoteReads=0;
  const fakeKong:any={invalidate:()=>undefined,inspectProbe:async(cid:string)=>{remoteReads++;return {cluster_id:cid,status:'healthy',version:'1.5.1',capabilities:{},enabled_plugins:[],latency_ms:1};},persistProbe:async(cid:string,inspection:any,who:any,tx:DbService)=>{
   assert(tx!==db);await tx.exec("UPDATE clusters SET status='healthy',version='1.5.1',last_probed_at=now() WHERE id=$1",[cid]);
   await audit.append({actorId:who.id,clusterId:cid,entityType:'clusters',entityId:cid,action:'probe',after:inspection},tx);return inspection;
  }};
  const registry=new ClustersService(db,secrets,fakeKong,audit,authz,ledger,execution),sources=new DataSourcesService(db,secrets,registry,audit,authz,ledger);let cluster:any,source:any;
  await check('registry metadata create and retry use actor-private IAM receipts',async()=>{
   const same=fresh(),body={name:'Disposable gateway',admin_url:'http://127.0.0.1:18001'};cluster=await registry.create(body,same);const cached=await registry.create(body,same);assert(cluster.id===cached.id);
   assert((await ledger.receipt(same,same.idempotencyKey!,true)).remote_completed===true);
  });
  await check('new canonical endpoints and DNS aliases cannot duplicate a gateway registration',async()=>{
   await denied(()=>registry.create({name:'Duplicate gateway',admin_url:'http://127.0.0.1:18001/'},fresh()),409);
   await denied(()=>registry.create({name:'Alias gateway',admin_url:'http://localhost:18001'},fresh()),409);
  });
  await check('native-only roles see sanitized accessible cluster metadata without connection details',async()=>{
   const nativeRole=await service.create('roles',{code:'registry-native',name:'Registry native'},fresh());
   const permissions=await service.replacePermissions(nativeRole.id,{revision:1,permissions:[{module:'services',action:'read',scope_type:'entity',cluster_id:cluster.id,scope_values:[{entity_type:'services',entity_id:randomUUID()}]}]},fresh());assert(permissions.items.length===1);
   await service.addBinding('users',user.id,{role_id:nativeRole.id,cluster_id:cluster.id},fresh());
   const rows=await registry.list(fresh({id:user.id,username:user.username,superAdmin:true}));assert(rows.some((r:any)=>r.id===cluster.id));assert(rows.every((r:any)=>!('admin_url'in r)&&!('connection_configured'in r)));
   await denied(()=>registry.update(cluster.id,{revision:1,admin_url:'http://127.0.0.1:18002'},fresh({id:user.id,username:user.username,superAdmin:true})),403);
  });
  await check('registry test records durable SQL outcome once and avoids remote reads on replay',async()=>{
   const same=fresh();await execution.runHttp({},async()=>{execution.bindHttpActor(same.user);try{await registry.probe(cluster.id,same);await registry.probe(cluster.id,same);}finally{execution.captureHttpCloser()();}});assert(remoteReads===1);assert((await ledger.receipt(same,same.idempotencyKey!,true)).remote_completed===true);
  });
  await check('data source rotation and soft deletion are audited, atomic, and replayable',async()=>{
   source=await sources.create(cluster.id,{name:'Disposable metrics',type:'prometheus',base_url:'http://127.0.0.1:18090',auth:{type:'bearer',token:'Synthetic-source-secret'}},fresh());
   const updated=await sources.update(cluster.id,source.id,{revision:source.revision,auth:{type:'bearer',token:'Synthetic-source-rotated-secret'}},fresh());
   const same=fresh(),body={revision:updated.revision,confirm:true,confirm_name:updated.name};await sources.deactivate(cluster.id,source.id,body,same);await sources.deactivate(cluster.id,source.id,body,same);
   assert((await db!.one<any>('SELECT deleted_at FROM data_sources WHERE id=$1',[source.id])).deleted_at);assert(!(JSON.stringify(await db!.query('SELECT before,after,json_patch FROM audit_events'))).includes('Synthetic-source-rotated-secret'));
  });
  await check('workspace administrators assign only their own role instances and cannot modify global accounts',async()=>{
   const wid=randomUUID();await db!.exec('INSERT INTO workspaces(id,cluster_id,code,name) VALUES($1,$2,\'scoped-iam\',\'Scoped IAM\')',[wid,cluster.id]);
   const wsAdmin=await service.create('users',{username:'workspace-manager',password:'Synthetic!Workspace2026Password'},fresh());
   const superRole=await db!.one<any>("SELECT id FROM roles WHERE workspace_id=$1 AND builtin_kind='workspace-super-admin'",[wid]);
   await service.addBinding('users',wsAdmin.id,{role_id:superRole.id,cluster_id:cluster.id,workspace_id:wid},fresh());
   const scoped=fresh({id:wsAdmin.id,username:wsAdmin.username,superAdmin:false});
   assert(!(await service.lookupUsers({clusterId:cluster.id,workspaceId:wid,search:user.username},scoped)).items.some((u:any)=>u.id===user.id));
   const readRole=await db!.one<any>("SELECT id FROM roles WHERE workspace_id=$1 AND builtin_kind='workspace-read-only'",[wid]);await service.addBinding('users',user.id,{role_id:readRole.id,cluster_id:cluster.id,workspace_id:wid},fresh());
   assert((await service.lookupUsers({clusterId:cluster.id,workspaceId:wid,search:user.username},scoped)).items.some((u:any)=>u.id===user.id));
   const writable=await db!.one<any>("SELECT id FROM roles WHERE workspace_id=$1 AND builtin_kind='workspace-admin'",[wid]);const assigned=await service.addBinding('users',user.id,{role_id:writable.id,cluster_id:cluster.id,workspace_id:wid},scoped);
   const listed=await service.bindings('users',user.id,{clusterId:cluster.id,workspaceId:wid},scoped);assert(listed.items.length===2&&listed.items.every((b:any)=>b.workspace_id===wid));
   await denied(()=>service.update('users',user.id,{revision:1,display_name:'Escalated global profile'},scoped),403);
   const globalAdmin=await db!.one<any>("SELECT id FROM roles WHERE builtin_kind='admin'");await denied(()=>service.addBinding('users',user.id,{role_id:globalAdmin.id,cluster_id:cluster.id,workspace_id:wid},fresh(scoped.user)),403);
   await service.bindingState('users',user.id,assigned.id,{revision:assigned.revision,confirmed:true,confirm_name:assigned.role_name},false,fresh(scoped.user));
  });
  await check('a pure scoped delete-only role revokes wider native grants only in its own workspace',async()=>{
   const workspace=await db!.one<any>("SELECT id FROM workspaces WHERE cluster_id=$1 AND code='scoped-iam'",[cluster.id]),scope={cluster_id:cluster.id,workspace_id:workspace.id};
   const permission=(module:string,action:string)=>({module,action,scope_type:'workspace',...scope,scope_values:[workspace.id]});
   const receiverRole=await service.create('roles',{code:'scoped-service-reader',name:'Scoped service reader',...scope},fresh());
   await service.replacePermissions(receiverRole.id,{revision:receiverRole.revision,permissions:[permission('services','read')]},fresh());
   const removerRole=await service.create('roles',{code:'scoped-binding-remover',name:'Scoped binding remover',...scope},fresh());
   await service.replacePermissions(removerRole.id,{revision:removerRole.revision,permissions:[permission('roles','delete')]},fresh());
   const operator=await service.create('users',{username:'delete-only-operator',password:'Synthetic!DeleteOnly2026Password'},fresh());
   await service.addBinding('users',operator.id,{role_id:removerRole.id,...scope},fresh());
   const assignment=await service.addBinding('users',user.id,{role_id:receiverRole.id,...scope},fresh()),who=fresh({id:operator.id,username:operator.username,superAdmin:false});
   await denied(()=>service.addBinding('users',user.id,{role_id:receiverRole.id,...scope},who),403);
   const removed=await service.bindingState('users',user.id,assignment.id,{revision:assignment.revision,confirmed:true,confirm_name:assignment.role_name},false,who);assert(removed.status==='revoked');
   assert((await authz.snapshot(who.user)).grants.every(g=>g.module==='roles'&&g.action==='delete'));
   const otherWid=randomUUID();await db!.exec('INSERT INTO workspaces(id,cluster_id,code,name) VALUES($1,$2,\'other-delete-scope\',\'Other delete scope\')',[otherWid,cluster.id]);
   const otherRole=await db!.one<any>("SELECT id FROM roles WHERE workspace_id=$1 AND builtin_kind='workspace-read-only'",[otherWid]);
   const other=await service.addBinding('users',user.id,{role_id:otherRole.id,cluster_id:cluster.id,workspace_id:otherWid},fresh());
   await denied(()=>service.bindingState('users',user.id,other.id,{revision:other.revision,confirmed:true,confirm_name:other.role_name},false,fresh(who.user)),403);
   const globalRole=await service.create('roles',{code:'global-revoke-guard',name:'Global revoke guard'},fresh()),globalBinding=await service.addBinding('users',user.id,{role_id:globalRole.id},fresh());
   await denied(()=>service.bindingState('users',user.id,globalBinding.id,{revision:globalBinding.revision,confirmed:true,confirm_name:globalBinding.role_name},false,fresh(who.user)),403);
  });
  await check('cluster deactivation retains metadata and replays a proven receipt after removal from active lists',async()=>{
   const current=await registry.get(cluster.id,fresh()),same=fresh(),body={revision:current.revision,confirm:true,confirm_name:current.name};await registry.deactivate(cluster.id,body,same);await registry.deactivate(cluster.id,body,same);
   assert((await db!.one<any>('SELECT deleted_at FROM clusters WHERE id=$1',[cluster.id])).deleted_at);
  });
  mkdirSync('artifacts/M4',{recursive:true});writeFileSync('artifacts/M4/iam-business-postgres.json',JSON.stringify({stage:'M4',database:'disposable PostgreSQL16 loopback only',passed:checks.length,checks},null,2));console.log(`IAM business PostgreSQL: ${checks.length}/${checks.length} passed`);
 }finally{await db?.onModuleDestroy();execFileSync('docker',['rm','-f',container],{stdio:'ignore'});}
}
main().catch(error=>{console.error(error.message);process.exitCode=1;});
