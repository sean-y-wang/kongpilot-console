import { BadRequestException,ConflictException,ForbiddenException,Injectable,NotFoundException } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import { AsyncLocalStorage } from 'node:async_hooks';
import { DbService } from '../../infrastructure/db.service';
import { SecretService } from '../../infrastructure/secret.service';
import { decodeTag } from '../../infrastructure/kong/tags';
import { AuditService } from '../audit/audit.service';
import { AuthService } from '../auth/auth.service';
import { AuthorizationService } from '../authorization/authorization.service';
import { PERMISSION_ACTIONS,PERMISSION_MODULES,type EffectiveGrant } from '../../common/authorization.types';
import { IamMutationsService } from './iam-mutations.service';
import { iamScope,normalizePermission,resolveAssignedGrants,SCOPE_TYPES } from './iam-policy';
import { iamBody,iamConfirm,iamId,iamRevision,iamText,pagination,publicUser,retentionDays,USER_COLUMNS,type IamActor,type IamPageQuery,type IamScope } from './iam.types';
import {immutableJson} from '../../infrastructure/kong/immutable-json';
import {normalizeIamChangeRequest} from './iam-workflow-plan';
import type {IamChangeRequest,IamCapturedChange,IamChangeBeforeGraph,IamWorkflowApiDelegate,IamApprovedChangePolicy} from './iam-workflow.types';

interface FixedIamChange {active:boolean;mode:'capture'|'approved';transaction:DbService;request:Readonly<IamChangeRequest>;handle?:object;capture?:Readonly<IamCapturedChange>;
 mutation?:IamCapturedChange['mutation'];scopes:IamScope[];grants:EffectiveGrant[];ids:string[];idIndex:number;executed:boolean;}

type Resource='users'|'teams'|'roles';
const GLOBAL:IamScope={cluster_id:null,workspace_id:null};
const changed=()=>new ConflictException({code:'IAM_CHANGED',message:'身份配置已变更，请刷新后重试'});
const protectedRole=()=>new ForbiddenException({code:'PROTECTED_ROLE',message:'内置角色不能修改或删除；超级管理员角色不能克隆或授予团队'});

@Injectable()
export class IamService {
 private readonly fixedChanges=new AsyncLocalStorage<FixedIamChange>();
 private workflowApi?:Readonly<IamWorkflowApiDelegate>;
 private approvedChangePolicy?:Readonly<IamApprovedChangePolicy>;
 constructor(private readonly storageDb:DbService,private readonly secrets:SecretService,private readonly audit:AuditService,
  private readonly authz:AuthorizationService,private readonly auth:AuthService,private readonly mutations:IamMutationsService){}
 private get db():DbService{const fixed=this.fixedChanges.getStore();if(fixed&&!fixed.active)throw new ForbiddenException({code:'IAM_WORKFLOW_FIXED_OPERATION_REQUIRED'});return fixed?.transaction??this.storageDb;}
 private scope(row:any):IamScope{return {cluster_id:row.cluster_id??null,workspace_id:row.workspace_id??null};}
 private async authorize(actor:IamActor,module:string,action:string,scope:IamScope=GLOBAL):Promise<void>{
  const fixed=this.fixedChanges.getStore();if(fixed){const snapshot=await this.authz.snapshot(actor.user,fixed.transaction);
   if(!snapshot.user.superAdmin&&!snapshot.grants.some(g=>g.module===module&&g.action===action&&(scope.cluster_id===null?g.scope_type==='global'&&g.cluster_id===null&&g.workspace_id===null
    :(!g.cluster_id||g.cluster_id===scope.cluster_id)&&(!g.workspace_id||g.workspace_id===scope.workspace_id)&&(g.scope_type==='global'||g.scope_type==='workspace'&&!!scope.workspace_id&&g.scope_values.includes(scope.workspace_id)))))throw new ForbiddenException({code:'IAM_SCOPE_DENIED'});
   if(scope.cluster_id)await this.ensureScope(fixed.transaction,scope);return;}
  if(!scope.cluster_id){await this.authz.assertConsole(actor.user,module,action);return;}
  await this.authz.assertCluster(actor.user,scope.cluster_id,module,action,scope.workspace_id??undefined);
  const snapshot=await this.authz.snapshot(actor.user);
  if(snapshot.user.superAdmin)return;
  if(!snapshot.grants.some(g=>g.module===module&&g.action===action&&(!g.cluster_id||g.cluster_id===scope.cluster_id)
   &&(!g.workspace_id||g.workspace_id===scope.workspace_id)&&(g.scope_type==='global'||g.scope_type==='workspace'&&!!scope.workspace_id&&g.scope_values.includes(scope.workspace_id))))
   throw new ForbiddenException({code:'IAM_SCOPE_DENIED',message:'身份管理权限须覆盖此完整集群和工作区范围'});
 }
 private async row(type:Resource,id:string,tx=this.db,lock=false):Promise<any>{
  iamId(id);const row=await tx.one<any>(`SELECT ${type==='users'?USER_COLUMNS:'*'} FROM ${type} WHERE id=$1${lock?' FOR UPDATE':''}`,[id]);
  if(!row)throw new NotFoundException({code:'IAM_RESOURCE_NOT_FOUND',message:'身份资源不存在'});return row;
 }
 private active(row:any):void{if(row.status!=='active')throw new ConflictException({code:'IAM_RESOURCE_INACTIVE',message:'身份资源须为启用状态'});}
 private editableRole(row:any):void{if(row.protected||row.builtin_kind)throw protectedRole();}
 private async protectUser(actor:IamActor,row:any):Promise<void>{if(row.super_admin&&!await this.authz.isPlatformAdmin(actor.user))throw new ForbiddenException({code:'PROTECTED_SUPER_ADMIN',message:'只有平台超级管理员可以管理超级管理员账号'});}
 private async lastAdmin(tx:DbService,row:any):Promise<void>{
  if(row.super_admin&&row.status==='active'){
   const count=await tx.one<any>("SELECT count(*)::int AS count FROM users WHERE super_admin AND status='active' AND deleted_at IS NULL");
   if(Number(count?.count)<=1)throw new ConflictException({code:'LAST_SUPER_ADMIN',message:'必须保留至少一个启用的超级管理员'});
  }
 }
 private async auditChange(tx:DbService,actor:IamActor,module:string,action:string,id:string,scope:IamScope,before:any,after:any):Promise<void>{
  await this.audit.append({actorId:actor.user.id,clusterId:scope.cluster_id,workspaceId:scope.workspace_id,entityType:module,entityId:id,
   action:`iam.${action}`,before,after,requestId:actor.requestId,ip:actor.ip,result:'success',scopeHints:{quality:'verified',module,subject:{type:module,id},beforeExists:before!=null,afterExists:after!=null,beforeWorkspaceId:scope.workspace_id,afterWorkspaceId:scope.workspace_id,beforeTags:[],afterTags:[]}},tx);
 }
 private async execute<T>(actor:IamActor,module:string,action:string,targetId:string|undefined,scope:IamScope,payload:unknown,fn:(tx:DbService)=>Promise<T>):Promise<T>{
  const fixed=this.fixedChanges.getStore();if(fixed){
   if(!fixed.active||fixed.executed)throw new ForbiddenException({code:'IAM_WORKFLOW_FIXED_OPERATION_REQUIRED'});fixed.executed=true;
   const mutation=immutableJson({module,action,...(targetId?{targetId}:{}),...scope,payload});
   if(fixed.mode==='capture'){fixed.mutation=mutation;fixed.scopes.push(scope);return Promise.resolve({prepared:true} as T);}
   if(!fixed.handle||!fixed.capture||this.secrets.fingerprint(mutation)!==this.secrets.fingerprint(fixed.capture.mutation))throw new ForbiddenException({code:'IAM_WORKFLOW_MUTATION_MISMATCH'});
   return this.mutations.executeApprovedFixed({...mutation,actor},fixed.handle,fixed.transaction,fn);
  }
  const mutation={actor,module,action,targetId,...scope,payload};if(this.workflowApi)await this.workflowApi.assertDirectMutation(mutation);
  return this.mutations.execute(mutation,async tx=>{if(this.workflowApi)await this.workflowApi.assertDirectMutation(mutation,tx);return fn(tx);});
 }
 installWorkflowApi(delegate:IamWorkflowApiDelegate):void{
  const names=['prepare','submit','receipt','receiptByKey','assertDirectMutation']as const;if(this.workflowApi||!delegate||names.some(k=>typeof delegate[k]!=='function'))throw new Error('IAM workflow API requires one fixed provider');
  this.workflowApi=Object.freeze(Object.fromEntries(names.map(k=>[k,delegate[k].bind(delegate)]))) as unknown as Readonly<IamWorkflowApiDelegate>;
 }
 installApprovedChangePolicy(policy:IamApprovedChangePolicy):void{
  if(this.approvedChangePolicy||!policy||typeof policy.verifyCapture!=='function'||Object.keys(policy).some(k=>k!=='verifyCapture'))throw new Error('IAM changes require one fixed original capture verifier');
  this.approvedChangePolicy=Object.freeze({verifyCapture:policy.verifyCapture.bind(policy)});
 }
 prepareChange(request:unknown,actor:IamActor){if(!this.workflowApi)throw new ConflictException({code:'IAM_WORKFLOW_UNAVAILABLE'});return this.workflowApi.prepare(request,actor);}
 submitChange(id:string,request:unknown,actor:IamActor){if(!this.workflowApi)throw new ConflictException({code:'IAM_WORKFLOW_UNAVAILABLE'});return this.workflowApi.submit(iamId(id),request,actor);}
 changeReceipt(id:string,actor:IamActor){if(!this.workflowApi)throw new ConflictException({code:'IAM_WORKFLOW_UNAVAILABLE'});return this.workflowApi.receipt(iamId(id),actor);}
 changeReceiptByKey(key:string,actor:IamActor){if(!this.workflowApi)throw new ConflictException({code:'IAM_WORKFLOW_UNAVAILABLE'});return this.workflowApi.receiptByKey(key,actor);}
 private allocateId():string{const fixed=this.fixedChanges.getStore();if(!fixed)return randomUUID();
  if(!fixed.active||fixed.mode!=='approved'||fixed.idIndex>=fixed.ids.length)throw new ForbiddenException({code:'IAM_WORKFLOW_ALLOCATION_MISMATCH'});return fixed.ids[fixed.idIndex++];}
 private invokeChange(request:Readonly<IamChangeRequest>,actor:IamActor):Promise<any>{const {resource,operation,resourceId:id,relatedId,input}=request;
  if(operation==='create')return this.create(resource,input,actor);if(operation==='update')return this.update(resource,id!,input,actor);
  if(['status','archive','restore'].includes(operation))return this.state(resource,id!,input,operation==='archive'?'delete':operation as 'status'|'restore',actor);
  if(operation==='permissions')return this.replacePermissions(id!,input,actor);if(operation==='clone')return this.clone(id!,input,actor);
  if(operation==='binding.grant')return this.addBinding(resource as 'users'|'teams',id!,input,actor);
  if(operation==='binding.revoke'||operation==='binding.restore')return this.bindingState(resource as 'users'|'teams',id!,relatedId!,input,operation==='binding.restore',actor);
  if(operation==='member.add')return this.addMember(id!,input,actor);
  return this.memberState(id!,relatedId!,input,operation==='member.restore',actor);
 }
 async changeBeforeGraph(raw:Readonly<IamChangeRequest>,tx:DbService=this.db):Promise<Readonly<IamChangeBeforeGraph>>{
  const request=normalizeIamChangeRequest(raw),resource=request.resourceId?await this.row(request.resource,request.resourceId,tx):null,related:any[]=[];
  let permissions:any[]=[],bindings:any[]=[],members:any[]=[];
  const bounded=async(sql:string,p:any[])=>{const rows=await tx.query<any>(`${sql} LIMIT 1001`,p);if(rows.length>1000)throw new ConflictException({code:'IAM_WORKFLOW_GRAPH_BUDGET'});return rows;};
  if(request.resource==='roles'&&resource){permissions=await this.permissionRows(resource.id,tx,false);
   bindings=await bounded(`SELECT 'user' AS subject_type,b.* FROM user_role_bindings b WHERE role_id=$1 UNION ALL SELECT 'team' AS subject_type,b.* FROM team_role_bindings b WHERE role_id=$1 ORDER BY id`,[resource.id]);}
  if(request.resource==='teams'&&resource){bindings=await bounded('SELECT * FROM team_role_bindings WHERE team_id=$1 ORDER BY id',[resource.id]);members=await bounded('SELECT * FROM team_members WHERE team_id=$1 ORDER BY user_id',[resource.id]);}
  if(request.resource==='users'&&resource)bindings=await bounded('SELECT * FROM user_role_bindings WHERE user_id=$1 ORDER BY id',[resource.id]);
  const roleIds=new Set<string>(bindings.map(b=>b.role_id));if(request.operation==='binding.grant')roleIds.add(iamId(request.input.role_id));
  if(roleIds.size>100)throw new ConflictException({code:'IAM_WORKFLOW_GRAPH_BUDGET'});
  for(const roleId of [...roleIds].sort()){const role=await this.row('roles',roleId,tx);related.push({type:'roles',row:role,permissions:await this.permissionRows(roleId,tx,false)});}
  if(request.operation==='member.add'||request.operation==='member.revoke'||request.operation==='member.restore')related.push({type:'users',row:await this.row('users',iamId(request.operation==='member.add'?request.input.user_id:request.relatedId),tx)});
  const graph={resource,permissions,bindings,members,related};if(Buffer.byteLength(JSON.stringify(graph))>1024*1024)throw new ConflictException({code:'IAM_WORKFLOW_GRAPH_BUDGET'});return immutableJson(graph);
 }
 async captureChange(raw:unknown,actor:IamActor,tx:DbService=this.db):Promise<Readonly<IamCapturedChange>>{
  if(this.fixedChanges.getStore())throw new ForbiddenException({code:'IAM_WORKFLOW_FIXED_REENTRY'});const request=normalizeIamChangeRequest(raw),before=await this.changeBeforeGraph(request,tx);
  const state:FixedIamChange={active:true,mode:'capture',transaction:tx,request,scopes:[],grants:[],ids:[],idIndex:0,executed:false};
  try{return await this.fixedChanges.run(state,async()=>{
   await this.invokeChange(request,actor);if(!state.mutation||!state.executed)throw new ConflictException({code:'IAM_WORKFLOW_CAPTURE_INCOMPLETE'});
   // A single binding or clone does not mutate every other binding of the
   // target user or the source role. Freeze that full dependency graph while
   // deriving approvals only from the actual operation and delegated grants.
   const teamGrants=request.resource==='teams'?before.bindings.flatMap((b:any)=>{const r:any=before.related.find((v:any)=>v.type==='roles'&&v.row?.id===b.role_id);
    return r?resolveAssignedGrants(r.permissions,this.scope(r.row),this.scope(b)):[];}):[];
   const dependencyScopes=request.operation.startsWith('binding.')||request.operation==='clone'?[]:request.resource==='teams'
    ?[...before.bindings as IamScope[],...teamGrants]
    :[...before.permissions as IamScope[],...before.bindings as IamScope[],...before.related.flatMap((v:any)=>[v.row,...(v.permissions??[])])];
   const scopes=[...state.scopes,...dependencyScopes]
    .map(s=>({cluster_id:s.cluster_id??null,workspace_id:s.workspace_id??null}));
   const affectedScopes=[...new Map(scopes.map(s=>[`${s.cluster_id}:${s.workspace_id}`,s])).values()];
   const grants=immutableJson(state.grants),count=(request.operation==='create'||request.operation==='clone'?1:request.operation==='binding.grant'?1:0)
    +(request.operation==='permissions'||request.operation==='clone'?grants.length:0);
   return immutableJson({request,mutation:state.mutation,before,delegatedGrants:grants,affectedScopes,allocatedIds:Array.from({length:count},()=>randomUUID())});
  });}finally{state.active=false;}
 }
 async applyApprovedChange(originalHandle:object,capture:Readonly<IamCapturedChange>,actor:IamActor,tx:DbService):Promise<any>{
  if(this.fixedChanges.getStore()||!originalHandle||!capture)throw new ForbiddenException({code:'IAM_WORKFLOW_FIXED_REENTRY'});
  if(!this.approvedChangePolicy)throw new ForbiddenException({code:'IAM_APPROVED_METADATA_UNAVAILABLE'});
  capture=immutableJson(capture);
  await this.approvedChangePolicy.verifyCapture(originalHandle,capture,actor,tx);
  const request=normalizeIamChangeRequest(capture.request),state:FixedIamChange={active:true,mode:'approved',transaction:tx,request,handle:originalHandle,capture,
   scopes:[],grants:[],ids:[...capture.allocatedIds],idIndex:0,executed:false};
  try{return await this.fixedChanges.run(state,async()=>{const result=await this.invokeChange(request,actor);
   if(!state.executed||state.idIndex!==state.ids.length)throw new ForbiddenException({code:'IAM_WORKFLOW_ALLOCATION_MISMATCH'});return result;});}finally{state.active=false;}
 }
 /** Same-transaction SQL readback; a handler result alone proves no write. */
 async readAppliedChange(capture:Readonly<IamCapturedChange>,tx:DbService):Promise<any>{
  const request=normalizeIamChangeRequest(capture.request),id=request.operation==='create'||request.operation==='clone'?capture.allocatedIds[0]:request.resourceId!;
  if(request.operation==='permissions'){const role=await this.row('roles',id,tx),items=await this.permissionRows(id,tx,true);
   this.assertAppliedPermissions(capture,items,this.scope(role),0);return{items,revision:role.revision};}
  if(request.operation.startsWith('binding.')){const table=request.resource==='users'?'user_role_bindings':'team_role_bindings',column=request.resource==='users'?'user_id':'team_id',bindingId=request.operation==='binding.grant'?capture.allocatedIds[0]:request.relatedId;
   const row=await tx.one<any>(`SELECT b.*,r.name AS role_name FROM ${table} b JOIN roles r ON r.id=b.role_id WHERE b.id=$1 AND b.${column}=$2`,[bindingId,id]);if(!row)throw changed();return row;}
  if(request.operation.startsWith('member.')){const memberId=request.operation==='member.add'?request.input.user_id:request.relatedId;
   const row=await tx.one<any>('SELECT m.*,u.username,u.display_name FROM team_members m JOIN users u ON u.id=m.user_id WHERE m.team_id=$1 AND m.user_id=$2',[id,memberId]);if(!row)throw changed();return row;}
  const row=await this.row(request.resource,iamId(id),tx);
  if(request.operation==='clone')this.assertAppliedPermissions(capture,await this.permissionRows(id,tx,true),this.scope(row),1);
  return request.resource==='users'?publicUser(row):row;
 }
 private assertAppliedPermissions(capture:Readonly<IamCapturedChange>,items:any[],owner:IamScope,idOffset:number):void{
  const keys=['module','action','scope_type','cluster_id','workspace_id','scope_values'],project=(g:any)=>Object.fromEntries(keys.map(k=>[k,g[k]]));
  // Public permission readback uses logical tags. Normalize those real SQL
  // rows once before comparing them with the sealed physical grant tuples.
  const expected=capture.delegatedGrants.map(project).map(g=>this.secrets.fingerprint(g)).sort(),actual=items.map(g=>normalizePermission(project(g),owner)).map(g=>this.secrets.fingerprint(project(g))).sort();
  if(this.secrets.fingerprint(actual)!==this.secrets.fingerprint(expected)||this.secrets.fingerprint(items.map(g=>g.id).sort())!==this.secrets.fingerprint(capture.allocatedIds.slice(idOffset).sort()))throw new ConflictException({code:'IAM_WORKFLOW_PERMISSION_READBACK_MISMATCH'});
 }
 private queryScope(query:IamPageQuery):IamScope{return iamScope({cluster_id:query.clusterId,workspace_id:query.workspaceId});}
 private async page(actor:IamActor,module:string,query:IamPageQuery,scope:IamScope,sql:string,params:any[],where:string[],searchColumns:string[],extraBinding:any={},created='created_at',id='id'):Promise<any>{
  const version=await this.authz.permissionVersion(actor.user),search=iamText(query.search,'搜索',128)??'';
  const pager=pagination(query,this.secrets.fingerprint({actor:actor.user.id,version,module,...scope,search,status:query.status??'active',size:query.size??20,...extraBinding}));
  if(search){params.push(search.toLowerCase());where.push(`(${searchColumns.map(col=>`position($${params.length} in lower(${col}))>0`).join(' OR ')})`);}
  if(pager.prior){params.push(pager.prior.created_at,pager.prior.id);where.push(`(${created},${id})<($${params.length-1}::timestamptz,$${params.length}::uuid)`);}
  params.push(pager.size+1);const rows=await this.db.query<any>(`${sql} WHERE ${where.join(' AND ')} ORDER BY ${created} DESC,${id} DESC LIMIT $${params.length}`,params);
  return {items:rows.slice(0,pager.size),nextCursor:rows.length>pager.size?pager.next(rows[pager.size-1]):null,size:pager.size,total:null};
 }
 async list(type:Resource,query:IamPageQuery,actor:IamActor):Promise<any>{
  const scope=type==='users'?GLOBAL:this.queryScope(query);await this.authorize(actor,type,'read',scope);
  if(type==='users'&&(query.clusterId||query.workspaceId))throw new BadRequestException('用户目录是全局资源');
  const status=query.status??'active';if(!['active','disabled','deleted'].includes(status))throw new BadRequestException('身份状态无效');
  const params:any[]=[status],where=['status=$1'];
  if(type!=='users'){params.push(scope.cluster_id,scope.workspace_id);where.push('cluster_id IS NOT DISTINCT FROM $2::uuid','workspace_id IS NOT DISTINCT FROM $3::uuid');}
  const result=await this.page(actor,type,query,scope,`SELECT ${type==='users'?USER_COLUMNS:'*'} FROM ${type}`,params,where,type==='users'?['username','display_name','coalesce(email,\'\')']:['code','name']);
  if(type==='users')result.items=result.items.map(publicUser);return result;
 }
 async get(type:Resource,id:string,actor:IamActor):Promise<any>{const row=await this.row(type,id);await this.authorize(actor,type,'read',this.scope(row));return type==='users'?publicUser(row):row;}
 async lookupUsers(query:IamPageQuery,actor:IamActor):Promise<any>{
  const scope=this.queryScope(query);await this.authorize(actor,scope.cluster_id?'workspaces':'users','read',scope);
  const params:any[]=[],where=["status='active'"];
  if(scope.cluster_id){const snapshot=await this.authz.snapshot(actor.user),directory=snapshot.user.superAdmin||snapshot.grants.some(g=>g.module==='users'&&g.action==='read'&&g.scope_type==='global'&&!g.cluster_id&&!g.workspace_id);
   if(!directory){params.push(scope.cluster_id,scope.workspace_id);where.push(`(EXISTS(SELECT 1 FROM iam_effective_grants g WHERE g.user_id=users.id AND g.cluster_id=$1 AND g.workspace_id IS NOT DISTINCT FROM $2::uuid) OR EXISTS(SELECT 1 FROM team_members m JOIN teams t ON t.id=m.team_id WHERE m.user_id=users.id AND m.status='active' AND t.status='active' AND t.cluster_id=$1 AND t.workspace_id IS NOT DISTINCT FROM $2::uuid))`);}
  }
  return this.page(actor,'users',query,scope,'SELECT id,username,display_name,created_at FROM users',params,where,['username','display_name'],{lookup:true});
 }
 catalog(){return {modules:PERMISSION_MODULES,actions:PERMISSION_ACTIONS,scope_types:SCOPE_TYPES};}
 async create(type:Resource,input:unknown,actor:IamActor):Promise<any>{
  const body=iamBody(input,type==='users'?['username','password','display_name','email']:['code','name','description','cluster_id','workspace_id']);
  const scope=type==='users'?GLOBAL:iamScope(body);await this.authorize(actor,type,'write',scope);
  let payload:any;
  if(type==='users'){
   const username=iamText(body.username,'账号',64,true)!;if(!/^[A-Za-z\d_.@-]{3,64}$/.test(username))throw new BadRequestException('账号格式无效');
   const passwordHash=await this.auth.hashPassword(body.password,{username});
   payload={username,display_name:iamText(body.display_name,'显示名',128)??username,email:this.email(body.email)};
   return this.execute(actor,type,'write',undefined,scope,{...payload,password:body.password},async tx=>{
    if(await tx.one('SELECT id FROM users WHERE lower(username)=lower($1)',[username]))throw new ConflictException({code:'USERNAME_RESERVED',message:'账号已存在或保留在回收区'});
    const row=await tx.one<any>(`INSERT INTO users(id,username,password_hash,display_name,email) VALUES($1,$2,$3,$4,$5) RETURNING ${USER_COLUMNS}`,[this.allocateId(),username,passwordHash,payload.display_name,payload.email]);
    const result=publicUser(row);await this.auditChange(tx,actor,type,'create',row.id,scope,null,result);return result;
   });
  }
  payload=this.resourceInput(body,true);
  return this.execute(actor,type,'write',undefined,scope,{...payload,...scope},async tx=>{
   await this.ensureScope(tx,scope);
   if(await tx.one(`SELECT id FROM ${type} WHERE code=$1 AND cluster_id IS NOT DISTINCT FROM $2::uuid AND workspace_id IS NOT DISTINCT FROM $3::uuid`,[payload.code,scope.cluster_id,scope.workspace_id]))throw new ConflictException({code:'IAM_CODE_RESERVED',message:'编码已存在或保留在回收区'});
   const row=await tx.one<any>(`INSERT INTO ${type}(id,code,name,description,cluster_id,workspace_id) VALUES($1,$2,$3,$4,$5,$6) RETURNING *`,[this.allocateId(),payload.code,payload.name,payload.description??'',scope.cluster_id,scope.workspace_id]);
   await this.auditChange(tx,actor,type,'create',row.id,scope,null,row);return row;
  });
 }
 private email(value:any):string|null{if(value==null||value==='')return null;const email=iamText(value,'邮箱',254,true)!;if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))throw new BadRequestException('邮箱格式无效');return email;}
 private resourceInput(body:any,create=false):any{
  const code=create?iamText(body.code,'编码',64,true):undefined;if(code&&!/^[a-z][a-z0-9_-]{0,63}$/.test(code))throw new BadRequestException('编码格式无效');
  return {code,name:iamText(body.name,'名称',128,create),description:iamText(body.description,'描述',8192)};
 }
 private async ensureScope(tx:DbService,scope:IamScope):Promise<void>{
  if(scope.cluster_id&&!await tx.one('SELECT id FROM clusters WHERE id=$1 AND deleted_at IS NULL',[scope.cluster_id]))throw new NotFoundException('集群不存在');
  if(scope.workspace_id&&!await tx.one("SELECT id FROM workspaces WHERE cluster_id=$1 AND id=$2 AND status<>'deleted'",[scope.cluster_id,scope.workspace_id]))throw new ForbiddenException({code:'WORKSPACE_ACCESS_DENIED',message:'工作区不存在或不可访问'});
 }
 async update(type:Resource,id:string,input:unknown,actor:IamActor):Promise<any>{
  const body=iamBody(input,type==='users'?['revision','display_name','email']:['revision','name','description']);iamRevision(body.revision);
  const old=await this.row(type,id),scope=this.scope(old);await this.authorize(actor,type,'write',scope);if(type==='roles')this.editableRole(old);if(type==='users')await this.protectUser(actor,old);
  const patch=type==='users'?{display_name:iamText(body.display_name,'显示名',128),email:body.email===undefined?undefined:this.email(body.email)}:this.resourceInput(body);
  const fields=Object.keys(patch).filter(key=>patch[key]!==undefined&&key!=='code');if(!fields.length)throw new BadRequestException('请至少修改一个字段');
  return this.execute(actor,type,'write',id,scope,body,async tx=>{
   const before=await this.row(type,id,tx,true);if(before.revision!==body.revision)throw changed();if(before.status==='deleted')throw new ConflictException('请先恢复资源');if(type==='roles')this.editableRole(before);if(type==='users')await this.protectUser(actor,before);
   const params=fields.map(key=>patch[key]);params.push(id,body.revision);
   const after=await tx.one<any>(`UPDATE ${type} SET ${fields.map((key,i)=>`${key}=$${i+1}`).join(',')},revision=revision+1,updated_at=now() WHERE id=$${fields.length+1} AND revision=$${fields.length+2} RETURNING ${type==='users'?USER_COLUMNS:'*'}`,params);
   if(!after)throw changed();await this.auditChange(tx,actor,type,'update',id,scope,before,after);return type==='users'?publicUser(after):after;
  });
 }
 async state(type:Resource,id:string,input:unknown,mode:'status'|'delete'|'restore',actor:IamActor):Promise<any>{
  const body=iamBody(input,mode==='status'?['revision','confirmed','confirm_name','status']:['revision','confirmed','confirm_name']);
  const old=await this.row(type,id),scope=this.scope(old),action=mode==='delete'?'delete':'write';iamConfirm(body,type==='users'?old.username:old.name);
  await this.authorize(actor,type,action,scope);if(type==='roles')this.editableRole(old);if(type==='users')await this.protectUser(actor,old);
  if(mode==='status'&&!['active','disabled'].includes(body.status))throw new BadRequestException('状态无效');
  return this.execute(actor,type,action,id,scope,{...body,mode},async tx=>{
   const before=await this.row(type,id,tx,true);if(before.revision!==body.revision)throw changed();iamConfirm(body,type==='users'?before.username:before.name);
   if(type==='roles')this.editableRole(before);if(type==='users')await this.protectUser(actor,before);
   if(mode==='restore'&&(before.status!=='deleted'||new Date(before.retention_until).getTime()<Date.now()))throw new ConflictException({code:'IAM_RESTORE_UNAVAILABLE',message:'资源未删除或已超过恢复保留期'});
   if(mode!=='restore'&&before.status==='deleted')throw new ConflictException('资源已进入回收区');
   const status=mode==='delete'?'deleted':mode==='restore'?'active':body.status;
   if(type==='users'&&status!=='active')await this.lastAdmin(tx,before);
   if(status==='active')await this.validateReactivation(type,id,actor,tx);
   const after=await tx.one<any>(`UPDATE ${type} SET status=$2,revision=revision+1,updated_at=now(),deleted_at=CASE WHEN $2='deleted' THEN now() ELSE NULL END,retention_until=CASE WHEN $2='deleted' THEN now()+($3::int*interval '1 day') ELSE NULL END ${type==='users'?',permissions_epoch=permissions_epoch+1,credential_epoch=credential_epoch+1':''} WHERE id=$1 AND revision=$4 RETURNING ${type==='users'?USER_COLUMNS:'*'}`,[id,status,retentionDays(),body.revision]);
   if(!after)throw changed();if(type==='users'&&status!=='active')await this.auth.revokeAllSessions(id,tx,{actorId:actor.user.id,reason:`iam.${mode}`,requestId:actor.requestId,ip:actor.ip});
   await this.auditChange(tx,actor,type,mode,id,scope,before,after);return type==='users'?publicUser(after):after;
  });
 }
 private async validateReactivation(type:Resource,id:string,actor:IamActor,tx:DbService):Promise<void>{
  let bindings:any[];
  if(type==='roles')bindings=await tx.query('SELECT * FROM user_role_bindings WHERE role_id=$1 AND status=\'active\' UNION ALL SELECT id,team_id AS user_id,role_id,cluster_id,workspace_id,status,revision,expires_at,granted_by,revoked_at,retention_until,created_at,updated_at FROM team_role_bindings WHERE role_id=$1 AND status=\'active\'',[id]);
  else if(type==='users')bindings=await tx.query(`SELECT b.* FROM user_role_bindings b WHERE b.user_id=$1 AND b.status='active' UNION ALL SELECT b.id,$1::uuid AS user_id,b.role_id,b.cluster_id,b.workspace_id,b.status,b.revision,b.expires_at,b.granted_by,b.revoked_at,b.retention_until,b.created_at,b.updated_at FROM team_role_bindings b JOIN team_members m ON m.team_id=b.team_id AND m.status='active' JOIN teams t ON t.id=b.team_id AND t.status='active' WHERE m.user_id=$1 AND b.status='active'`,[id]);
  else bindings=await tx.query("SELECT * FROM team_role_bindings WHERE team_id=$1 AND status='active'",[id]);
  if(bindings.length>1000)throw new ConflictException({code:'IAM_GRANT_BUDGET',message:'关联授权超过安全检查预算'});
  for(const binding of bindings){if(binding.expires_at&&new Date(binding.expires_at).getTime()<=Date.now())continue;const role=await this.row('roles',binding.role_id,tx);if(type==='roles'||role.status==='active')await this.checkGrantAssignment(actor,role,this.scope(binding),tx,type==='teams');}
 }
 private async permissionRows(roleId:string,tx=this.db,logical=false):Promise<any[]>{
  const rows=await tx.query<any>(`SELECT p.*,CASE p.scope_type WHEN 'tag_group' THEN coalesce((SELECT jsonb_agg(v.physical_tag ORDER BY v.physical_tag) FROM role_permission_tags v WHERE v.permission_id=p.id AND v.status='active'),'[]'::jsonb) WHEN 'entity' THEN coalesce((SELECT jsonb_agg(jsonb_build_object('entity_type',v.entity_type,'entity_id',v.entity_id) ORDER BY v.entity_type,v.entity_id) FROM role_permission_entities v WHERE v.permission_id=p.id AND v.status='active'),'[]'::jsonb) WHEN 'workspace' THEN jsonb_build_array(p.workspace_id) ELSE '[]'::jsonb END AS scope_values FROM role_permissions p WHERE p.role_id=$1 AND p.status='active' ORDER BY p.module,p.action,p.id LIMIT 513`,[roleId]);
  if(rows.length>512)throw new ConflictException({code:'IAM_GRANT_BUDGET',message:'角色权限定义超过 512 条'});
  if(logical)for(const row of rows)if(row.scope_type==='tag_group')row.scope_values=row.scope_values.map(decodeTag);return rows;
 }
 async permissions(roleId:string,actor:IamActor):Promise<any>{const role=await this.row('roles',roleId);await this.authorize(actor,'roles','read',this.scope(role));await this.authorize(actor,'permissions','read',this.scope(role));return {items:await this.permissionRows(roleId,this.db,true),revision:role.revision};}
 private async validateGrants(grants:EffectiveGrant[],actor:IamActor,tx:DbService):Promise<void>{
  for(const grant of grants)await this.ensureScope(tx,grant);await this.authz.assertDelegatable(actor.user,grants);
  const fixed=this.fixedChanges.getStore();if(fixed?.active&&fixed.mode==='capture')fixed.grants.push(...grants);
  await this.executionScopes(tx,grants);
 }
 private async executionScopes(tx:DbService,scopes:IamScope[]):Promise<void>{
  const fixed=this.fixedChanges.getStore();if(fixed){if(!fixed.active)throw new ForbiddenException({code:'IAM_WORKFLOW_FIXED_OPERATION_REQUIRED'});
   fixed.scopes.push(...scopes);return;}
  const ids=[...new Set(scopes.map(s=>s.cluster_id).filter(Boolean))];if(!ids.length)return;
  const blocked=await tx.one("SELECT id FROM clusters WHERE id=ANY($1::uuid[]) AND execution_mode='approval' AND deleted_at IS NULL LIMIT 1",[ids]);
  if(blocked)throw new ConflictException({code:'APPROVAL_REQUIRED',message:'授权涉及工单模式集群，当前阶段禁止直接变更'});
 }
 private async insertPermissions(tx:DbService,roleId:string,grants:EffectiveGrant[]):Promise<void>{
  for(const grant of grants){const id=this.allocateId();await tx.exec('INSERT INTO role_permissions(id,role_id,module,action,scope_type,cluster_id,workspace_id) VALUES($1,$2,$3,$4,$5,$6,$7)',[id,roleId,grant.module,grant.action,grant.scope_type,grant.cluster_id,grant.workspace_id]);
   if(grant.scope_type==='tag_group')for(const tag of grant.scope_values as string[])await tx.exec('INSERT INTO role_permission_tags(permission_id,logical_tag,physical_tag) VALUES($1,$2,$3)',[id,decodeTag(tag),tag]);
   if(grant.scope_type==='entity')for(const item of grant.scope_values as any[])await tx.exec('INSERT INTO role_permission_entities(permission_id,entity_type,entity_id) VALUES($1,$2,$3)',[id,item.entity_type,item.entity_id]);
  }
 }
 async replacePermissions(roleId:string,input:unknown,actor:IamActor):Promise<any>{
  const body=iamBody(input,['revision','permissions']);iamRevision(body.revision);if(!Array.isArray(body.permissions)||body.permissions.length>512)throw new BadRequestException('权限列表最多 512 条');
  const role=await this.row('roles',roleId),scope=this.scope(role);await this.authorize(actor,'roles','write',scope);await this.authorize(actor,'permissions','write',scope);this.editableRole(role);
  const grants=body.permissions.map((p:any)=>normalizePermission(p,scope));await this.validateGrants(grants,actor,this.db);
  return this.execute(actor,'roles','write',roleId,scope,body,async tx=>{
   const current=await this.row('roles',roleId,tx,true);this.editableRole(current);if(current.revision!==body.revision)throw changed();this.active(current);await this.validateGrants(grants,actor,tx);
   await this.authorize(actor,'permissions','write',scope);
   const before=await this.permissionRows(roleId,tx,true);
   await this.executionScopes(tx,before);
   await tx.exec("UPDATE role_permissions SET status='revoked',revoked_at=now(),retention_until=now()+($2::int*interval '1 day'),revision=revision+1,updated_at=now() WHERE role_id=$1 AND status='active'",[roleId,retentionDays()]);
   await this.insertPermissions(tx,roleId,grants);const updated=await tx.one<any>('UPDATE roles SET revision=revision+1,updated_at=now() WHERE id=$1 AND revision=$2 RETURNING revision',[roleId,body.revision]);if(!updated)throw changed();
   const items=await this.permissionRows(roleId,tx,true);await this.auditChange(tx,actor,'roles','permissions',roleId,scope,before,items);return {items,revision:updated.revision};
  });
 }
 async clone(roleId:string,input:unknown,actor:IamActor):Promise<any>{
  const body=iamBody(input,['code','name','cluster_id','workspace_id']),source=await this.row('roles',roleId),scope=iamScope(body);await this.authorize(actor,'roles','read',this.scope(source));await this.authorize(actor,'roles','write',scope);
  if(source.builtin_kind==='super-admin')throw protectedRole();this.active(source);const payload=this.resourceInput(body,true);
  await this.authorize(actor,'permissions','write',scope);await this.authorize(actor,'permissions','read',this.scope(source));
  const remap=(rows:any[])=>rows.map(row=>normalizePermission({...Object.fromEntries(['module','action','scope_type','scope_values'].map(k=>[k,row[k]])),cluster_id:scope.cluster_id??row.cluster_id,workspace_id:scope.workspace_id??row.workspace_id,scope_type:scope.workspace_id&&row.scope_type==='global'?'workspace':row.scope_type,scope_values:scope.workspace_id&&['global','workspace'].includes(row.scope_type)?[scope.workspace_id]:row.scope_values},scope));
  await this.validateGrants(remap(await this.permissionRows(roleId,this.db,true)),actor,this.db);
  return this.execute(actor,'roles','write',undefined,scope,{...body,source:roleId},async tx=>{
   const locked=await this.row('roles',roleId,tx,true);this.active(locked);if(locked.revision!==source.revision)throw changed();const grants=remap(await this.permissionRows(roleId,tx,true));await this.validateGrants(grants,actor,tx);
   await this.authorize(actor,'permissions','write',scope);await this.authorize(actor,'permissions','read',this.scope(source));
   if(await tx.one('SELECT id FROM roles WHERE code=$1 AND cluster_id IS NOT DISTINCT FROM $2::uuid AND workspace_id IS NOT DISTINCT FROM $3::uuid',[payload.code,scope.cluster_id,scope.workspace_id]))throw new ConflictException('角色编码已保留');
   const role=await tx.one<any>('INSERT INTO roles(id,code,name,description,cluster_id,workspace_id) VALUES($1,$2,$3,$4,$5,$6) RETURNING *',[this.allocateId(),payload.code,payload.name,'',scope.cluster_id,scope.workspace_id]);await this.insertPermissions(tx,role.id,grants);await this.auditChange(tx,actor,'roles','clone',role.id,scope,null,{...role,permissions:grants});return role;
  });
 }
 private async checkGrantAssignment(actor:IamActor,role:any,scope:IamScope,tx:DbService,team=false):Promise<void>{
  await this.executionScopes(tx,[scope]);
  if(role.builtin_kind==='super-admin'){
   if(team||scope.cluster_id||scope.workspace_id||!await this.authz.isPlatformAdmin(actor.user))throw protectedRole();return;
  }
  // A workspace administrator cannot grant a platform-owned role, even with a narrowed binding.
  await this.authorize(actor,'roles','write',this.scope(role));
  if(role.workspace_id&&(role.cluster_id!==scope.cluster_id||role.workspace_id!==scope.workspace_id))throw new BadRequestException({code:'ROLE_SCOPE_MISMATCH',message:'工作区角色仅能绑定所属工作区'});
  await this.validateGrants(resolveAssignedGrants(await this.permissionRows(role.id,tx),this.scope(role),scope),actor,tx);
 }
 private async authorizeUserBinding(actor:IamActor,scope:IamScope,action:string):Promise<void>{
  if(scope.cluster_id)await this.authorize(actor,'roles',action,scope);
  else {await this.authorize(actor,'users',action==='read'?'read':'write');await this.authorize(actor,'roles',action);}
 }
 async bindings(subject:'users'|'teams',subjectId:string,query:IamPageQuery,actor:IamActor):Promise<any>{
  const row=await this.row(subject,subjectId),scope=subject==='users'?this.queryScope(query):this.scope(row);if(subject==='users')await this.authorizeUserBinding(actor,scope,'read');else await this.authorize(actor,subject,'read',scope);
  const table=subject==='users'?'user_role_bindings':'team_role_bindings',column=subject==='users'?'user_id':'team_id',status=query.status??'active';if(!['active','revoked'].includes(status))throw new BadRequestException('授权状态无效');
  // Global user management is privileged; scoped team management is bounded by its owner.
  const params:any[]=[subjectId,status],where=[`b.${column}=$1`,'b.status=$2'];if(subject==='users'){params.push(scope.cluster_id,scope.workspace_id);where.push('b.cluster_id IS NOT DISTINCT FROM $3::uuid','b.workspace_id IS NOT DISTINCT FROM $4::uuid');}
  return this.page(actor,subject,query,scope,`SELECT b.*,r.name AS role_name FROM ${table} b JOIN roles r ON r.id=b.role_id`,params,where,['r.name','r.code'],{bindings:true,subjectId},'b.created_at','b.id');
 }
 async addBinding(subject:'users'|'teams',subjectId:string,input:unknown,actor:IamActor):Promise<any>{
  const body=iamBody(input,['role_id','cluster_id','workspace_id','expires_at']),owner=await this.row(subject,subjectId),role=await this.row('roles',iamId(body.role_id)),scope=iamScope(body);
  if(subject==='users')await this.authorizeUserBinding(actor,scope,'write');else await this.authorize(actor,subject,'write',this.scope(owner));this.active(owner);this.active(role);if(subject==='users')await this.protectUser(actor,owner);
  if(subject==='teams'&&(owner.cluster_id&&owner.cluster_id!==scope.cluster_id||owner.workspace_id&&owner.workspace_id!==scope.workspace_id))throw new ForbiddenException({code:'TEAM_SCOPE_MISMATCH',message:'团队授权不得超过所属范围'});
  const expires=body.expires_at==null?null:iamText(body.expires_at,'到期时间',64,true);if(expires&&(!Number.isFinite(Date.parse(expires))||Date.parse(expires)<=Date.now()||Date.parse(expires)>Date.now()+31536000000))throw new BadRequestException('授权到期时间须在未来一年内');
  if(role.builtin_kind==='super-admin'&&expires)throw protectedRole();await this.checkGrantAssignment(actor,role,scope,this.db,subject==='teams');
  const table=subject==='users'?'user_role_bindings':'team_role_bindings',column=subject==='users'?'user_id':'team_id';
  const operationScope=subject==='users'?scope:this.scope(owner),operationModule=subject==='users'&&scope.cluster_id?'roles':subject;
  return this.execute(actor,operationModule,'write',subjectId,operationScope,body,async tx=>{
   const current=await this.row(subject,subjectId,tx,true),currentRole=await this.row('roles',role.id,tx,true);this.active(current);this.active(currentRole);if(subject==='users'){await this.authorizeUserBinding(actor,scope,'write');await this.protectUser(actor,current);}await this.checkGrantAssignment(actor,currentRole,scope,tx,subject==='teams');
   if(await tx.one(`SELECT id FROM ${table} WHERE ${column}=$1 AND role_id=$2 AND cluster_id IS NOT DISTINCT FROM $3::uuid AND workspace_id IS NOT DISTINCT FROM $4::uuid AND status='active'`,[subjectId,role.id,scope.cluster_id,scope.workspace_id]))throw new ConflictException({code:'BINDING_EXISTS',message:'相同角色范围已授予'});
   const row=await tx.one<any>(`INSERT INTO ${table}(id,${column},role_id,cluster_id,workspace_id,expires_at,granted_by) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING *`,[this.allocateId(),subjectId,role.id,scope.cluster_id,scope.workspace_id,expires,actor.user.id]);
   if(currentRole.builtin_kind==='super-admin')await tx.exec('UPDATE users SET super_admin=true,permissions_epoch=permissions_epoch+1,revision=revision+1,updated_at=now() WHERE id=$1',[subjectId]);
   const result={...row,role_name:currentRole.name};await this.auditChange(tx,actor,subject,'grant',subjectId,scope,null,result);return result;
  });
 }
 async bindingState(subject:'users'|'teams',subjectId:string,bindingId:string,input:unknown,restore:boolean,actor:IamActor):Promise<any>{
  iamId(bindingId);const body=iamBody(input,['revision','confirmed','confirm_name']),owner=await this.row(subject,subjectId),table=subject==='users'?'user_role_bindings':'team_role_bindings',column=subject==='users'?'user_id':'team_id';
  const before=await this.db.one<any>(`SELECT b.*,r.name AS role_name FROM ${table} b JOIN roles r ON r.id=b.role_id WHERE b.id=$1 AND b.${column}=$2`,[bindingId,subjectId]);if(!before)throw new NotFoundException('角色授权不存在');iamConfirm(body,before.role_name);
  if(subject==='users')await this.authorizeUserBinding(actor,this.scope(before),restore?'write':'delete');else await this.authorize(actor,subject,restore?'write':'delete',this.scope(owner));
  const role=await this.row('roles',before.role_id);
  if(restore)await this.checkGrantAssignment(actor,role,this.scope(before),this.db,subject==='teams');
  else {await this.executionScopes(this.db,[this.scope(before)]);if(role.builtin_kind==='super-admin'&&(subject==='teams'||!await this.authz.isPlatformAdmin(actor.user)))throw protectedRole();}
  const operationScope=subject==='users'?this.scope(before):this.scope(owner),operationModule=subject==='users'&&before.cluster_id?'roles':subject,operationAction=subject==='users'&&!before.cluster_id?'write':restore?'write':'delete';
  return this.execute(actor,operationModule,operationAction,subjectId,operationScope,{...body,bindingId,restore},async tx=>{
   const currentOwner=await this.row(subject,subjectId,tx,true),currentRole=await this.row('roles',role.id,tx,true),current=await tx.one<any>(`SELECT * FROM ${table} WHERE id=$1 AND ${column}=$2 FOR UPDATE`,[bindingId,subjectId]);if(!current||current.revision!==body.revision)throw changed();iamConfirm(body,currentRole.name);if(subject==='users')await this.protectUser(actor,currentOwner);
   if(subject==='users')await this.authorizeUserBinding(actor,this.scope(current),restore?'write':'delete');
   if(restore){this.active(currentOwner);this.active(currentRole);if(current.status!=='revoked'||new Date(current.retention_until).getTime()<Date.now()||current.expires_at&&new Date(current.expires_at).getTime()<=Date.now())throw new ConflictException('授权不可恢复');await this.checkGrantAssignment(actor,currentRole,this.scope(current),tx,subject==='teams');}
   else {if(current.status!=='active')throw new ConflictException('授权已撤销');await this.executionScopes(tx,[this.scope(current)]);}
   if(currentRole.builtin_kind==='super-admin'){if(!await this.authz.isPlatformAdmin(actor.user)||subject==='teams')throw protectedRole();if(!restore)await this.lastAdmin(tx,currentOwner);}
   const after=await tx.one<any>(`UPDATE ${table} SET status=$2,revision=revision+1,updated_at=now(),revoked_at=CASE WHEN $2='revoked' THEN now() ELSE NULL END,retention_until=CASE WHEN $2='revoked' THEN now()+($3::int*interval '1 day') ELSE NULL END WHERE id=$1 AND revision=$4 RETURNING *`,[bindingId,restore?'active':'revoked',retentionDays(),body.revision]);if(!after)throw changed();
   if(currentRole.builtin_kind==='super-admin')await tx.exec('UPDATE users SET super_admin=$2,permissions_epoch=permissions_epoch+1,revision=revision+1,updated_at=now() WHERE id=$1',[subjectId,restore]);
   const result={...after,role_name:currentRole.name};await this.auditChange(tx,actor,subject,restore?'grant.restore':'grant.revoke',subjectId,this.scope(current),before,result);return result;
  });
 }
 async members(teamId:string,query:IamPageQuery,actor:IamActor):Promise<any>{
  const team=await this.row('teams',teamId);await this.authorize(actor,'teams','read',this.scope(team));const status=query.status??'active';if(!['active','revoked'].includes(status))throw new BadRequestException('成员状态无效');
  return this.page(actor,'teams',query,this.scope(team),'SELECT m.*,u.username,u.display_name,m.user_id AS id,m.joined_at AS created_at FROM team_members m JOIN users u ON u.id=m.user_id',[teamId,status],['m.team_id=$1','m.status=$2'],['u.username','u.display_name'],{members:true,teamId},'m.joined_at','m.user_id');
 }
 private async memberDelegation(teamId:string,actor:IamActor,tx:DbService):Promise<void>{
  const bindings=await tx.query<any>("SELECT * FROM team_role_bindings WHERE team_id=$1 AND status='active' AND(expires_at IS NULL OR expires_at>now()) LIMIT 1001",[teamId]);if(bindings.length>1000)throw new ConflictException('团队授权超过安全检查预算');
  for(const binding of bindings){const role=await this.row('roles',binding.role_id,tx);if(role.status==='active')await this.checkGrantAssignment(actor,role,this.scope(binding),tx,true);}
 }
 async addMember(teamId:string,input:unknown,actor:IamActor):Promise<any>{
  const body=iamBody(input,['user_id']),userId=iamId(body.user_id),team=await this.row('teams',teamId);await this.authorize(actor,'teams','write',this.scope(team));await this.memberDelegation(teamId,actor,this.db);
  return this.execute(actor,'teams','write',teamId,this.scope(team),body,async tx=>{
   this.active(await this.row('teams',teamId,tx,true));const user=await this.row('users',userId,tx,true);this.active(user);await this.memberDelegation(teamId,actor,tx);
   if(await tx.one('SELECT user_id FROM team_members WHERE team_id=$1 AND user_id=$2',[teamId,userId]))throw new ConflictException({code:'MEMBERSHIP_RESERVED',message:'成员已存在；撤销的成员须显式恢复'});
   const row=await tx.one<any>('INSERT INTO team_members(team_id,user_id) VALUES($1,$2) RETURNING *',[teamId,userId]);const result={...row,username:user.username,display_name:user.display_name};await this.auditChange(tx,actor,'teams','member.add',teamId,this.scope(team),null,result);return result;
  });
 }
 async memberState(teamId:string,userId:string,input:unknown,restore:boolean,actor:IamActor):Promise<any>{
  const body=iamBody(input,['revision','confirmed','confirm_name']),team=await this.row('teams',teamId),user=await this.row('users',userId);iamConfirm(body,user.username);await this.authorize(actor,'teams',restore?'write':'delete',this.scope(team));
  return this.execute(actor,'teams',restore?'write':'delete',teamId,this.scope(team),{...body,userId,restore},async tx=>{
   const current=await tx.one<any>('SELECT * FROM team_members WHERE team_id=$1 AND user_id=$2 FOR UPDATE',[teamId,userId]);if(!current)throw new NotFoundException('成员不存在');if(current.revision!==body.revision)throw changed();
   if(restore){this.active(await this.row('teams',teamId,tx,true));this.active(await this.row('users',userId,tx,true));if(current.status!=='revoked'||new Date(current.retention_until).getTime()<Date.now())throw new ConflictException('成员不可恢复');await this.memberDelegation(teamId,actor,tx);}else if(current.status!=='active')throw new ConflictException('成员已撤销');
   const after=await tx.one<any>("UPDATE team_members SET status=$3,revision=revision+1,updated_at=now(),revoked_at=CASE WHEN $3='revoked' THEN now() ELSE NULL END,retention_until=CASE WHEN $3='revoked' THEN now()+($4::int*interval '1 day') ELSE NULL END WHERE team_id=$1 AND user_id=$2 AND revision=$5 RETURNING *",[teamId,userId,restore?'active':'revoked',retentionDays(),body.revision]);if(!after)throw changed();const result={...after,username:user.username,display_name:user.display_name};await this.auditChange(tx,actor,'teams',restore?'member.restore':'member.revoke',teamId,this.scope(team),current,result);return result;
  });
 }
 async resetPassword(userId:string,input:unknown,actor:IamActor):Promise<any>{const body=iamBody(input,['revision','new_password','confirmed']);iamRevision(body.revision);return this.auth.resetPassword(actor.user,iamId(userId),body.new_password,body.revision,body.confirmed);}
}
