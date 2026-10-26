import 'reflect-metadata';
import {EventEmitter} from 'node:events';
import {randomUUID,createHash} from 'node:crypto';
import {BadRequestException,ForbiddenException,ServiceUnavailableException,UnauthorizedException} from '@nestjs/common';
import {Reflector} from '@nestjs/core';
import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {KongExecutionContextService} from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import {RequestFailureAuditService} from '../../apps/console-api/src/modules/audit/request-failure-audit.service';
import {AuditService} from '../../apps/console-api/src/modules/audit/audit.service';
import {SecretService,canonicalJson} from '../../apps/console-api/src/infrastructure/secret.service';
import {AuthGuard} from '../../apps/console-api/src/modules/auth/auth.guard';
import {DeckSessionGuard} from '../../apps/console-api/src/modules/deck-adapter/deck-session.guard';
import {DeckErrorFilter} from '../../apps/console-api/src/modules/deck-adapter/deck-adapter.controller';
import {PortalGuard} from '../../apps/console-api/src/modules/portal-auth/portal-auth.guard';
import {Public,RequireSuperAdmin} from '../../apps/console-api/src/common/auth';
import {ErrorFilter} from '../../apps/console-api/src/common/http';
import {AuditOutboxWriter} from '../../apps/console-api/src/modules/event-core/audit-outbox-writer.service';
import {mapAuditEvent} from '../../apps/console-api/src/modules/event-core/audit-outbox-writer.service';
import {historicalAllows} from '../../apps/console-api/src/modules/authorization/historical-scope-policy';

/** Source integration: actual guards/private Context/filter/AuditService/hash;
 * authenticated providers, response emitter and SQL persistence are controlled
 * adapters. No network, live PostgreSQL or Native Kong request is performed. */
const SECRET='never-store-private-key-password-in-request-failure-audit';
class Controller {write(){} @RequireSuperAdmin() admin(){} @Public() login(){}}
function fixture(method='POST'){
 const execution=new KongExecutionContextService(),uid=randomUUID(),sid=randomUUID(),requestId=randomUUID();
 const user={id:uid,username:'current-reader',superAdmin:false,forcePasswordChange:false},res:any=new EventEmitter();
 res.statusCode=200;res.writableFinished=false;res.status=vi.fn((status:number)=>{res.statusCode=status;return res;});res.json=vi.fn();
 const req:any={method,headers:{authorization:'Bearer trusted-console-token'},cookies:{},res,requestId:'client-forged-request-id',
  body:{clusterId:randomUUID(),workspaceId:randomUUID(),user:{id:randomUUID()},key:SECRET},query:{api_key:SECRET},url:`/api/v1/foreign?key=${SECRET}`,
  path:'/api/v1/foreign',ip:'attacker-ip',get:(name:string)=>req.headers[name]};
 const append=vi.fn(async()=>({id:randomUUID()})),audit=new RequestFailureAuditService({append} as any,execution);
 const auth:any={authenticate:vi.fn(async()=>({user,sessionId:sid,csrfHash:'hash'})),checkCsrf:vi.fn()};
 const guard=new AuthGuard(new Reflector(),auth,execution,audit);
 const context=(action:'write'|'admin'|'login'='write'):any=>({getHandler:()=>Controller.prototype[action],getClass:()=>Controller,switchToHttp:()=>({getRequest:()=>req})});
 const host:any={switchToHttp:()=>({getRequest:()=>req,getResponse:()=>res})};
 const filter=new ErrorFilter(audit);
 const run=<T>(fn:()=>T)=>execution.runHttp({requestId,ip:'127.0.0.1'},fn);
 return {execution,uid,sid,requestId,user,req,res,append,audit,auth,guard,context,host,filter,run};
}
async function tick(){await Promise.resolve();await Promise.resolve();await Promise.resolve();}
beforeEach(()=>vi.stubEnv('CONSOLE_ENCRYPTION_KEY','ab'.repeat(32)));
afterEach(()=>{vi.unstubAllEnvs();vi.restoreAllMocks();});

describe('authenticated write failure facts',()=>{
 it('records prepare 500 after trusted guard authentication without inventing entity/native outcomes',async()=>{
  const f=fixture();vi.spyOn(console,'error').mockImplementation(()=>undefined);
  await f.run(async()=>{await f.guard.canActivate(f.context());await f.filter.catch(new Error(SECRET),f.host);});
  expect(f.append).toHaveBeenCalledTimes(1);expect(f.append).toHaveBeenCalledWith({actorId:f.uid,actorType:'user',entityType:'http_requests',entityId:f.requestId,requestId:f.requestId,ip:'127.0.0.1',clusterId:null,workspaceId:null,action:'http.request.POST.failed',before:null,after:{error_code:expect.any(String)},result:'http_500'});
  const encoded=JSON.stringify(f.append.mock.calls);expect(encoded).not.toContain(SECRET);expect(encoded).not.toContain(f.req.body.clusterId);expect(encoded).not.toContain('client-forged');
  expect(f.res.status).toHaveBeenCalledWith(500);expect(f.res.json.mock.calls[0][0].error.code).toBe('INTERNAL_ERROR');
 });
 it.each(['POST','PUT','PATCH','DELETE'])('includes authenticated CSRF denial on %s before controller/interceptors',async method=>{
  const f=fixture(method);delete f.req.headers.authorization;f.req.cookies.kongos_access='trusted-cookie';
  const original=new ForbiddenException({code:'CSRF_FAILED',message:'safe denial'});f.auth.checkCsrf.mockImplementation(()=>{throw original;});
  await f.run(async()=>{await expect(f.guard.canActivate(f.context())).rejects.toBe(original);await f.filter.catch(original,f.host);});
  expect(f.append).toHaveBeenCalledWith(expect.objectContaining({actorId:f.uid,action:`http.request.${method}.failed`,result:'http_403'}));expect(f.res.json.mock.calls[0][0].error.code).toBe('CSRF_FAILED');
 });
 it('records authenticated super-admin route rejection and password-change denial',async()=>{
  for(const forced of [false,true]){const f=fixture();if(forced)f.user.forcePasswordChange=true;
   await f.run(async()=>{try{await f.guard.canActivate(f.context(forced?'write':'admin'));throw Error('expected denial');}catch(e){expect(e).toBeInstanceOf(ForbiddenException);await f.filter.catch(e,f.host);}});
   expect(f.append).toHaveBeenCalledTimes(1);expect(f.append.mock.calls[0][0]).toMatchObject({actorId:f.uid,result:'http_403'});
  }
 });
 it('preserves recovery IDs, original uncertain result and existing partial business audit',async()=>{
  const f=fixture(),operationId=randomUUID(),entryId=randomUUID(),business={action:'create',result:'success',entityType:'consumers'};
  vi.spyOn(console,'error').mockImplementation(()=>undefined);
  const committed=[business];
  await f.run(async()=>{await f.guard.canActivate(f.context());await f.filter.catch(new ServiceUnavailableException({code:'MUTATION_UNCERTAIN',message:'requires observation',operationId,entryId,state:'uncertain',payload:{password:SECRET}}),f.host);});
  expect(committed).toEqual([business]);expect(f.res.json.mock.calls[0][0].error).toEqual({code:'MUTATION_UNCERTAIN',message:'requires observation',operationId,entryId,state:'uncertain'});
  expect(f.append.mock.calls[0][0]).toMatchObject({before:null,after:{error_code:expect.any(String)},result:'http_503'});expect(f.append.mock.calls[0][0]).not.toHaveProperty('workflowId');
 });
 it('deduplicates concurrent exception/finish/close into one independent append',async()=>{
  const f=fixture();let release!:()=>void;f.append.mockImplementation(()=>new Promise<void>(resolve=>{release=resolve;}));
  await f.run(async()=>{await f.guard.canActivate(f.context());const a=f.audit.recordFailure(f.req,409),b=f.audit.recordFailure(f.req,500);f.res.statusCode=409;f.res.emit('finish');f.res.emit('close');await tick();expect(f.append).toHaveBeenCalledTimes(1);expect(a).toBe(b);release();await a;});
  expect(f.append.mock.calls[0][0]).toMatchObject({result:'http_409'});
 });
 it('keeps only a bounded error code constant for rejected requests',async()=>{
  const f=fixture('POST');await f.run(async()=>{await f.guard.canActivate(f.context());await f.audit.recordFailure(f.req,403,'PROTECTED_PROXY_DESTINATION');});
  expect(f.append).toHaveBeenCalledWith(expect.objectContaining({result:'http_403',after:{error_code:'PROTECTED_PROXY_DESTINATION'}}));
  const g=fixture('POST');await g.run(async()=>{await g.guard.canActivate(g.context());await g.audit.recordFailure(g.req,403,'secret host 10.0.0.1:5432');});
  expect(g.append.mock.calls[0][0].after).toBeNull();
 });
 it('captures explicit response failure without an exception filter',async()=>{
  const f=fixture('PATCH');await f.run(async()=>{await f.guard.canActivate(f.context());f.res.statusCode=422;f.res.emit('finish');await f.audit.recordFailure(f.req,422);});
  expect(f.append).toHaveBeenCalledWith(expect.objectContaining({result:'http_422'}));
 });
 it('records disconnected HTTP observation without calling it failed business or KnownNotSent',async()=>{
  const f=fixture();await f.run(async()=>{await f.guard.canActivate(f.context());f.res.emit('close');await f.audit.recordFailure(f.req,'disconnected');});
  expect(f.append.mock.calls[0][0]).toMatchObject({result:'http_disconnected',before:null,after:null});expect(JSON.stringify(f.append.mock.calls)).not.toMatch(/known.?not.?sent|remoteStarted|failed_business/i);
 });
 it('does not record successful response or successful-finish late close as failure',async()=>{
  const f=fixture();await f.run(async()=>{await f.guard.canActivate(f.context());f.res.statusCode=201;f.res.emit('finish');f.res.emit('close');await tick();});expect(f.append).not.toHaveBeenCalled();
 });
 it.each(['GET','HEAD','OPTIONS'])('does not classify authenticated %s as a write failure',async method=>{
  const f=fixture(method);await f.run(async()=>{await f.guard.canActivate(f.context());await f.filter.catch(new BadRequestException('bad'),f.host);});expect(f.append).not.toHaveBeenCalled();
 });
 it('does not trust unauthenticated req.user, request IDs or attacker principal fields',async()=>{
  const f=fixture();f.req.user=f.user;f.req.sessionId=f.sid;f.auth.authenticate.mockRejectedValue(new UnauthorizedException());
  await f.run(async()=>{await expect(f.guard.canActivate(f.context())).rejects.toMatchObject({status:401});await f.filter.catch(new UnauthorizedException(),f.host);});expect(f.append).not.toHaveBeenCalled();
 });
 it('does not add a fabricated identity to public routes or parser failures before authentication',async()=>{
  const f=fixture();await f.run(async()=>{expect(await f.guard.canActivate(f.context('login'))).toBe(true);await f.filter.catch(Object.assign(new Error(SECRET),{type:'entity.parse.failed'}),f.host);});expect(f.append).not.toHaveBeenCalled();
 });
 it('does not allow request copies or late actor/request mutation to change captured identity',async()=>{
  const f=fixture();await f.run(async()=>{await f.guard.canActivate(f.context());f.req.user={id:randomUUID()};f.req.requestId=randomUUID();f.req.method='DELETE';await f.audit.recordFailure({...f.req},500);await f.audit.recordFailure(f.req,400);});
  expect(f.append).toHaveBeenCalledTimes(1);expect(f.append.mock.calls[0][0]).toMatchObject({actorId:f.uid,requestId:f.requestId,action:'http.request.POST.failed'});
 });
 it('can append the captured HTTP fact after the original private Context is closed without gaining authority',async()=>{
  const f=fixture();await f.run(async()=>{await f.guard.canActivate(f.context());f.execution.captureHttpCloser()();expect(()=>f.execution.current()).toThrow();await f.audit.recordFailure(f.req,503);expect(()=>f.execution.current()).toThrow();});expect(f.append).toHaveBeenCalledTimes(1);
 });
 it('does not mask original exception or leak failed audit adapter error',async()=>{
  const f=fixture(),logger=vi.spyOn(console,'error').mockImplementation(()=>undefined);f.append.mockRejectedValue(new Error(SECRET));
  await f.run(async()=>{await f.guard.canActivate(f.context());await f.filter.catch(new BadRequestException({code:'ORIGINAL_SAFE_ERROR',message:'original'}),f.host);});
  expect(f.res.status).toHaveBeenCalledWith(400);expect(f.res.json.mock.calls[0][0].error.code).toBe('ORIGINAL_SAFE_ERROR');
  expect(logger).toHaveBeenCalledWith(JSON.stringify({level:'error',code:'HTTP_FAILURE_AUDIT_APPEND_FAILED',requestId:f.requestId}));expect(JSON.stringify(logger.mock.calls)).not.toContain(SECRET);
 });
 it('keeps known tenant rejection global and unreadable by unrelated workspace/tag/entity audit roles',async()=>{
  const f=fixture();await f.run(async()=>{await f.guard.canActivate(f.context());await f.filter.catch(new ForbiddenException({code:'PERMISSION_DENIED'}),f.host);});
  const event=f.append.mock.calls[0][0],identity={clusterId:event.clusterId,workspaceId:event.workspaceId,scope:{version:1,quality:'legacy_unknown',module:event.entityType,before:null,after:null}};
  for(const scope_type of ['workspace','tag_group','entity'])expect(historicalAllows({user:f.user,version:'v1',grants:[{module:'audit',action:'read',scope_type,scope_values:[f.req.body.workspaceId],cluster_id:f.req.body.clusterId,workspace_id:f.req.body.workspaceId}]} as any,'audit',identity as any)).toBe(false);
  expect(historicalAllows({user:f.user,version:'v1',grants:[{module:'audit',action:'read',scope_type:'global',scope_values:[],cluster_id:null,workspace_id:null}]} as any,'audit',identity as any)).toBe(true);
 });
 it('never accesses raw body/query/URL/header/user/IP fields while capturing or appending a trusted fact',async()=>{
  const f=fixture();await f.run(async()=>{f.execution.bindHttpActor(f.user,f.sid);
   for(const name of ['body','query','url','originalUrl','headers','user','ip'])Object.defineProperty(f.req,name,{get(){throw new Error(`raw ${name} accessed`);}});
   f.audit.captureConsole(f.req);await f.audit.recordFailure(f.req,400);
  });expect(f.append).toHaveBeenCalledWith(expect.objectContaining({actorId:f.uid,requestId:f.requestId,result:'http_400'}));
 });
 it('does not generate entity.changed/event-hooks from an HTTP failure fact',()=>{
  for(const method of ['POST','PUT','PATCH','DELETE'])for(const result of ['http_400','http_403','http_409','http_500','http_503','http_disconnected'])expect(mapAuditEvent(`http.request.${method}.failed`,result)).toBeNull();
  expect(mapAuditEvent('create','success')).toMatchObject({eventType:'entity.created'});
 });
});

describe('independent portal identity and audit append contracts',()=>{
 it.each(['scope','csrf','password'])('captures real portal authentication before %s rejection, never console/caller identity',async denial=>{
  const f=fixture(),principal:any={kind:'portal_developer',developerId:randomUUID(),sessionId:randomUUID(),clusterId:randomUUID(),workspaceId:randomUUID(),credentialEpoch:1};
  delete f.req.headers.authorization;f.req.cookies.kongos_portal_access='trusted-portal-cookie';f.req.portalPrincipal={...principal,developerId:randomUUID()};
  f.req.body={clusterId:principal.clusterId,workspaceId:principal.workspaceId,key:SECRET};
  const auth:any={authenticate:vi.fn(async()=>principal),assertScope:vi.fn(),verifyOrigin:vi.fn(),checkCsrf:vi.fn(),assertCurrent:vi.fn(async()=>({mustChangePassword:denial==='password'}))};
  if(denial==='scope')auth.assertScope.mockImplementation(()=>{throw new ForbiddenException({code:'PORTAL_SCOPE_DENIED'});});
  if(denial==='csrf')auth.checkCsrf.mockRejectedValue(new ForbiddenException({code:'PORTAL_CSRF_DENIED'}));
  const guard=new PortalGuard(auth,f.audit);
  await f.run(async()=>{try{await guard.canActivate(f.context());throw Error('expected rejection');}catch(e){expect(e).toBeInstanceOf(ForbiddenException);await f.filter.catch(e,f.host);}});
  expect(f.append).toHaveBeenCalledTimes(1);expect(f.append.mock.calls[0][0]).toMatchObject({actorId:null,actorType:'developer',entityType:'portal_developers',entityId:principal.developerId,clusterId:null,workspaceId:null,result:'http_403'});
  expect(JSON.stringify(f.append.mock.calls)).not.toContain(principal.sessionId);expect(JSON.stringify(f.append.mock.calls)).not.toContain(SECRET);
 });
 it('captures authenticated portal malformed-scope validation 400 before a business mutation exists',async()=>{
  const f=fixture(),principal:any={kind:'portal_developer',developerId:randomUUID(),sessionId:randomUUID(),clusterId:randomUUID(),workspaceId:randomUUID(),credentialEpoch:1};
  delete f.req.headers.authorization;f.req.cookies.kongos_portal_access='trusted';f.req.body={password:SECRET};
  const guard=new PortalGuard({authenticate:vi.fn(async()=>principal)} as any,f.audit);
  await f.run(async()=>{try{await guard.canActivate(f.context());throw Error('expected malformed-scope rejection');}catch(e){expect(e).toMatchObject({status:400});await f.filter.catch(e,f.host);}});
  expect(f.append.mock.calls[0][0]).toMatchObject({actorType:'developer',entityId:principal.developerId,result:'http_400'});
 });
 it('does not capture a portal principal from rejected Bearer or invalid cookie authentication',async()=>{
  const f=fixture(),auth:any={authenticate:vi.fn().mockRejectedValue(new UnauthorizedException())},guard=new PortalGuard(auth,f.audit);
  await f.run(async()=>{await expect(guard.canActivate(f.context())).rejects.toMatchObject({status:401});delete f.req.headers.authorization;f.req.cookies.kongos_portal_access='invalid';await expect(guard.canActivate(f.context())).rejects.toMatchObject({status:401});await f.filter.catch(new UnauthorizedException(),f.host);});expect(f.append).not.toHaveBeenCalled();
 });
 it('uses original AuditService independent append-only chain transaction after rollback with null snapshots/empty diff',async()=>{
  const f=fixture(),order:string[]=[],rows:any[]=[],head={last_sequence:'0',last_hash:'GENESIS'};
  const sqlTx:any={one:vi.fn(async()=>head),exec:vi.fn(async(sql:string,args:any[])=>{if(sql.startsWith('INSERT INTO audit_events')){order.push('audit-insert');rows.push(args);}return 1;})};
  const db:any={transaction:vi.fn(async(fn:any)=>{order.push('independent-begin');const result=await fn(sqlTx);order.push('independent-commit');return result;})};
  const fromAudit=vi.fn(async()=>null),actualAudit=new AuditService(db,new SecretService(),{fromAudit} as any),observer=new RequestFailureAuditService(actualAudit,f.execution);
  await f.run(async()=>{f.execution.bindHttpActor(f.user,f.sid);observer.captureConsole(f.req);try{order.push('business-begin');throw new Error('business rollback');}catch{order.push('business-rollback');await observer.recordFailure(f.req,500);}});
  expect(order).toEqual(['business-begin','business-rollback','independent-begin','audit-insert','independent-commit']);expect(rows).toHaveLength(1);
  const a=rows[0];expect(a[1]).toBe('global');expect(a[3]).toBe(f.uid);expect(a[6]).toBeNull();expect(a[7]).toBeNull();expect(a[11]).toBe('null');expect(a[12]).toBe('null');expect(a[13]).toBe('[]');expect(a[15]).toBe('http_500');expect(a[16]).toBe(f.requestId);expect(a[18]).toMatch(/^[a-f\d]{64}$/);
  const record={id:a[0],chain_scope:a[1],sequence:a[2],actor_id:a[3],actor_type:a[4],source_ip:a[5],cluster_id:a[6],workspace_id:a[7],entity_type:a[8],entity_id:a[9],action:a[10],before:null,after:null,json_patch:[],workflow_id:a[14],result:a[15],request_id:a[16],prev_hash:a[17],occurred_at:a[19]};
  expect(createHash('sha256').update(canonicalJson(record)).digest('hex')).toBe(a[18]);expect(sqlTx.exec.mock.calls.every(([sql]:any)=>!sql.startsWith('DELETE FROM audit_events')&&!sql.startsWith('UPDATE audit_events'))).toBe(true);
  expect(fromAudit).toHaveBeenCalledWith(expect.objectContaining({chainScope:'global'}),{quality:'legacy_unknown',module:'http_requests'},sqlTx);
 });
});


describe('authenticated decK custom guard/filter coverage',()=>{
 it('records authenticated decK dispatch failure with original Kong-shaped safe response',async()=>{
  const f=fixture('PATCH'),proof=Object.freeze({}),authority={user:f.user,sessionId:f.sid};
  f.req.params={deckSessionId:randomUUID()};f.req.rawHeaders=['Authorization',`KongOS-Deck ${SECRET}`];f.res.setHeader=vi.fn();
  const sessions:any={authenticate:vi.fn(async()=>proof),authority:vi.fn((p:object)=>{expect(p).toBe(proof);return authority;})};
  const guard=new DeckSessionGuard(sessions,f.execution,f.audit),filter=new DeckErrorFilter(f.audit);
  await f.run(async()=>{await guard.canActivate(f.context());await filter.catch(new BadRequestException({code:'DECK_BAD_INPUT',message:SECRET,fields:{key:SECRET}}),f.host);});
  expect(f.append).toHaveBeenCalledTimes(1);expect(f.append.mock.calls[0][0]).toMatchObject({actorId:f.uid,result:'http_400',action:'http.request.PATCH.failed'});
  expect(f.res.json).toHaveBeenCalledWith({message:'DECK_BAD_INPUT'});expect(JSON.stringify(f.append.mock.calls)).not.toContain(SECRET);
 });
 it('does not forge a decK identity before actual session authentication',async()=>{
  const f=fixture(),sessions:any={authenticate:vi.fn().mockRejectedValue(new ForbiddenException())};f.req.params={deckSessionId:randomUUID()};f.res.setHeader=vi.fn();
  await f.run(async()=>{const guard=new DeckSessionGuard(sessions,f.execution,f.audit);await expect(guard.canActivate(f.context())).rejects.toMatchObject({status:403});await new DeckErrorFilter(f.audit).catch(new ForbiddenException(),f.host);});expect(f.append).not.toHaveBeenCalled();
 });
 it('records a decK headers-already-sent disconnect without inventing a final HTTP status or business outcome',async()=>{
  const f=fixture();f.res.headersSent=true;f.res.destroy=vi.fn();
  await f.run(async()=>{await f.guard.canActivate(f.context());await new DeckErrorFilter(f.audit).catch(new Error(SECRET),f.host);});
  expect(f.append.mock.calls[0][0]).toMatchObject({result:'http_disconnected'});expect(f.res.destroy).toHaveBeenCalledTimes(1);expect(f.res.json).not.toHaveBeenCalled();
 });
});

for(const Filter of [ErrorFilter,DeckErrorFilter])describe(`safe asynchronous ${Filter.name} finalization`,()=>{
 it.each(['destroyed','writableEnded'])('does not write again when response becomes %s during actual independent append',async flag=>{
  const f=fixture();let release!:()=>void;f.append.mockImplementation(()=>new Promise<void>(resolve=>{release=resolve;}));f.res.setHeader=vi.fn();f.res.destroy=vi.fn();
  await f.run(async()=>{await f.guard.canActivate(f.context());const pending=new Filter(f.audit).catch(new BadRequestException({code:'ORIGINAL_SAFE_ERROR'}),f.host);await tick();f.res[flag]=true;release();await pending;});
  expect(f.append).toHaveBeenCalledTimes(1);expect(f.res.status).not.toHaveBeenCalled();expect(f.res.json).not.toHaveBeenCalled();expect(f.res.destroy).not.toHaveBeenCalled();
 });
 it('contains final JSON and destroy exceptions without losing original HTTP fact or logging transport secrets',async()=>{
  const f=fixture(),logger=vi.spyOn(console,'error').mockImplementation(()=>undefined);f.res.setHeader=vi.fn();f.res.json.mockImplementation(()=>{throw Error(SECRET);});f.res.destroy=vi.fn(()=>{throw Error(SECRET);});
  await f.run(async()=>{await f.guard.canActivate(f.context());await expect(new Filter(f.audit).catch(new BadRequestException({code:'ORIGINAL_SAFE_ERROR'}),f.host)).resolves.toBeUndefined();});
  expect(f.append.mock.calls[0][0]).toMatchObject({result:'http_400',before:null});expect(f.res.destroy).toHaveBeenCalledTimes(1);expect(JSON.stringify(logger.mock.calls)).not.toContain(SECRET);
 });
});

describe('original AuditService and actual AuditOutboxWriter seam',()=>{
 it('commits global immutable history scope with no entity event/hook/outbox for an HTTP rejection',async()=>{
  const f=fixture(),secrets=new SecretService();let row:any,scope:any;
  const tx:any={exec:vi.fn(async(sql:string,p:any[])=>{
   if(sql.startsWith('INSERT INTO audit_events'))row={id:p[0],chain_scope:p[1],sequence:p[2],actor_id:p[3],actor_type:p[4],source_ip:p[5],cluster_id:p[6],workspace_id:p[7],entity_type:p[8],entity_id:p[9],action:p[10],before:JSON.parse(p[11]),after:JSON.parse(p[12]),json_patch:JSON.parse(p[13]),workflow_id:p[14],result:p[15],request_id:p[16],prev_hash:p[17],event_hash:p[18],occurred_at:p[19]};
   if(sql.startsWith('INSERT INTO audit_event_scopes'))scope={auditEventId:p[0],auditEventHash:p[1],clusterId:p[2],workspaceId:p[3],scope:JSON.parse(p[4]),scope_hmac:p[5]};
   return 1;
  }),one:vi.fn(async(sql:string)=>{if(sql.startsWith('SELECT last_sequence'))return{last_sequence:'0',last_hash:'GENESIS'};if(sql.startsWith('SELECT * FROM audit_events'))return row;if(sql.startsWith('SELECT scope_hmac'))return{scope_hmac:scope?.scope_hmac};throw Error('Unexpected SQL in controlled audit adapter');})};
  const db:any={transaction:vi.fn(async(fn:any)=>fn(tx))},outbox=new AuditOutboxWriter(db,secrets),audit=new AuditService(db,secrets,outbox),observer=new RequestFailureAuditService(audit,f.execution);
  await f.run(async()=>{f.execution.bindHttpActor(f.user,f.sid);observer.captureConsole(f.req);await observer.recordFailure(f.req,403);});
  expect(row).toMatchObject({actor_id:f.uid,chain_scope:'global',cluster_id:null,workspace_id:null,result:'http_403',before:null,after:null,json_patch:[]});
  expect(scope).toMatchObject({clusterId:null,workspaceId:null,scope:{version:1,quality:'legacy_unknown',module:'http_requests',before:null,after:null}});expect(scope.scope_hmac).toMatch(/^[a-f\d]{64}$/);
  expect(tx.exec.mock.calls.some(([sql]:any)=>/INSERT INTO (event_records|event_delivery_outbox|event_delivery_attempts)/.test(sql))).toBe(false);
 });
});
