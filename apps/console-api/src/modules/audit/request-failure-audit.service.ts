import { Injectable } from '@nestjs/common';
import { isIP } from 'node:net';
import { KongExecutionContextService } from '../../infrastructure/kong/execution-context.service';
import type { PortalPrincipal } from '../portal-auth/portal-auth.types';
import { AuditService, type AuditEvent } from './audit.service';

const UUID=/^[a-f\d]{8}-[a-f\d]{4}-[1-8][a-f\d]{3}-[89ab][a-f\d]{3}-[a-f\d]{12}$/i;
const METHODS=new Set(['POST','PUT','PATCH','DELETE']);
type ObservedRequest={method?:unknown;res?:{once(event:string,listener:()=>void):unknown;statusCode:number;writableFinished?:boolean}};
type Capture={readonly event:Readonly<AuditEvent>;pending?:Promise<void>;finished:boolean};

/** Records HTTP failure facts, not entity outcomes or evidence of a Native
 * send. The principal is captured only after a guard authenticated it. No URL,
 * request payload, supplied tenant, exception details or credentials are read.
 * Global-only visibility prevents a rejected foreign-tenant request from
 * creating an audit row in an attacker-selected cluster/workspace. */
@Injectable()
export class RequestFailureAuditService {
  readonly #captured=new WeakMap<object,Capture>();
  constructor(private readonly audit:AuditService,private readonly execution:KongExecutionContextService){}

  captureConsole(request:ObservedRequest):void {
    const frame=this.execution.current();
    if(frame.kind!=='http'||!frame.actor||!UUID.test(frame.actor.id)||!frame.sessionId||!UUID.test(frame.sessionId))return;
    this.capture(request,{actorId:frame.actor.id,actorType:'user',entityType:'http_requests',entityId:frame.requestId});
  }
  capturePortal(request:ObservedRequest,principal:Readonly<PortalPrincipal>):void {
    const frame=this.execution.current();
    if(frame.kind!=='http'||frame.actor||principal.kind!=='portal_developer'||!UUID.test(principal.developerId)||!UUID.test(principal.sessionId))return;
    // Developers belong to a separate identity table; never forge a users FK.
    this.capture(request,{actorId:null,actorType:'developer',entityType:'portal_developers',entityId:principal.developerId});
  }
  private capture(request:ObservedRequest,identity:Pick<AuditEvent,'actorId'|'actorType'|'entityType'|'entityId'>):void {
    if(this.#captured.has(request)||typeof request.method!=='string'||!METHODS.has(request.method))return;
    const frame=this.execution.current();
    if(!frame.requestId||!UUID.test(frame.requestId))return;
    const event:Readonly<AuditEvent>=Object.freeze({...identity,requestId:frame.requestId,
      ...(frame.ip&&isIP(frame.ip)?{ip:frame.ip}:{}),clusterId:null,workspaceId:null,
      action:`http.request.${request.method}.failed`,before:null,after:null});
    const capture:Capture={event,finished:false};this.#captured.set(request,capture);
    const response=request.res;
    response?.once('finish',()=>{capture.finished=true;void this.recordFailure(request,response.statusCode);});
    response?.once('close',()=>{if(!capture.finished&&!response.writableFinished)void this.recordFailure(request,'disconnected');});
  }
  /** Called after the original handler/transaction has rejected. The append
   * uses AuditService's independent transaction, never the rolled-back one.
   * A private per-request Promise deduplicates exception/finish/close races. */
  recordFailure(request:object,status:number|'disconnected'):Promise<void> {
    const capture=this.#captured.get(request);
    if(!capture||status!=='disconnected'&&(!Number.isInteger(status)||status<400||status>599))return Promise.resolve();
    if(capture.pending)return capture.pending;
    const result=status==='disconnected'?'http_disconnected':`http_${status}`;
    capture.pending=Promise.resolve().then(()=>this.audit.append({...capture.event,result})).then(()=>undefined).catch(()=>{
      // Audit storage failure must not replace the original HTTP/uncertain
      // result. This alert is truthful; it does not claim a durable audit row.
      console.error(JSON.stringify({level:'error',code:'HTTP_FAILURE_AUDIT_APPEND_FAILED',requestId:capture.event.requestId}));
    });
    return capture.pending;
  }
}
