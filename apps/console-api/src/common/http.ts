import { ArgumentsHost, Catch, ExceptionFilter, HttpException, Injectable, NestInterceptor, ExecutionContext, CallHandler, StreamableFile } from '@nestjs/common';
import { RequestFailureAuditService } from '../modules/audit/request-failure-audit.service';
import { randomUUID } from 'node:crypto';
import { Observable, map } from 'rxjs';
import type { Request, Response } from 'express';

export function safeDatabaseDiagnostic(error:unknown):Record<string,string> {
  const diagnostic:Record<string,string>={};
  if(error&&typeof error==='object') {
    const dbError=error as Record<string,unknown>;
    if(typeof dbError.code==='string'&&/^[0-9A-Z]{5}$/.test(dbError.code)) {
      diagnostic.sqlState=dbError.code;
      for(const field of ['constraint','table','schema','routine'])if(typeof dbError[field]==='string'&&/^[a-zA-Z_][a-zA-Z0-9_]{0,127}$/.test(dbError[field] as string))diagnostic[field]=dbError[field] as string;
    }
  }
  return diagnostic;
}

/** Nest invokes exception filters without awaiting their Promise. An audit
 * append may outlive the client connection or race a completed response; no
 * late send/destroy exception may become an unhandled rejection. This changes
 * transport finalization only, never the original business/unknown result. */
export function finalizeHttpErrorResponse(response:{headersSent?:boolean;destroyed?:boolean;writableEnded?:boolean;destroy?:()=>unknown},send:()=>unknown):void {
  const close=()=>{try{if(!response.destroyed&&!response.writableEnded)response.destroy?.();}catch{/* Already broken transport; never log exception/payload. */}};
  try {
    if(response.destroyed||response.writableEnded)return;
    if(response.headersSent){close();return;}
    send();
  }catch{close();}
}

@Catch()
export class ErrorFilter implements ExceptionFilter {
  constructor(private readonly requestAudit?:RequestFailureAuditService){}
  catch(error:unknown, host:ArgumentsHost) {
    const ctx=host.switchToHttp(), response=ctx.getResponse<Response>(), request=ctx.getRequest<Request & {requestId?:string}>();
    const parserType=error&&typeof error==='object'&&'type' in error?String(error.type):'';
    const parserStatus=parserType==='entity.too.large'?413:parserType==='entity.parse.failed'?400:null;
    const status=error instanceof HttpException?error.getStatus():parserStatus??500;
    const raw=error instanceof HttpException?error.getResponse():parserStatus?{code:parserStatus===413?'BODY_TOO_LARGE':'INVALID_JSON',message:parserStatus===413?'请求内容超过大小限制':'请求内容不是有效的 JSON'}:{code:'INTERNAL_ERROR',message:'服务暂时不可用'};
    const detail=typeof raw==='string'?{message:raw}:raw as Record<string,unknown>;
    const recovery:Record<string,unknown>={};
    for(const key of ['operationId','entryId'])if(typeof detail[key]==='string'&&/^[0-9a-f-]{36}$/i.test(detail[key] as string))recovery[key]=detail[key];
    if(typeof detail.state==='string'&&/^[a-z_]{1,40}$/.test(detail.state))recovery.state=detail.state;
    if(status>=500) {
      // Database messages/details can contain credential values. Preserve only
      // bounded SQLSTATE and server identifiers for operational diagnosis.
      const diagnostic=safeDatabaseDiagnostic(error);
      console.error(JSON.stringify({level:'error',requestId:request.requestId,errorType:error instanceof Error?error.name:'unknown',code:detail.code??'INTERNAL_ERROR',status,...diagnostic}));
    }
    const send=()=>finalizeHttpErrorResponse(response,()=>response.status(status).json({error:{code:detail.code??`HTTP_${status}`,message:detail.message??'请求失败',...(detail.fields?{fields:detail.fields}:{}),...recovery},meta:{requestId:request.requestId??randomUUID()}}));
    // The guard captured the trusted identity before authorization/CSRF. The
    // original business transaction has unwound; append a separate HTTP fact.
    // Keep the synchronous filter contract for isolated uses without auditing.
    if(this.requestAudit)return this.requestAudit.recordFailure(request,status).then(send,send);
    send();
  }
}
@Injectable()
export class EnvelopeInterceptor implements NestInterceptor {
 intercept(context:ExecutionContext,next:CallHandler):Observable<unknown> {
  const request=context.switchToHttp().getRequest();
  return next.handle().pipe(map(data=>data instanceof StreamableFile ? data : ({data,meta:{requestId:request.requestId}})));
 }
}
