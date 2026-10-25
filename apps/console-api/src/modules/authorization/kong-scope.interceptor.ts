import { BadRequestException, CallHandler, ExecutionContext, Injectable, NestInterceptor } from '@nestjs/common';
import { defer, lastValueFrom } from 'rxjs';
import { KongExecutionContextService } from '../../infrastructure/kong/execution-context.service';
import { configurationHttpWait } from '../../infrastructure/kong/configuration-budget';

/** Encloses the controller subscription, including all asynchronous service work. */
@Injectable()
export class KongScopeInterceptor implements NestInterceptor {
 constructor(private readonly execution:KongExecutionContextService){}
 intercept(context:ExecutionContext,next:CallHandler){
  const req=context.switchToHttp().getRequest(),cid=req.params?.clusterId;
  if(!cid)return next.handle();
  const wid=req.params?.workspaceId??req.query?.workspaceId;
  const valid=(value:unknown)=>typeof value==='string'&&/^[\da-f]{8}-[\da-f]{4}-[1-8][\da-f]{3}-[89ab][\da-f]{3}-[\da-f]{12}$/i.test(value);
  if(!valid(cid)||wid!==undefined&&!valid(wid))throw new BadRequestException({code:'INVALID_SCOPE_ID',message:'集群和工作区必须是单个有效 UUID'});
  // The subscription envelope can wait for an M8 receipt. Service actor
  // frames and sealed workflow proofs independently enforce their budgets.
  return defer(()=>this.execution.runActor({actor:req.user,clusterId:cid,workspaceId:wid,requestId:req.requestId,
    ...(configurationHttpWait(req.method,req.path)?{purpose:'configuration' as const}:{})},()=>lastValueFrom(next.handle())));
 }
}
