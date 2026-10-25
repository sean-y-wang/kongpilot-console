import { Injectable, CanActivate, ExecutionContext, UnauthorizedException, ForbiddenException, Optional } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { RequestFailureAuditService } from '../audit/request-failure-audit.service';
import { AuthService } from './auth.service';
import { PUBLIC_ROUTE, SUPER_ADMIN_ROUTE } from '../../common/auth';
import { KongExecutionContextService } from '../../infrastructure/kong/execution-context.service';
@Injectable()
export class AuthGuard implements CanActivate {
 constructor(private readonly reflector:Reflector,private readonly auth:AuthService,private readonly execution:KongExecutionContextService,@Optional() private readonly requestAudit?:RequestFailureAuditService){}
 async canActivate(ctx:ExecutionContext){
  if(this.reflector.getAllAndOverride<boolean>(PUBLIC_ROUTE,[ctx.getHandler(),ctx.getClass()]))return true;
  const req=ctx.switchToHttp().getRequest(), bearer=req.headers.authorization?.match(/^Bearer (.+)$/i)?.[1],token=bearer??req.cookies?.kongos_access;
  if(!token)throw new UnauthorizedException({code:'LOGIN_REQUIRED',message:'请先登录'});
  const session=await this.auth.authenticate(token);req.user=session.user;req.sessionId=session.sessionId;
  this.execution.bindHttpActor(session.user,session.sessionId);
  this.requestAudit?.captureConsole(req);
  if(!bearer&&!['GET','HEAD','OPTIONS'].includes(req.method))this.auth.checkCsrf(req.headers['x-csrf-token'],session.csrfHash);
  if(this.reflector.getAllAndOverride<boolean>(SUPER_ADMIN_ROUTE,[ctx.getHandler(),ctx.getClass()])&&!req.user.superAdmin)throw new ForbiddenException({code:'PERMISSION_DENIED',message:'需要平台管理员权限'});
  if(req.user.forcePasswordChange&&!((req.method==='GET'&&req.path==='/api/v1/auth/me')||(req.method==='POST'&&['/api/v1/auth/me/password','/api/v1/auth/logout'].includes(req.path))))throw new ForbiddenException({code:'PASSWORD_CHANGE_REQUIRED',message:'请先修改初始密码'});
  return true;
 }
}
