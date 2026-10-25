import { CanActivate, ExecutionContext, ForbiddenException, Injectable, Optional, UnauthorizedException } from '@nestjs/common';
import { RequestFailureAuditService } from '../audit/request-failure-audit.service';
import { PortalAuthService } from './portal-auth.service';
import { PORTAL_COOKIES, portalScope } from './portal-auth.types';

@Injectable()
export class PortalGuard implements CanActivate {
  constructor(private readonly auth:PortalAuthService,@Optional() private readonly requestAudit?:RequestFailureAuditService){}
  async canActivate(context:ExecutionContext):Promise<boolean> {
    const req=context.switchToHttp().getRequest();
    // Portal authentication has its own namespace and never accepts a console bearer.
    if(req.headers.authorization)throw new UnauthorizedException({code:'PORTAL_COOKIE_REQUIRED',message:'门户仅接受独立门户会话'});
    const token=req.cookies?.[PORTAL_COOKIES.access];
    if(typeof token!=='string')throw new UnauthorizedException({code:'PORTAL_LOGIN_REQUIRED',message:'请先登录此门户'});
    const principal=await this.auth.authenticate(token);
    this.requestAudit?.capturePortal(req,principal);
    const scope=portalScope(['GET','HEAD','OPTIONS'].includes(req.method)?req.query:req.body);
    this.auth.assertScope(principal,scope);
    if(!['GET','HEAD','OPTIONS'].includes(req.method)) {
      this.auth.verifyOrigin({origin:req.get('origin'),secFetchSite:req.get('sec-fetch-site'),host:req.headers.host,method:req.method});
      await this.auth.checkCsrf(principal,req.get('x-portal-csrf'));
      const developer=await this.auth.assertCurrent(principal,undefined,true);
      if(developer.mustChangePassword&&!req.path.endsWith('/auth/password')&&!req.path.endsWith('/auth/logout'))throw new ForbiddenException({code:'PORTAL_PASSWORD_CHANGE_REQUIRED',message:'请先更改门户密码'});
    }
    req.portalPrincipal=principal;return true;
  }
}
