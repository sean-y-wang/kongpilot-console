import { Body, Controller, Get, Param, Patch, Post, Query, Req, Res, UseGuards } from '@nestjs/common';
import type { Request,Response } from 'express';
import { Public } from '../../common/auth';
import { PortalAuthService } from './portal-auth.service';
import { PortalGuard } from './portal-auth.guard';
import { PORTAL_COOKIE_PATH,PORTAL_COOKIES,portalExact,portalScope,type PortalAuthResult,type PortalRequestContext } from './portal-auth.types';

@Public()
@Controller('portal/auth')
export class PortalAuthController {
  constructor(private readonly auth:PortalAuthService){}
  private origin(req:Request){return this.auth.verifyOrigin({origin:req.get('origin'),secFetchSite:req.get('sec-fetch-site'),host:req.headers.host,method:req.method});}
  private context(req:any):PortalRequestContext {return {requestId:req.requestId,ip:req.ip,userAgent:req.get('user-agent'),idempotencyKey:req.get('x-idempotency-key')};}
  private clear(res:Response):void {for(const name of Object.values(PORTAL_COOKIES))res.clearCookie(name,{path:PORTAL_COOKIE_PATH,httpOnly:true,secure:process.env.NODE_ENV==='production'||process.env.COOKIE_SECURE==='true',sameSite:'strict'});}
  private cookies(res:Response,result:PortalAuthResult):void {
    const options={httpOnly:true,secure:process.env.NODE_ENV==='production'||process.env.COOKIE_SECURE==='true',sameSite:'strict' as const,path:PORTAL_COOKIE_PATH};
    res.cookie(PORTAL_COOKIES.access,result.accessToken,{...options,maxAge:900000});
    const remaining=Math.max(0,new Date(result.expiresAt).getTime()-Date.now());
    res.cookie(PORTAL_COOKIES.refresh,result.refreshToken,{...options,maxAge:remaining});res.cookie(PORTAL_COOKIES.csrf,result.csrfToken,{...options,maxAge:remaining});
  }
  @Get('csrf') async csrf(@Query() query:unknown,@Req() req:Request,@Res({passthrough:true}) res:Response) {
    const value=portalExact(query,['clusterId','workspaceId']),scope=portalScope(value),proof=this.origin(req);
    try {const result=await this.auth.csrf(scope,{accessToken:req.cookies?.[PORTAL_COOKIES.access],refreshToken:req.cookies?.[PORTAL_COOKIES.refresh],csrfCookie:req.cookies?.[PORTAL_COOKIES.csrf]},proof);
      if(result.cookieToken)res.cookie(PORTAL_COOKIES.csrf,result.cookieToken,{httpOnly:true,secure:process.env.NODE_ENV==='production'||process.env.COOKIE_SECURE==='true',sameSite:'strict',path:PORTAL_COOKIE_PATH,maxAge:600000});
      return {csrfToken:result.csrfToken,expiresAt:result.expiresAt};
    }catch(error:any){const response=error.getResponse?.();if(response?.code==='PORTAL_CSRF_INVALID')this.clear(res);throw error;}
  }
  @Post('register') async register(@Body() body:unknown,@Req() req:Request,@Res({passthrough:true}) res:Response) {
    const value=portalExact(body,['clusterId','workspaceId','username','email','displayName','password']),scope=portalScope(value);
    this.auth.verifyAnonymousCsrf(scope,req.cookies?.[PORTAL_COOKIES.csrf],req.get('x-portal-csrf'),this.origin(req));
    const result=await this.auth.register(scope,{username:value.username,email:value.email,displayName:value.displayName,password:value.password},this.context(req));res.status(202);return result;
  }
  @Post('login') async login(@Body() body:unknown,@Req() req:Request,@Res({passthrough:true}) res:Response) {
    const value=portalExact(body,['clusterId','workspaceId','username','password']),scope=portalScope(value);
    this.auth.verifyAnonymousCsrf(scope,req.cookies?.[PORTAL_COOKIES.csrf],req.get('x-portal-csrf'),this.origin(req));
    const result=await this.auth.login(scope,{username:value.username,password:value.password},this.context(req));this.cookies(res,result);
    return {developer:result.developer,csrfToken:result.csrfToken,expiresAt:result.expiresAt};
  }
  @Post('refresh') async refresh(@Body() body:unknown,@Req() req:Request,@Res({passthrough:true}) res:Response) {
    const value=portalExact(body,['clusterId','workspaceId']),scope=portalScope(value);this.origin(req);
    const result=await this.auth.refresh(scope,req.cookies?.[PORTAL_COOKIES.refresh],req.get('x-portal-csrf'),this.context(req));this.cookies(res,result);
    return {developer:result.developer,csrfToken:result.csrfToken,expiresAt:result.expiresAt};
  }
  @UseGuards(PortalGuard) @Post('logout') async logout(@Body() body:unknown,@Req() req:any,@Res({passthrough:true}) res:Response) {
    portalExact(body,['clusterId','workspaceId']);await this.auth.logout(req.portalPrincipal,this.context(req));this.clear(res);return {loggedOut:true};
  }
  @UseGuards(PortalGuard) @Get('me') async me(@Query() query:unknown,@Req() req:any) {portalExact(query,['clusterId','workspaceId']);return this.auth.me(req.portalPrincipal);}
  @UseGuards(PortalGuard) @Patch('me') async profile(@Body() body:unknown,@Req() req:any) {
    const value=portalExact(body,['clusterId','workspaceId','revision','displayName']);return this.auth.updateProfile(req.portalPrincipal,{revision:value.revision,displayName:value.displayName},this.context(req));
  }
  @UseGuards(PortalGuard) @Post('password') async password(@Body() body:unknown,@Req() req:any,@Res({passthrough:true}) res:Response) {
    const value=portalExact(body,['clusterId','workspaceId','revision','currentPassword','newPassword','confirmed']);
    const result=await this.auth.changePassword(req.portalPrincipal,{revision:value.revision,currentPassword:value.currentPassword,newPassword:value.newPassword,confirmed:value.confirmed},this.context(req));this.clear(res);return result;
  }
}

@Public() @UseGuards(PortalGuard) @Controller('portal/operations')
export class PortalOperationsController {
  constructor(private readonly auth:PortalAuthService){}
  @Get('by-key/:key') byKey(@Param('key') key:string,@Query() query:unknown,@Req() req:any){portalExact(query,['clusterId','workspaceId']);return this.auth.operation(req.portalPrincipal,key,true);}
  @Get(':id') get(@Param('id') id:string,@Query() query:unknown,@Req() req:any){portalExact(query,['clusterId','workspaceId']);return this.auth.operation(req.portalPrincipal,id);}
}
