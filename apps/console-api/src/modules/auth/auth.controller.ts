import { Controller, Get, Post, Patch, Param, Query, Body, Req, Res, ForbiddenException, BadRequestException } from '@nestjs/common';
import type { Request, Response } from 'express';
import { Public } from '../../common/auth';
import { AuthService } from './auth.service';

@Controller('auth')
export class AuthController {
 constructor(private readonly auth:AuthService){}
 private cookies(res:Response,result:any){
  const secure=process.env.COOKIE_SECURE==='true';
  res.cookie('kongos_access',result.accessToken,{httpOnly:true,secure,sameSite:'strict',path:'/api',maxAge:900000});
  res.cookie('kongos_refresh',result.refreshToken,{httpOnly:true,secure,sameSite:'strict',path:'/api/v1/auth',maxAge:604800000});
  if(result.csrfToken)res.cookie('kongos_csrf',result.csrfToken,{httpOnly:true,secure,sameSite:'strict',path:'/api',maxAge:604800000});
 }
 private clear(res:Response){res.clearCookie('kongos_access',{path:'/api'});res.clearCookie('kongos_refresh',{path:'/api/v1/auth'});res.clearCookie('kongos_csrf',{path:'/api'});}
 private origin(req:Request){const origin=req.get('origin');if(origin&&![`${req.protocol}://${req.get('host')}`,...(process.env.PUBLIC_ORIGINS??'').split(',').filter(Boolean)].includes(origin))throw new ForbiddenException('不允许的来源');}
 @Public() @Post('login')
 async login(@Body() body:any,@Req() req:Request,@Res({passthrough:true}) res:Response){
  if(!body||typeof body!=='object'||Array.isArray(body)||Object.keys(body).some(key=>!['username','password'].includes(key)))throw new BadRequestException({code:'INVALID_AUTH_PAYLOAD',message:'登录请求包含不允许的字段'});
  this.origin(req);
  const result=await this.auth.login(body.username,body.password,req.ip??'',req.get('user-agent')??'');this.cookies(res,result);return {user:result.user,csrfToken:result.csrfToken};
 }
 @Get('me') async me(@Req() req:any){return {user:await this.auth.currentUser(req.user),csrfToken:req.cookies?.kongos_csrf??null};}
 @Patch('me/profile') async profile(@Body() body:unknown,@Req() req:any){return {user:await this.auth.updateProfile(req.user,body)};}
 @Post('me/password') async password(@Body() body:unknown,@Req() req:any,@Res({passthrough:true}) res:Response){const result=await this.auth.changePassword(req.user,body);this.clear(res);return result;}
 @Public() @Get('csrf') async csrf(@Req() req:Request){return {csrfToken:await this.auth.csrfForRefresh(req.cookies?.kongos_refresh,req.cookies?.kongos_csrf)};}
 @Public() @Post('refresh')
 async refresh(@Req() req:Request,@Res({passthrough:true}) res:Response){const result=await this.auth.refresh(req.cookies?.kongos_refresh,req.get('x-csrf-token'));this.cookies(res,result);return {user:result.user};}
 @Post('logout')
 async logout(@Req() req:any,@Res({passthrough:true}) res:Response){await this.auth.revoke(req.sessionId,req.user.id);this.clear(res);return {loggedOut:true};}
 @Public() @Get('providers') providers(){return this.auth.providerCatalog();}
 @Get('me/sessions') sessions(@Req() req:any,@Query('size') size:string|undefined,@Query('cursor') cursor:string|undefined){return this.auth.listSessions(req.user,req.user.id,{size:size===undefined?undefined:Number(size),cursor});}
 @Get('users/:userId/sessions') userSessions(@Req() req:any,@Param('userId') id:string,@Query('size') size:string|undefined,@Query('cursor') cursor:string|undefined){return this.auth.listSessions(req.user,id,{size:size===undefined?undefined:Number(size),cursor});}
 @Post('me/sessions/revoke-all') async allSessions(@Req() req:any,@Body() body:unknown,@Res({passthrough:true}) res:Response){const result=await this.auth.revokeSessions(req.user,req.user.id,body);this.clear(res);return result;}
 @Post('me/sessions/:sessionId/revoke') async oneSession(@Req() req:any,@Param('sessionId') sid:string,@Body() body:unknown,@Res({passthrough:true}) res:Response){const result=await this.auth.revokeSessions(req.user,req.user.id,body,sid);if(result.loggedOut)this.clear(res);return result;}
 @Post('users/:userId/sessions/revoke-all') async userAllSessions(@Req() req:any,@Param('userId') id:string,@Body() body:unknown,@Res({passthrough:true}) res:Response){const result=await this.auth.revokeSessions(req.user,id,body);if(result.loggedOut)this.clear(res);return result;}
 @Post('users/:userId/sessions/:sessionId/revoke') async userOneSession(@Req() req:any,@Param('userId') id:string,@Param('sessionId') sid:string,@Body() body:unknown,@Res({passthrough:true}) res:Response){const result=await this.auth.revokeSessions(req.user,id,body,sid);if(result.loggedOut)this.clear(res);return result;}
 @Public() @Post('ldap/:providerId/login') async ldap(@Param('providerId') id:string,@Body() body:unknown,@Req() req:Request,@Res({passthrough:true}) res:Response){this.origin(req);const result=await this.auth.ldapLogin(id,body,req.ip??'',req.get('user-agent')??'');this.cookies(res,result);return {user:result.user,csrfToken:result.csrfToken};}
 @Public() @Get('oidc/:providerId/start') async oidcStart(@Param('providerId') id:string,@Query('redirect') redirect:string|undefined,@Req() req:Request,@Res({passthrough:true}) res:Response){
  const result=await this.auth.oidcStart(id,redirect??'/',req.ip??'');res.cookie('kongos_oidc',result.correlation,{httpOnly:true,secure:result.callbackSecure,sameSite:'lax',path:'/api/v1/auth/oidc',maxAge:300000});return {authorizationUrl:result.authorizationUrl};
 }
 @Public() @Get('oidc/:providerId/callback') async oidcCallback(@Param('providerId') id:string,@Query('code') code:string,@Query('state') state:string,@Req() req:Request,@Res() res:Response){
  const correlation=req.cookies?.kongos_oidc;res.clearCookie('kongos_oidc',{path:'/api/v1/auth/oidc'});
  const result=await this.auth.oidcCallback(id,code,state,correlation,req.ip??'',req.get('user-agent')??'');this.cookies(res,result);res.redirect(303,result.redirect);
 }
}
