import {All,ArgumentsHost,Body,Catch,Controller,Delete,ExceptionFilter,ForbiddenException,HttpException,Inject,Optional,Param,Post,Query,Req,Res,UseFilters,UseGuards} from '@nestjs/common';
import {ApiTags} from '@nestjs/swagger';
import type {Response} from 'express';
import {Public} from '../../common/auth';
import {finalizeHttpErrorResponse} from '../../common/http';
import {RequestFailureAuditService} from '../audit/request-failure-audit.service';
import {DeckAdapterService} from './deck-adapter.service';
import {DeckSessionGuard} from './deck-session.guard';
import {DeckSessionService} from './deck-session.service';
import {DECK_UUID,deckObject} from './deck-protocol';

@Catch()
export class DeckErrorFilter implements ExceptionFilter{
 constructor(@Optional() @Inject(RequestFailureAuditService)private readonly requestAudit?:RequestFailureAuditService){}
 catch(error:unknown,host:ArgumentsHost){
  const http=host.switchToHttp(),res=http.getResponse<Response>(),req=http.getRequest<object>();
  if(res.headersSent){const close=()=>finalizeHttpErrorResponse(res,()=>res.destroy());if(this.requestAudit)return this.requestAudit.recordFailure(req,'disconnected').then(close,close);close();return;}
  const status=error instanceof HttpException?error.getStatus():503,response=error instanceof HttpException?error.getResponse():null;
  const code=response&&typeof response==='object'&&'code'in response&&typeof response.code==='string'&&/^[A-Z0-9_]{2,128}$/.test(response.code)?response.code:'DECK_REQUEST_FAILED';
  // go-kong expects a Kong-shaped message. Never relay free-form validator
  // strings/fields, bodies, URLs, stack traces or credential-bearing errors.
  const failureStatus=status>=400&&status<=599?status:503;
  const send=()=>finalizeHttpErrorResponse(res,()=>{res.setHeader('Cache-Control','no-store');res.status(failureStatus).json({message:code});});
  if(this.requestAudit)return this.requestAudit.recordFailure(req,failureStatus).then(send,send);send();
 }
}
@ApiTags('受控 decK 1.1 协议')
@Public()
@UseGuards(DeckSessionGuard)
@UseFilters(DeckErrorFilter)
@Controller('deck/:deckSessionId')
export class DeckAdapterController{
 constructor(@Inject(DeckAdapterService)private readonly adapter:DeckAdapterService){}
 @All(['',':type',':type/:id',':type/:parentId/:childType',':type/:parentId/:childType/:childId'])
 async request(@Req()req:any,@Res()res:Response){
  const prefix=`/api/v1/deck/${req.params.deckSessionId}`,raw=String(req.originalUrl??'').split('?')[0];
  if(raw!==prefix&&!raw.startsWith(prefix+'/'))throw new ForbiddenException({code:'DECK_PATH_INVALID'});
  const result=await this.adapter.dispatch(req.deckSession,req.method,raw.slice(prefix.length)||'/',req.query,req.body);
  res.setHeader('Cache-Control','no-store');res.setHeader('Content-Type','application/json');
  if(result.status===204){res.status(204).end();return;}res.status(result.status).json(result.body);
 }
}
@ApiTags('GitOps 专用会话')
@Controller('clusters/:clusterId/configuration/deck-sessions')
export class DeckSessionsController{
 constructor(@Inject(DeckSessionService)private readonly sessions:DeckSessionService){}
 private actor(req:any,cid:string,query:unknown){
  const q=query&&typeof query==='object'&&!Array.isArray(query)?query as any:null;
  if(!q||Object.keys(q).some(k=>k!=='workspaceId')||q.workspaceId!==undefined&&(typeof q.workspaceId!=='string'||!DECK_UUID.test(q.workspaceId)))throw new ForbiddenException({code:'DECK_SCOPE_INVALID'});
  return{user:req.user,sessionId:req.sessionId,clusterId:cid,workspaceId:q.workspaceId,requestId:req.requestId};
 }
 @Post()issue(@Param('clusterId')cid:string,@Query()query:unknown,@Body()body:unknown,@Req()req:any){return this.sessions.issue(body,this.actor(req,cid,query));}
 @Delete(':deckSessionId')revoke(@Param('clusterId')cid:string,@Param('deckSessionId')id:string,@Query()query:unknown,@Body()body:unknown,@Req()req:any){
  const row=deckObject(body,4096);if(Object.keys(row).some(k=>!['revision','confirmed','confirm_name'].includes(k))||row.confirmed!==true||row.confirm_name!==id||!Number.isSafeInteger(row.revision))throw new ForbiddenException({code:'DECK_REVOKE_CONFIRMATION_REQUIRED'});
  return this.sessions.revoke(id,Number(row.revision),this.actor(req,cid,query));
 }
}
