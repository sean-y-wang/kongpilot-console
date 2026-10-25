import {Body,Controller,Get,Headers,HttpCode,Param,Post,Query,Req} from '@nestjs/common';
import {ApiTags} from '@nestjs/swagger';
import type {EntityActor} from '../entities/entities.types';
import {portalObject} from '../portal/portal-input';
import {workflowId} from './workflow-validation';
import {WorkflowBusinessSchedulesService} from './workflow-business-schedules.service';

/** Global authentication guard supplies the real HTTP actor. No principal,
 * SID, native plan, approval result or claim can be supplied in request DTOs. */
@ApiTags('业务排程')
@Controller('clusters/:clusterId/workflow-schedules')
export class WorkflowBusinessSchedulesController {
 constructor(private readonly service:WorkflowBusinessSchedulesService){}
 private actor(req:EntityActor,query:Record<string,unknown>,key?:string):EntityActor{
  return{user:req.user,requestId:req.requestId,ip:req.ip,workspaceId:workflowId(query.workspaceId),idempotencyKey:key};
 }
 @Get() list(@Param('clusterId') cid:string,@Query() query:Record<string,unknown>,@Req() req:EntityActor){
  const q=portalObject(query,['workspaceId','size','cursor']);return this.service.list(cid,q,this.actor(req,q));
 }
 @Get('receipts/by-key/:key') receipt(@Param('clusterId') cid:string,@Param('key') key:string,@Query() query:Record<string,unknown>,@Req() req:EntityActor){
  const q=portalObject(query,['workspaceId']);return this.service.receiptByKey(cid,key,this.actor(req,q));
 }
 @Get(':id') get(@Param('clusterId') cid:string,@Param('id') id:string,@Query() query:Record<string,unknown>,@Req() req:EntityActor){
  const q=portalObject(query,['workspaceId']);return this.service.get(cid,id,this.actor(req,q));
 }
 @Post() @HttpCode(201) author(@Param('clusterId') cid:string,@Query() query:Record<string,unknown>,@Body() body:unknown,@Headers('x-idempotency-key') key:string,@Req() req:EntityActor){
  const q=portalObject(query,['workspaceId']);return this.service.author(cid,body,this.actor(req,q,key));
 }
 @Post(':id/activate') @HttpCode(200) activate(@Param('clusterId') cid:string,@Param('id') id:string,@Query() query:Record<string,unknown>,@Body() body:unknown,@Headers('x-idempotency-key') key:string,@Req() req:EntityActor){
  const q=portalObject(query,['workspaceId']);return this.service.command(cid,id,'activate',body,this.actor(req,q,key));
 }
 @Post(':id/cancel') @HttpCode(200) cancel(@Param('clusterId') cid:string,@Param('id') id:string,@Query() query:Record<string,unknown>,@Body() body:unknown,@Headers('x-idempotency-key') key:string,@Req() req:EntityActor){
  const q=portalObject(query,['workspaceId']);return this.service.command(cid,id,'cancel',body,this.actor(req,q,key));
 }
}
