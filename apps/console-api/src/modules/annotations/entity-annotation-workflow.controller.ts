import {Body,Controller,Get,Headers,Param,Post,Query,Req} from '@nestjs/common';
import {ApiTags} from '@nestjs/swagger';
import type {EntityActor} from '../entities/entities.types';
import {EntityAnnotationWorkflowService} from './entity-annotation-workflow.service';
@ApiTags('实体备注审批')
@Controller('clusters/:clusterId/annotation-changes')
export class EntityAnnotationWorkflowController {
 constructor(private readonly service:EntityAnnotationWorkflowService){}
 private actor(req:EntityActor,wid:string,key?:string):EntityActor{return {user:req.user,requestId:req.requestId,ip:req.ip,workspaceId:wid,idempotencyKey:key};}
 @Post('prepare') prepare(@Param('clusterId') cid:string,@Query('workspaceId') wid:string,@Body() body:unknown,@Headers('x-idempotency-key') key:string,@Req() req:EntityActor){return this.service.prepare(cid,wid,body,this.actor(req,wid,key));}
 @Get('by-key/:key') byKey(@Param('clusterId') cid:string,@Query('workspaceId') wid:string,@Param('key') key:string,@Req() req:EntityActor){return this.service.receiptByKey(cid,wid,key,this.actor(req,wid));}
 @Get(':id') receipt(@Param('clusterId') cid:string,@Query('workspaceId') wid:string,@Param('id') id:string,@Req() req:EntityActor){return this.service.receipt(cid,wid,id,this.actor(req,wid));}
 @Post(':id/submit') submit(@Param('clusterId') cid:string,@Query('workspaceId') wid:string,@Param('id') id:string,@Body() body:unknown,@Headers('x-idempotency-key') key:string,@Req() req:EntityActor){return this.service.submit(cid,wid,id,body,this.actor(req,wid,key));}
}
