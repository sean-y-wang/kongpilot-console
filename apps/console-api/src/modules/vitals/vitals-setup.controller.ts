import {Body,Controller,Get,Headers,Param,Post,Query,Req} from '@nestjs/common';
import {ApiTags} from '@nestjs/swagger';
import type {EntityActor} from '../entities/entities.types';
import {VitalsSetupService} from './vitals-setup.service';
/** Registered by WorkflowsModule; VitalsModule never imports workflows. */
@ApiTags('Vitals 监控设置审批')
@Controller('clusters/:clusterId/vitals')
export class VitalsSetupController {
 constructor(private readonly setup:VitalsSetupService){}
 private actor(req:EntityActor,query:Record<string,unknown>,key?:string):EntityActor{return{user:req.user,requestId:req.requestId,ip:req.ip,
  workspaceId:typeof query.workspaceId==='string'?query.workspaceId:undefined,idempotencyKey:key};}
 @Post('setup/prepare') prepare(@Param('clusterId') cid:string,@Query() query:Record<string,unknown>,@Body() body:unknown,@Headers('x-idempotency-key') key:string,@Req() req:EntityActor){return this.setup.prepare(cid,query,body,this.actor(req,query,key));}
 @Get('setup/intents/by-key/:key') byKey(@Param('clusterId') cid:string,@Param('key') key:string,@Query() query:Record<string,unknown>,@Req() req:EntityActor){return this.setup.byKey(cid,key,query,this.actor(req,query));}
 @Get('setup/intents/:id') get(@Param('clusterId') cid:string,@Param('id') id:string,@Query() query:Record<string,unknown>,@Req() req:EntityActor){return this.setup.get(cid,id,query,this.actor(req,query));}
 @Post('setup/intents/:id/submit') submit(@Param('clusterId') cid:string,@Param('id') id:string,@Query() query:Record<string,unknown>,@Body() body:unknown,@Headers('x-idempotency-key') key:string,@Req() req:EntityActor){return this.setup.submit(cid,id,query,body,this.actor(req,query,key));}
 @Get('setup/intents/:id/receipt') receipt(@Param('clusterId') cid:string,@Param('id') id:string,@Query() query:Record<string,unknown>,@Req() req:EntityActor){return this.setup.receipt(cid,id,query,this.actor(req,query));}
}
