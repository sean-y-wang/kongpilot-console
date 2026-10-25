import {Body,Controller,Get,Headers,Param,Post,Req} from '@nestjs/common';
import {ApiTags} from '@nestjs/swagger';
import type {EntityActor} from '../entities/entities.types';
import {ControlMetadataService} from './control-metadata.service';

@ApiTags('控制面配置审批')
@Controller('clusters/:clusterId/control-changes')
export class ControlMetadataController {
 constructor(private readonly service:ControlMetadataService){}
 private actor(req:EntityActor,key?:string):EntityActor{return {user:req.user,requestId:req.requestId,ip:req.ip,idempotencyKey:key};}
 @Post('prepare') prepare(@Param('clusterId') cid:string,@Body() body:unknown,@Headers('x-idempotency-key') key:string,@Req() req:EntityActor){return this.service.prepare(cid,body,this.actor(req,key));}
 @Get('by-key/:key') byKey(@Param('clusterId') cid:string,@Param('key') key:string,@Req() req:EntityActor){return this.service.receiptByKey(cid,key,this.actor(req));}
 @Get(':id') receipt(@Param('clusterId') cid:string,@Param('id') id:string,@Req() req:EntityActor){return this.service.receipt(cid,id,this.actor(req));}
 @Post(':id/submit') submit(@Param('clusterId') cid:string,@Param('id') id:string,@Body() body:unknown,@Headers('x-idempotency-key') key:string,@Req() req:EntityActor){return this.service.submit(cid,id,body,this.actor(req,key));}
}
