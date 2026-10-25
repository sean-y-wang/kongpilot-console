import { Body, Controller, Delete, Get, Headers, Param, Patch, Post, Req } from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import { Actor } from '../clusters/clusters.service';
import { DataSourcesService } from './data-sources.service';

@ApiTags('数据源管理')
@Controller('clusters/:clusterId/data-sources')
export class DataSourcesController {
  constructor(private readonly service: DataSourcesService) {}
  private actor(req:Actor,key?:string):Actor{return {user:req.user,requestId:req.requestId,ip:req.ip,idempotencyKey:key};}
  @Get() list(@Param('clusterId') clusterId: string,@Req() req:Actor) { return this.service.list(clusterId,this.actor(req)); }
  @Post() create(@Param('clusterId') clusterId: string, @Body() body: unknown,@Headers('x-idempotency-key') key:string, @Req() req: Actor) { return this.service.create(clusterId, body,this.actor(req,key)); }
  @Get(':id') get(@Param('clusterId') clusterId: string, @Param('id') id: string,@Req() req:Actor) { return this.service.get(clusterId, id,this.actor(req)); }
  @Patch(':id') update(@Param('clusterId') clusterId: string, @Param('id') id: string, @Body() body: unknown,@Headers('x-idempotency-key') key:string, @Req() req: Actor) { return this.service.update(clusterId, id, body,this.actor(req,key)); }
  @Post(':id/probe') probe(@Param('clusterId') clusterId: string, @Param('id') id: string,@Headers('x-idempotency-key') key:string, @Req() req: Actor) { return this.service.probe(clusterId, id,this.actor(req,key)); }
  @Post(':id/test') test(@Param('clusterId') cid:string,@Param('id') id:string,@Headers('x-idempotency-key') key:string,@Req() req:Actor){return this.service.probe(cid,id,this.actor(req,key));}
  @Post(':id/deactivate') deactivate(@Param('clusterId') clusterId: string, @Param('id') id: string, @Body() body: unknown,@Headers('x-idempotency-key') key:string, @Req() req: Actor) { return this.service.deactivate(clusterId, id, body,this.actor(req,key)); }
  @Delete(':id') delete(@Param('clusterId') cid:string,@Param('id') id:string,@Body() body:unknown,@Headers('x-idempotency-key') key:string,@Req() req:Actor){return this.service.deactivate(cid,id,body,this.actor(req,key));}
}
