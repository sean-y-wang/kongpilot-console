import { Body, Controller, Delete, Get, Headers, Param, Patch, Post, Req } from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import { Actor, ClustersService } from './clusters.service';

@ApiTags('集群管理')
@Controller('clusters')
export class ClustersController {
  constructor(private readonly service: ClustersService) {}
  private actor(req:Actor,key?:string):Actor{return {user:req.user,requestId:req.requestId,ip:req.ip,idempotencyKey:key};}
  @Get() list(@Req() req:Actor) { return this.service.list(this.actor(req)); }
  @Post() create(@Body() body: unknown,@Headers('x-idempotency-key') key:string, @Req() req: Actor) { return this.service.create(body,this.actor(req,key)); }
  @Get(':clusterId') get(@Param('clusterId') id: string,@Req() req:Actor) { return this.service.get(id,this.actor(req)); }
  @Patch(':clusterId') update(@Param('clusterId') id: string, @Body() body: unknown,@Headers('x-idempotency-key') key:string, @Req() req: Actor) { return this.service.update(id, body,this.actor(req,key)); }
  @Post(':clusterId/probe') probe(@Param('clusterId') id: string,@Headers('x-idempotency-key') key:string, @Req() req: Actor) { return this.service.probe(id,this.actor(req,key)); }
  @Post(':clusterId/test') test(@Param('clusterId') id:string,@Headers('x-idempotency-key') key:string,@Req() req:Actor){return this.service.probe(id,this.actor(req,key));}
  @Get(':clusterId/capabilities') capabilities(@Param('clusterId') id: string,@Req() req:Actor) { return this.service.capabilities(id,this.actor(req)); }
  @Post(':clusterId/deactivate') deactivate(@Param('clusterId') id: string, @Body() body: unknown,@Headers('x-idempotency-key') key:string, @Req() req: Actor) { return this.service.deactivate(id, body,this.actor(req,key)); }
  @Delete(':clusterId') delete(@Param('clusterId') id:string,@Body() body:unknown,@Headers('x-idempotency-key') key:string,@Req() req:Actor){return this.service.deactivate(id,body,this.actor(req,key));}
}
