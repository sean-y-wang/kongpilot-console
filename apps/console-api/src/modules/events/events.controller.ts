import { Body, Controller, Delete, Get, Headers, Param, Patch, Post, Query, Req } from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import type { EntityActor } from '../entities/entities.types';
import { eventId, eventObject } from './events-input';
import { EventsService } from './events.service';
import { EventsCompilerService } from './events-compiler.service';

@ApiTags('事件钩子') @Controller('clusters/:clusterId/events')
export class EventsController {
  constructor(private readonly reads:EventsService,private readonly writes:EventsCompilerService) {}
  private actor(req:EntityActor,query:Record<string,unknown>,key?:string,write=false):EntityActor {
    if(write)eventObject(query,['workspaceId']);
    return{user:req.user,requestId:req.requestId,ip:req.ip,workspaceId:eventId(query.workspaceId),idempotencyKey:key};
  }
  @Get('catalog') catalog(@Param('clusterId') cid:string,@Query() query:Record<string,unknown>,@Req() req:EntityActor){eventObject(query,['workspaceId']);return this.reads.catalog(cid,this.actor(req,query));}
  @Get('operations/by-key/:key') receipt(@Param('clusterId') cid:string,@Param('key') key:string,@Query() query:Record<string,unknown>,@Req() req:EntityActor){eventObject(query,['workspaceId']);return this.writes.receipt(cid,key,this.actor(req,query));}
  @Get('records') records(@Param('clusterId') cid:string,@Query() q:Record<string,unknown>,@Req() req:EntityActor){return this.reads.records(cid,q,this.actor(req,q));}
  @Get('records/:id') record(@Param('clusterId') cid:string,@Param('id') id:string,@Query() q:Record<string,unknown>,@Req() req:EntityActor){eventObject(q,['workspaceId']);return this.reads.record(cid,id,this.actor(req,q));}
  @Get('channels') channels(@Param('clusterId') cid:string,@Query() q:Record<string,unknown>,@Req() req:EntityActor){return this.reads.directory('channels',cid,q,this.actor(req,q));}
  @Get('channels/:id') channel(@Param('clusterId') cid:string,@Param('id') id:string,@Query() q:Record<string,unknown>,@Req() req:EntityActor){eventObject(q,['workspaceId']);return this.reads.detail('channels',cid,id,this.actor(req,q));}
  @Post('channels') createChannel(@Param('clusterId') cid:string,@Query() q:Record<string,unknown>,@Body() b:unknown,@Headers('x-idempotency-key') key:string,@Req() req:EntityActor){return this.writes.channel(cid,undefined,b,this.actor(req,q,key,true));}
  @Patch('channels/:id') updateChannel(@Param('clusterId') cid:string,@Param('id') id:string,@Query() q:Record<string,unknown>,@Body() b:unknown,@Headers('x-idempotency-key') key:string,@Req() req:EntityActor){return this.writes.channel(cid,id,b,this.actor(req,q,key,true));}
  @Post('channels/:id/status') status(@Param('clusterId') cid:string,@Param('id') id:string,@Query() q:Record<string,unknown>,@Body() b:unknown,@Headers('x-idempotency-key') key:string,@Req() req:EntityActor){return this.writes.action(cid,id,'event.channel.status',b,this.actor(req,q,key,true));}
  @Delete('channels/:id') deleteChannel(@Param('clusterId') cid:string,@Param('id') id:string,@Query() q:Record<string,unknown>,@Body() b:unknown,@Headers('x-idempotency-key') key:string,@Req() req:EntityActor){return this.writes.action(cid,id,'event.channel.delete',b,this.actor(req,q,key,true));}
  @Post('channels/:id/restore') restoreChannel(@Param('clusterId') cid:string,@Param('id') id:string,@Query() q:Record<string,unknown>,@Body() b:unknown,@Headers('x-idempotency-key') key:string,@Req() req:EntityActor){return this.writes.action(cid,id,'event.channel.restore',b,this.actor(req,q,key,true));}
  @Post('channels/:id/test') test(@Param('clusterId') cid:string,@Param('id') id:string,@Query() q:Record<string,unknown>,@Body() b:unknown,@Headers('x-idempotency-key') key:string,@Req() req:EntityActor){return this.writes.action(cid,id,'event.channel.test',b,this.actor(req,q,key,true));}
  @Get('subscriptions') subscriptions(@Param('clusterId') cid:string,@Query() q:Record<string,unknown>,@Req() req:EntityActor){return this.reads.directory('subscriptions',cid,q,this.actor(req,q));}
  @Get('subscriptions/:id') subscription(@Param('clusterId') cid:string,@Param('id') id:string,@Query() q:Record<string,unknown>,@Req() req:EntityActor){eventObject(q,['workspaceId']);return this.reads.detail('subscriptions',cid,id,this.actor(req,q));}
  @Post('subscriptions') createSubscription(@Param('clusterId') cid:string,@Query() q:Record<string,unknown>,@Body() b:unknown,@Headers('x-idempotency-key') key:string,@Req() req:EntityActor){return this.writes.subscription(cid,undefined,b,this.actor(req,q,key,true));}
  @Patch('subscriptions/:id') updateSubscription(@Param('clusterId') cid:string,@Param('id') id:string,@Query() q:Record<string,unknown>,@Body() b:unknown,@Headers('x-idempotency-key') key:string,@Req() req:EntityActor){return this.writes.subscription(cid,id,b,this.actor(req,q,key,true));}
  @Delete('subscriptions/:id') deleteSubscription(@Param('clusterId') cid:string,@Param('id') id:string,@Query() q:Record<string,unknown>,@Body() b:unknown,@Headers('x-idempotency-key') key:string,@Req() req:EntityActor){return this.writes.action(cid,id,'event.subscription.delete',b,this.actor(req,q,key,true));}
  @Post('subscriptions/:id/restore') restoreSubscription(@Param('clusterId') cid:string,@Param('id') id:string,@Query() q:Record<string,unknown>,@Body() b:unknown,@Headers('x-idempotency-key') key:string,@Req() req:EntityActor){return this.writes.action(cid,id,'event.subscription.restore',b,this.actor(req,q,key,true));}
  @Get('deliveries') deliveries(@Param('clusterId') cid:string,@Query() q:Record<string,unknown>,@Req() req:EntityActor){return this.reads.deliveries(cid,q,this.actor(req,q));}
  @Get('deliveries/:id') delivery(@Param('clusterId') cid:string,@Param('id') id:string,@Query() q:Record<string,unknown>,@Req() req:EntityActor){eventObject(q,['workspaceId']);return this.reads.delivery(cid,id,this.actor(req,q));}
  @Get('deliveries/:id/attempts') attempts(@Param('clusterId') cid:string,@Param('id') id:string,@Query() q:Record<string,unknown>,@Req() req:EntityActor){return this.reads.attempts(cid,id,q,this.actor(req,q));}
  @Post('deliveries/:id/replay') replay(@Param('clusterId') cid:string,@Param('id') id:string,@Query() q:Record<string,unknown>,@Body() b:unknown,@Headers('x-idempotency-key') key:string,@Req() req:EntityActor){return this.writes.action(cid,id,'event.delivery.replay',b,this.actor(req,q,key,true));}
}
