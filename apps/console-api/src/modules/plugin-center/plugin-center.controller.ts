import { Body, Controller, Get, Headers, Param, Post, Query, Req } from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import type { EntityActor } from '../entities/entities.types';
import { PluginCenterService, PluginQuery } from './plugin-center.service';

@ApiTags('动态插件中心')
@Controller('clusters/:clusterId/plugin-center')
export class PluginCenterController {
  constructor(private readonly service: PluginCenterService) {}
  private actor(req: EntityActor, workspaceId?: string, key?: string): EntityActor { return { user: req.user, requestId: req.requestId, ip: req.ip, idempotencyKey: key, workspaceId }; }
  @Get('catalog') catalog(@Param('clusterId') cid: string, @Query() query: PluginQuery, @Req() actor: EntityActor) { return this.service.catalog(cid, query, this.actor(actor, query.workspaceId)); }
  @Get('schemas/:name') schema(@Param('clusterId') cid: string, @Param('name') name: string, @Query('workspaceId') workspaceId: string | undefined, @Req() actor: EntityActor) { return this.service.schema(cid, name, this.actor(actor, workspaceId)); }
  @Get('instances') instances(@Param('clusterId') cid: string, @Query() query: PluginQuery, @Req() actor: EntityActor) { return this.service.instances(cid, query, this.actor(actor, query.workspaceId)); }
  @Get('precedence') precedence(@Param('clusterId') cid: string, @Query('workspaceId') workspaceId: string | undefined, @Req() actor: EntityActor) { return this.service.precedence(cid, this.actor(actor, workspaceId)); }
  @Get('context') context(@Param('clusterId') cid: string, @Query() query: PluginQuery, @Req() actor: EntityActor) { return this.service.context(cid, query, this.actor(actor, query.workspaceId)); }
  @Post('instances/:pluginId/toggle') toggle(@Param('clusterId') cid: string, @Param('pluginId') id: string, @Body() body: unknown, @Headers('x-idempotency-key') key: string, @Query('workspaceId') workspaceId: string | undefined, @Req() req: EntityActor) { return this.service.toggle(cid, id, body, this.actor(req, workspaceId, key)); }
}
