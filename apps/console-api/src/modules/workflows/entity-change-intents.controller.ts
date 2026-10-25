import { Body, Controller, Get, Headers, Param, Post, Query, Req } from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import type { EntityActor } from '../entities/entities.types';
import { workflowId } from './workflow-validation';
import { portalObject } from '../portal/portal-input';
import { EntityChangeIntentsService } from './entity-change-intents.service';
@ApiTags('配置变更意图')
@Controller('clusters/:clusterId/entity-changes')
export class EntityChangeIntentsController {
  constructor(private readonly service: EntityChangeIntentsService) {}
  private actor(req: EntityActor, query: Record<string, unknown>, key?: string): EntityActor { portalObject(query, ['workspaceId']); return { user: req.user, requestId: req.requestId, ip: req.ip, workspaceId: workflowId(query.workspaceId), idempotencyKey: key }; }
  @Post('prepare') prepare(@Param('clusterId') cid: string, @Query() query: Record<string, unknown>, @Body() body: unknown, @Headers('x-idempotency-key') key: string, @Req() req: EntityActor) { return this.service.prepare(cid, body, this.actor(req, query, key)); }
  @Post('prepare-scheduled') prepareScheduled(@Param('clusterId') cid: string, @Query() query: Record<string, unknown>, @Body() body: unknown, @Headers('x-idempotency-key') key: string, @Req() req: EntityActor) { return this.service.prepareScheduled(cid, body, this.actor(req, query, key)); }
  @Get('by-prepare-key/:key') byPrepareKey(@Param('clusterId') cid:string,@Param('key') key:string,@Query() query:Record<string,unknown>,@Req() req:EntityActor){return this.service.byPrepareKey(cid,key,this.actor(req,query));}
  @Get(':id') get(@Param('clusterId') cid: string, @Param('id') id: string, @Query() query: Record<string, unknown>, @Req() req: EntityActor) { return this.service.get(cid, id, this.actor(req, query)); }
  @Post(':id/submit') submit(@Param('clusterId') cid: string, @Param('id') id: string, @Query() query: Record<string, unknown>, @Body() body: unknown, @Headers('x-idempotency-key') key: string, @Req() req: EntityActor) { return this.service.submit(cid, id, body, this.actor(req, query, key)); }
}
