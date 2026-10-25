import { Body, Controller, Get, Headers, Post, Query, Req, Param } from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import type { EntityActor } from '../entities/entities.types';
import { VitalsService } from './vitals.service';
import type { VitalsQuery } from './vitals.types';
@ApiTags('Vitals 监控')
@Controller('clusters/:clusterId/vitals')
export class VitalsController {
  constructor(private readonly service: VitalsService) {}
  private actor(req: EntityActor, wid?: string, key?: string): EntityActor { return { user: req.user, requestId: req.requestId, ip: req.ip, workspaceId: wid, idempotencyKey: key }; }
  @Get('capabilities') capabilities(@Param('clusterId') cid: string, @Query() query: VitalsQuery, @Req() req: EntityActor) { return this.service.capabilities(cid, query, this.actor(req, query.workspaceId)); }
  @Get('overview') overview(@Param('clusterId') cid: string, @Query() query: VitalsQuery, @Req() req: EntityActor) { return this.service.overview(cid, query, this.actor(req, query.workspaceId)); }
  @Get('entities') entities(@Param('clusterId') cid: string, @Query() query: Record<string, unknown>, @Req() req: EntityActor) { return this.service.entities(cid, query, this.actor(req, typeof query.workspaceId === 'string' ? query.workspaceId : undefined)); }
  @Post('setup') setup(@Param('clusterId') cid: string, @Query() query: Record<string, unknown>, @Body() body: unknown, @Headers('x-idempotency-key') key: string, @Req() req: EntityActor) { return this.service.setup(cid, query, body, this.actor(req, typeof query.workspaceId === 'string' ? query.workspaceId : undefined, key)); }
  @Get('setup/receipts/by-key/:key') setupReceipt(@Param('clusterId') cid: string, @Param('key') key: string, @Query() query: Record<string, unknown>, @Req() req: EntityActor) { return this.service.setupReceipt(cid, key, query, this.actor(req, typeof query.workspaceId === 'string' ? query.workspaceId : undefined)); }
}
