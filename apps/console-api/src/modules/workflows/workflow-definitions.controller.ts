import { Body, Controller, Get, Headers, Param, Post, Query, Req } from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import type { EntityActor } from '../entities/entities.types';
import { workflowId } from './workflow-validation';
import { WorkflowDefinitionsService } from './workflow-definitions.service';
@ApiTags('审批政策')
@Controller('clusters/:clusterId/workflow-definitions')
export class WorkflowDefinitionsController {
  constructor(private readonly service: WorkflowDefinitionsService) {}
  private actor(req: EntityActor, query: Record<string, unknown>, key?: string): EntityActor { return { user: req.user, requestId: req.requestId, ip: req.ip, workspaceId: workflowId(query.workspaceId), idempotencyKey: key }; }
  @Get() list(@Param('clusterId') cid: string, @Query() query: Record<string, unknown>, @Req() req: EntityActor) { return this.service.list(cid, query, this.actor(req, query)); }
  @Post(':id/versions') version(@Param('clusterId') cid: string, @Param('id') id: string, @Query() query: Record<string, unknown>, @Body() body: unknown, @Headers('x-idempotency-key') key: string, @Req() req: EntityActor) { return this.service.mutate(cid, id, 'version', body, this.actor(req, query, key)); }
  @Post(':id/archive') archive(@Param('clusterId') cid: string, @Param('id') id: string, @Query() query: Record<string, unknown>, @Body() body: unknown, @Headers('x-idempotency-key') key: string, @Req() req: EntityActor) { return this.service.mutate(cid, id, 'archive', body, this.actor(req, query, key)); }
  @Post(':id/restore') restore(@Param('clusterId') cid: string, @Param('id') id: string, @Query() query: Record<string, unknown>, @Body() body: unknown, @Headers('x-idempotency-key') key: string, @Req() req: EntityActor) { return this.service.mutate(cid, id, 'restore', body, this.actor(req, query, key)); }
}
