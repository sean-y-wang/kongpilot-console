import { Body, Controller, Delete, Get, Headers, Param, Post, Put, Query, Req } from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import type { EntityActor } from '../entities/entities.types';
import { EntityAnnotationsService, type ConfirmEntityAnnotationInput, type SetEntityAnnotationInput } from './entity-annotations.service';

@ApiTags('实体负责人和备注')
@Controller('clusters/:clusterId/entity-annotations/:entityType/:entityId')
export class EntityAnnotationsController {
  constructor(private readonly service: EntityAnnotationsService) {}
  private actor(req: EntityActor, key?: string): EntityActor {
    return { user: req.user, requestId: req.requestId, ip: req.ip, idempotencyKey: key };
  }

  @Get() get(@Param('clusterId') cid: string, @Param('entityType') type: string, @Param('entityId') id: string,
    @Query('workspaceId') workspaceId: string | undefined, @Req() req: EntityActor) {
    return this.service.get(cid, type, id, this.actor(req), workspaceId);
  }

  @Put() set(@Param('clusterId') cid: string, @Param('entityType') type: string, @Param('entityId') id: string,
    @Body() body: SetEntityAnnotationInput, @Query('workspaceId') workspaceId: string | undefined,
    @Headers('x-idempotency-key') key: string | undefined, @Req() req: EntityActor) {
    return this.service.set(cid, type, id, body, this.actor(req, key), workspaceId);
  }

  @Delete() remove(@Param('clusterId') cid: string, @Param('entityType') type: string, @Param('entityId') id: string,
    @Body() body: ConfirmEntityAnnotationInput, @Query('workspaceId') workspaceId: string | undefined,
    @Headers('x-idempotency-key') key: string | undefined, @Req() req: EntityActor) {
    return this.service.remove(cid, type, id, body, this.actor(req, key), workspaceId);
  }

  @Post('restore') restore(@Param('clusterId') cid: string, @Param('entityType') type: string, @Param('entityId') id: string,
    @Body() body: ConfirmEntityAnnotationInput, @Query('workspaceId') workspaceId: string | undefined,
    @Headers('x-idempotency-key') key: string | undefined, @Req() req: EntityActor) {
    return this.service.restore(cid, type, id, body, this.actor(req, key), workspaceId);
  }
}
