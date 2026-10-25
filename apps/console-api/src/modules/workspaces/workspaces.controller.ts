import { Body, Controller, Delete, Get, Headers, Param, Patch, Post, Query, Req } from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import type { EntityActor } from '../entities/entities.types';
import { WorkspaceService, CreateWorkspaceInput, UpdateWorkspaceInput, ConfirmWorkspaceInput, WorkspaceListOptions } from './workspace.service';

@ApiTags('工作区')
@Controller('clusters/:clusterId/workspaces')
export class WorkspacesController {
  constructor(private readonly service:WorkspaceService){}
  private actor(req:EntityActor,key?:string):EntityActor{return {user:req.user,requestId:req.requestId,ip:req.ip,idempotencyKey:key};}
  @Get() list(@Param('clusterId') cid:string,@Query() query:WorkspaceListOptions,@Req() req:EntityActor){return this.service.list(cid,query,this.actor(req));}
  @Post() create(@Param('clusterId') cid:string,@Body() body:CreateWorkspaceInput,@Headers('x-idempotency-key') key:string,@Req() req:EntityActor){return this.service.create(cid,body,this.actor(req,key));}
  @Get(':workspaceId') get(@Param('clusterId') cid:string,@Param('workspaceId') wid:string,@Req() req:EntityActor){return this.service.get(cid,wid,this.actor(req));}
  @Patch(':workspaceId') update(@Param('clusterId') cid:string,@Param('workspaceId') wid:string,@Body() body:UpdateWorkspaceInput,@Headers('x-idempotency-key') key:string,@Req() req:EntityActor){return this.service.update(cid,wid,body,this.actor(req,key));}
  @Delete(':workspaceId') remove(@Param('clusterId') cid:string,@Param('workspaceId') wid:string,@Body() body:ConfirmWorkspaceInput,@Headers('x-idempotency-key') key:string,@Req() req:EntityActor){return this.service.remove(cid,wid,body,this.actor(req,key));}
  @Post(':workspaceId/restore') restore(@Param('clusterId') cid:string,@Param('workspaceId') wid:string,@Body() body:ConfirmWorkspaceInput,@Headers('x-idempotency-key') key:string,@Req() req:EntityActor){return this.service.restore(cid,wid,body,this.actor(req,key));}
}
