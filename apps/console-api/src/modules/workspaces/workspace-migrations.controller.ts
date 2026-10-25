import { Body, Controller, Get, Headers, Param, ParseUUIDPipe, Post, Query, Req } from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import { EntityActor } from '../entities/entities.types';
import { WorkspaceMigrationService } from './workspace-migration.service';
import { WorkspaceMigrationWorkflowService } from '../workflows/workspace-migration-workflow.service';

@ApiTags('工作区迁移')
@Controller('clusters/:clusterId/workspace-migrations')
export class WorkspaceMigrationsController {
 constructor(private readonly migrations:WorkspaceMigrationService,private readonly workflow:WorkspaceMigrationWorkflowService){}
 private actor(req:EntityActor,workspaceId?:string,key?:string):EntityActor{return {user:req.user,requestId:req.requestId,ip:req.ip,workspaceId,idempotencyKey:key};}
 @Post('plan') plan(@Param('clusterId',ParseUUIDPipe) cid:string,@Body() body:unknown,@Req() req:EntityActor,@Query('workspaceId') wid?:string){return this.migrations.plan(cid,body,this.actor(req,wid));}
 @Get(':id') get(@Param('clusterId',ParseUUIDPipe) cid:string,@Param('id',ParseUUIDPipe) id:string,@Req() req:EntityActor,@Query('workspaceId') wid?:string){return this.migrations.get(cid,id,this.actor(req,wid));}
 @Post(':id/apply') apply(@Param('clusterId',ParseUUIDPipe) cid:string,@Param('id',ParseUUIDPipe) id:string,@Body() body:unknown,@Req() req:EntityActor,@Query('workspaceId') wid?:string,@Headers('x-idempotency-key') key?:string){return this.migrations.apply(cid,id,body,this.actor(req,wid,key));}
 @Post(':id/submit') submit(@Param('clusterId',ParseUUIDPipe) cid:string,@Param('id',ParseUUIDPipe) id:string,@Body() body:unknown,@Req() req:EntityActor,@Query('workspaceId') wid?:string,@Headers('x-idempotency-key') key?:string){return this.workflow.submit(cid,id,body,this.actor(req,wid,key));}
 @Post(':id/reconcile') reconcile(@Param('clusterId',ParseUUIDPipe) cid:string,@Param('id',ParseUUIDPipe) id:string,@Body() body:unknown,@Req() req:EntityActor,@Query('workspaceId') wid?:string){return this.migrations.reconcile(cid,id,body,this.actor(req,wid));}
}
