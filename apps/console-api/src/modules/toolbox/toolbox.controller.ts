import { Body, Controller, Delete, Get, Param, Patch, Post, Query, Req } from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import type { EntityActor } from '../entities/entities.types';
import { ToolboxService } from './toolbox.service';
import { DraftsService } from './drafts.service';
import { CacheOperationsService } from './cache-operations.service';
import { toolboxId, toolboxObject } from './toolbox-input';

@ApiTags('运维工具箱') @Controller('clusters/:clusterId')
export class ToolboxController {
  constructor(private readonly toolbox:ToolboxService,private readonly drafts:DraftsService,private readonly cache:CacheOperationsService){}
  private scope(req:any,query:unknown,extra:string[]=[]){const value=toolboxObject(query,['workspaceId',...extra]);return{query:value,actor:{user:req.user,workspaceId:value.workspaceId===undefined?undefined:toolboxId(value.workspaceId),requestId:req.requestId,ip:req.ip,idempotencyKey:req.headers['x-idempotency-key']} as EntityActor};}
  @Get('toolbox/capabilities') capabilities(@Param('clusterId')cid:string,@Query()q:unknown,@Req()req:any){return this.toolbox.capabilities(toolboxId(cid),this.scope(req,q).actor);}
  @Get('toolbox/status') status(@Param('clusterId')cid:string,@Query()q:unknown,@Req()req:any){return this.toolbox.status(toolboxId(cid),this.scope(req,q).actor);}
  @Get('toolbox/cache') readCache(@Param('clusterId')cid:string,@Query()q:unknown,@Req()req:any){const value=this.scope(req,q,['key']);return this.toolbox.readCache(toolboxId(cid),value.query.key,value.actor);}
  @Post('toolbox/cache/invalidate') invalidate(@Param('clusterId')cid:string,@Query()q:unknown,@Body()body:unknown,@Req()req:any){return this.cache.invalidate(toolboxId(cid),body,this.scope(req,q).actor);}
  @Get('toolbox/operations/:operationId') operation(@Param('clusterId')cid:string,@Param('operationId')id:string,@Query()q:unknown,@Req()req:any){return this.cache.get(toolboxId(cid),toolboxId(id),this.scope(req,q).actor);}
  @Get('toolbox/operations/by-key/:key') cacheReceipt(@Param('clusterId')cid:string,@Param('key')key:string,@Query()q:unknown,@Req()req:any){return this.cache.byKey(toolboxId(cid),key,this.scope(req,q).actor);}
  @Post('toolbox/routes/debug') debug(@Param('clusterId')cid:string,@Query()q:unknown,@Body()body:unknown,@Req()req:any){return this.toolbox.debug(toolboxId(cid),body,this.scope(req,q).actor);}
  @Post('toolbox/probes') probe(@Param('clusterId')cid:string,@Query()q:unknown,@Body()body:unknown,@Req()req:any){return this.toolbox.probe(toolboxId(cid),body,this.scope(req,q).actor);}
  @Post('batches/plan') batch(@Param('clusterId')cid:string,@Query()q:unknown,@Body()body:unknown,@Req()req:any){return this.toolbox.batch(toolboxId(cid),body,this.scope(req,q).actor);}
  @Get('drafts') listDrafts(@Param('clusterId')cid:string,@Query()q:unknown,@Req()req:any){const value=this.scope(req,q,['size','cursor','state']);return this.drafts.list(toolboxId(cid),value.query,value.actor);}
  @Get('drafts/operations/by-key/:key') draftReceipt(@Param('clusterId')cid:string,@Param('key')key:string,@Query()q:unknown,@Req()req:any){return this.drafts.byKey(toolboxId(cid),key,this.scope(req,q).actor);}
  @Get('drafts/:draftId') draft(@Param('clusterId')cid:string,@Param('draftId')id:string,@Query()q:unknown,@Req()req:any){return this.drafts.get(toolboxId(cid),toolboxId(id),this.scope(req,q).actor);}
  @Post('drafts') createDraft(@Param('clusterId')cid:string,@Query()q:unknown,@Body()body:unknown,@Req()req:any){return this.drafts.save(toolboxId(cid),undefined,body,this.scope(req,q).actor);}
  @Patch('drafts/:draftId') updateDraft(@Param('clusterId')cid:string,@Param('draftId')id:string,@Query()q:unknown,@Body()body:unknown,@Req()req:any){return this.drafts.save(toolboxId(cid),toolboxId(id),body,this.scope(req,q).actor);}
  @Delete('drafts/:draftId') archiveDraft(@Param('clusterId')cid:string,@Param('draftId')id:string,@Query()q:unknown,@Body()body:unknown,@Req()req:any){return this.drafts.archive(toolboxId(cid),toolboxId(id),body,this.scope(req,q).actor);}
  @Post('drafts/:draftId/restore') restoreDraft(@Param('clusterId')cid:string,@Param('draftId')id:string,@Query()q:unknown,@Body()body:unknown,@Req()req:any){return this.drafts.archive(toolboxId(cid),toolboxId(id),body,this.scope(req,q).actor,true);}
}
