import { BadRequestException, Body, Controller, Delete, Get, Param, Patch, Post, Query, Req, Res } from '@nestjs/common';
import { ApiOperation, ApiTags } from '@nestjs/swagger';
import type { Response } from 'express';
import {once} from 'node:events';
import { ConfigurationService } from './configuration.service';
import { ConfigurationAccessService } from './configuration-access.service';
import { configurationId, configurationObject } from './configuration-input';
import type { EntityActor } from '../entities/entities.types';

const scopeFields=['scope','serviceIds'],confirmationFields=['confirmed','confirm_name','confirm_deletes'];
/** There is no generic URL/path/SQL proxy. Every route selects a fixed server
 * workflow and an independently verified current actor/cluster/workspace. */
@ApiTags('配置快照与 GitOps')
@Controller('clusters/:clusterId')
export class ConfigurationController {
  constructor(private readonly service:ConfigurationService,private readonly access:ConfigurationAccessService){}
  private actor(req:any,query:Record<string,any>):EntityActor{
    if(query.workspaceId!==undefined)configurationId(query.workspaceId);
    return{user:req.user,workspaceId:query.workspaceId,requestId:req.requestId,ip:req.ip,idempotencyKey:req.headers['x-idempotency-key']};
  }
  private q(query:unknown,extra:string[]=[]):Record<string,any>{const q=configurationObject(query,['workspaceId',...extra]);
    if(q.serviceIds!==undefined){if(typeof q.serviceIds!=='string'||q.serviceIds.length>3700)throw new BadRequestException({code:'INVALID_CONFIGURATION_ROOT_QUERY'});q.serviceIds=q.serviceIds.split(',').map(configurationId);}return q;}
  @Post('snapshots') @ApiOperation({summary:'完整分页捕获与加密封存；返回真实作业回执'})
  capture(@Param('clusterId')cid:string,@Body()value:unknown,@Query()query:unknown,@Req()req:any){const q=this.q(query),body=configurationObject(value,[...scopeFields,'name','description']);return this.service.captureSnapshot(configurationId(cid),body,this.actor(req,q));}
  @Get('snapshots') listSnapshots(@Param('clusterId')cid:string,@Query()query:unknown,@Req()req:any){const q=this.q(query,[...scopeFields,'size','cursor','includeDeleted','state','search']);return this.service.listSnapshots(configurationId(cid),q,this.actor(req,q));}
  @Get('snapshots/schedules') schedules(@Param('clusterId')cid:string,@Query()query:unknown,@Req()req:any){const q=this.q(query,[...scopeFields,'size','cursor','includeDeleted','state','search']);return this.service.listSchedules(configurationId(cid),q,this.actor(req,q));}
  @Post('snapshots/schedules') createSchedule(@Param('clusterId')cid:string,@Body()value:unknown,@Query()query:unknown,@Req()req:any){const q=this.q(query),body=configurationObject(value,[...scopeFields,'name','intervalMinutes','timezone','retentionDays',...confirmationFields]);return this.service.mutateSchedule(configurationId(cid),undefined,'create',body,this.actor(req,q));}
  @Patch('snapshots/schedules/:scheduleId') updateSchedule(@Param('clusterId')cid:string,@Param('scheduleId')id:string,@Body()value:unknown,@Query()query:unknown,@Req()req:any){const q=this.q(query),body=configurationObject(value,[...scopeFields,'revision','name','intervalMinutes','timezone','retentionDays','paused',...confirmationFields]);return this.service.mutateSchedule(configurationId(cid),configurationId(id),'update',body,this.actor(req,q));}
  @Delete('snapshots/schedules/:scheduleId') archiveSchedule(@Param('clusterId')cid:string,@Param('scheduleId')id:string,@Body()value:unknown,@Query()query:unknown,@Req()req:any){const q=this.q(query),body=configurationObject(value,['revision',...confirmationFields]);return this.service.mutateSchedule(configurationId(cid),configurationId(id),'archive',body,this.actor(req,q));}
  @Post('snapshots/schedules/:scheduleId/restore') restoreSchedule(@Param('clusterId')cid:string,@Param('scheduleId')id:string,@Body()value:unknown,@Query()query:unknown,@Req()req:any){const q=this.q(query),body=configurationObject(value,['revision',...confirmationFields]);return this.service.mutateSchedule(configurationId(cid),configurationId(id),'restore',body,this.actor(req,q));}
  @Post('snapshots/schedules/:scheduleId/purge') purgeSchedule(@Param('clusterId')cid:string,@Param('scheduleId')id:string,@Body()value:unknown,@Query()query:unknown,@Req()req:any){const q=this.q(query),body=configurationObject(value,['revision',...confirmationFields]);return this.service.mutateSchedule(configurationId(cid),configurationId(id),'purge',body,this.actor(req,q));}
  @Post('snapshots/:snapshotId/archive') archiveSnapshot(@Param('clusterId')cid:string,@Param('snapshotId')id:string,@Body()value:unknown,@Query()query:unknown,@Req()req:any){const q=this.q(query),body=configurationObject(value,['revision',...confirmationFields]);return this.service.mutateSnapshot(configurationId(cid),configurationId(id),'archive',body,this.actor(req,q));}
  @Post('snapshots/:snapshotId/restore') restoreSnapshot(@Param('clusterId')cid:string,@Param('snapshotId')id:string,@Body()value:unknown,@Query()query:unknown,@Req()req:any){const q=this.q(query),body=configurationObject(value,['revision',...confirmationFields]);return this.service.mutateSnapshot(configurationId(cid),configurationId(id),'restore',body,this.actor(req,q));}
  @Post('snapshots/:snapshotId/purge') purgeSnapshot(@Param('clusterId')cid:string,@Param('snapshotId')id:string,@Body()value:unknown,@Query()query:unknown,@Req()req:any){const q=this.q(query),body=configurationObject(value,['revision',...confirmationFields]);return this.service.mutateSnapshot(configurationId(cid),configurationId(id),'purge',body,this.actor(req,q));}
  @Get('snapshots/:snapshotId') snapshot(@Param('clusterId')cid:string,@Param('snapshotId')id:string,@Query()query:unknown,@Req()req:any){const q=this.q(query,['size','cursor']);return this.service.snapshot(configurationId(cid),configurationId(id),q,this.actor(req,q));}
  @Get('snapshots/:snapshotId/compare/:otherId') compare(@Param('clusterId')cid:string,@Param('snapshotId')id:string,@Param('otherId')other:string,@Query()query:unknown,@Req()req:any){const q=this.q(query,['view']);if(q.view!==undefined&&!['configuration','schema'].includes(q.view))throw new BadRequestException({code:'INVALID_CONFIGURATION_COMPARE_VIEW'});return this.service.compareSnapshots(configurationId(cid),configurationId(id),configurationId(other),this.actor(req,q),q.view);}
  @Post('snapshots/:snapshotId/export') exportSnapshot(@Param('clusterId')cid:string,@Param('snapshotId')id:string,@Body()value:unknown,@Query()query:unknown,@Req()req:any){const q=this.q(query),body=configurationObject(value,['mode',...confirmationFields]);return this.service.exportSnapshot(configurationId(cid),configurationId(id),body,this.actor(req,q));}
  @Post('snapshots/:snapshotId/rollback-plan') rollback(@Param('clusterId')cid:string,@Param('snapshotId')id:string,@Body()value:unknown,@Query()query:unknown,@Req()req:any){const q=this.q(query),body=configurationObject(value,['revision',...confirmationFields]);return this.service.rollbackPreview(configurationId(cid),configurationId(id),body,this.actor(req,q));}
  @Post('configuration/imports') import(@Param('clusterId')cid:string,@Body()value:unknown,@Query()query:unknown,@Req()req:any){const q=this.q(query),body=configurationObject(value,[...scopeFields,'yaml','mode','basicPasswordIntents','confirm_deletes']);return this.service.importDocument(configurationId(cid),body,this.actor(req,q));}
  @Get('configuration/plans/:planId') plan(@Param('clusterId')cid:string,@Param('planId')id:string,@Query()query:unknown,@Req()req:any){const q=this.q(query,['size','cursor']);return this.service.plan(configurationId(cid),configurationId(id),q,this.actor(req,q));}
  @Get('configuration/plans/:planId/changes') changes(@Param('clusterId')cid:string,@Param('planId')id:string,@Query()query:unknown,@Req()req:any){const q=this.q(query,['size','cursor']);return this.service.plan(configurationId(cid),configurationId(id),q,this.actor(req,q));}
  @Post('configuration/plans/:planId/apply') apply(@Param('clusterId')cid:string,@Param('planId')id:string,@Body()value:unknown,@Query()query:unknown,@Req()req:any){const q=this.q(query),body=configurationObject(value,['planRevision','planHash','revision','driver',...confirmationFields]);return this.service.apply(configurationId(cid),configurationId(id),body,this.actor(req,q));}
  @Post('configuration/plans/:planId/durable-submissions') @ApiOperation({summary:'重新捕获、编译并签发全新耐久配置工单；不续旧期限'})
  durable(@Param('clusterId')cid:string,@Param('planId')id:string,@Body()value:unknown,@Query()query:unknown,@Req()req:any){const q=this.q(query),body=configurationObject(value,['planRevision','planHash',...confirmationFields]);return this.service.submitDurable(configurationId(cid),configurationId(id),body,this.actor(req,q));}
  @Post('configuration/plans/:planId/reconcile') reconcile(@Param('clusterId')cid:string,@Param('planId')id:string,@Body()value:unknown,@Query()query:unknown,@Req()req:any){const q=this.q(query),body=configurationObject(value,['revision','planHash']);return this.service.reconcilePlan(configurationId(cid),configurationId(id),body,this.actor(req,q));}
  @Get('configuration/jobs/by-key/:key') byKey(@Param('clusterId')cid:string,@Param('key')key:string,@Query()query:unknown,@Req()req:any){const q=this.q(query);return this.service.receipt(configurationId(cid),key,this.actor(req,q));}
  @Get('configuration/jobs/:jobId') job(@Param('clusterId')cid:string,@Param('jobId')id:string,@Query()query:unknown,@Req()req:any){const q=this.q(query);return this.service.job(configurationId(cid),configurationId(id),this.actor(req,q));}
  @Get('configuration/jobs/:jobId/steps') steps(@Param('clusterId')cid:string,@Param('jobId')id:string,@Query()query:unknown,@Req()req:any){const q=this.q(query,['size','cursor']);return this.service.steps(configurationId(cid),configurationId(id),q,this.actor(req,q));}
  @Post('configuration/jobs/:jobId/abandon') @ApiOperation({summary:'二次确认后记录原过期执行的未决事实；绝不重发网关请求'})
  abandon(@Param('clusterId')cid:string,@Param('jobId')id:string,@Body()value:unknown,@Query()query:unknown,@Req()req:any){
    const q=this.q(query),body=configurationObject(value,['revision','executionId','executionRevision','planRevision','planHash','leaseGeneration','workflowExecutionId',...confirmationFields]);
    return this.service.abandon(configurationId(cid),configurationId(id),body,this.actor(req,q));
  }
  @Post('configuration/exports') exportCurrent(@Param('clusterId')cid:string,@Body()value:unknown,@Query()query:unknown,@Req()req:any){const q=this.q(query),body=configurationObject(value,[...scopeFields,'mode',...confirmationFields]);return this.service.exportCurrent(configurationId(cid),body,this.actor(req,q));}
  @Get('configuration/jobs') jobs(@Param('clusterId')cid:string,@Query()query:unknown,@Req()req:any){const q=this.q(query,[...scopeFields,'size','cursor']);return this.service.listJobs(configurationId(cid),q,this.actor(req,q));}
  @Get('configuration/gitops/runs') gitops(@Param('clusterId')cid:string,@Query()query:unknown,@Req()req:any){const q=this.q(query,[...scopeFields,'size','cursor']);return this.service.listGitOps(configurationId(cid),q,this.actor(req,q));}
  @Post('configuration/gitops/runs') createGitops(@Param('clusterId')cid:string,@Body()value:unknown,@Query()query:unknown,@Req()req:any){const q=this.q(query),body=configurationObject(value,['jobId','repositoryLabel','commitSha','pipelineReference']);return this.service.createGitOps(configurationId(cid),body,this.actor(req,q));}
  @Post('configuration/exports/:exportId/download') @ApiOperation({summary:'再次校验秘密权限并消费一次性下载许可；禁止缓存'})
  async download(@Param('clusterId')cid:string,@Param('exportId')id:string,@Body()value:unknown,@Query()query:unknown,@Req()req:any,@Res()res:Response){
    const q=this.q(query),body=configurationObject(value,['revision',...confirmationFields]),result=await this.service.download(configurationId(cid),configurationId(id),body,this.actor(req,q));
    res.setHeader('Cache-Control','no-store');res.setHeader('Pragma','no-cache');res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('Content-Type','application/yaml; charset=utf-8');res.setHeader('Content-Disposition',`attachment; filename="${result.filename}"`);
    const buffer=Buffer.from(result.content,'utf8');
    try{for(let at=0;at<buffer.length;at+=65536){if(req.aborted||res.destroyed)return;await this.access.assertCurrent(result.handle,{phase:'download'});if(!res.write(buffer.subarray(at,at+65536))){await once(res,'drain',{signal:AbortSignal.timeout(10000)});}}res.end();}
    catch(error){if(res.headersSent)res.destroy();else throw error;}finally{buffer.fill(0);result.content='';}
  }
}
