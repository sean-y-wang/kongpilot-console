import {Body,Controller,Delete,Get,Param,Patch,Post,Query,Req} from '@nestjs/common';
import {ApiTags} from '@nestjs/swagger';
import type {EntityActor} from '../entities/entities.types';
import {GovernanceService} from './governance.service';
import {GovernanceMetadataService} from './governance-metadata.service';
import {governanceId,governanceObject,governancePage} from './governance-input';

@ApiTags('配置治理')
@Controller('clusters/:clusterId/governance')
export class GovernanceController {
 constructor(private readonly governance:GovernanceService,private readonly metadata:GovernanceMetadataService){}
 private request(req:any,raw:unknown,extra:string[]=[]):{query:Record<string,any>;actor:EntityActor}{
  const query=governanceObject(raw,['workspaceId',...extra]);if(query.workspaceId!==undefined)query.workspaceId=governanceId(query.workspaceId);
  if(extra.includes('size'))governancePage(query);
  return{query,actor:{user:req.user,workspaceId:query.workspaceId,requestId:req.requestId,ip:req.ip,idempotencyKey:req.headers['x-idempotency-key']}};
 }
 @Get('capabilities') capabilities(@Param('clusterId')cid:string,@Query()q:unknown,@Req()r:any){return this.governance.capabilities(governanceId(cid),this.request(r,q).actor);}
 @Get('catalog') catalog(@Param('clusterId')cid:string,@Query()q:unknown,@Req()r:any){return this.governance.catalog(governanceId(cid),this.request(r,q).actor);}
 @Post('inspections') inspect(@Param('clusterId')cid:string,@Query()q:unknown,@Body()b:unknown,@Req()r:any){return this.governance.inspect(governanceId(cid),b,this.request(r,q).actor);}
 @Get('reports') reports(@Param('clusterId')cid:string,@Query()q:unknown,@Req()r:any){const v=this.request(r,q,['size','cursor','quality']);return this.governance.reports(governanceId(cid),v.query,v.actor);}
 @Get('reports/:id') report(@Param('clusterId')cid:string,@Param('id')id:string,@Query()q:unknown,@Req()r:any){return this.governance.report(governanceId(cid),governanceId(id),this.request(r,q).actor);}
 @Get('reports/:id/findings') findings(@Param('clusterId')cid:string,@Param('id')id:string,@Query()q:unknown,@Req()r:any){const v=this.request(r,q,['size','cursor','severity','ruleCode']);return this.governance.findings(governanceId(cid),governanceId(id),v.query,v.actor);}
 @Post('reports/:id/findings/:findingId/fix-plan') fix(@Param('clusterId')cid:string,@Param('id')id:string,@Param('findingId')findingId:string,@Query()q:unknown,@Body()b:unknown,@Req()r:any){return this.governance.fixPlan(governanceId(cid),governanceId(id),governanceId(findingId),b,this.request(r,q).actor);}
 @Get('rules') rules(@Param('clusterId')cid:string,@Query()q:unknown,@Req()r:any){const v=this.request(r,q,['size','cursor','state']);return this.governance.resources(governanceId(cid),'governance_rules',v.query,v.actor);}
 @Get('rules/:id') rule(@Param('clusterId')cid:string,@Param('id')id:string,@Query()q:unknown,@Req()r:any){return this.governance.resource(governanceId(cid),'governance_rules',governanceId(id),this.request(r,q).actor);}
 @Post('rules') createRule(@Param('clusterId')cid:string,@Query()q:unknown,@Body()b:unknown,@Req()r:any){return this.metadata.mutate(governanceId(cid),'governance_rules',undefined,'create',b,this.request(r,q).actor);}
 @Patch('rules/:id') updateRule(@Param('clusterId')cid:string,@Param('id')id:string,@Query()q:unknown,@Body()b:unknown,@Req()r:any){return this.metadata.mutate(governanceId(cid),'governance_rules',governanceId(id),'update',b,this.request(r,q).actor);}
 @Post('rules/:id/clone') clone(@Param('clusterId')cid:string,@Param('id')id:string,@Query()q:unknown,@Body()b:unknown,@Req()r:any){return this.governance.cloneRule(governanceId(cid),governanceId(id),b,this.request(r,q).actor);}
 @Delete('rules/:id') archiveRule(@Param('clusterId')cid:string,@Param('id')id:string,@Query()q:unknown,@Body()b:unknown,@Req()r:any){return this.metadata.mutate(governanceId(cid),'governance_rules',governanceId(id),'archive',b,this.request(r,q).actor);}
 @Post('rules/:id/restore') restoreRule(@Param('clusterId')cid:string,@Param('id')id:string,@Query()q:unknown,@Body()b:unknown,@Req()r:any){return this.metadata.mutate(governanceId(cid),'governance_rules',governanceId(id),'restore',b,this.request(r,q).actor);}
 @Get('schedules') schedules(@Param('clusterId')cid:string,@Query()q:unknown,@Req()r:any){const v=this.request(r,q,['size','cursor','state']);return this.governance.resources(governanceId(cid),'governance_schedules',v.query,v.actor);}
 @Get('schedules/:id') schedule(@Param('clusterId')cid:string,@Param('id')id:string,@Query()q:unknown,@Req()r:any){return this.governance.resource(governanceId(cid),'governance_schedules',governanceId(id),this.request(r,q).actor);}
 @Post('schedules') createSchedule(@Param('clusterId')cid:string,@Query()q:unknown,@Body()b:unknown,@Req()r:any){return this.metadata.mutate(governanceId(cid),'governance_schedules',undefined,'create',b,this.request(r,q).actor);}
 @Patch('schedules/:id') updateSchedule(@Param('clusterId')cid:string,@Param('id')id:string,@Query()q:unknown,@Body()b:unknown,@Req()r:any){return this.metadata.mutate(governanceId(cid),'governance_schedules',governanceId(id),'update',b,this.request(r,q).actor);}
 @Delete('schedules/:id') archiveSchedule(@Param('clusterId')cid:string,@Param('id')id:string,@Query()q:unknown,@Body()b:unknown,@Req()r:any){return this.metadata.mutate(governanceId(cid),'governance_schedules',governanceId(id),'archive',b,this.request(r,q).actor);}
 @Post('schedules/:id/restore') restoreSchedule(@Param('clusterId')cid:string,@Param('id')id:string,@Query()q:unknown,@Body()b:unknown,@Req()r:any){return this.metadata.mutate(governanceId(cid),'governance_schedules',governanceId(id),'restore',b,this.request(r,q).actor);}
 @Post('comparisons') compare(@Param('clusterId')cid:string,@Query()q:unknown,@Body()b:unknown,@Req()r:any){return this.governance.compare(governanceId(cid),b,this.request(r,q).actor);}
 @Get('comparisons') comparisons(@Param('clusterId')cid:string,@Query()q:unknown,@Req()r:any){const v=this.request(r,q,['size','cursor','quality']);return this.governance.comparisons(governanceId(cid),v.query,v.actor);}
 @Get('comparisons/:id') comparison(@Param('clusterId')cid:string,@Param('id')id:string,@Query()q:unknown,@Req()r:any){const v=this.request(r,q,['size','cursor']);return this.governance.comparison(governanceId(cid),governanceId(id),v.query,v.actor);}
 @Get('comparisons/:id/source-objects') sourceObjects(@Param('clusterId')cid:string,@Param('id')id:string,@Query()q:unknown,@Req()r:any){const v=this.request(r,q,['size','cursor','entityType']);return this.governance.sourceObjects(governanceId(cid),governanceId(id),v.query,v.actor);}
 @Post('comparisons/:id/promote-plan') promote(@Param('clusterId')cid:string,@Param('id')id:string,@Query()q:unknown,@Body()b:unknown,@Req()r:any){return this.governance.promotePlan(governanceId(cid),governanceId(id),b,this.request(r,q).actor);}
 @Get('operations/by-key/:key') receipt(@Param('clusterId')cid:string,@Param('key')key:string,@Query()q:unknown,@Req()r:any){return this.governance.receipt(governanceId(cid),key,this.request(r,q).actor);}
 @Post('operations/by-key/:key/reconcile') reconcile(@Param('clusterId')cid:string,@Param('key')key:string,@Query()q:unknown,@Body()b:unknown,@Req()r:any){return this.governance.reconcileReceipt(governanceId(cid),key,b,this.request(r,q).actor);}
}
