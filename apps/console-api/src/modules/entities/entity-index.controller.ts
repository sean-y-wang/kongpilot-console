import { Controller, Get, Post, Param, Query, Req } from '@nestjs/common';
import { EntityIndexService } from './entity-index.service';
import { AuthorizationService } from '../authorization/authorization.service';
import { AuditService } from '../audit/audit.service';
@Controller('clusters/:clusterId/inventory')
export class EntityIndexController {
 constructor(private readonly index:EntityIndexService,private readonly authz:AuthorizationService,private readonly audit:AuditService){}
 @Get() summary(@Param('clusterId') cid:string,@Req() req:any,@Query('workspaceId') workspaceId?:string){return this.index.summary(cid,req.user,workspaceId);}
 @Post('refresh') async refresh(@Param('clusterId') cid:string,@Req() req:any,@Query('workspaceId') workspaceId?:string){const result=await this.index.refreshForActor(cid,req.user,workspaceId);await this.audit.append({actorId:req.user.id,clusterId:cid,workspaceId:result.workspace_id,entityType:'inventory',action:'refresh',after:result,requestId:req.requestId,ip:req.ip});return result;}
}
