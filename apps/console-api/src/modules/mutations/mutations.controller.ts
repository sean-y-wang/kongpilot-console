import { Body, Controller, Get, HttpCode, Param, ParseUUIDPipe, Post, Query, Req } from '@nestjs/common';
import { MutationService } from './mutation.service';
import { MutationReconciliationService } from './mutation-reconciliation.service';

@Controller('clusters/:clusterId/mutations')
export class MutationsController {
  constructor(private readonly mutations: MutationService,private readonly reconciliation:MutationReconciliationService) {}
  @Post(':id/reconcile') @HttpCode(200)
  reconcile(@Param('clusterId',ParseUUIDPipe) clusterId:string,@Param('id',ParseUUIDPipe) id:string,@Query() query:{workspaceId?:string},@Body() body:unknown,@Req() req:any){
    return this.reconciliation.reconcile(clusterId,id,query,body,{user:req.user,requestId:req.requestId,ip:req.ip,idempotencyKey:req.headers['x-idempotency-key']});
  }
  @Get('by-key/:idempotencyKey')
  byKey(@Param('clusterId',ParseUUIDPipe) clusterId:string,@Param('idempotencyKey') idempotencyKey:string,@Req() req:any,@Query('workspaceId') workspaceId?:string){
    return this.mutations.operationByKey(clusterId,idempotencyKey,req.user,workspaceId);
  }
  @Get(':id')
  operation(@Param('clusterId',ParseUUIDPipe) clusterId:string,@Param('id',ParseUUIDPipe) id:string,@Req() req:any,@Query('workspaceId') workspaceId?:string) {
    return this.mutations.operation(clusterId,id,req.user,workspaceId);
  }
}
