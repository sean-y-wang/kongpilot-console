import { BadRequestException, Body, Controller, Get, Param, ParseUUIDPipe, Post, Query, Req } from '@nestjs/common';
import { RecycleService } from './recycle.service';

@Controller('clusters/:clusterId/recycle-bin')
export class RecycleController {
  constructor(private readonly recycle:RecycleService){}
  @Get()
  list(@Param('clusterId',ParseUUIDPipe) clusterId:string,@Req() req:any,@Query() query:any){
    return this.recycle.list(clusterId,req.user,{size:query.size===undefined?undefined:Number(query.size),cursor:query.cursor,type:query.type,state:query.state,search:query.search,workspaceId:query.workspaceId});
  }
  @Get(':id')
  preview(@Param('clusterId',ParseUUIDPipe) clusterId:string,@Param('id',ParseUUIDPipe) id:string,@Req() req:any,@Query('workspaceId') workspaceId?:string){return this.recycle.preview(clusterId,id,req.user,workspaceId);}
  private confirmation(body:any):{confirmed:boolean;confirm_name:string}{
    if(!body||body.confirmed!==true||typeof body.confirm_name!=='string')throw new BadRequestException({code:'CONFIRMATION_REQUIRED',message:'请输入对象名称并二次确认'});
    return {confirmed:true,confirm_name:body.confirm_name};
  }
  @Post(':id/restore')
  restore(@Param('clusterId',ParseUUIDPipe) clusterId:string,@Param('id',ParseUUIDPipe) id:string,@Body() body:any,@Req() req:any,@Query('workspaceId') workspaceId?:string){
    return this.recycle.restore(clusterId,id,req.user,this.confirmation(body),{requestId:req.requestId,ip:req.ip,idempotencyKey:req.headers['x-idempotency-key'],workspaceId});
  }
  @Post(':id/purge')
  purge(@Param('clusterId',ParseUUIDPipe) clusterId:string,@Param('id',ParseUUIDPipe) id:string,@Body() body:any,@Req() req:any,@Query('workspaceId') workspaceId?:string){
    return this.recycle.purge(clusterId,id,req.user,this.confirmation(body),{requestId:req.requestId,ip:req.ip,idempotencyKey:req.headers['x-idempotency-key'],workspaceId});
  }
}
