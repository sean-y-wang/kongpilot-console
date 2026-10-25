import { BadRequestException,Body,Controller,Delete,Get,Headers,Param,Patch,Post,Put,Query,Req } from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import { IamService } from './iam.service';
import { IamMutationsService } from './iam-mutations.service';
import type { IamActor,IamPageQuery } from './iam.types';

@ApiTags('身份、团队与四维权限')
@Controller('iam')
export class IamController {
 constructor(private readonly service:IamService,private readonly operations:IamMutationsService){}
 private actor(req:IamActor,key?:string):IamActor{return {user:req.user,requestId:req.requestId,ip:req.ip,idempotencyKey:key};}
 private resource(type:string):'users'|'teams'|'roles'{if(!['users','teams','roles'].includes(type))throw new BadRequestException('身份资源类型无效');return type as 'users'|'teams'|'roles';}
 private subject(type:string):'users'|'teams'{if(!['users','teams'].includes(type))throw new BadRequestException('授权对象类型无效');return type as 'users'|'teams';}
 @Get('permissions/catalog') catalog(){return this.service.catalog();}
 @Post('changes/prepare') prepareChange(@Body() body:unknown,@Headers('x-idempotency-key') key:string,@Req() req:IamActor){return this.service.prepareChange(body,this.actor(req,key));}
 @Post('changes/:id/submit') submitChange(@Param('id') id:string,@Body() body:unknown,@Headers('x-idempotency-key') key:string,@Req() req:IamActor){return this.service.submitChange(id,body,this.actor(req,key));}
 @Get('changes/by-key/:key') changeReceiptByKey(@Param('key') key:string,@Req() req:IamActor){return this.service.changeReceiptByKey(key,this.actor(req));}
 @Get('changes/:id') changeReceipt(@Param('id') id:string,@Req() req:IamActor){return this.service.changeReceipt(id,this.actor(req));}
 @Get('lookups/users') usersLookup(@Query() query:IamPageQuery,@Req() req:IamActor){return this.service.lookupUsers(query,this.actor(req));}
 @Get('operations/by-key/:key') byKey(@Param('key') key:string,@Req() req:IamActor){return this.operations.receipt(this.actor(req),key,true);}
 @Get('operations/:id') operation(@Param('id') id:string,@Req() req:IamActor){return this.operations.receipt(this.actor(req),id);}
 @Get('roles/:id/permissions') permissions(@Param('id') id:string,@Req() req:IamActor){return this.service.permissions(id,this.actor(req));}
 @Put('roles/:id/permissions') putPermissions(@Param('id') id:string,@Body() body:unknown,@Headers('x-idempotency-key') key:string,@Req() req:IamActor){return this.service.replacePermissions(id,body,this.actor(req,key));}
 @Post('roles/:id/clone') clone(@Param('id') id:string,@Body() body:unknown,@Headers('x-idempotency-key') key:string,@Req() req:IamActor){return this.service.clone(id,body,this.actor(req,key));}
 @Post('users/:id/reset-password') reset(@Param('id') id:string,@Body() body:unknown,@Req() req:IamActor){return this.service.resetPassword(id,body,this.actor(req));}
 @Get('teams/:id/members') members(@Param('id') id:string,@Query() query:IamPageQuery,@Req() req:IamActor){return this.service.members(id,query,this.actor(req));}
 @Post('teams/:id/members') addMember(@Param('id') id:string,@Body() body:unknown,@Headers('x-idempotency-key') key:string,@Req() req:IamActor){return this.service.addMember(id,body,this.actor(req,key));}
 @Delete('teams/:id/members/:uid') removeMember(@Param('id') id:string,@Param('uid') uid:string,@Body() body:unknown,@Headers('x-idempotency-key') key:string,@Req() req:IamActor){return this.service.memberState(id,uid,body,false,this.actor(req,key));}
 @Post('teams/:id/members/:uid/restore') restoreMember(@Param('id') id:string,@Param('uid') uid:string,@Body() body:unknown,@Headers('x-idempotency-key') key:string,@Req() req:IamActor){return this.service.memberState(id,uid,body,true,this.actor(req,key));}
 @Get(':subject/:id/role-bindings') bindings(@Param('subject') subject:string,@Param('id') id:string,@Query() query:IamPageQuery,@Req() req:IamActor){return this.service.bindings(this.subject(subject),id,query,this.actor(req));}
 @Post(':subject/:id/role-bindings') grant(@Param('subject') subject:string,@Param('id') id:string,@Body() body:unknown,@Headers('x-idempotency-key') key:string,@Req() req:IamActor){return this.service.addBinding(this.subject(subject),id,body,this.actor(req,key));}
 @Delete(':subject/:id/role-bindings/:bid') revoke(@Param('subject') subject:string,@Param('id') id:string,@Param('bid') bid:string,@Body() body:unknown,@Headers('x-idempotency-key') key:string,@Req() req:IamActor){return this.service.bindingState(this.subject(subject),id,bid,body,false,this.actor(req,key));}
 @Post(':subject/:id/role-bindings/:bid/restore') restoreGrant(@Param('subject') subject:string,@Param('id') id:string,@Param('bid') bid:string,@Body() body:unknown,@Headers('x-idempotency-key') key:string,@Req() req:IamActor){return this.service.bindingState(this.subject(subject),id,bid,body,true,this.actor(req,key));}
 @Get(':resource') list(@Param('resource') resource:string,@Query() query:IamPageQuery,@Req() req:IamActor){return this.service.list(this.resource(resource),query,this.actor(req));}
 @Post(':resource') create(@Param('resource') resource:string,@Body() body:unknown,@Headers('x-idempotency-key') key:string,@Req() req:IamActor){return this.service.create(this.resource(resource),body,this.actor(req,key));}
 @Get(':resource/:id') get(@Param('resource') resource:string,@Param('id') id:string,@Req() req:IamActor){return this.service.get(this.resource(resource),id,this.actor(req));}
 @Patch(':resource/:id') update(@Param('resource') resource:string,@Param('id') id:string,@Body() body:unknown,@Headers('x-idempotency-key') key:string,@Req() req:IamActor){return this.service.update(this.resource(resource),id,body,this.actor(req,key));}
 @Post(':resource/:id/status') status(@Param('resource') resource:string,@Param('id') id:string,@Body() body:unknown,@Headers('x-idempotency-key') key:string,@Req() req:IamActor){return this.service.state(this.resource(resource),id,body,'status',this.actor(req,key));}
 @Delete(':resource/:id') delete(@Param('resource') resource:string,@Param('id') id:string,@Body() body:unknown,@Headers('x-idempotency-key') key:string,@Req() req:IamActor){return this.service.state(this.resource(resource),id,body,'delete',this.actor(req,key));}
 @Post(':resource/:id/restore') restore(@Param('resource') resource:string,@Param('id') id:string,@Body() body:unknown,@Headers('x-idempotency-key') key:string,@Req() req:IamActor){return this.service.state(this.resource(resource),id,body,'restore',this.actor(req,key));}
}
