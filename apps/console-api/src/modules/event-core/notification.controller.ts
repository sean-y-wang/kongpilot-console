import {Body,Controller,Delete,Get,Headers,Param,Patch,Post,Put,Query,Req} from '@nestjs/common';
import {ApiTags} from '@nestjs/swagger';
import {NotificationService} from './notification.service';
import {NotificationOperationsService} from './notification-operations.service';
import type {NotificationActor,NotificationQuery} from './event.types';
@ApiTags('通知中心与个人订阅')
@Controller('notifications')
export class NotificationsController {
 constructor(private readonly service:NotificationService,private readonly operations:NotificationOperationsService){}
 private actor(req:any,key:string=''):NotificationActor{return {user:req.user,idempotencyKey:key,requestId:req.requestId,ip:req.ip};}
 @Get() list(@Query() q:NotificationQuery,@Req() req:any){return this.service.list(req.user,q);}
 @Get('unread-count') unread(@Query() q:Pick<NotificationQuery,'clusterId'|'workspaceId'>,@Req() req:any){return this.service.unreadCount(req.user,q);}
 @Get('operations/by-key/:key') byKey(@Param('key') key:string,@Req() req:any){return this.operations.receipt(this.actor(req),key);}
 @Get('approval-settings') approvalSetting(@Query() q:any,@Req() req:any){return this.operations.approvalSetting(req.user,q);}
 @Put('approval-settings') saveApprovalSetting(@Body() b:unknown,@Headers('x-idempotency-key') k:string,@Req() req:any){return this.operations.saveApprovalSetting(this.actor(req,k),b);}
 @Get('preferences') preferences(@Query() q:any,@Req() req:any){return this.service.preferences(req.user,q);}
 @Get('preferences/:id') preference(@Param('id') id:string,@Req() req:any){return this.service.preference(req.user,id);}
 @Post('preferences') createPreference(@Body() b:unknown,@Headers('x-idempotency-key') k:string,@Req() req:any){return this.operations.savePreference(this.actor(req,k),null,b);}
 @Patch('preferences/:id') savePreference(@Param('id') id:string,@Body() b:unknown,@Headers('x-idempotency-key') k:string,@Req() req:any){return this.operations.savePreference(this.actor(req,k),id,b);}
 @Delete('preferences/:id') deletePreference(@Param('id') id:string,@Body() b:unknown,@Headers('x-idempotency-key') k:string,@Req() req:any){return this.operations.preferenceState(this.actor(req,k),id,b,false);}
 @Post('preferences/:id/restore') restorePreference(@Param('id') id:string,@Body() b:unknown,@Headers('x-idempotency-key') k:string,@Req() req:any){return this.operations.preferenceState(this.actor(req,k),id,b,true);}
 @Post(['batch-read','read-batch']) batch(@Body() b:unknown,@Headers('x-idempotency-key') k:string,@Req() req:any){return this.operations.batchRead(this.actor(req,k),b);}
 @Post('dismiss-batch') dismissBatch(@Body() b:unknown,@Headers('x-idempotency-key') k:string,@Req() req:any){return this.operations.batchRead(this.actor(req,k),b,'dismiss');}
 @Get('catalog') catalog(@Query() q:any,@Req() req:any){return this.service.catalog(req.user,q);}
 @Get(':id') detail(@Param('id') id:string,@Req() req:any){return this.service.detail(req.user,id);}
 @Post(':id/read') read(@Param('id') id:string,@Body() b:unknown,@Headers('x-idempotency-key') k:string,@Req() req:any){return this.operations.mark(this.actor(req,k),id,b,'read');}
 @Post(':id/dismiss') dismiss(@Param('id') id:string,@Body() b:unknown,@Headers('x-idempotency-key') k:string,@Req() req:any){return this.operations.mark(this.actor(req,k),id,b,'dismiss');}
}
