import { Body, Controller, Delete, Get, Headers, Param, Patch, Post, Query, Req, Res, UseGuards } from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import type { Response } from 'express';
import { portalId } from './portal-input';
import { Public } from '../../common/auth';
import type { EntityActor } from '../entities/entities.types';
import { PortalGuard } from '../portal-auth/portal-auth.guard';
import type { PortalRequestContext } from '../portal-auth/portal-auth.types';
import { PortalAdminService } from './portal-admin.service';
import { PortalCredentialsService } from './portal-credentials.service';
import { PortalIdentitiesService } from './portal-identities.service';
import { PortalPublicService } from './portal-public.service';
const portalContext=(req:any):PortalRequestContext=>({requestId:req.requestId,ip:req.ip,userAgent:req.get('user-agent'),idempotencyKey:req.get('x-idempotency-key')});
@ApiTags('开发者门户管理') @Controller('clusters/:clusterId/portal')
export class PortalAdminController {
  constructor(private readonly admin:PortalAdminService,private readonly identities:PortalIdentitiesService){}
  private actor(req:EntityActor,query:Record<string,unknown>,key?:string):EntityActor{return{user:req.user,requestId:req.requestId,ip:req.ip,workspaceId:query.workspaceId===undefined?undefined:portalId(query.workspaceId),idempotencyKey:key};}
  @Get('settings') settings(@Param('clusterId') cid:string,@Query() query:Record<string,unknown>,@Req() req:EntityActor){return this.admin.settings(cid,this.actor(req,query));}
  @Post('settings') createSettings(@Param('clusterId') cid:string,@Query() query:Record<string,unknown>,@Body() body:unknown,@Headers('x-idempotency-key') key:string,@Req() req:EntityActor){return this.admin.saveSettings(cid,body,this.actor(req,query,key),true);}
  @Patch('settings') saveSettings(@Param('clusterId') cid:string,@Query() query:Record<string,unknown>,@Body() body:unknown,@Headers('x-idempotency-key') key:string,@Req() req:EntityActor){return this.admin.saveSettings(cid,body,this.actor(req,query,key));}
  @Get('service-identities') serviceIdentities(@Param('clusterId') cid:string,@Query() query:Record<string,unknown>,@Req() req:EntityActor){return this.identities.list(cid,query,this.actor(req,query),true);}
  @Get('entity-identities') entityIdentities(@Param('clusterId') cid:string,@Query() query:Record<string,unknown>,@Req() req:EntityActor){return this.identities.list(cid,query,this.actor(req,query));}
  @Get('publications') publications(@Param('clusterId') cid:string,@Query() query:Record<string,unknown>,@Req() req:EntityActor){return this.admin.publications(cid,query,this.actor(req,query));}
  @Get('publications/:id') publication(@Param('clusterId') cid:string,@Param('id') id:string,@Query() query:Record<string,unknown>,@Req() req:EntityActor){return this.admin.publication(cid,id,this.actor(req,query));}
  @Post('publications') createPublication(@Param('clusterId') cid:string,@Query() query:Record<string,unknown>,@Body() body:unknown,@Headers('x-idempotency-key') key:string,@Req() req:EntityActor){return this.admin.savePublication(cid,undefined,body,this.actor(req,query,key));}
  @Patch('publications/:id') updatePublication(@Param('clusterId') cid:string,@Param('id') id:string,@Query() query:Record<string,unknown>,@Body() body:unknown,@Headers('x-idempotency-key') key:string,@Req() req:EntityActor){return this.admin.savePublication(cid,id,body,this.actor(req,query,key));}
  @Post('publications/:id/document/generate') generateDocument(@Param('clusterId') cid:string,@Param('id') id:string,@Query() query:Record<string,unknown>,@Body() body:unknown,@Headers('x-idempotency-key') key:string,@Req() req:EntityActor){return this.admin.generateDocument(cid,id,body,this.actor(req,query,key));}
  @Post('publications/:id/document') document(@Param('clusterId') cid:string,@Param('id') id:string,@Query() query:Record<string,unknown>,@Body() body:unknown,@Headers('x-idempotency-key') key:string,@Req() req:EntityActor){return this.admin.uploadDocument(cid,id,body,this.actor(req,query,key));}
  @Post('publications/:id/publish') publish(@Param('clusterId') cid:string,@Param('id') id:string,@Query() query:Record<string,unknown>,@Body() body:unknown,@Headers('x-idempotency-key') key:string,@Req() req:EntityActor){return this.admin.publish(cid,id,body,this.actor(req,query,key));}
  @Post('publications/:id/unpublish') unpublish(@Param('clusterId') cid:string,@Param('id') id:string,@Query() query:Record<string,unknown>,@Body() body:unknown,@Headers('x-idempotency-key') key:string,@Req() req:EntityActor){return this.admin.publish(cid,id,body,this.actor(req,query,key),false);}
  @Delete('publications/:id') deletePublication(@Param('clusterId') cid:string,@Param('id') id:string,@Query() query:Record<string,unknown>,@Body() body:unknown,@Headers('x-idempotency-key') key:string,@Req() req:EntityActor){return this.admin.archive(cid,id,body,this.actor(req,query,key),'publications');}
  @Post('publications/:id/restore') restorePublication(@Param('clusterId') cid:string,@Param('id') id:string,@Query() query:Record<string,unknown>,@Body() body:unknown,@Headers('x-idempotency-key') key:string,@Req() req:EntityActor){return this.admin.archive(cid,id,body,this.actor(req,query,key),'publications',true);}
  @Get('pages') pages(@Param('clusterId') cid:string,@Query() query:Record<string,unknown>,@Req() req:EntityActor){return this.admin.pages(cid,query,this.actor(req,query));}
  @Get('pages/:id') page(@Param('clusterId') cid:string,@Param('id') id:string,@Query() query:Record<string,unknown>,@Req() req:EntityActor){return this.admin.page(cid,id,this.actor(req,query));}
  @Post('pages') createPage(@Param('clusterId') cid:string,@Query() query:Record<string,unknown>,@Body() body:unknown,@Headers('x-idempotency-key') key:string,@Req() req:EntityActor){return this.admin.savePage(cid,undefined,body,this.actor(req,query,key));}
  @Patch('pages/:id') updatePage(@Param('clusterId') cid:string,@Param('id') id:string,@Query() query:Record<string,unknown>,@Body() body:unknown,@Headers('x-idempotency-key') key:string,@Req() req:EntityActor){return this.admin.savePage(cid,id,body,this.actor(req,query,key));}
  @Post('pages/:id/publish') publishPage(@Param('clusterId') cid:string,@Param('id') id:string,@Query() query:Record<string,unknown>,@Body() body:unknown,@Headers('x-idempotency-key') key:string,@Req() req:EntityActor){return this.admin.publishPage(cid,id,body,this.actor(req,query,key));}
  @Post('pages/:id/unpublish') unpublishPage(@Param('clusterId') cid:string,@Param('id') id:string,@Query() query:Record<string,unknown>,@Body() body:unknown,@Headers('x-idempotency-key') key:string,@Req() req:EntityActor){return this.admin.publishPage(cid,id,body,this.actor(req,query,key),false);}
  @Delete('pages/:id') deletePage(@Param('clusterId') cid:string,@Param('id') id:string,@Query() query:Record<string,unknown>,@Body() body:unknown,@Headers('x-idempotency-key') key:string,@Req() req:EntityActor){return this.admin.archive(cid,id,body,this.actor(req,query,key),'pages');}
  @Post('pages/:id/restore') restorePage(@Param('clusterId') cid:string,@Param('id') id:string,@Query() query:Record<string,unknown>,@Body() body:unknown,@Headers('x-idempotency-key') key:string,@Req() req:EntityActor){return this.admin.archive(cid,id,body,this.actor(req,query,key),'pages',true);}
  @Get('developers') developers(@Param('clusterId') cid:string,@Query() query:Record<string,unknown>,@Req() req:EntityActor){return this.admin.developers(cid,query,this.actor(req,query));}
  @Get('developers/:id') developer(@Param('clusterId') cid:string,@Param('id') id:string,@Query() query:Record<string,unknown>,@Req() req:EntityActor){return this.admin.developer(cid,id,query,this.actor(req,query));}
  @Post('developers/:id/review') review(@Param('clusterId') cid:string,@Param('id') id:string,@Query() query:Record<string,unknown>,@Body() body:unknown,@Headers('x-idempotency-key') key:string,@Req() req:EntityActor){return this.admin.reviewDeveloper(cid,id,body,this.actor(req,query,key));}
  @Get('applications') applications(@Param('clusterId') cid:string,@Query() query:Record<string,unknown>,@Req() req:EntityActor){return this.admin.applications(cid,query,this.actor(req,query));}
  @Get('applications/:id') application(@Param('clusterId') cid:string,@Param('id') id:string,@Query() query:Record<string,unknown>,@Req() req:EntityActor){return this.admin.application(cid,id,query,this.actor(req,query));}
  @Get('applications/:id/grants') applicationGrants(@Param('clusterId') cid:string,@Param('id') id:string,@Query() query:Record<string,unknown>,@Req() req:EntityActor){return this.admin.applicationGrants(cid,id,query,this.actor(req,query));}
  @Get('applications/:id/requests') applicationRequests(@Param('clusterId') cid:string,@Param('id') id:string,@Query() query:Record<string,unknown>,@Req() req:EntityActor){return this.admin.applicationRequests(cid,id,query,this.actor(req,query));}
  @Get('requests') requests(@Param('clusterId') cid:string,@Query() query:Record<string,unknown>,@Req() req:EntityActor){return this.admin.requests(cid,query,this.actor(req,query));}
  @Patch('applications/:id') updateApplication(@Param('clusterId') cid:string,@Param('id') id:string,@Query() query:Record<string,unknown>,@Body() body:unknown,@Headers('x-idempotency-key') key:string,@Req() req:EntityActor){return this.admin.updateApplication(cid,id,body,this.actor(req,query,key));}
  @Get('operations/by-key/:key') receipt(@Param('clusterId') cid:string,@Param('key') key:string,@Query() query:Record<string,unknown>,@Req() req:EntityActor){return this.admin.operations(cid,key,this.actor(req,query));}
}
@Public() @ApiTags('公开开发者门户') @Controller('portal')
export class PortalPublicController {
  constructor(private readonly service:PortalPublicService){}
  @Get('tenants') tenants(@Query() query:Record<string,unknown>){return this.service.tenants(query);}
  @Get('tenants/:slug') tenant(@Param('slug') slug:string){return this.service.tenant(slug);}
  @Get('publications') publications(@Query() query:Record<string,unknown>){return this.service.publications(query);}
  @Get('publications/:id') publication(@Param('id') id:string,@Query() query:Record<string,unknown>){return this.service.publication(id,query);}
  @Get('publications/:id/document') document(@Param('id') id:string,@Query() query:Record<string,unknown>){return this.service.publication(id,query,true);}
  @Get('pages') pages(@Query() query:Record<string,unknown>){return this.service.pages(query);}
  @Get('pages/:slug') page(@Param('slug') slug:string,@Query() query:Record<string,unknown>){return this.service.page(slug,query);}
}
@Public() @UseGuards(PortalGuard) @ApiTags('开发者应用与凭证') @Controller('portal')
export class PortalDeveloperController {
  constructor(private readonly service:PortalCredentialsService){}
  @Get('applications') applications(@Query() query:Record<string,unknown>,@Req() req:any){return this.service.applications(req.portalPrincipal,query);}
  @Get('applications/:id') application(@Param('id') id:string,@Req() req:any){return this.service.application(req.portalPrincipal,id);}
  @Post('applications') create(@Body() body:unknown,@Req() req:any){return this.service.saveApplication(req.portalPrincipal,undefined,body,portalContext(req));}
  @Patch('applications/:id') update(@Param('id') id:string,@Body() body:unknown,@Req() req:any){return this.service.saveApplication(req.portalPrincipal,id,body,portalContext(req));}
  @Delete('applications/:id') archive(@Param('id') id:string,@Body() body:unknown,@Req() req:any){return this.service.archiveApplication(req.portalPrincipal,id,body,portalContext(req));}
  @Post('applications/:id/restore') restore(@Param('id') id:string,@Body() body:unknown,@Req() req:any){return this.service.archiveApplication(req.portalPrincipal,id,body,portalContext(req),true);}
  @Get('applications/:appId/grants') grants(@Param('appId') id:string,@Query() query:Record<string,unknown>,@Req() req:any){return this.service.grants(req.portalPrincipal,id,query);}
  @Get('applications/:appId/grants/:grantId/credentials') credentials(@Param('appId') id:string,@Param('grantId') grant:string,@Query() query:Record<string,unknown>,@Req() req:any){return this.service.credentials(req.portalPrincipal,id,grant,query);}
  @Post('applications/:appId/grants/:grantId/credentials/:id/reveal') reveal(@Param('appId') app:string,@Param('grantId') grant:string,@Param('id') id:string,@Body() body:unknown,@Req() req:any,@Res({passthrough:true}) res:Response){res.setHeader('Cache-Control','no-store');res.setHeader('Pragma','no-cache');return this.service.reveal(req.portalPrincipal,app,grant,id,body,portalContext(req));}
  @Post('applications/:appId/grants/:grantId/credentials/:id/rotate') rotate(@Param('appId') app:string,@Param('grantId') grant:string,@Param('id') id:string,@Body() body:unknown,@Req() req:any){return this.service.change(req.portalPrincipal,app,grant,id,body,portalContext(req),'rotate');}
  @Post('applications/:appId/grants/:grantId/credentials/:id/revoke') revoke(@Param('appId') app:string,@Param('grantId') grant:string,@Param('id') id:string,@Body() body:unknown,@Req() req:any){return this.service.change(req.portalPrincipal,app,grant,id,body,portalContext(req),'revoke');}
  /** KP-006: UI「停用/禁用」与 revoke 同义；独立路由避免客户端歧义。 */
  @Post('applications/:appId/grants/:grantId/credentials/:id/disable') disable(@Param('appId') app:string,@Param('grantId') grant:string,@Param('id') id:string,@Body() body:unknown,@Req() req:any){return this.service.change(req.portalPrincipal,app,grant,id,body,portalContext(req),'disable');}
  @Post('requests') request(@Body() body:unknown,@Req() req:any){return this.service.request(req.portalPrincipal,body,portalContext(req));}
  @Get('requests') requests(@Query() query:Record<string,unknown>,@Req() req:any){return this.service.requests(req.portalPrincipal,query);}
  @Get('requests/:id') requestDetail(@Param('id') id:string,@Req() req:any){return this.service.requestDetail(req.portalPrincipal,id);}
  @Post('requests/:id/cancel') cancelRequest(@Param('id') id:string,@Body() body:unknown,@Req() req:any){return this.service.cancelRequest(req.portalPrincipal,id,body,portalContext(req));}
}
