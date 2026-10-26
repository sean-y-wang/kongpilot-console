import { Body,Controller,Get,Headers,Param,Post,Query,Req,Res,StreamableFile } from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import type { Response } from 'express';
import type { AuthUser } from '../../common/auth';
import { AuditQueryService } from './audit-query.service';
import { AuditIntegrityService } from './audit-integrity.service';
import { AuditExportService } from './audit-export.service';
import { auditQuery,auditScope } from './audit.types';

interface AuditRequest {user:AuthUser;requestId?:string;ip?:string}
function fileResponse(output:{buffer:Buffer;filename:string;contentType:string},res:Response):StreamableFile {
  res.setHeader('Content-Type',output.contentType);res.setHeader('Content-Disposition',`attachment; filename="${output.filename}"`);
  res.setHeader('Cache-Control','no-store');res.setHeader('X-Content-Type-Options','nosniff');
  res.setHeader('Content-Length',output.buffer.length);return new StreamableFile(output.buffer);
}

@ApiTags('审计日志与完整性')
@Controller('clusters/:clusterId/audit')
export class AuditController {
  constructor(private readonly queries:AuditQueryService,private readonly integrity:AuditIntegrityService,private readonly exports:AuditExportService){}
  @Get('integrity') verify(@Param('clusterId') cid:string,@Req() req:AuditRequest,@Query() query:Record<string,unknown>){return this.integrity.verify(req.user,cid,query);}
  @Post('exports') create(@Param('clusterId') cid:string,@Req() req:AuditRequest,@Body() body:unknown,@Headers('x-idempotency-key') key:string){return this.exports.create(req.user,cid,body,key,req);}
  @Get('exports/by-key/:key') byKey(@Param('clusterId') cid:string,@Param('key') key:string,@Req() req:AuditRequest,@Query() query:Record<string,unknown>){return this.exports.receipt(req.user,auditScope(cid,query),key);}
  @Get('exports/:id/download') async download(@Param('clusterId') cid:string,@Param('id') id:string,@Req() req:AuditRequest,@Query() query:Record<string,unknown>,@Res({passthrough:true}) res:Response){return fileResponse(await this.exports.download(req.user,auditScope(cid,query),id),res);}
  @Get('exports/:id') export(@Param('clusterId') cid:string,@Param('id') id:string,@Req() req:AuditRequest,@Query() query:Record<string,unknown>){return this.exports.get(req.user,auditScope(cid,query),id);}
  @Get() async list(@Param('clusterId') cid:string,@Req() req:AuditRequest,@Query() query:Record<string,unknown>){const page=await this.queries.list(req.user,auditQuery(cid,query));return{...page,items:await this.queries.withActorNames(page.items)};}
  @Get(':id') async get(@Param('clusterId') cid:string,@Param('id') id:string,@Req() req:AuditRequest,@Query() query:Record<string,unknown>){return(await this.queries.withActorNames([await this.queries.get(req.user,auditScope(cid,query),id)]))[0];}
}

@ApiTags('全局身份审计')
@Controller('audit/global')
export class GlobalAuditController {
  constructor(private readonly queries:AuditQueryService,private readonly integrity:AuditIntegrityService,private readonly exports:AuditExportService){}
  @Get('integrity') verify(@Req() req:AuditRequest,@Query() query:Record<string,unknown>){return this.integrity.verify(req.user,null,query);}
  @Post('exports') create(@Req() req:AuditRequest,@Body() body:unknown,@Headers('x-idempotency-key') key:string){return this.exports.create(req.user,null,body,key,req);}
  @Get('exports/by-key/:key') byKey(@Param('key') key:string,@Req() req:AuditRequest,@Query() query:Record<string,unknown>){return this.exports.receipt(req.user,auditScope(null,query),key);}
  @Get('exports/:id/download') async download(@Param('id') id:string,@Req() req:AuditRequest,@Query() query:Record<string,unknown>,@Res({passthrough:true}) res:Response){return fileResponse(await this.exports.download(req.user,auditScope(null,query),id),res);}
  @Get('exports/:id') export(@Param('id') id:string,@Req() req:AuditRequest,@Query() query:Record<string,unknown>){return this.exports.get(req.user,auditScope(null,query),id);}
  @Get() async list(@Req() req:AuditRequest,@Query() query:Record<string,unknown>){const page=await this.queries.list(req.user,auditQuery(null,query));return{...page,items:await this.queries.withActorNames(page.items)};}
  @Get(':id') async get(@Param('id') id:string,@Req() req:AuditRequest,@Query() query:Record<string,unknown>){return(await this.queries.withActorNames([await this.queries.get(req.user,auditScope(null,query),id)]))[0];}
}
