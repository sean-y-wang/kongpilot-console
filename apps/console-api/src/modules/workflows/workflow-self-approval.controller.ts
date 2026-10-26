import { Body, Controller, Get, Put, Req } from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import { RequireSuperAdmin } from '../../common/auth';
import { WorkflowSelfApprovalService } from './workflow-self-approval.service';

@ApiTags('统一工作流')
@Controller('workflow-settings/self-approval')
export class WorkflowSelfApprovalController {
  constructor(private readonly service: WorkflowSelfApprovalService) {}
  @Get() get() { return this.service.read(); }
  @RequireSuperAdmin() @Put() put(@Body() body: unknown, @Req() req: any) { return this.service.update(body, { user: req.user, requestId: req.requestId, ip: req.ip }); }
}
