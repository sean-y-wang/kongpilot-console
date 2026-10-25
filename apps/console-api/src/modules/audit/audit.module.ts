import { Module } from '@nestjs/common';
import { AuditController,GlobalAuditController } from './audit.controller';
import { AuditQueryService } from './audit-query.service';
import { AuditIntegrityService } from './audit-integrity.service';
import { AuditExportService } from './audit-export.service';
import { AuditCursorService } from './audit-cursor.service';

@Module({controllers:[AuditController,GlobalAuditController],providers:[AuditQueryService,AuditIntegrityService,AuditExportService,AuditCursorService],
  exports:[AuditQueryService,AuditIntegrityService,AuditExportService]})
export class AuditModule {}
