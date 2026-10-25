import { Module } from '@nestjs/common';
import { EntitiesModule } from '../entities/entities.module';
import { ConfigurationModule } from '../configuration/configuration.module';
import { WorkflowsModule } from '../workflows/workflows.module';
import { ToolboxController } from './toolbox.controller';
import { ToolboxService } from './toolbox.service';
import { DraftsService } from './drafts.service';
import { CacheOperationsService } from './cache-operations.service';
@Module({imports:[EntitiesModule,ConfigurationModule,WorkflowsModule],controllers:[ToolboxController],providers:[ToolboxService,DraftsService,CacheOperationsService]})
export class ToolboxModule {}
