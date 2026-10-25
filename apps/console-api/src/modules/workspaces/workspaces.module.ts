import { Module } from '@nestjs/common';
import { WorkspaceService } from './workspace.service';
import { WorkspacesController } from './workspaces.controller';
import { EntityAnnotationsService } from './entity-annotations.service';
import { EntityAnnotationsController } from './entity-annotations.controller';

/** The database-only resolver is registered once by the global infrastructure module. */
@Module({providers:[WorkspaceService,EntityAnnotationsService],controllers:[WorkspacesController,EntityAnnotationsController],exports:[WorkspaceService,EntityAnnotationsService]})
export class WorkspacesModule {}
