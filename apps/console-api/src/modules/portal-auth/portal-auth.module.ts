import { Module } from '@nestjs/common';
import { PortalAuthService } from './portal-auth.service';
import { PortalGuard } from './portal-auth.guard';
import { PortalAuthController,PortalOperationsController } from './portal-auth.controller';
@Module({providers:[PortalAuthService,PortalGuard],controllers:[PortalAuthController,PortalOperationsController],exports:[PortalAuthService,PortalGuard]})
export class PortalAuthModule {}
