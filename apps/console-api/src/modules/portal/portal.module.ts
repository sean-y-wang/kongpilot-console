import { Module } from '@nestjs/common';
import { WorkflowsModule } from '../workflows/workflows.module';
import { IamModule } from '../iam/iam.module';
import { PortalAuthModule } from '../portal-auth/portal-auth.module';
import { PortalDocumentService } from './portal-document.service';
import { PortalNativeService } from './portal-native.service';
import { PortalAdminService } from './portal-admin.service';
import { PortalPublicService } from './portal-public.service';
import { PortalCredentialsService } from './portal-credentials.service';
import { PortalIdentitiesService } from './portal-identities.service';
import { PortalAdminController,PortalPublicController,PortalDeveloperController } from './portal.controller';
@Module({imports:[WorkflowsModule,IamModule,PortalAuthModule],providers:[PortalDocumentService,PortalNativeService,PortalAdminService,PortalPublicService,PortalCredentialsService,PortalIdentitiesService],controllers:[PortalAdminController,PortalPublicController,PortalDeveloperController],exports:[PortalAdminService,PortalCredentialsService]})
export class PortalModule {}
