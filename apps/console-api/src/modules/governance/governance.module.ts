import {Module} from '@nestjs/common';
import {ConfigurationModule} from '../configuration/configuration.module';
import {EntitiesModule} from '../entities/entities.module';
import {WorkspacesModule} from '../workspaces/workspaces.module';
import {IamModule} from '../iam/iam.module';
import {WorkflowsModule} from '../workflows/workflows.module';
import {EventCoreModule} from '../event-core/event-core.module';
import {GovernanceAuthorityService} from './governance-authority.service';
import {GovernanceInventoryService} from './governance-inventory.service';
import {GovernanceRepositoryService} from './governance-repository.service';
import {GovernanceMetadataService} from './governance-metadata.service';
import {GovernanceService} from './governance.service';
import {GovernanceSchedulerService} from './governance-scheduler.service';
import {GovernanceController} from './governance.controller';
import {GovernancePromotionSourceService} from './governance-promotion-source.service';

@Module({imports:[ConfigurationModule,EntitiesModule,WorkspacesModule,IamModule,WorkflowsModule,EventCoreModule],
 providers:[GovernanceAuthorityService,GovernanceInventoryService,GovernanceRepositoryService,GovernanceMetadataService,GovernanceService,GovernanceSchedulerService,GovernancePromotionSourceService],
 controllers:[GovernanceController],exports:[GovernanceAuthorityService,GovernanceInventoryService,GovernanceRepositoryService,GovernanceMetadataService,GovernanceService]})
export class GovernanceModule{}
