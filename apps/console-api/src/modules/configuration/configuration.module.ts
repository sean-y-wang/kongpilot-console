import { Global, Module } from '@nestjs/common';
import { ConfigStorageModule } from '../config-storage/config-storage.module';
import { ConfigCaptureModule } from '../config-capture/config-capture.module';
import { WorkflowsModule } from '../workflows/workflows.module';
import { CONFIGURATION_ACCESS } from './configuration.types';
import { ConfigurationDurableService } from './configuration-durable.service';
import { ConfigurationDurableRepository } from './configuration-durable.repository';
import { ConfigurationAccessService } from './configuration-access.service';
import { ConfigurationNativeService } from './configuration-native.service';
import { ConfigurationService } from './configuration.service';
import { ConfigurationController } from './configuration.controller';
import {ConfigurationSchedulerService} from './configuration-scheduler.service';
import {ConfigurationDeckService} from './configuration-deck.service';
import {CONFIGURATION_DECK_ACCESS} from '../deck-adapter/deck.types';
import {ConfigurationFailureLedgerService} from './configuration-failure-ledger.service';
import { ConfigurationRecycleGraphsService } from './configuration-recycle-graphs.service';
import {ConfigurationOriginService} from './configuration-origin.service';
@Global()
@Module({imports:[ConfigStorageModule,ConfigCaptureModule,WorkflowsModule],providers:[ConfigurationOriginService,ConfigurationAccessService,ConfigurationDurableService,ConfigurationDurableRepository,
  {provide:CONFIGURATION_ACCESS,useExisting:ConfigurationAccessService},ConfigurationNativeService,ConfigurationService,ConfigurationFailureLedgerService,ConfigurationRecycleGraphsService,ConfigurationSchedulerService,ConfigurationDeckService,
  {provide:CONFIGURATION_DECK_ACCESS,useExisting:ConfigurationDeckService}],
  controllers:[ConfigurationController],exports:[ConfigurationAccessService,CONFIGURATION_ACCESS,ConfigurationService,CONFIGURATION_DECK_ACCESS]})
export class ConfigurationModule{}
