import { Module } from '@nestjs/common';
import { EventCoreModule } from '../event-core/event-core.module';
import { EventDeliveryModule } from '../event-delivery/event-delivery.module';
import { WorkflowsModule } from '../workflows/workflows.module';
import { IamModule } from '../iam/iam.module';
import { EventsMetadataService } from './events-metadata.service';
import { EventsCompilerService } from './events-compiler.service';
import { EventsService } from './events.service';
import { EventsController } from './events.controller';

@Module({imports:[EventCoreModule,EventDeliveryModule,WorkflowsModule,IamModule],providers:[EventsMetadataService,EventsCompilerService,EventsService],controllers:[EventsController],exports:[EventsService,EventsCompilerService]})
export class EventsModule {}
