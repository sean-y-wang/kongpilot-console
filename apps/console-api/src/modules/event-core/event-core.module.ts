import {Global,Module} from '@nestjs/common';
import {AuditOutboxWriter} from './audit-outbox-writer.service';
import {EventRepositoryService} from './event-repository.service';
import {OutboxRepositoryService} from './outbox-repository.service';
import {DeliveryRepositoryService} from './delivery-repository.service';
import {NotificationService} from './notification.service';
import {NotificationOperationsService} from './notification-operations.service';
import {NotificationsController} from './notification.controller';
import {OutboxWorkerService,EVENT_OUTBOX_WORKER_OPTIONS,outboxWorkerOptions} from './outbox-worker.service';
@Global()
@Module({controllers:[NotificationsController],providers:[AuditOutboxWriter,EventRepositoryService,OutboxRepositoryService,OutboxWorkerService,{provide:EVENT_OUTBOX_WORKER_OPTIONS,useFactory:outboxWorkerOptions},DeliveryRepositoryService,NotificationService,NotificationOperationsService],exports:[AuditOutboxWriter,EventRepositoryService,OutboxRepositoryService,OutboxWorkerService,DeliveryRepositoryService,NotificationService,NotificationOperationsService]})
export class EventCoreModule {}
