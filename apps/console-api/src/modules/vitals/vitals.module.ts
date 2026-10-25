import { Module } from '@nestjs/common';
import { EntitiesModule } from '../entities/entities.module';
import { IamModule } from '../iam/iam.module';
import { VitalsController } from './vitals.controller';
import { VitalsService } from './vitals.service';
import { MetricsScopeService } from './metrics-scope.service';
import { MetricsSourceService } from './providers/metrics-source.service';
import { MetricsCatalogService } from './bridges/metrics-catalog.service';
import { MetricsBridgeService } from './bridges/metrics-bridge.service';
@Module({ imports: [EntitiesModule, IamModule], controllers: [VitalsController], providers: [VitalsService, MetricsScopeService, MetricsSourceService, MetricsCatalogService, MetricsBridgeService], exports: [VitalsService,MetricsSourceService] })
export class VitalsModule {}
