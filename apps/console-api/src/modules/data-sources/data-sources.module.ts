import { Module } from '@nestjs/common';
import { ClustersModule } from '../clusters/clusters.module';
import { DataSourcesController } from './data-sources.controller';
import { DataSourcesService } from './data-sources.service';
import { IamModule } from '../iam/iam.module';

@Module({ imports: [ClustersModule,IamModule], controllers: [DataSourcesController], providers: [DataSourcesService], exports: [DataSourcesService] })
export class DataSourcesModule {}
