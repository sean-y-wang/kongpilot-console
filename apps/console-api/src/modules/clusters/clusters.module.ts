import { Module } from '@nestjs/common';
import { ClustersController } from './clusters.controller';
import { ClustersService } from './clusters.service';
import { IamModule } from '../iam/iam.module';

@Module({ imports:[IamModule],controllers: [ClustersController], providers: [ClustersService], exports: [ClustersService] })
export class ClustersModule {}
