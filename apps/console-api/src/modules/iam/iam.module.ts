import { Module } from '@nestjs/common';
import { IamService } from './iam.service';
import { IamController } from './iam.controller';
import { IamMutationsService } from './iam-mutations.service';

@Module({providers:[IamService,IamMutationsService],controllers:[IamController],exports:[IamService,IamMutationsService]})
export class IamModule {}
