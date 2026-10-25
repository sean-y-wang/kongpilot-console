import { Module } from '@nestjs/common';
import { EntitiesController } from './entities.controller';
import { EntityService } from './entities.service';
import { EntityChangeCompilerService } from './entity-change-compiler.service';
import { EntityChangeBoundaryService } from './entity-change-boundary.service';
import {EntityPreparedWriterService} from './entity-prepared-writer.service';

@Module({ controllers: [EntitiesController], providers: [EntityService, EntityChangeCompilerService, EntityChangeBoundaryService,EntityPreparedWriterService], exports: [EntityService, EntityChangeCompilerService, EntityChangeBoundaryService,EntityPreparedWriterService] })
export class EntitiesModule {}
