import { Module } from '@nestjs/common';
import { EntitiesModule } from '../entities/entities.module';
import { PluginCenterController } from './plugin-center.controller';
import { PluginCenterService } from './plugin-center.service';
@Module({ imports: [EntitiesModule], controllers: [PluginCenterController], providers: [PluginCenterService], exports: [PluginCenterService] })
export class PluginCenterModule {}
