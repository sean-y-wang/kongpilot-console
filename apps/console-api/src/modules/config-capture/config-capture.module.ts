import { Module } from '@nestjs/common';
import { ConfigurationCaptureService } from './configuration-capture.service';
import { ConfigStorageModule } from '../config-storage/config-storage.module';

@Module({ imports: [ConfigStorageModule], providers: [ConfigurationCaptureService], exports: [ConfigurationCaptureService] })
export class ConfigCaptureModule {}
