import { Global, Module } from '@nestjs/common';
import { KongService } from './kong.service';

@Global()
@Module({ providers: [KongService], exports: [KongService] })
export class KongModule {}
