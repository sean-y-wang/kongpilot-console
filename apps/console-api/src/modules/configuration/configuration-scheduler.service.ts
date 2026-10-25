import {Injectable,Logger,OnModuleDestroy,OnModuleInit} from '@nestjs/common';
import {ConfigurationService} from './configuration.service';
import {safeConfigurationError} from './configuration-input';

@Injectable()
export class ConfigurationSchedulerService implements OnModuleInit,OnModuleDestroy{
  private timer?:ReturnType<typeof setInterval>;
  private running=false;
  private readonly logger=new Logger(ConfigurationSchedulerService.name);
  constructor(private readonly configuration:ConfigurationService){}
  onModuleInit():void{this.timer=setInterval(()=>{void this.tick();},10000);this.timer.unref();}
  onModuleDestroy():void{if(this.timer)clearInterval(this.timer);}
  private async tick():Promise<void>{if(this.running)return;this.running=true;
    try{await this.configuration.runDueSchedules();}catch(error){this.logger.warn({code:safeConfigurationError(error),component:'configuration-scheduler'});}finally{this.running=false;}}
}
