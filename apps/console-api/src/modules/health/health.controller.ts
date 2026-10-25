import { Controller, Get, ServiceUnavailableException, Res } from '@nestjs/common';
import { Public } from '../../common/auth';
import { DbService } from '../../infrastructure/db.service';
import { RedisService } from '../../infrastructure/redis.service';
import { assertScheduleWorkersReadyForProbe, readScheduleWorkerProbe } from '../../infrastructure/schedule-worker-probe';
import { collectDefaultMetrics, register } from 'prom-client';
import type { Response } from 'express';
collectDefaultMetrics({prefix:'kongos_'});
@Public() @Controller()
export class HealthController {
 constructor(private readonly db:DbService,private readonly redis:RedisService){}
 @Get('health/live') live(){return {status:'alive'};}
 @Get('health/ready') async ready(){
  try{
   await this.db.one('SELECT 1');
   await this.redis.client.ping();
   const schedules=readScheduleWorkerProbe();
   assertScheduleWorkersReadyForProbe(schedules);
   return {status:'ready',schedules};
  }catch(error){
   const code=(error as {code?:string})?.code;
   if(code==='BUSINESS_SCHEDULE_WORKER_NOT_READY'){
    throw new ServiceUnavailableException({code,message:'业务排程 worker 未就绪'});
   }
   throw new ServiceUnavailableException({code:'NOT_READY',message:'控制台存储暂不可用'});
  }
 }
 @Get('metrics') async metrics(@Res() res:Response){res.type(register.contentType).send(await register.metrics());}
}
