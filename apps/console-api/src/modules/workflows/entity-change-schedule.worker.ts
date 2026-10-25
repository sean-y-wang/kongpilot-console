import { Injectable, ServiceUnavailableException } from '@nestjs/common';
import { EntityChangeScheduleRepository } from './entity-change-schedule.repository';
import type { EntityScheduleWorkerDelegate } from './entity-change-schedule.contract';

/** Explicitly invoked orchestration only; no timer or native authority is
 * installed by this class. Root owns due authorization and genuine handles.
 * It receives original opaque identity unchanged, never a reconstructed actor. */
@Injectable()
export class EntityChangeScheduleWorker {
  private delegate?:Readonly<EntityScheduleWorkerDelegate>;
  private busy=false;
  constructor(private readonly repository:EntityChangeScheduleRepository){}
  installFixedDelegate(delegate:EntityScheduleWorkerDelegate):void{
    if(this.delegate||!delegate||typeof delegate.acquireDueClaim!=='function'||typeof delegate.executeClaim!=='function')throw new Error('Scheduled worker requires one fixed native delegate');
    this.delegate=Object.freeze({acquireDueClaim:delegate.acquireDueClaim.bind(delegate),executeClaim:delegate.executeClaim.bind(delegate)});
  }
  async tick():Promise<{checked:number;claimed:number;completed:number;blocked:number;busy:boolean}>{
    if(!this.delegate)throw new ServiceUnavailableException({code:'ENTITY_SCHEDULE_WORKER_NOT_ENABLED'});
    if(this.busy)return{checked:0,claimed:0,completed:0,blocked:0,busy:true};
    this.busy=true;let checked=0,claimed=0,completed=0,blocked=0;
    try{
      for(const id of await this.repository.listDue(25)){
        checked++;
        try{const handle=await this.delegate.acquireDueClaim(id);if(!handle){blocked++;continue;}
          if(typeof handle!=='object'||Array.isArray(handle))throw new Error('Invalid genuine claim handle');
          claimed++;await this.delegate.executeClaim(handle);completed++;
        }catch{blocked++;/* Root preserves exact failure/unknown evidence; no retry or error material escapes. */}
      }
      return{checked,claimed,completed,blocked,busy:false};
    }finally{this.busy=false;}
  }
}
