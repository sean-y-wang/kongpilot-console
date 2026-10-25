import {EntityRecycleCurrentWitnessService} from '../recycle-bin/entity-recycle-current-witness.service';
import {Injectable, OnModuleInit, Optional} from '@nestjs/common';
import {EntityChangeCompilerService} from '../entities/entity-change-compiler.service';
import {EntityChangeBoundaryService} from '../entities/entity-change-boundary.service';
import {RecycleService} from '../recycle-bin/recycle.service';
import {EntityChangeIntentsService} from './entity-change-intents.service';
import {EntityChangeExecutionService} from './entity-change-execution.service';
import {WorkflowService} from './workflow.service';

/** Registers fixed read/subject delegates only. Neither registration nor an
 * accepted intent authorizes execution; the native adapter remains closed. */
@Injectable()
export class EntityChangeBootstrapService implements OnModuleInit {
  constructor(private readonly compiler: EntityChangeCompilerService, private readonly boundary: EntityChangeBoundaryService,
    private readonly recycle: RecycleService, private readonly intents: EntityChangeIntentsService,
    private readonly executor:EntityChangeExecutionService,private readonly workflows:WorkflowService,@Optional() private readonly current?:EntityRecycleCurrentWitnessService) {}
  onModuleInit(): void {
    if(this.current)this.boundary.installCurrentRecycleWitnessReader({resolve:handle=>this.current!.resolve(handle)});
    this.compiler.installPreparationBoundary({
      assertPacket: input => this.boundary.assertPacket(input),
      assertStoredSubject: input => this.boundary.assertStoredSubject(input),
      prepareRecycle: (cid, request, actor) => this.recycle.prepareEntityChange(cid, request, actor),
      assertRecycleCurrent: (cid, request, material, actor, scope) => this.recycle.assertPreparedEntityChange(cid, request, material, actor, scope)
    });
    this.intents.installSubjectPolicy({
      assertSubject: (envelope, id, action, tx) => this.boundary.assertIntentSubject(envelope, id, action, tx),
      verifyReviewer: (envelope, id, tx) => this.boundary.assertReviewer(id, envelope.prepared, tx)
    });
    this.workflows.installEntityChangeExecutor({canExecute:(plan,actor)=>this.executor.canExecute(plan,actor),canPreflight:(plan,actor)=>this.executor.canPreflight(plan,actor),canRollback:(plan,actor)=>this.executor.canRollback(plan,actor),execute:(plan,body,actor)=>this.executor.execute(plan,body,actor),historical:(plan,actor)=>this.executor.historical(plan,actor),rollbackPrepare:(plan,body,actor)=>this.executor.rollbackPrepare(plan,body,actor),preflight:(plan,actor)=>this.executor.preflight(plan,actor),closeUnsent:(plan,body,actor)=>this.executor.closeUnsent(plan,body,actor),reconcileNoSend:(plan,body,actor)=>this.executor.reconcileNoSend(plan,body,actor),reconcileTerminalMetadata:(plan,body,actor)=>this.executor.reconcileTerminalMetadata(plan,body,actor),reconcilePartialRestoreNoSend:(plan,body,actor)=>this.executor.reconcilePartialRestoreNoSend(plan,body,actor),reconcileTargetResult:(plan,body,actor)=>this.executor.reconcileTargetResult(plan,body,actor)});
  }
}
