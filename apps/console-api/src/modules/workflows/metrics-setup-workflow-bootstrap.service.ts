import { Injectable, OnModuleInit } from '@nestjs/common';
import { VitalsSetupService } from '../vitals/vitals-setup.service';
import { WorkflowPlansService } from './workflow-plans.service';
import { WorkflowService } from './workflow.service';
import { ApprovedWorkflowExecutionService } from './approved-workflow-execution.service';

/** Only this fixed bootstrap registers the managed Native origin verifier. */
@Injectable()
export class MetricsSetupWorkflowBootstrapService implements OnModuleInit {
  private installed=false;
  constructor(private readonly setup:VitalsSetupService,private readonly plans:WorkflowPlansService,
    private readonly workflows:WorkflowService,private readonly approved:ApprovedWorkflowExecutionService){}
  onModuleInit():void{
    if(this.installed)return;
    const delegate=this.setup.approvedDelegate();
    this.plans.installMetricsSetupDelegate(delegate);
    this.approved.installMetricsSetupDelegate(delegate);
    this.workflows.installMetricsSetupExecutionDelegate(this.setup.executionDelegate());
    this.setup.installExecutionBridge({verify:(plan,executionId,phase,tx)=>this.approved.verifyMetricsSetupExecution(plan,executionId,phase,tx)});
    this.installed=true;
  }
}
