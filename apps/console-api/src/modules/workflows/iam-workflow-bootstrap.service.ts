import { Injectable, OnModuleInit } from '@nestjs/common';
import { IamWorkflowService } from '../iam/iam-workflow.service';
import { WorkflowPlansService } from './workflow-plans.service';
import { ApprovedWorkflowExecutionService } from './approved-workflow-execution.service';
import { WorkflowService } from './workflow.service';

/** Fixed server registration. HTTP input cannot replace the IAM verifier. */
@Injectable()
export class IamWorkflowBootstrapService implements OnModuleInit {
  private installed = false;
  constructor(private readonly iam: IamWorkflowService, private readonly plans: WorkflowPlansService,
    private readonly approved: ApprovedWorkflowExecutionService, private readonly workflows: WorkflowService) {}
  onModuleInit(): void {
    if (this.installed) return;
    const delegate = this.iam.approvedDelegate();
    this.plans.installIamMetadataDelegate(delegate);
    this.approved.installIamMetadataDelegate(delegate);
    this.workflows.installIamMetadataCompletionDelegate(this.iam.completionDelegate());
    this.installed = true;
  }
}
