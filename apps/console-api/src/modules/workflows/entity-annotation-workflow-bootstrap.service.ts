import {Injectable,OnModuleInit} from '@nestjs/common';
import {EntityAnnotationWorkflowService} from '../annotations/entity-annotation-workflow.service';
import {WorkflowPlansService} from './workflow-plans.service';
import {ApprovedWorkflowExecutionService} from './approved-workflow-execution.service';
import {WorkflowService} from './workflow.service';

/** Fixed server wiring only. Annotation retains the genuine selected scope,
 * current entity proof and ordinary Kong version/transport validation. */
@Injectable()
export class EntityAnnotationWorkflowBootstrapService implements OnModuleInit {
 private installed=false;
 constructor(private readonly annotations:EntityAnnotationWorkflowService,private readonly plans:WorkflowPlansService,
  private readonly approved:ApprovedWorkflowExecutionService,private readonly workflows:WorkflowService){}
 onModuleInit():void {
  if(this.installed)return;
  const original=this.annotations.approvedDelegate();
  this.plans.installEntityAnnotationDelegate(original);
  this.approved.installEntityAnnotationDelegate(original);
  this.workflows.installEntityAnnotationCompletionDelegate(this.annotations.completionDelegate());
  this.installed=true;
 }
}
