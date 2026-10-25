import {Injectable,OnModuleInit} from '@nestjs/common';
import {ControlMetadataService} from '../control-plane/control-metadata.service';
import {WorkflowPlansService} from './workflow-plans.service';
import {ApprovedWorkflowExecutionService} from './approved-workflow-execution.service';
import {WorkflowService} from './workflow.service';
@Injectable()
export class ControlMetadataWorkflowBootstrapService implements OnModuleInit {
 private installed=false;
 constructor(private readonly control:ControlMetadataService,private readonly plans:WorkflowPlansService,private readonly approved:ApprovedWorkflowExecutionService,private readonly workflows:WorkflowService){}
 onModuleInit():void{if(this.installed)return;const original=this.control.approvedDelegate();this.plans.installControlMetadataDelegate(original);this.approved.installControlMetadataDelegate(original);this.workflows.installControlMetadataCompletionDelegate(this.control.completionDelegate());this.installed=true;}
}
