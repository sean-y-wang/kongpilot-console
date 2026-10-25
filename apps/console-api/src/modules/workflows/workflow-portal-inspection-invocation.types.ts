import type {DbService} from '../../infrastructure/db.service';
import type {KongExecutionFrame} from '../../infrastructure/kong/execution-context.service';
import type {ApprovedExecutionProof,ApprovedStepProof} from './approved-execution.types';
import type {WorkflowScheduledNamespaceProof,WorkflowScheduledNamespaceCheckpoint} from './workflow-scheduled-authority.types';
/** Bootstrap-only read selector. The handle is created only by Approved's JS
 * private invocation ALS after its original execution/step WeakMap checks.
 * A serialized projection is never an execution, read or Native permit. */
export interface PortalInspectionInvocationOriginal {
 readonly handle:object;readonly frame:KongExecutionFrame;readonly namespaceHandle:object;
 readonly namespace:Readonly<WorkflowScheduledNamespaceProof>;readonly execution:Readonly<ApprovedExecutionProof>;
 readonly step:Readonly<ApprovedStepProof>|null;readonly checkpoint:WorkflowScheduledNamespaceCheckpoint;readonly transaction:DbService;
}
export interface PortalInspectionInvocationVerifier {
 current():Readonly<PortalInspectionInvocationOriginal>|null;
 assert(original:Readonly<PortalInspectionInvocationOriginal>):void;
}
