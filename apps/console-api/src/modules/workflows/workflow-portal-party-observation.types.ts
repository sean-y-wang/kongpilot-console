import type {DbService} from '../../infrastructure/db.service';
import type {KongExecutionFrame,ScheduledPortalFinalNativePhase} from '../../infrastructure/kong/execution-context.service';
import type {ApprovedExecutionProof,ApprovedStepProof} from './approved-execution.types';
import type {WorkflowScheduledNamespaceProof,WorkflowScheduledAuthorityCheckpoint} from './workflow-scheduled-authority.types';
import type {WorkflowScheduledPlanV1,WorkflowScheduleDraft} from './workflow-schedule.contract';

/** Read-only identities from one hard-private Authority invocation. The handle
 * is neither a READ grant, a new SDK/404 witness nor a Native capability. Each
 * party must independently authorize the complete same original observations. */
export interface PortalPartyObservationRoundOriginal {
 readonly handle:object;readonly frame:KongExecutionFrame;readonly namespaceHandle:object;
 readonly namespace:Readonly<WorkflowScheduledNamespaceProof>;readonly execution:ApprovedExecutionProof|null;
 readonly step:ApprovedStepProof|null;readonly final:Readonly<ScheduledPortalFinalNativePhase>|null;
 readonly checkpoint:WorkflowScheduledAuthorityCheckpoint;readonly transaction:DbService;
 readonly plan:Readonly<WorkflowScheduledPlanV1>;readonly draft:Readonly<WorkflowScheduleDraft>;
 readonly parties:readonly Readonly<{userId:string;role:'executor'|'reviewer'}>[];
}
export interface PortalPartyObservationRoundVerifier {
 current():Readonly<PortalPartyObservationRoundOriginal>|null;
 assert(original:Readonly<PortalPartyObservationRoundOriginal>):void;
}
export interface PortalPartyObservationRoundRunner {
 run<T>(original:Readonly<PortalPartyObservationRoundOriginal>,fn:()=>Promise<T>):Promise<T>;
}
