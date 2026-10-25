import type {DbService} from '../db.service';
import type {MutationContext} from '../../modules/mutations/mutation.service';
import type {ApprovedMutationBindingV3, ApprovedNativeRequest, ApprovedNativeStage} from '../../modules/workflows/approved-execution.types';
/** Shape is never authority. Root verifies the original opaque object in a
 * private WeakMap and its exact current SQL/source/baseline/approval facts. */
export interface EntityChangePacketExecutionProof {
  sourceId:string;baselineId:string;packetKey:string;workflowId:string;executionId:string;stepId:string;
  actorId:string;sessionId:string|null;origin?:'scheduled-entity';clusterId:string;workspaceId:string;transportScope:string;
  permissionVersion:string;expiresAt:number;
}
export interface EntityChangePacketExecutionPolicy {
  verifyHandle(handle:object):Promise<EntityChangePacketExecutionProof>;
  mutationBinding(handle:object,context:Readonly<MutationContext>):Promise<ApprovedMutationBindingV3>;
  bindOperation(handle:object,context:Readonly<MutationContext>,binding:ApprovedMutationBindingV3,operationId:string,tx:DbService):Promise<void>;
  assertNative(handle:object,input:Readonly<ApprovedNativeRequest>,stage:ApprovedNativeStage):Promise<void>;
  beforeNativeSend(handle:object,input:Readonly<ApprovedNativeRequest>):Promise<void>;
  observeTransportResponse(handle:object,input:Readonly<ApprovedNativeRequest>,status:number,result:unknown):void;
  /** Actual fixed transport GET observation. No result or asserted status
   * supplied through HTTP can enter this original private ticket path. */
  observeVerificationResponse?(handle:object,input:Readonly<ApprovedNativeRequest>,status:number):void;
  spendTransport(handle:object,input:Readonly<ApprovedNativeRequest>):void;
}
