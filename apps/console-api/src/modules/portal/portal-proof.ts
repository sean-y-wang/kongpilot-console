import { ConflictException } from '@nestjs/common';
import type { SecretService } from '../../infrastructure/secret.service';
import type { WorkflowPlanV1 } from '../workflows/workflow.types';
export interface PortalPublicationProofV1 {
  version:1;clusterId:string;workspaceId:string;publicationId:string;publicationRevision:number;
  transportScope:string;clusterRevision:number;workspaceRevision:number;executionMode:'direct'|'approval';
  workflowId:string;executionId:string;planRevision:number;planHash:string;verifiedAt:string;
  serviceId:string;aclGroup:string;aclPluginId:string;keyAuthPluginId:string;
  service:any;aclPlugin:any;keyAuthPlugin:any;
  publicationInfo?:{name:string;slug:string;description:string;category:string|null};
  schemas:{consumers:any;acls:any;keyAuth:any};
  definitions:Partial<Record<WorkflowPlanV1['kind'],WorkflowPlanV1['definition']>>;
}
export const publicationProofAad=(cid:string,wid:string,id:string,revision:number)=>`portal:publication:${cid}:${wid}:${id}:${revision}:proof`;
export const portalKeyAad=(cid:string,wid:string,id:string,generation:number)=>`portal:credential:${cid}:${wid}:${id}:${generation}:key`;
export function decodePublicationProof(row:any,secrets:SecretService):PortalPublicationProofV1{
  const proof=secrets.decrypt<PortalPublicationProofV1>(row.publication_proof_secret,publicationProofAad(row.cluster_id,row.workspace_id,row.publication_id,row.publication_revision));
  if(proof.version!==1||proof.clusterId!==row.cluster_id||proof.workspaceId!==row.workspace_id||proof.publicationId!==row.publication_id||proof.publicationRevision!==row.publication_revision||proof.transportScope!==row.transport_scope||proof.workflowId!==row.workflow_id||proof.executionId!==row.workflow_execution_id||proof.planRevision!==row.workflow_plan_revision||proof.planHash!==row.workflow_plan_hash||secrets.fingerprint(proof)!==row.publication_proof_hmac)throw new ConflictException({code:'PORTAL_PUBLICATION_PROOF_INVALID'});
  return proof;
}
