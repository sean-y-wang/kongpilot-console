import {ConflictException} from '@nestjs/common';
import type {SecretService} from '../../infrastructure/secret.service';
import {immutableJson} from '../../infrastructure/kong/immutable-json';
import type {TargetReconciliationHistoryCertificate} from './entity-change-target-reconciliation-proof';

export const TARGET_APPEND_RESPONSE_CONTRACT='root-entity-v3-target-append-201-before-response-hmac-v1' as const;
export interface TargetOriginalProducerAttestation{
 readonly version:1;readonly contract:typeof TARGET_APPEND_RESPONSE_CONTRACT;
 readonly producerProtocol:'http-source-v1/entity-mutation-v3/packet-fact-v1';
 readonly sourceId:string;readonly sourceHmac:string;readonly outcomeFactHmac:string;readonly resultHmac:string;
 readonly nativeStatusInferred:201;readonly evidenceHmac:string;
}

/** A fixed protocol interpretation, not an HTTP status receipt or a native
 * permit. V1 HTTP sources / V3 entity mutation bindings / V1 packet facts for
 * typed Target append are produced only by Root's exact response branch:
 * transport status 201 + allocated UUID + raw transport HMAC, before setting
 * claim.responseHmac. The history certificate verifies that authenticated
 * response HMAC against the unchanged raw result and every original tuple.
 * Old sent-unknown/native_status=NULL remains an immutable historical fact.
 * New protocols must install their own explicit interpretation; never treat
 * arbitrary result ciphertext, a user DTO, or observed current state as 201.
 * The caller still needs current reads, scope checks and atomic observation.
 */
export function attestTargetOriginalProducer(certificate:Readonly<TargetReconciliationHistoryCertificate>,secrets:Pick<SecretService,'fingerprint'>):Readonly<TargetOriginalProducerAttestation>{
 const {proofHmac,...material}=certificate,invalid=()=>new ConflictException({code:'ENTITY_CHANGE_TARGET_PRODUCER_CONTRACT_INVALID'});
 if(proofHmac!==secrets.fingerprint(material)||certificate.version!==1||certificate.kind!=='target-weight-zero-original-response'
  ||certificate.nativeAuthority!==false||certificate.nativeWrites!==0||certificate.originalOutcome!=='sent-unknown'||certificate.nativeStatusRecorded!==null
  ||certificate.originalResponseAuthenticated!==true||certificate.requiresFrozenOriginalProducerAttestation!==true
  ||certificate.requiresFreshCurrentStateObservation!==true||certificate.metadataEligibility!=='requires-frozen-producer-and-current-observation')throw invalid();
 const proof={version:1,contract:TARGET_APPEND_RESPONSE_CONTRACT,producerProtocol:'http-source-v1/entity-mutation-v3/packet-fact-v1',
  sourceId:certificate.sourceId,sourceHmac:certificate.sourceHmac,outcomeFactHmac:certificate.outcomeFactHmac,resultHmac:certificate.resultHmac,nativeStatusInferred:201} as const;
 return immutableJson({...proof,evidenceHmac:secrets.fingerprint(proof)});
}
