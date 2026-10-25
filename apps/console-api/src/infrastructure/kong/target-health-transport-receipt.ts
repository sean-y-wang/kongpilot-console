/** Original fixed transport observation, never an authorization capability.
 * Only KongService's private original-frame registry can issue/consume it. */
export interface TargetHealthTransportReceipt {
  readonly version:1;
  readonly kind:'original-target-health-transport-response';
  readonly clusterId:string;
  readonly operationId:string;
  readonly upstreamId:string;
  readonly targetId:string;
  readonly action:'mark_healthy'|'mark_unhealthy';
  readonly nativeStatus:number;
  readonly rawResponse:unknown;
  readonly responseHmac:string;
  readonly responseBytes:number;
  readonly emptyBody:boolean;
  readonly contractValid:boolean;
}
