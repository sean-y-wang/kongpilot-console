import { ConflictException, ForbiddenException, Injectable, ServiceUnavailableException } from '@nestjs/common';
import { KongService } from '../../infrastructure/kong/kong.service';
import { immutableJson } from '../../infrastructure/kong/immutable-json';
import { assertKongPath, ENTITIES } from '../../infrastructure/kong/policy';
import { SecretService } from '../../infrastructure/secret.service';
import { CredentialStoreService } from '../credentials/credential-store.service';
import { MutationService, type MutationContext } from '../mutations/mutation.service';
import { UUID } from '../config-transfer/schema-normalization';
import { EntityIndexService } from './entity-index.service';
import { CREDENTIAL_KINDS, type CredentialKind, type EntityActor, type EntityType } from './entities.types';
import { entityReferenceId } from './entity-reference';
import type { EntityChangeMetadataObligation, EntityChangePacket } from './entity-change.types';
import {assertTargetHealthObservation,type TargetHealthObservation} from '../../infrastructure/kong/target-health-observation';

declare const preparedWriteHandleBrand: unique symbol;
/** Only the Root execution kernel can issue a handle. This brand is type
 * information, not a runtime authority: the installed delegate must verify
 * its private registry and durable source before invoking the fixed writer. */
export type EntityPreparedWriteHandle = object & { readonly [preparedWriteHandleBrand]: 'entity-prepared-write' };
export type EntityPreparedWriteObligation = Extract<EntityChangeMetadataObligation, { kind: 'entity-index' | 'credential-remember' }>;
export interface EntityPreparedWriteGrant {
  clusterId: string; workspaceId: string; actor: EntityActor; operationKey: string;
  packet: Readonly<EntityChangePacket>; obligations: ReadonlyArray<EntityPreparedWriteObligation>;
  /** Original private baseline fact, never copied from an HTTP change DTO. */
  targetHealthBefore?: Readonly<TargetHealthObservation>;
}
/** Bootstrap-only delegate. It creates the genuine current execution scope;
 * neither this provider nor a DTO can mint a native permit or approval. */
export interface EntityPreparedWriterDelegate {
  run<T>(handle: EntityPreparedWriteHandle, fixedWriter: (grant: Readonly<EntityPreparedWriteGrant>) => Promise<T>): Promise<T>;
}
export interface EntityPreparedWriteResult {
  packetKey: string; operationKey: string; nativeId: string; state: 'succeeded'; metadata: 'complete';
}
type Body = Record<string, unknown>;
type EntityBefore = Body & { id: string };
export type PreparedEntityNativeWrite =
  | { kind: 'core'; action: 'create' | 'update'; entityType: EntityType; nativeId: string; before: EntityBefore | null; body: Body }
  | { kind: 'target-create'; action: 'create'; upstreamId: string; nativeId: string; before: null; body: Body }
  | { kind: 'target-weight'; action: 'update'; upstreamId: string; nativeId: string; originalNativeId: string; before: EntityBefore; body: Body }
  | { kind: 'target-health'; action: 'mark_healthy' | 'mark_unhealthy'; upstreamId: string; nativeId: string; before: EntityBefore; state: 'healthy' | 'unhealthy' }
  | { kind: 'credential'; action: 'create' | 'update'; consumerId: string; credentialKind: CredentialKind; nativeId: string; before: EntityBefore | null; body: Body };

const invalid = () => new ForbiddenException({ code: 'ENTITY_PREPARED_PACKET_INVALID', message: '固定执行材料或对象范围不匹配，未发送网关变更' });
const object = (value: unknown): value is Body => !!value && typeof value === 'object' && !Array.isArray(value);
const uuid = (value: unknown): value is string => typeof value === 'string' && UUID.test(value);

/** A pure fixed union parser, never an authorization decision. Native paths
 * and methods are derived below; the packet's copies must match exactly. */
export function derivePreparedEntityWrite(packet: Readonly<EntityChangePacket>): PreparedEntityNativeWrite {
  if (!packet || !uuid(packet.nativeId) || packet.permissionAction !== 'write') throw invalid();
  const before = packet.before, body = packet.body;
  const ordinary = packet.mutationAction === 'create' || packet.mutationAction === 'update';
  const validOrdinary = (): void => {
    if (!ordinary || !object(body) || body.id !== undefined && body.id !== packet.nativeId) throw invalid();
    if (packet.mutationAction === 'create') {
      if (before !== null || body.id !== packet.nativeId) throw invalid();
    } else if (!object(before) || before.id !== packet.nativeId) throw invalid();
  };
  if ((ENTITIES as readonly string[]).includes(packet.nativeType)) {
    validOrdinary();
    if (packet.parentId !== undefined || packet.credentialKind !== undefined || packet.originalNativeId !== undefined
      || packet.nativeType === 'certificates' && Object.hasOwn(body!, 'snis')) throw invalid();
    return { kind: 'core', action: packet.mutationAction as 'create' | 'update', entityType: packet.nativeType as EntityType,
      nativeId: packet.nativeId, before: before as EntityBefore | null, body: body! };
  }
  if (packet.nativeType === 'targets') {
    if (!uuid(packet.parentId) || packet.credentialKind !== undefined || object(body) && body.upstream !== undefined
      || before !== null && (!object(before) || entityReferenceId(before.upstream) !== packet.parentId)) throw invalid();
    if (packet.mutationAction === 'mark_healthy' || packet.mutationAction === 'mark_unhealthy') {
      if (body !== undefined || packet.originalNativeId !== undefined || !object(before) || before.id !== packet.nativeId) throw invalid();
      return { kind: 'target-health', action: packet.mutationAction, upstreamId: packet.parentId, nativeId: packet.nativeId,
        before: before as EntityBefore, state: packet.mutationAction === 'mark_healthy' ? 'healthy' : 'unhealthy' };
    }
    if (!object(body) || body.id !== packet.nativeId || typeof body.target !== 'string' || !body.target) throw invalid();
    if (packet.mutationAction === 'create' && before === null && packet.originalNativeId === undefined)
      return { kind: 'target-create', action: 'create', upstreamId: packet.parentId, nativeId: packet.nativeId, before: null, body };
    if (packet.mutationAction !== 'update' || !uuid(packet.originalNativeId) || packet.originalNativeId === packet.nativeId
      || !object(before) || before.id !== packet.originalNativeId || before.target !== body.target) throw invalid();
    return { kind: 'target-weight', action: 'update', upstreamId: packet.parentId, nativeId: packet.nativeId,
      originalNativeId: packet.originalNativeId, before: before as EntityBefore, body };
  }
  if ((CREDENTIAL_KINDS as readonly string[]).includes(packet.nativeType)) {
    validOrdinary();
    if (!uuid(packet.parentId) || packet.credentialKind !== packet.nativeType || packet.originalNativeId !== undefined
      || body!.consumer !== undefined || before !== null && entityReferenceId((before as Body).consumer) !== packet.parentId) throw invalid();
    return { kind: 'credential', action: packet.mutationAction as 'create' | 'update', consumerId: packet.parentId,
      credentialKind: packet.credentialKind, nativeId: packet.nativeId, before: before as EntityBefore | null, body: body! };
  }
  // Recycle needs its sealed graph state machine, never an ordinary DELETE.
  throw invalid();
}

function nativeRequest(operation: PreparedEntityNativeWrite): { method: 'POST' | 'PATCH'; path: string; body?: Body } {
  if (operation.kind === 'core') return { method: operation.action === 'create' ? 'POST' : 'PATCH',
    path: operation.action === 'create' ? `/${operation.entityType}` : `/${operation.entityType}/${operation.nativeId}`, body: operation.body };
  if (operation.kind === 'credential') return { method: operation.action === 'create' ? 'POST' : 'PATCH',
    path: `/consumers/${operation.consumerId}/${operation.credentialKind}${operation.action === 'create' ? '' : `/${operation.nativeId}`}`, body: operation.body };
  if (operation.kind === 'target-health') return { method: 'POST', path: `/upstreams/${operation.upstreamId}/targets/${operation.nativeId}/${operation.state}` };
  return { method: 'POST', path: `/upstreams/${operation.upstreamId}/targets`, body: operation.body };
}

/** Source-only until Root activates its kernel and bootstrap delegate. It
 * never re-enters EntityService's frontend input/tag/default/SNI callbacks. */
@Injectable()
export class EntityPreparedWriterService {
  private delegate?: Readonly<EntityPreparedWriterDelegate>;
  constructor(private readonly mutations: MutationService, private readonly kong: KongService,
    private readonly index: EntityIndexService, private readonly credentials: CredentialStoreService, private readonly secrets: SecretService) {}

  installExecutionDelegate(delegate: EntityPreparedWriterDelegate): void {
    if (this.delegate || !delegate || typeof delegate.run !== 'function') throw new ConflictException({ code: 'ENTITY_PREPARED_WRITER_DELEGATE_INVALID' });
    this.delegate = Object.freeze({ run: delegate.run.bind(delegate) });
  }

  async execute(handle: EntityPreparedWriteHandle): Promise<EntityPreparedWriteResult> {
    if (!this.delegate) throw new ServiceUnavailableException({ code: 'ENTITY_PREPARED_WRITER_UNAVAILABLE', message: '固定执行策略尚未安装' });
    if (!handle || typeof handle !== 'object' || Array.isArray(handle)) throw invalid();
    return this.delegate.run(handle, grant => this.write(grant));
  }

  private obligation(grant: Readonly<EntityPreparedWriteGrant>, operation: PreparedEntityNativeWrite): EntityPreparedWriteObligation | undefined {
    const obligations = grant.obligations;
    if (!Array.isArray(obligations)) throw invalid();
    if (operation.kind !== 'core' && operation.kind !== 'credential') {
      if (obligations.length) throw invalid(); return undefined;
    }
    if (obligations.length !== 1) throw invalid();
    const obligation = obligations[0];
    if (!obligation || obligation.packetKey !== grant.packet.key) throw invalid();
    if (operation.kind === 'core') {
      if (obligation.kind !== 'entity-index' || obligation.entityType !== operation.entityType) throw invalid();
    } else if (obligation.kind !== 'credential-remember' || obligation.consumerId !== operation.consumerId
      || obligation.credentialKind !== operation.credentialKind || !object(obligation.rawInput)
      || this.secrets.fingerprint(obligation.rawInput) !== grant.packet.bodyHmac) throw invalid();
    return obligation;
  }

  private async write(input: Readonly<EntityPreparedWriteGrant>): Promise<EntityPreparedWriteResult> {
    const grant = immutableJson(input), packet = grant.packet;
    if (!uuid(grant.clusterId) || !uuid(grant.workspaceId) || !uuid(grant.actor?.user?.id) || grant.actor.workspaceId !== grant.workspaceId
      || typeof grant.operationKey !== 'string' || !/^[a-zA-Z\d_.:-]{1,128}$/.test(grant.operationKey)
      || !packet || typeof packet.key !== 'string' || !/^[a-zA-Z\d_.:-]{1,128}$/.test(packet.key)
      || this.secrets.fingerprint(packet.body ?? null) !== packet.bodyHmac || this.secrets.fingerprint(packet.before ?? null) !== packet.beforeHmac) throw invalid();
    const operation = derivePreparedEntityWrite(packet), request = nativeRequest(operation), obligation = this.obligation(grant, operation);
    if(operation.kind==='target-health')assertTargetHealthObservation(grant.targetHealthBefore,{upstreamId:operation.upstreamId,target:operation.before},this.secrets);
    else if(grant.targetHealthBefore!==undefined)throw invalid();
    if (packet.method !== request.method || packet.canonicalPath !== request.path) throw invalid();
    assertKongPath(request.method, request.path);
    const context: MutationContext = { clusterId: grant.clusterId, workspaceId: grant.workspaceId, actor: grant.actor.user,
      entityType: operation.kind === 'core' ? operation.entityType : operation.kind === 'credential' ? 'credentials' : 'targets',
      entityId: operation.action === 'create' ? undefined : operation.kind === 'target-weight' ? operation.originalNativeId : operation.nativeId,
      // Packet absence is sealed as null. The existing create mutation path
      // uses undefined to avoid asking for permission on a nonexistent before
      // object; the final native guard still authorizes the real new payload.
      action: operation.action, before: operation.action === 'create' ? undefined : operation.before,
      payload: operation.kind === 'target-health' ? { state: operation.state } : operation.body,
      idempotencyKey: grant.operationKey, requestId: grant.actor.requestId, ip: grant.actor.ip,
      ...(operation.kind==='target-health'?{targetHealthBefore:grant.targetHealthBefore}:{}),
      ...(operation.kind === 'credential' ? { parentId: operation.consumerId, credentialKind: operation.credentialKind }
        : operation.kind === 'core' ? {} : { parentId: operation.upstreamId }) };
    let entered = false, nativeResult: any;
    await this.mutations.execute(context, async () => {
      if (entered) throw new ConflictException({ code: 'ENTITY_PREPARED_NATIVE_ALREADY_ATTEMPTED' });
      entered = true;
      // All final Kong/NativePolicy, managed-boundary and lock checks remain.
      const result = await this.kong.request(grant.clusterId, request.method, request.path, request.body);
      // A health override acknowledges with HTTP 204 and no JSON object.
      // Retain that original null response; Mutation's fixed health bridge
      // observes node-local health separately and never fabricates an Entity.
      nativeResult = result;
      return result;
    });
    const receipt = { packetKey: packet.key, operationKey: grant.operationKey, nativeId: operation.nativeId };
    if (!entered || nativeResult === undefined) throw new ConflictException({ code: 'ENTITY_PREPARED_METADATA_RECOVERY_REQUIRED',
      message: '原操作已有回执，请通过原操作恢复元数据，不会重复发送网关变更', ...receipt, knownNativeComplete: true });
    if (operation.kind === 'target-health' ? nativeResult !== null : !object(nativeResult) || nativeResult.id !== operation.nativeId) throw new ServiceUnavailableException({ code: 'ENTITY_PREPARED_NATIVE_RESULT_MISMATCH',
      message: '网关已响应，但返回对象与封存对象不一致，请核验原操作', ...receipt, knownNativeComplete: true });
    try {
      if (obligation?.kind === 'entity-index') await this.index.upsert(grant.clusterId, obligation.entityType, nativeResult);
      if (obligation?.kind === 'credential-remember') await this.credentials.save(grant.clusterId, obligation.consumerId, obligation.credentialKind, nativeResult, obligation.rawInput);
    } catch {
      // Native result is already durable. Never retry POST, alter its key, or
      // leak a credential/raw persistence error to an HTTP response.
      throw new ServiceUnavailableException({ code: 'ENTITY_PREPARED_METADATA_INCOMPLETE',
        message: '网关变更已完成，元数据待恢复；请核验原操作，勿重新提交', ...receipt, knownNativeComplete: true });
    }
    return { ...receipt, state: 'succeeded', metadata: 'complete' };
  }
}
