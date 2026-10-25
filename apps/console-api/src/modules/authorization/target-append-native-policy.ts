import { ForbiddenException, ServiceUnavailableException } from '@nestjs/common';
import { currentEffectiveTarget } from '../../infrastructure/kong/effective-target';
import type { KongService } from '../../infrastructure/kong/kong.service';
import { immutableJson } from '../../infrastructure/kong/immutable-json';
import type { SecretService } from '../../infrastructure/secret.service';

type JsonObject = Readonly<Record<string, any>>;

/** This is a source-side validator, not a native capability. The caller must
 * first authenticate the genuine HTTP packet/frame and its SQL mutation,
 * current SID/epoch, original actor/key, approval set and live transport lock.
 * approvedBefore/approvedBody must come from that operation's authenticated
 * secrets, never from an HTTP projection or a regenerated packet. */
interface TargetAppendPolicyFields {
  actorId: string;
  clusterId: string;
  workspaceId: string;
  upstreamId: string;
  originalNativeId: string;
  method: 'POST';
  mutationAction: 'update';
  canonicalPath: string;
  body: unknown;
  approvedBody: unknown;
  approvedBefore: unknown;
}
export type TargetAppendPolicyInput = TargetAppendPolicyFields & (
  { origin: 'http'; sessionId: string; originalScheduledReference?: never }
  | { origin: 'scheduled-entity'; sessionId: null; originalScheduledReference: object });

export interface TargetAppendReadScope {
  clusterId: string;
  workspaceId: string;
  actorId: string;
  sessionId: string | null;
  origin?: 'scheduled-entity';
  originalScheduledReference?: object;
  paths: readonly string[];
  maxCalls: 100;
  maxPages: 100;
  maxRecords: 10000;
  maxBytes: number;
  timeoutMs: 120000;
}

export interface TargetAppendPermissionInput {
  clusterId: string;
  workspaceId: string;
  actorId: string;
  sessionId: string | null;
  origin?: 'scheduled-entity';
  originalScheduledReference?: object;
  upstreamId: string;
  phase: 'before' | 'prospective';
  entity: JsonObject;
}

export interface TargetAppendPolicyDependencies {
  kong: Pick<KongService, 'list'>;
  secrets: Pick<SecretService, 'fingerprint'>;
  /** Run the provided lookup under a genuine current actor's bounded internal
   * read capability. The helper itself follows only the parent-scoped effective
   * collection to EOF; this provider must not replace the lookup with sealed
   * before data, a filtered list, a historical UUID/address GET or a cache. */
  runFreshRead<T>(scope: Readonly<TargetAppendReadScope>, lookup: () => Promise<T>): Promise<T>;
  /** Recheck current workspace/parent membership AND write authorization for
   * each real identity. Prospective uses the NEW UUID, not an old-ID alias.
   * An old-Target-only entity grant therefore fails before any native send. */
  assertWorkspaceAndWrite(input: Readonly<TargetAppendPermissionInput>): Promise<void>;
  /** Fixed private origin verifier. A shape-only scheduled DTO, copied handle
   * or omitted provider is closed. The original reference is never cloned. */
  assertOriginalScheduled?(originalReference: object, input: Readonly<Omit<TargetAppendPolicyInput, 'originalScheduledReference'>>, checkpoint: 'before-read' | 'after-read' | 'after-permissions'): Promise<void>;
}

export interface TargetAppendAuthorization {
  readonly kind: 'target-weight-append';
  readonly before: JsonObject;
  readonly body: JsonObject;
  readonly upstreamId: string;
  readonly originalNativeId: string;
  readonly nativeId: string;
  readonly workspaceId: string;
}

const uuid = /^[a-f\d]{8}-[a-f\d]{4}-[1-8][a-f\d]{3}-[89ab][a-f\d]{3}-[a-f\d]{12}$/i;
const object = (value: unknown): value is JsonObject => !!value && typeof value === 'object' && !Array.isArray(value);
const denied = (code: string) => new ForbiddenException({ code, message: 'Target 追加权重变更未获得有效授权' });
const invalidResponse = () => new ServiceUnavailableException({ code: 'TARGET_APPEND_RESPONSE_MISMATCH',
  message: '网关已响应，但 Target 回执与原变更不一致；请核验原操作，勿重复提交' });

/** Tags are a Kong set. Only comparison normalizes null/omission to the empty
 * set and ignores order; the real native body/result are never rewritten. */
function tags(value: unknown): string[] | null {
  if (value === null || value === undefined) return [];
  if (!Array.isArray(value) || value.some(tag => typeof tag !== 'string' || !tag) || new Set(value).size !== value.length) return null;
  return [...value].sort();
}

export class TargetAppendNativePolicy {
  private readonly issued = new WeakSet<object>();
  constructor(private readonly dependencies: TargetAppendPolicyDependencies) {}

  async authorize(input: Readonly<TargetAppendPolicyInput>): Promise<Readonly<TargetAppendAuthorization>> {
    // Snapshot before the first await: a retained caller reference cannot
    // change the approved new UUID/body while grants or pagination await.
    if (!input || typeof input !== 'object' || Array.isArray(input)) throw denied('TARGET_APPEND_PACKET_INVALID');
    const originalScheduledReference = input.originalScheduledReference;
    const { originalScheduledReference: _reference, ...serializable } = input;
    const frozen = immutableJson(serializable), { body, approvedBody, approvedBefore } = frozen;
    const { secrets } = this.dependencies;
    const scheduled = frozen.origin === 'scheduled-entity';
    if (scheduled ? frozen.sessionId !== null || !originalScheduledReference || typeof originalScheduledReference !== 'object' || Array.isArray(originalScheduledReference) || !this.dependencies.assertOriginalScheduled : frozen.origin !== 'http' || !uuid.test(frozen.sessionId ?? '') || originalScheduledReference !== undefined) throw denied('TARGET_APPEND_PACKET_INVALID');
    if (frozen.method !== 'POST' || frozen.mutationAction !== 'update'
      || [frozen.actorId, frozen.clusterId, frozen.workspaceId, frozen.upstreamId, frozen.originalNativeId].some(id => !uuid.test(id ?? ''))
      || frozen.canonicalPath !== `/upstreams/${frozen.upstreamId}/targets`
      || !object(body) || !object(approvedBody) || !object(approvedBefore)
      || !uuid.test(body.id ?? '') || body.id === frozen.originalNativeId
      || typeof body.target !== 'string' || !body.target || body.target.length > 1024
      || !Number.isInteger(body.weight) || body.weight < 0 || body.weight > 1000
      || Object.keys(body).some(key => !['id', 'target', 'weight', 'tags'].includes(key)) || tags(body.tags) === null
      || approvedBefore.id !== frozen.originalNativeId || approvedBefore.upstream?.id !== frozen.upstreamId
      || approvedBefore.target !== body.target || secrets.fingerprint(body) !== secrets.fingerprint(approvedBody)) {
      throw denied('TARGET_APPEND_PACKET_INVALID');
    }
    const verifyScheduled = async (checkpoint: 'before-read' | 'after-read' | 'after-permissions') => {
      if (scheduled) await this.dependencies.assertOriginalScheduled!(originalScheduledReference!, frozen, checkpoint);
    };
    await verifyScheduled('before-read');
    const origin = scheduled ? { origin: 'scheduled-entity' as const, originalScheduledReference } : {};
    const scope: Readonly<TargetAppendReadScope> = Object.freeze({
      clusterId: frozen.clusterId, workspaceId: frozen.workspaceId, actorId: frozen.actorId, sessionId: frozen.sessionId,
      ...origin,
      paths: Object.freeze([frozen.canonicalPath]), maxCalls: 100, maxPages: 100, maxRecords: 10000,
      maxBytes: 32 * 1024 * 1024, timeoutMs: 120000,
    });
    const observed = await this.dependencies.runFreshRead(scope, () => currentEffectiveTarget(this.dependencies.kong,
      frozen.clusterId, frozen.upstreamId, body.target,
      { maxPages: scope.maxPages, maxRecords: scope.maxRecords, maxBytes: scope.maxBytes }));
    await verifyScheduled('after-read');
    if (!observed.target || observed.target.id !== frozen.originalNativeId
      || secrets.fingerprint(observed.target) !== secrets.fingerprint(approvedBefore)) throw denied('TARGET_APPEND_BEFORE_CHANGED');
    const before = immutableJson(observed.target);
    const permission = { clusterId: frozen.clusterId, workspaceId: frozen.workspaceId, actorId: frozen.actorId,
      sessionId: frozen.sessionId, upstreamId: frozen.upstreamId, ...origin };
    await this.dependencies.assertWorkspaceAndWrite(Object.freeze({ ...permission, phase: 'before', entity: before }));
    // Keep the allocated ID and prospective tags. Do not silently extend an
    // old UUID entity whitelist to the new historical row.
    // POST creates a row; omission does not inherit the old row's tags or
    // timestamps. Authorize the new POST view, including its actual empty-tag
    // semantics, rather than a PATCH-like merge with the historical before.
    const prospective = immutableJson({ ...body, tags: body.tags ?? [], upstream: { id: frozen.upstreamId } });
    await this.dependencies.assertWorkspaceAndWrite(Object.freeze({ ...permission, phase: 'prospective', entity: prospective }));
    await verifyScheduled('after-permissions');
    const authorization: Readonly<TargetAppendAuthorization> = Object.freeze({ kind: 'target-weight-append', before, body,
      upstreamId: frozen.upstreamId, originalNativeId: frozen.originalNativeId, nativeId: body.id, workspaceId: frozen.workspaceId });
    this.issued.add(authorization);
    return authorization;
  }

  /** Call only on the actual, unmodified native response, after Root has
   * certified its real transport status (Kong 1.5 collection POST: 201) and
   * response HMAC. This does not manufacture send/outcome facts, prove a 201,
   * settle a workflow or authorize replay. Keep raw result/status even when
   * reflection validation fails; a genuine send must never become not-sent.
   * weight=0 is a valid disabled historical row, absent from the effective
   * collection. Propagation observations are separate from this receipt. */
  assertRawResponse(authorization: Readonly<TargetAppendAuthorization>, rawResult: unknown): void {
    if (!authorization || !this.issued.has(authorization)) throw denied('TARGET_APPEND_AUTHORIZATION_REQUIRED');
    if (!object(rawResult) || rawResult.id !== authorization.nativeId || rawResult.upstream?.id !== authorization.upstreamId
      || rawResult.target !== authorization.body.target || rawResult.weight !== authorization.body.weight) throw invalidResponse();
    const actualTags = tags(rawResult.tags), expectedTags = tags(authorization.body.tags);
    if (actualTags === null || expectedTags === null
      || this.dependencies.secrets.fingerprint(actualTags) !== this.dependencies.secrets.fingerprint(expectedTags)) throw invalidResponse();
  }
}
