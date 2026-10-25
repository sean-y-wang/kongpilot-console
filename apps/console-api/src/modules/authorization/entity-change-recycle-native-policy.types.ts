import type { KongExecutionFrame } from '../../infrastructure/kong/execution-context.service';
import type { GraphNode, RecycleGraph } from '../recycle-bin/graph-capturer.service';

/** Actual SQL tuple supplied by NativePolicy, never HTTP input or a permit. */
export interface EntityChangeRecycleNativeOperation {
  readonly id: string; readonly cluster_id: string; readonly workspace_id: string; readonly actor_id: string;
  readonly workflow_id: string; readonly entity_type: string; readonly entity_id: string;
  readonly action: 'delete' | 'restore'; readonly parent_id: string | null; readonly credential_kind: string | null;
  readonly idempotency_key: string; readonly state: 'running'; readonly remote_started: true; readonly remote_completed: false;
  readonly entity_change_source_id: string; readonly entity_change_baseline_id: string;
  readonly entity_change_attempt_id: string; readonly entity_change_packet_key: string;
  readonly before_secret: string; readonly payload_secret: string;
}
export interface EntityChangeRecycleNativeInput {
  /** The original current ALS frame object. Copying its shape loses identity. */
  readonly frame: KongExecutionFrame;
  readonly operation: Readonly<EntityChangeRecycleNativeOperation>;
  readonly canonicalPath: string; readonly body: unknown; readonly nativeType: string;
  readonly parentId?: string; readonly credentialKind?: string;
}
export interface EntityChangeRecycleArchiveInput extends EntityChangeRecycleNativeInput {
  readonly entry: Readonly<Record<string, unknown>>;
  /** Full decrypted graph stays exclusively inside fixed server callbacks. */
  readonly graph: Readonly<RecycleGraph>; readonly node: Readonly<GraphNode>;
}
/** Once-installed Root policy, closed by default. Root must recover the
 * original opaque handle through requireEntityChangePacketFrame(frame),
 * verify its live source/baseline/attempt/operation tuple and SQL23 complete
 * graph/node binding. A callback result or a frame/ID DTO never mints a handle. */
export interface EntityChangeRecycleNativePolicy {
  /** Only genuine NativePolicy beforeNativeSend calls this after current
   * re-authorization. DNS preflight repeats it; no permit is memoized. */
  assertCurrentBeforeSend(input:Readonly<EntityChangeRecycleNativeInput>):Promise<void>;
  assertDeleteArchive(input: Readonly<EntityChangeRecycleArchiveInput>): Promise<void>;
  /** Derive the archive ID from Root's private packet and persisted binding.
   * The V3 native payload cannot contain the legacy entryId field. */
  resolveRestoreArchive(input: Readonly<EntityChangeRecycleNativeInput>): Promise<Readonly<{ entryId: string }>>;
  assertRestoreArchive(input: Readonly<EntityChangeRecycleArchiveInput>): Promise<void>;
}
