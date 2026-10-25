import { ConflictException, ForbiddenException, Injectable } from '@nestjs/common';
import { randomUUID, X509Certificate } from 'node:crypto';
import { DbService } from '../../infrastructure/db.service';
import { SecretService } from '../../infrastructure/secret.service';
import { KongService } from '../../infrastructure/kong/kong.service';
import { KongExecutionContextService } from '../../infrastructure/kong/execution-context.service';
import { transportScopeFor } from '../../infrastructure/kong/transport-scope';
import { WorkspaceResolverService } from '../workspaces/workspace-resolver.service';
import type { ObservationAuthority } from '../event-core/event-access';
import type { DetectorObservationInput, DetectorSubject, SafeHealth, SafeObservation, TrustedObservationProof } from '../event-core/event.types';
import { nativeHistoricalScope } from '../event-producers/native-audit-scope';

const uuid = /^[\da-f]{8}-[\da-f]{4}-[1-8][\da-f]{3}-[89ab][\da-f]{3}-[\da-f]{12}$/i;
const denied = () => new ForbiddenException({ code: 'OBSERVATION_PROOF_INVALID', message: '观察来源已失效，未发布事件' });
interface RegistrySnapshot { revision: number; transportScope: string; endpointHmac: string; fenceCount: string; latestFence: string | null; }
interface PrivateProof { inputHmac: string; snapshot: RegistrySnapshot; createdAt: number; active: boolean; }

/** A private capability is minted only after fixed, real, bounded Kong reads.
 * JSON, copied objects and caller timestamps cannot create this capability. */
@Injectable()
export class ObservationAuthorityService implements ObservationAuthority {
  private readonly proofs = new WeakMap<object, PrivateProof>();
  private readonly discontinuities = new Set<string>();
  private readonly confirmedSubjects = new Set<string>();
  constructor(private readonly db: DbService, private readonly secrets: SecretService,
    private readonly kong: KongService, private readonly execution: KongExecutionContextService,
    private readonly workspaces: WorkspaceResolverService) {}

  private hashInput(input: DetectorObservationInput): string {
    const { sourceProof: _proof, ...facts } = input;
    return this.secrets.fingerprint(facts);
  }
  noteGap(cid: string, type: DetectorSubject, id: string): void {
    this.discontinuities.add(`${cid}:${type}:${id}`);
    if (this.discontinuities.size > 1000) {
      const old = this.discontinuities.values().next().value!;
      this.discontinuities.delete(old); this.confirmedSubjects.delete(old);
    }
  }
  private async snapshot(cid: string, db: DbService, lock = false): Promise<RegistrySnapshot> {
    const cluster = await db.one<any>(`SELECT * FROM clusters WHERE id=$1 AND deleted_at IS NULL${lock ? ' FOR SHARE' : ''}`, [cid]);
    if (!cluster || ['disabled', 'incompatible'].includes(cluster.status) || !/^1\.5\.\d+$/.test(cluster.version ?? '')) throw denied();
    const transportScope = transportScopeFor(cluster.admin_url, cluster.transport_scope);
    if (lock) await db.exec('SELECT pg_advisory_xact_lock(hashtext($1))', [`kongos:metrics-transport:${transportScope}`]);
    const aliases = await db.query<any>(`SELECT id,admin_url,transport_scope FROM clusters
      WHERE deleted_at IS NULL ORDER BY id LIMIT 10001${lock ? ' FOR SHARE' : ''}`);
    if (aliases.length > 10000) throw new ConflictException({ code: 'OBSERVATION_CLUSTER_BUDGET' });
    const physicalIds = aliases.filter(row => transportScopeFor(row.admin_url, row.transport_scope) === transportScope).map(row => row.id);
    if (!physicalIds.includes(cid)) throw denied();
    // The native transport installs a durable fence before every send. This
    // shared transaction lock stops a new native packet until the source commits.
    // Fence state records transport history, not the durable operation outcome:
    // an acknowledged send can still have an uncertain parent, while a pending
    // fence can belong to a completed parent. Keep every fence in the continuity
    // stamp and reject missing, mismatched or unresolved parents.
    const fences = await db.one<any>(`SELECT count(*)::text AS count,
      (SELECT id::text FROM metrics_write_fences latest WHERE latest.transport_scope=$1 ORDER BY created_at DESC,id DESC LIMIT 1) AS latest,
      count(*) FILTER(WHERE m.id IS NULL OR m.transport_scope IS DISTINCT FROM f.transport_scope
        OR m.state IS NULL OR m.state NOT IN ('succeeded','failed'))::text AS unsettled
      FROM metrics_write_fences f LEFT JOIN (
        SELECT id,cluster_id,transport_scope,state FROM mutation_operations
        WHERE id IN (SELECT operation_id FROM metrics_write_fences WHERE transport_scope=$1)${lock ? ' FOR SHARE' : ''}
      ) m
        ON m.id=f.operation_id AND m.cluster_id=f.cluster_id WHERE f.transport_scope=$1`, [transportScope]);
    const unfinished = await db.one<any>(`SELECT count(*)::text AS count FROM mutation_operations
      WHERE (transport_scope=$1 OR (transport_scope IS NULL AND cluster_id=ANY($2::uuid[])))
        AND state IN ('pending','running','uncertain')`, [transportScope, physicalIds]);
    if (!fences || fences.unsettled !== '0' || unfinished?.count !== '0') throw new ConflictException({ code: 'OBSERVATION_NATIVE_CHANGE_PENDING' });
    return { revision: cluster.revision, transportScope,
      endpointHmac: this.secrets.fingerprint({ url: cluster.admin_url, transportScope, version: cluster.version, connectionSecret: cluster.connection_secret ?? null }),
      fenceCount: fences.count, latestFence: fences.latest ?? null };
  }
  async assertCurrent(input: DetectorObservationInput, tx: DbService): Promise<void> {
    const proof = input?.sourceProof && this.proofs.get(input.sourceProof);
    if (!proof?.active || input.actorType !== 'system' || input.actorId !== null
      || this.hashInput(input) !== proof.inputHmac || Date.now() - proof.createdAt > 15_000
      || Date.parse(input.observedAt) > Date.now() || Date.now() - Date.parse(input.observedAt) > 15_000) throw denied();
    const current = await this.snapshot(input.clusterId, tx, true);
    if (this.secrets.fingerprint(current) !== this.secrets.fingerprint(proof.snapshot)) throw denied();
    const workspace = await tx.one<any>('SELECT revision,status FROM workspaces WHERE cluster_id=$1 AND id=$2 FOR SHARE', [input.clusterId, input.workspaceId]);
    if (!workspace || workspace.status !== 'active' || workspace.revision !== input.workspaceRevision
      || input.transportScope !== current.transportScope || input.clusterRevision !== current.revision) throw denied();
  }

  private node(root: any): string | null {
    const id = root?.node_id;
    return typeof id === 'string' && id.length > 0 && Buffer.byteLength(id) <= 256 ? id : null;
  }
  private async completeCollection(cid: string, path: string): Promise<any[]> {
    const rows: any[] = [];
    let cursor: string | undefined;
    const seen = new Set<string>();
    for (let page = 0; page < 8; page++) {
      const result = await this.kong.list(cid, path, { size: 100 }, cursor, 'event-observation-membership');
      if (result.console_permission_projection || rows.length + result.items.length > 800) throw new ConflictException({ code: 'OBSERVATION_MEMBERSHIP_INCOMPLETE' });
      for (const item of result.items) {
        if (!item || !uuid.test(item.id) || seen.has(item.id)) throw new ConflictException({ code: 'OBSERVATION_MEMBERSHIP_INVALID' });
        seen.add(item.id); rows.push(item);
      }
      if (!result.nextCursor) return rows;
      if (cursor === result.nextCursor) throw new ConflictException({ code: 'OBSERVATION_CURSOR_STALLED' });
      cursor = result.nextCursor;
    }
    throw new ConflictException({ code: 'OBSERVATION_MEMBERSHIP_BUDGET' });
  }
  private health(rows: any[], targets: any[], upstreamId: string): SafeHealth {
    const effective = new Map<string, any>();
    for (const target of targets) {
      if (target.upstream?.id !== upstreamId || typeof target.target !== 'string' || !Number.isFinite(target.created_at) || !Number.isInteger(target.weight)) throw denied();
      const old = effective.get(target.target);
      if (!old || old.created_at < target.created_at) effective.set(target.target, target);
      else if (old.created_at === target.created_at && old.id !== target.id) throw new ConflictException({ code: 'OBSERVATION_TARGET_ORDER_UNKNOWN' });
    }
    const active = [...effective.values()].filter(row => row.weight > 0);
    if (!active.length || active.length !== rows.length || rows.some(row => row.upstream?.id !== upstreamId || !active.some(target => target.id === row.id))) throw new ConflictException({ code: 'OBSERVATION_HEALTH_INCOMPLETE' });
    const statuses = rows.map(row => String(row.health).toLowerCase());
    if (statuses.some(value => !['healthy', 'unhealthy', 'healthchecks_off'].includes(value))) throw new ConflictException({ code: 'OBSERVATION_HEALTH_UNKNOWN' });
    if (statuses.every(value => value === 'healthchecks_off')) return 'checks_off';
    if (statuses.every(value => value === 'healthy')) return 'healthy';
    if (statuses.every(value => value === 'unhealthy')) return 'unhealthy';
    return 'degraded';
  }

  /** No HTTP route exposes this method. It never accepts observed values. */
  async observe(cid: string, type: DetectorSubject, id: string): Promise<{ input: DetectorObservationInput; release(committed?: boolean): void }> {
    if (!uuid.test(cid) || !uuid.test(id) || !['certificates', 'ca_certificates', 'upstreams'].includes(type)) throw denied();
    const captured = await this.snapshot(cid, this.db);
    const path = `/${type}/${id}`, targetPath = `/upstreams/${id}/targets/all`, healthPath = `/upstreams/${id}/health`;
    const paths = type === 'upstreams' ? ['/', path, targetPath, healthPath] : ['/', path];
    return this.execution.runEventObservationRead(cid, paths, async () => {
      const startRoot = await this.kong.request(cid, 'GET', '/');
      if (!/^1\.5\.\d+$/.test(startRoot?.version ?? '')) throw denied();
      const actual = await this.kong.request(cid, 'GET', path);
      if (actual?.id !== id) throw denied();
      const membership = await this.workspaces.classify(cid, actual.tags);
      if (membership.state !== 'resolved' || membership.workspace?.status !== 'active') throw denied();
      const workspace = membership.workspace!;
      let value: SafeObservation, config: unknown;
      if (type === 'upstreams') {
        const targets = await this.completeCollection(cid, targetPath);
        const health = await this.completeCollection(cid, healthPath);
        const afterTargets = await this.completeCollection(cid, targetPath);
        const stable = (items: any[]) => [...items].sort((a, b) => a.id.localeCompare(b.id));
        if (this.secrets.fingerprint(stable(targets)) !== this.secrets.fingerprint(stable(afterTargets))) throw denied();
        value = { kind: 'upstream_health', health: this.health(health, targets, id) };
        config = { actual, targets: stable(targets) };
      } else {
        if (typeof actual.cert !== 'string') throw denied();
        const cert = new X509Certificate(actual.cert), expiresAt = new Date(cert.validTo).toISOString();
        value = { kind: 'certificate_expiry', expiresAt }; config = { actual, leaf: cert.fingerprint256, expiresAt };
      }
      const verifiedAfter = await this.kong.request(cid, 'GET', path), endRoot = await this.kong.request(cid, 'GET', '/');
      if (this.secrets.fingerprint(actual) !== this.secrets.fingerprint(verifiedAfter)
        || startRoot.version !== endRoot.version || this.node(startRoot) !== this.node(endRoot)
        || type === 'upstreams' && !this.node(endRoot)) throw denied();
      const finalSnapshot = await this.snapshot(cid, this.db);
      if (this.secrets.fingerprint(captured) !== this.secrets.fingerprint(finalSnapshot)) throw denied();
      const sourceScope = nativeHistoricalScope({ type, id, before: actual, after: verifiedAfter,
        beforeWorkspaceId: workspace.id, afterWorkspaceId: workspace.id, module: 'events' });
      if (sourceScope.quality !== 'verified') throw denied();
      const detectorKey = type === 'upstreams' ? 'upstream.health.v1' : 'certificate.expiry.v1';
      const baseline = await this.db.one<any>(`SELECT revision FROM event_detection_state
        WHERE cluster_id=$1 AND workspace_id=$2 AND detector_key=$3 AND subject_type=$4 AND subject_id=$5`, [cid, workspace.id, detectorKey, type, id]);
      const proof = Object.freeze({}) as TrustedObservationProof;
      const subjectKey = `${cid}:${type}:${id}`;
      const continuityLost = this.discontinuities.has(subjectKey) || !!baseline && !this.confirmedSubjects.has(subjectKey);
      const input: DetectorObservationInput = { observationId: randomUUID(), actorType: 'system', actorId: null,
        clusterId: cid, workspaceId: workspace.id, detectorKey, subjectType: type, subjectId: id,
        transportScope: captured.transportScope, observedNodeId: this.node(endRoot), clusterRevision: captured.revision,
        workspaceRevision: workspace.revision, configFingerprint: this.secrets.fingerprint({ config, registry: captured.endpointHmac, node: this.node(endRoot) }),
        scopeEpoch: this.secrets.fingerprint({ version: 1, clusterId: cid, workspaceId: workspace.id, subjectType: type, subjectId: id, sourceScope }),
        // A fresh read after a failed interval cannot prove continuous health.
        // Publish only a quality record; the next verified sample resets baseline.
        observedAt: new Date().toISOString(), quality: continuityLost ? 'partial' : 'verified', sourceScope, observationSafe: continuityLost ? null : value,
        beforeBaselineRevision: baseline?.revision ?? null, sourceProof: proof };
      const registered: PrivateProof = { inputHmac: this.hashInput(input), snapshot: captured, createdAt: Date.now(), active: true };
      this.proofs.set(proof, registered);
      return { input, release: (committed = false) => {
        registered.active = false; this.proofs.delete(proof);
        if (committed) {
          this.discontinuities.delete(subjectKey); this.confirmedSubjects.add(subjectKey);
          if (this.confirmedSubjects.size > 1000) this.confirmedSubjects.delete(this.confirmedSubjects.values().next().value!);
        } else this.noteGap(cid, type, id);
      } };
    });
  }
}
